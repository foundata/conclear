from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from conclear.adapters.podman import RuntimeControlObservation
from conclear.config import ImageConfig, load_repository_config
from conclear.errors import OperationalError
from conclear.services.runtime_controls import control_findings, controls_dict


@pytest.fixture
def image(repository_factory: Callable[..., Path]) -> ImageConfig:
    return load_repository_config(repository_factory() / "conclear.toml").images[0]


def matching_observation(image: ImageConfig) -> RuntimeControlObservation:
    runtime = image.runtime
    capabilities = tuple(item.removeprefix("CAP_") for item in runtime.capabilities)
    return RuntimeControlObservation(
        user=f"{runtime.user}:{runtime.user}",
        read_only=runtime.read_only,
        writable_mounts=tuple(sorted(runtime.writable_mounts)),
        memory_bytes=512 * 1024 * 1024,
        nano_cpus=round(runtime.cpus * 1_000_000_000),
        pids_limit=runtime.pids,
        nofile_soft=runtime.nofile,
        nofile_hard=runtime.nofile,
        cap_add=capabilities,
        cap_drop=("ALL",),
        bounding_capabilities=capabilities,
        effective_capabilities=capabilities,
        security_options=("label=disable", "no_new_privileges"),
    )


def test_matching_controls_produce_no_findings_and_render_completely(
    image: ImageConfig,
) -> None:
    assert image.runtime.memory == "512MiB"
    observed = matching_observation(image)
    assert control_findings(image, observed) == ()
    rendered = controls_dict(observed)
    assert rendered["user"] == observed.user
    assert rendered["nofile"] == [observed.nofile_soft, observed.nofile_hard]
    assert rendered["writableMounts"] == list(observed.writable_mounts)
    assert set(rendered) == {
        "user",
        "readOnly",
        "writableMounts",
        "memoryBytes",
        "nanoCpus",
        "pidsLimit",
        "nofile",
        "capAdd",
        "capDrop",
        "boundingCapabilities",
        "effectiveCapabilities",
        "securityOptions",
        "userNamespace",
        "cgroupNamespace",
        "privileged",
        "stopSignal",
    }


@pytest.mark.parametrize(
    ("changes", "code", "control"),
    [
        ({"user": "0:0"}, "CC0401", "user"),
        ({"read_only": False}, "CC0401", "read-only root"),
        ({"security_options": ("label=disable",)}, "CC0401", "no-new-privileges"),
        ({"user_namespace": "host"}, "CC0401", "user namespace"),
        ({"cgroup_namespace": "host"}, "CC0401", "cgroup namespace"),
        ({"privileged": True}, "CC0401", "privileged mode"),
        ({"bounding_capabilities": ("NET_ADMIN",)}, "CC0401", "added capabilities"),
        ({"effective_capabilities": ("SYS_ADMIN",)}, "CC0401", "capability drop"),
        ({"memory_bytes": 256 * 1024 * 1024}, "CC0402", "memory"),
        ({"nano_cpus": 2_000_000_000}, "CC0402", "CPU"),
        ({"pids_limit": 1}, "CC0402", "PID"),
        ({"nofile_hard": 2048}, "CC0402", "nofile"),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_each_control_mismatch_is_classified_by_its_stable_check(
    image: ImageConfig, changes: dict[str, Any], code: str, control: str
) -> None:
    observed = replace(matching_observation(image), **changes)
    findings = control_findings(image, observed)
    assert [(item.check_id, item.severity) for item in findings] == [(code, "error")]
    assert findings[0].message == (
        f"Effective runtime {control} control does not match configuration"
    )


def test_writable_mount_mismatch_names_unexpected_and_missing_paths(
    image: ImageConfig,
) -> None:
    expected = replace(image.runtime, writable_mounts=("/var/cache", "/var/lib/app"))
    observed = replace(
        matching_observation(image), writable_mounts=("/tmp", "/var/lib/app")
    )
    findings = control_findings(replace(image, runtime=expected), observed)
    assert [item.check_id for item in findings] == ["CC0401"]
    assert findings[0].message == (
        "Effective runtime writable mounts do not match configuration "
        "(unexpected: /tmp; missing: /var/cache)"
    )


def test_stop_signal_is_compared_only_for_systemd_images(image: ImageConfig) -> None:
    observed = replace(matching_observation(image), stop_signal="SIGKILL")
    assert control_findings(image, observed) == ()


def test_unsupported_memory_unit_is_an_operational_failure(image: ImageConfig) -> None:
    unsupported = replace(image, runtime=replace(image.runtime, memory="512MB"))
    with pytest.raises(OperationalError, match="Unsupported memory value"):
        control_findings(unsupported, matching_observation(image))
