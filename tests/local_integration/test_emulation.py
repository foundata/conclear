"""Real arm64 execution through the host's enabled QEMU user-mode handler.

This tier is selected explicitly with ``-m emulation``. It skips when the host
has no enabled arm64 ``binfmt_misc`` handler, because ConClear never installs
emulators or registers handlers itself; the hermetic suite covers the refusal
paths for that situation.
"""

import json
import platform as host_platform
from pathlib import Path

import pytest

from conclear.emulation import detect_execution_mode, validate_execution_observation
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import atomic_write_json
from conclear.path_safety import contained_path
from conclear.runtime import ApplicationRuntime
from conclear.tools import ToolName
from conclear.values import Platform
from tests.local_integration.fixtures import (
    compile_fixture,
    manifest_run_id,
    runtime_config,
)

pytestmark = pytest.mark.emulation

TARGET = Platform.parse("linux/arm64")


def test_real_arm64_fixture_executes_through_the_detected_handler(
    tmp_path: Path,
) -> None:
    run_id = manifest_run_id()
    host = host_platform.machine()
    try:
        mode = detect_execution_mode(host, TARGET)
    except OperationalError as exc:
        pytest.skip(f"arm64 emulation is unavailable on this host: {exc}")
    if mode.native:
        pytest.skip("host executes arm64 natively; emulation cannot be exercised")
    assert mode.handler is not None
    resource_id = run_id.lower()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(
        root / "environment", names=(ToolName.BUILDAH, ToolName.PODMAN)
    )
    buildah_root = root / "buildah" / "root"
    buildah_runroot = root / "buildah" / "runroot"
    podman_root = root / "podman" / "root"
    podman_runroot = root / "podman" / "runroot"
    container = f"cc-{resource_id}-arm64-arch"
    buildah_ready = False
    podman_ready = False
    try:
        assert runtime.buildah().info(root=buildah_root, runroot=buildah_runroot)
        buildah_ready = True
        assert runtime.podman().info(root=podman_root, runroot=podman_runroot)
        podman_ready = True
        context = compile_fixture(runtime, root=root, architecture="arm64")
        observation = runtime.buildah().build(
            root=buildah_root,
            runroot=buildah_runroot,
            containerfile=context / "Containerfile",
            context=context,
            platform=TARGET,
            image_name=f"localhost/conclear-{resource_id}-arm64:fixture",
            layout_path=root / "layouts" / "arm64",
            layout_reference="fixture",
            source_epoch=946684800,
            build_arguments={
                "IMAGE_CREATED": "2000-01-01T00:00:00Z",
                "IMAGE_REVISION": "a" * 40,
                "IMAGE_SOURCE": "https://github.com/foundata/conclear",
                "IMAGE_VERSION": "integration",
            },
            auth_file=None,
        )
        assert observation.graph.manifests[0].platform == TARGET
        image_name = f"localhost/conclear-{resource_id}-arm64:runtime"
        runtime.podman().import_layout(
            root=podman_root,
            runroot=podman_runroot,
            layout_path=observation.layout_path,
            layout_reference="fixture",
            image_name=image_name,
            expected_digest=observation.graph.digest,
        )
        created = runtime.podman().create_container(
            root=podman_root,
            runroot=podman_runroot,
            name=container,
            image_name=image_name,
            runtime=runtime_config(profile="one-shot"),
            platform=TARGET,
            arguments=("arch-check", "arm64"),
        )
        assert created.status in {"running", "exited", "stopped"}
        exit_status = runtime.podman().wait(
            root=podman_root,
            runroot=podman_runroot,
            name=container,
            timeout_seconds=120,
        )
        # The fixture exits 3 when its runtime GOARCH differs from the
        # requested architecture, so 0 proves actual arm64 execution.
        assert exit_status == 0
        evidence = {
            **mode.to_dict(),
            "handler": mode.handler.name,
            "interpreter": mode.handler.interpreter,
            "flags": mode.handler.flags,
            "fixtureExitStatus": exit_status,
        }
        atomic_write_json(root / "execution-mode.json", evidence, mode=0o644)
        recorded = json.loads((root / "execution-mode.json").read_text("utf-8"))
        assert recorded["mechanism"] == "qemu-user"
        assert recorded["hostArchitecture"] == host
        assert recorded["executionArchitecture"] == "arm64"
        validate_execution_observation(mode.to_dict(), platform=TARGET)
        with pytest.raises(InvalidInvocationError, match="claims native"):
            validate_execution_observation(
                {**mode.to_dict(), "mechanism": "native"}, platform=TARGET
            )
    finally:
        if podman_ready:
            runtime.podman().remove(
                root=podman_root, runroot=podman_runroot, name=container, force=True
            )
            runtime.podman().remove_storage(root=podman_root, runroot=podman_runroot)
        if buildah_ready:
            runtime.buildah().remove_storage(root=buildah_root, runroot=buildah_runroot)
