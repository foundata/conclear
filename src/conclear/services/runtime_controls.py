"""Comparison of configured runtime controls with Podman's effective observation.

`control_findings` judges the user, read-only root, exact writable set, resource
limits, capabilities, namespaces, privilege and stop-signal expectations of one
image against the controls Podman reports for a created container. The runtime
test session applies it to every preparation container and to the primary
launch; `controls_dict` renders the observation for the test report.
"""

from conclear.adapters.podman import RuntimeControlObservation
from conclear.checks import normalized_signal
from conclear.config import SYSTEMD_STOP_SIGNAL, ImageConfig
from conclear.errors import OperationalError
from conclear.presentation import Finding


def control_findings(
    image: ImageConfig, observed: RuntimeControlObservation
) -> tuple[Finding, ...]:
    """Return one finding for every effective control that differs from the image."""
    expected = image.runtime
    mismatches: list[str] = []
    messages: dict[str, str] = {}
    if observed.user.split(":", maxsplit=1)[0] != str(expected.user):
        mismatches.append("user")
    if observed.read_only is not expected.read_only:
        mismatches.append("read-only root")
    if observed.writable_mounts != tuple(sorted(expected.writable_mounts)):
        mismatches.append("writable mounts")
        unexpected = sorted(
            set(observed.writable_mounts) - set(expected.writable_mounts)
        )
        missing = sorted(set(expected.writable_mounts) - set(observed.writable_mounts))
        messages["writable mounts"] = (
            "Effective runtime writable mounts do not match configuration "
            f"(unexpected: {', '.join(unexpected) or 'none'}; "
            f"missing: {', '.join(missing) or 'none'})"
        )
    if observed.memory_bytes != _memory_bytes(expected.memory):
        mismatches.append("memory")
    if observed.nano_cpus != round(expected.cpus * 1_000_000_000):
        mismatches.append("CPU")
    if observed.pids_limit != expected.pids:
        mismatches.append("PID")
    if (
        observed.nofile_soft != expected.nofile
        or observed.nofile_hard != expected.nofile
    ):
        mismatches.append("nofile")
    no_new_privileges = any(
        value.lower().replace("_", "-") == "no-new-privileges"
        for value in observed.security_options
    )
    if no_new_privileges is not expected.no_new_privileges:
        mismatches.append("no-new-privileges")
    if observed.user_namespace != "private":
        mismatches.append("user namespace")
    if observed.cgroup_namespace != "private":
        mismatches.append("cgroup namespace")
    if observed.privileged:
        mismatches.append("privileged mode")
    if expected.systemd is not None and normalized_signal(
        observed.stop_signal
    ) != normalized_signal(SYSTEMD_STOP_SIGNAL):
        mismatches.append("stop signal")
    # Podman reports CapAdd and CapDrop relative to its own default set, so an
    # explicitly added default capability is invisible there; the bounding set
    # is the authoritative statement of what the container may ever hold.
    expected_add = {item.removeprefix("CAP_") for item in expected.capabilities}
    bounding = {
        item.removeprefix("CAP_").upper() for item in observed.bounding_capabilities
    }
    effective = {
        item.removeprefix("CAP_").upper() for item in observed.effective_capabilities
    }
    if not effective.issubset(expected_add):
        mismatches.append("capability drop")
    if bounding != expected_add:
        mismatches.append("added capabilities")
    return tuple(
        Finding(
            "CC0401"
            if name
            in {
                "user",
                "read-only root",
                "writable mounts",
                "no-new-privileges",
                "capability drop",
                "added capabilities",
                "user namespace",
                "cgroup namespace",
                "privileged mode",
                "stop signal",
            }
            else "CC0402",
            "error",
            messages.get(
                name, f"Effective runtime {name} control does not match configuration"
            ),
        )
        for name in mismatches
    )


def controls_dict(value: RuntimeControlObservation) -> dict[str, object]:
    """Render the observed controls for the test report."""
    return {
        "user": value.user,
        "readOnly": value.read_only,
        "writableMounts": list(value.writable_mounts),
        "memoryBytes": value.memory_bytes,
        "nanoCpus": value.nano_cpus,
        "pidsLimit": value.pids_limit,
        "nofile": [value.nofile_soft, value.nofile_hard],
        "capAdd": list(value.cap_add),
        "capDrop": list(value.cap_drop),
        "boundingCapabilities": list(value.bounding_capabilities),
        "effectiveCapabilities": list(value.effective_capabilities),
        "securityOptions": list(value.security_options),
        "userNamespace": value.user_namespace,
        "cgroupNamespace": value.cgroup_namespace,
        "privileged": value.privileged,
        "stopSignal": value.stop_signal,
    }


def _memory_bytes(value: str) -> int:
    units = {"KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
    for suffix, multiplier in units.items():
        if value.endswith(suffix):
            return int(value.removesuffix(suffix)) * multiplier
    raise OperationalError(f"Unsupported memory value: {value}")
