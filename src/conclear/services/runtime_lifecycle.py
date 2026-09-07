"""Lifecycle of one constrained test container under its runtime profile.

`exercise_container` observes the effective controls of the created primary
container, then drives the profile-specific lifecycle: a one-shot image must
exit with the expected status within the startup budget; a service must keep
running, become healthy within one monotonic readiness budget, keep its
immutable paths root-owned and unwritable, and stop cleanly on the configured
signal; a systemd image additionally proves PID 1, an operational manager and
every required unit. `RuntimeAdapter` is the complete Podman boundary that the
session and this lifecycle use. Nothing here touches the run workspace; the
session in `conclear.services.runtime_tests` owns every resource.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from conclear.adapters.podman import (
    BindMount,
    ContainerObservation,
    ExecObservation,
    ImportObservation,
    RuntimeControlObservation,
)
from conclear.config import SYSTEMD_STOP_SIGNAL, RuntimeConfig
from conclear.errors import OperationalError
from conclear.jsonutil import canonical_json_bytes, sha256_bytes
from conclear.presentation import Finding
from conclear.services.qualification_inputs import (
    QualificationInputs,
    execution_observation,
)
from conclear.services.runtime_controls import control_findings, controls_dict
from conclear.values import Digest, Platform

_HEALTH_POLL_INTERVAL_SECONDS = 0.25
_HEALTH_DIAGNOSTIC_TIMEOUT_SECONDS = 5.0


class RuntimeAdapter(Protocol):
    """Podman adapter boundary used by qualification."""

    def import_layout(
        self,
        *,
        root: Path,
        runroot: Path,
        layout_path: Path,
        layout_reference: str,
        image_name: str,
        expected_digest: Digest,
    ) -> ImportObservation:
        """Import and re-resolve one exact layout."""
        ...

    def create_container(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        image_name: str,
        runtime: RuntimeConfig,
        platform: Platform,
        arguments: tuple[str, ...] = (),
        environment: tuple[tuple[str, str], ...] = (),
        mounts: tuple[BindMount, ...] = (),
        entrypoint: tuple[str, ...] = (),
    ) -> ContainerObservation:
        """Create one constrained runtime container."""
        ...

    def inspect_controls(
        self, *, root: Path, runroot: Path, name: str
    ) -> RuntimeControlObservation:
        """Observe effective runtime controls."""
        ...

    def inspect_container(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        timeout_seconds: float = 120,
    ) -> ContainerObservation:
        """Observe the current container process state."""
        ...

    def exec(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        command: tuple[str, ...],
        timeout_seconds: float,
    ) -> str:
        """Execute one fixed argument array."""
        ...

    def inspect_pid1(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        timeout_seconds: float,
    ) -> str:
        """Observe the command name for container PID 1."""
        ...

    def exec_observe(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        command: tuple[str, ...],
        timeout_seconds: float,
    ) -> ExecObservation:
        """Observe one in-container command without rejecting its exit status."""
        ...

    def signal(self, *, root: Path, runroot: Path, name: str, signal_name: str) -> None:
        """Signal the container's PID 1."""
        ...

    def wait(
        self, *, root: Path, runroot: Path, name: str, timeout_seconds: float
    ) -> int:
        """Wait and return the container process status."""
        ...

    def remove(
        self, *, root: Path, runroot: Path, name: str, force: bool = False
    ) -> None:
        """Remove one run-owned container."""
        ...

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        """Reset one isolated run-owned Podman storage root."""
        ...


@dataclass(frozen=True, slots=True)
class ReadinessTiming:
    """Monotonic clock and bounded sleep used by readiness polling.

    Production uses the process clock; tests inject a controlled clock through
    the private `_readiness_timing` seam of `test_platform`.
    """

    monotonic: Callable[[], float]
    sleep: Callable[[float], None]
    interval_seconds: float = _HEALTH_POLL_INTERVAL_SECONDS


@dataclass(frozen=True, slots=True)
class _HealthObservation:
    """Final bounded observation from service readiness polling."""

    outcome: Literal["ready", "timeout", "exited"]
    attempts: int
    elapsed_seconds: float
    timeout_seconds: int
    command: ExecObservation | None
    container: ContainerObservation


def exercise_container(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    imported: ImportObservation,
    container: ContainerObservation,
    *,
    storage_root: Path,
    runroot: Path,
    container_name: str,
    readiness_timing: ReadinessTiming | None,
) -> tuple[list[Finding], list[dict[str, object]], dict[str, object]]:
    """Judge the created primary container and return findings, results and mode."""
    findings: list[Finding] = []
    results: list[dict[str, object]] = [
        {
            "name": "importDigest",
            "status": "passed",
            "digest": str(imported.digest),
        }
    ]
    controls = runtime.inspect_controls(
        root=storage_root, runroot=runroot, name=container_name
    )
    findings.extend(control_findings(inputs.image, controls))
    results.append(
        {
            "name": "runtimeControls",
            "status": "passed" if not findings else "failed",
            "observed": controls_dict(controls),
        }
    )
    native = (
        _normalized_architecture(inputs.host_architecture)
        == inputs.platform.architecture
    )
    if inputs.platform in inputs.image.native_test_platforms and not native:
        findings.append(
            Finding(
                "CC0403",
                "error",
                f"Platform {inputs.platform} requires native runtime testing",
            )
        )
    if inputs.image.runtime.profile in {"service", "systemd"}:
        _exercise_service(
            inputs,
            runtime,
            container,
            storage_root=storage_root,
            runroot=runroot,
            container_name=container_name,
            findings=findings,
            results=results,
            readiness_timing=readiness_timing,
        )
    else:
        exit_status = runtime.wait(
            root=storage_root,
            runroot=runroot,
            name=container_name,
            timeout_seconds=inputs.image.runtime.startup_timeout_seconds,
        )
        expected_exit_status = inputs.image.test.launch.expected_exit_status
        if exit_status != expected_exit_status:
            findings.append(
                Finding(
                    "CC0403",
                    "error",
                    f"One-shot image exited with {exit_status}, expected {expected_exit_status}",
                )
            )
        results.append(
            {
                "name": "oneShotExit",
                "status": (
                    "passed" if exit_status == expected_exit_status else "failed"
                ),
                "exitStatus": exit_status,
            }
        )
    return findings, results, execution_observation(inputs)


def _exercise_service(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    container: ContainerObservation,
    *,
    storage_root: Path,
    runroot: Path,
    container_name: str,
    findings: list[Finding],
    results: list[dict[str, object]],
    readiness_timing: ReadinessTiming | None,
) -> None:
    running = _container_is_running(container)
    if not running:
        findings.append(Finding("CC0403", "error", "Service did not remain running"))
        results.append(
            {
                "name": "startup",
                "status": "failed",
                "containerStatus": container.status,
                "containerExitStatus": container.exit_code,
            }
        )
    else:
        results.append(
            {
                "name": "startup",
                "status": "passed",
                "containerStatus": container.status,
                "containerExitStatus": container.exit_code,
            }
        )
    timing = readiness_timing or ReadinessTiming(
        monotonic=time.monotonic, sleep=time.sleep
    )
    readiness_start = timing.monotonic()
    readiness_deadline = readiness_start + inputs.image.runtime.startup_timeout_seconds
    if running and inputs.image.runtime.systemd is not None:
        container, running = _exercise_systemd_readiness(
            inputs,
            runtime,
            container,
            storage_root=storage_root,
            runroot=runroot,
            container_name=container_name,
            findings=findings,
            results=results,
            timing=timing,
            readiness_start=readiness_start,
            readiness_deadline=readiness_deadline,
        )
    if running and inputs.image.runtime.health_command:
        health = _wait_for_service_health(
            runtime,
            root=storage_root,
            runroot=runroot,
            name=container_name,
            command=inputs.image.runtime.health_command,
            initial=container,
            timeout_seconds=inputs.image.runtime.startup_timeout_seconds,
            timing=timing,
            start_time=readiness_start,
            deadline=readiness_deadline,
        )
        results.append(_health_test_result(health))
        container = health.container
        running = _container_is_running(container)
        if health.outcome == "timeout":
            findings.append(
                Finding(
                    "CC0403",
                    "error",
                    "Service health did not succeed within "
                    f"{health.timeout_seconds}s after {health.attempts} attempts",
                )
            )
        elif health.outcome == "exited" and not any(
            finding.message == "Service did not remain running" for finding in findings
        ):
            suffix = (
                "unknown" if container.exit_code is None else str(container.exit_code)
            )
            findings.append(
                Finding(
                    "CC0403",
                    "error",
                    f"Service exited with status {suffix} before becoming ready",
                )
            )
    if not running:
        shutdown_result: dict[str, object] = {
            "name": "signalAndShutdown",
            "status": "failed",
            "containerStatus": container.status,
            "containerExitStatus": container.exit_code,
        }
        if container.exit_code is not None:
            shutdown_result["exitStatus"] = container.exit_code
        results.append(shutdown_result)
        return
    _check_immutable_paths(
        inputs, runtime, storage_root, runroot, container_name, findings
    )
    signal_name = (
        "TERM" if inputs.image.runtime.systemd is None else SYSTEMD_STOP_SIGNAL
    )
    runtime.signal(
        root=storage_root,
        runroot=runroot,
        name=container_name,
        signal_name=signal_name,
    )
    exit_status = runtime.wait(
        root=storage_root,
        runroot=runroot,
        name=container_name,
        timeout_seconds=inputs.image.runtime.shutdown_timeout_seconds,
    )
    expected_exit_status = inputs.image.test.launch.expected_exit_status
    if exit_status != expected_exit_status:
        findings.append(
            Finding(
                "CC0403",
                "error",
                f"Service returned {exit_status} after graceful termination, expected {expected_exit_status}",
            )
        )
    results.append(
        {
            "name": "signalAndShutdown",
            "status": "passed" if exit_status == expected_exit_status else "failed",
            "exitStatus": exit_status,
        }
    )


def _exercise_systemd_readiness(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    container: ContainerObservation,
    *,
    storage_root: Path,
    runroot: Path,
    container_name: str,
    findings: list[Finding],
    results: list[dict[str, object]],
    timing: ReadinessTiming,
    readiness_start: float,
    readiness_deadline: float,
) -> tuple[ContainerObservation, bool]:
    systemd = inputs.image.runtime.systemd
    if systemd is None:
        raise OperationalError("Systemd readiness requires systemd configuration")
    remaining = readiness_deadline - timing.monotonic()
    if remaining <= 0:
        findings.append(
            Finding("CC0403", "error", "Systemd readiness deadline expired")
        )
        return container, _container_is_running(container)
    pid1 = runtime.inspect_pid1(
        root=storage_root,
        runroot=runroot,
        name=container_name,
        timeout_seconds=remaining,
    )
    pid1_passed = Path(pid1).name == "systemd"
    results.append(
        {
            "name": "systemdPid1",
            "status": "passed" if pid1_passed else "failed",
            "outputDigest": sha256_bytes(pid1.encode("utf-8")),
        }
    )
    if not pid1_passed:
        findings.append(
            Finding("CC0403", "error", f"Container PID 1 is not systemd: {pid1}")
        )
        return container, _container_is_running(container)

    remaining = readiness_deadline - timing.monotonic()
    if remaining <= 0:
        findings.append(
            Finding("CC0403", "error", "Systemd readiness deadline expired")
        )
        return container, _container_is_running(container)
    manager = runtime.exec_observe(
        root=storage_root,
        runroot=runroot,
        name=container_name,
        command=("systemctl", "show", "--property=Version", "--value"),
        timeout_seconds=remaining,
    )
    manager_passed = manager.exit_status == 0 and bool(manager.stdout.strip())
    results.append(_command_test_result("systemdManager", manager, manager_passed))
    if not manager_passed:
        findings.append(
            Finding("CC0403", "error", "Systemd manager is not operational")
        )
        return container, _container_is_running(container)

    for unit in systemd.required_units:
        observation = _wait_for_service_health(
            runtime,
            root=storage_root,
            runroot=runroot,
            name=container_name,
            command=("systemctl", "is-active", "--quiet", unit),
            initial=container,
            timeout_seconds=inputs.image.runtime.startup_timeout_seconds,
            timing=timing,
            start_time=readiness_start,
            deadline=readiness_deadline,
        )
        result = _health_test_result(observation)
        result["name"] = f"systemdUnit:{unit}"
        results.append(result)
        container = observation.container
        if observation.outcome != "ready":
            findings.append(
                Finding(
                    "CC0403",
                    "error",
                    f"Required systemd unit did not become active: {unit}",
                )
            )
            return container, _container_is_running(container)
    return container, _container_is_running(container)


def _command_test_result(
    name: str, observation: ExecObservation, passed: bool
) -> dict[str, object]:
    return {
        "name": name,
        "status": "passed" if passed else "failed",
        "exitStatus": observation.exit_status,
        "outputDigest": sha256_bytes(
            canonical_json_bytes(
                {"stdout": observation.stdout, "stderr": observation.stderr}
            )
        ),
    }


def _wait_for_service_health(
    runtime: RuntimeAdapter,
    *,
    root: Path,
    runroot: Path,
    name: str,
    command: tuple[str, ...],
    initial: ContainerObservation,
    timeout_seconds: int,
    timing: ReadinessTiming,
    start_time: float | None = None,
    deadline: float | None = None,
) -> _HealthObservation:
    if timing.interval_seconds <= 0:
        raise OperationalError("Readiness polling interval must be positive")
    start = timing.monotonic() if start_time is None else start_time
    deadline = start + timeout_seconds if deadline is None else deadline
    attempts = 0
    current = initial
    final_command: ExecObservation | None = None
    while True:
        now = timing.monotonic()
        if not _container_is_running(current):
            return _HealthObservation(
                "exited",
                attempts,
                max(0.0, now - start),
                timeout_seconds,
                final_command,
                current,
            )
        remaining = deadline - now
        if remaining <= 0:
            return _HealthObservation(
                "timeout",
                attempts,
                max(0.0, now - start),
                timeout_seconds,
                final_command,
                current,
            )
        attempts += 1
        final_command = runtime.exec_observe(
            root=root,
            runroot=runroot,
            name=name,
            command=command,
            timeout_seconds=remaining,
        )
        now = timing.monotonic()
        if final_command.exit_status == 0:
            return _HealthObservation(
                "ready",
                attempts,
                max(0.0, now - start),
                timeout_seconds,
                final_command,
                current,
            )
        remaining = deadline - now
        if remaining > 0:
            timing.sleep(min(timing.interval_seconds, remaining))
        remaining = deadline - timing.monotonic()
        current = runtime.inspect_container(
            root=root,
            runroot=runroot,
            name=name,
            timeout_seconds=(
                remaining if remaining > 0 else _HEALTH_DIAGNOSTIC_TIMEOUT_SECONDS
            ),
        )


def _health_test_result(observation: _HealthObservation) -> dict[str, object]:
    command = observation.command
    result: dict[str, object] = {
        "name": "health",
        "status": "passed" if observation.outcome == "ready" else "failed",
        "outcome": observation.outcome,
        "attempts": observation.attempts,
        "elapsedSeconds": round(observation.elapsed_seconds, 6),
        "timeoutSeconds": observation.timeout_seconds,
        "containerStatus": observation.container.status,
        "containerExitStatus": observation.container.exit_code,
        "outputDigest": sha256_bytes(
            canonical_json_bytes(
                {
                    "stdout": "" if command is None else command.stdout,
                    "stderr": "" if command is None else command.stderr,
                }
            )
        ),
    }
    if command is not None:
        result["exitStatus"] = command.exit_status
    return result


def _container_is_running(container: ContainerObservation) -> bool:
    return container.status == "running" and container.pid > 0


def _check_immutable_paths(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    root: Path,
    runroot: Path,
    name: str,
    findings: list[Finding],
) -> None:
    paths = inputs.image.runtime.immutable_paths
    if not paths:
        return
    output = runtime.exec(
        root=root,
        runroot=runroot,
        name=name,
        command=("stat", "--format=%u:%a", "--", *paths),
        timeout_seconds=120,
    )
    lines = output.splitlines()
    if len(lines) != len(paths):
        raise OperationalError(
            "Immutable path ownership probe returned incomplete output"
        )
    for path, line in zip(paths, lines, strict=True):
        owner, separator, mode_text = line.partition(":")
        try:
            mode = int(mode_text, 8)
        except ValueError as exc:
            raise OperationalError("Immutable path mode probe is malformed") from exc
        if separator != ":" or owner != "0" or mode & 0o022:
            findings.append(
                Finding(
                    "CC0404",
                    "error",
                    (
                        "Immutable runtime path is not root-owned or has a "
                        "group/other write bit"
                    ),
                    path,
                )
            )


def _normalized_architecture(value: str) -> str:
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(value, value)
