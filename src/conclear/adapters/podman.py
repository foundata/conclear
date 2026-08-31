"""Rootless Podman runtime-test adapter."""

from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.adapters.parsing import json_value, object_value, string_value
from conclear.config import RuntimeConfig
from conclear.errors import OperationalError
from conclear.process import OperationKind
from conclear.values import Digest, Platform


@dataclass(frozen=True, slots=True)
class ImportObservation:
    """Digest and name observed after importing an OCI layout."""

    image_name: str
    digest: Digest


@dataclass(frozen=True, slots=True)
class ContainerObservation:
    """Observed runtime state for one run-owned container."""

    name: str
    container_id: str
    status: str
    pid: int
    exit_code: int | None


@dataclass(frozen=True, slots=True)
class RuntimeControlObservation:
    """Effective runtime controls observed from Podman state."""

    user: str
    read_only: bool
    writable_mounts: tuple[str, ...]
    memory_bytes: int
    nano_cpus: int
    pids_limit: int
    nofile_soft: int
    nofile_hard: int
    cap_add: tuple[str, ...]
    cap_drop: tuple[str, ...]
    effective_capabilities: tuple[str, ...]
    security_options: tuple[str, ...]


class PodmanAdapter(ToolAdapter):
    """Import exact layouts and run constrained rootless containers."""

    def _storage(self, root: Path, runroot: Path) -> tuple[str, ...]:
        return ("--root", str(root), "--runroot", str(runroot))

    def info(self, *, root: Path, runroot: Path) -> dict[str, object]:
        """Validate access to isolated rootless Podman storage."""
        output = self._run(
            (*self._storage(root, runroot), "info", "--format", "json"),
            timeout_seconds=120,
        ).stdout
        value = object_value(
            json_value(output, label="Podman info"), label="Podman info"
        )
        host = object_value(value.get("host"), label="Podman host info")
        security = object_value(host.get("security"), label="Podman security info")
        if security.get("rootless") is not True:
            raise OperationalError("Podman did not report rootless execution")
        return value

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
        """Import an OCI layout and resolve the imported manifest back by digest."""
        pull_result = self._run(
            (
                *self._storage(root, runroot),
                "pull",
                "--quiet",
                f"oci:{layout_path}:{layout_reference}",
            ),
            timeout_seconds=900,
            operation=OperationKind.WRITE,
        )
        identifiers = pull_result.stdout.strip().splitlines()
        if not identifiers:
            raise OperationalError("Podman pull returned no imported image identifier")
        imported_identifier = identifiers[-1]
        self._run(
            (*self._storage(root, runroot), "tag", imported_identifier, image_name),
            timeout_seconds=120,
            operation=OperationKind.WRITE,
        )
        result = self._run(
            (
                *self._storage(root, runroot),
                "image",
                "inspect",
                "--format",
                "{{.Digest}}",
                image_name,
            ),
            timeout_seconds=120,
        )
        try:
            observed = Digest(result.stdout.strip())
        except Exception as exc:
            raise OperationalError(
                "Podman returned an invalid imported digest"
            ) from exc
        if observed != expected_digest:
            raise OperationalError(
                f"Podman imported digest {observed} differs from layout {expected_digest}"
            )
        return ImportObservation(image_name, observed)

    def create_container(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        image_name: str,
        runtime: RuntimeConfig,
        platform: Platform,
        command: tuple[str, ...] = (),
    ) -> ContainerObservation:
        """Create and start a container with all declared resource controls."""
        arguments = [
            *self._storage(root, runroot),
            "run",
            "--detach",
            "--name",
            name,
            "--platform",
            str(platform),
            "--user",
            str(runtime.user),
            "--memory",
            runtime.memory,
            "--cpus",
            str(runtime.cpus),
            "--pids-limit",
            str(runtime.pids),
            "--ulimit",
            f"nofile={runtime.nofile}:{runtime.nofile}",
            "--cap-drop",
            "all",
            "--security-opt",
            "no-new-privileges",
        ]
        if runtime.read_only:
            arguments.append("--read-only")
        for mount in runtime.writable_mounts:
            arguments.extend(("--tmpfs", f"{mount}:rw,nosuid,nodev"))
        for capability in runtime.capabilities:
            arguments.extend(("--cap-add", capability.removeprefix("CAP_")))
        arguments.append(image_name)
        arguments.extend(command)
        self._run(arguments, timeout_seconds=300, operation=OperationKind.WRITE)
        return self.inspect_container(root=root, runroot=runroot, name=name)

    def inspect_container(
        self, *, root: Path, runroot: Path, name: str
    ) -> ContainerObservation:
        """Inspect one run-owned container without trusting Podman JSON types."""
        output = self._run(
            (
                *self._storage(root, runroot),
                "container",
                "inspect",
                "--format",
                "json",
                name,
            ),
            timeout_seconds=120,
        ).stdout
        value = json_value(output, label="Podman inspect")
        if not isinstance(value, list) or len(value) != 1:
            raise OperationalError("Podman inspect must return one container")
        item = object_value(value[0], label="Podman container")
        state = object_value(item.get("State"), label="Podman container state")
        pid_value = state.get("Pid")
        exit_value = state.get("ExitCode")
        if not isinstance(pid_value, int) or isinstance(pid_value, bool):
            raise OperationalError("Podman container PID is malformed")
        if exit_value is not None and (
            not isinstance(exit_value, int) or isinstance(exit_value, bool)
        ):
            raise OperationalError("Podman container exit code is malformed")
        return ContainerObservation(
            name=name,
            container_id=string_value(item.get("Id"), label="Podman container ID"),
            status=string_value(state.get("Status"), label="Podman container status"),
            pid=pid_value,
            exit_code=exit_value,
        )

    def exec(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        command: tuple[str, ...],
        timeout_seconds: float,
    ) -> str:
        """Execute one argument-array health or assertion command."""
        return self._run(
            (*self._storage(root, runroot), "exec", name, *command),
            timeout_seconds=timeout_seconds,
        ).stdout

    def inspect_controls(
        self, *, root: Path, runroot: Path, name: str
    ) -> RuntimeControlObservation:
        """Observe resource and hardening controls from Podman's stored state."""
        output = self._run(
            (
                *self._storage(root, runroot),
                "container",
                "inspect",
                "--format",
                "json",
                name,
            ),
            timeout_seconds=120,
        ).stdout
        value = json_value(output, label="Podman inspect")
        if not isinstance(value, list) or len(value) != 1:
            raise OperationalError("Podman inspect must return one container")
        item = object_value(value[0], label="Podman container")
        if "EffectiveCaps" not in item:
            raise OperationalError(
                "Podman did not report effective container capabilities"
            )
        config = object_value(item.get("Config"), label="Podman container config")
        host = object_value(item.get("HostConfig"), label="Podman host config")
        ulimits = host.get("Ulimits")
        if not isinstance(ulimits, list):
            raise OperationalError("Podman ulimit observation is malformed")
        nofile = [
            entry
            for entry in ulimits
            if isinstance(entry, dict) and entry.get("Name") == "RLIMIT_NOFILE"
        ]
        if len(nofile) != 1:
            raise OperationalError("Podman did not report exactly one nofile limit")
        limit = object_value(nofile[0], label="Podman nofile limit")
        return RuntimeControlObservation(
            user=string_value(config.get("User"), label="Podman effective user"),
            read_only=_bool(host.get("ReadonlyRootfs"), "Podman read-only root"),
            writable_mounts=_string_mapping_keys(
                host.get("Tmpfs"), "Podman tmpfs mounts"
            ),
            memory_bytes=_int(host.get("Memory"), "Podman memory limit"),
            nano_cpus=_int(host.get("NanoCpus"), "Podman CPU limit"),
            pids_limit=_int(host.get("PidsLimit"), "Podman PID limit"),
            nofile_soft=_int(limit.get("Soft"), "Podman nofile soft limit"),
            nofile_hard=_int(limit.get("Hard"), "Podman nofile hard limit"),
            cap_add=_strings(host.get("CapAdd"), "Podman added capabilities"),
            cap_drop=_strings(host.get("CapDrop"), "Podman dropped capabilities"),
            effective_capabilities=_strings(
                item.get("EffectiveCaps"), "Podman effective capabilities"
            ),
            security_options=_strings(
                host.get("SecurityOpt"), "Podman security options"
            ),
        )

    def signal(self, *, root: Path, runroot: Path, name: str, signal_name: str) -> None:
        """Send one named signal to the container's PID 1."""
        self._run(
            (*self._storage(root, runroot), "kill", "--signal", signal_name, name),
            timeout_seconds=120,
            operation=OperationKind.WRITE,
        )

    def wait(
        self, *, root: Path, runroot: Path, name: str, timeout_seconds: float
    ) -> int:
        """Wait for a container and return its observed process exit status."""
        output = self._run(
            (*self._storage(root, runroot), "wait", name),
            timeout_seconds=timeout_seconds,
        ).stdout.strip()
        try:
            return int(output)
        except ValueError as exc:
            raise OperationalError(
                "Podman wait returned an invalid exit status"
            ) from exc

    def remove(
        self, *, root: Path, runroot: Path, name: str, force: bool = False
    ) -> None:
        """Remove one run-owned container."""
        arguments = [*self._storage(root, runroot), "rm", "--ignore"]
        if force:
            arguments.append("--force")
        arguments.append(name)
        self._run(arguments, timeout_seconds=120, operation=OperationKind.WRITE)

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        """Reset one isolated Podman storage root after container removal."""
        self._run(
            (*self._storage(root, runroot), "system", "reset", "--force"),
            timeout_seconds=300,
            operation=OperationKind.WRITE,
        )


def _int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise OperationalError(f"{label} is malformed")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise OperationalError(f"{label} is malformed")
    return value


def _strings(value: object, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise OperationalError(f"{label} are malformed")
    return tuple(value)


def _string_mapping_keys(value: object, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in value.items()
    ):
        raise OperationalError(f"{label} are malformed")
    return tuple(sorted(value))
