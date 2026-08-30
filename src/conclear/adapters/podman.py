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


class PodmanAdapter(ToolAdapter):
    """Import exact layouts and run constrained rootless containers."""

    def _storage(self, root: Path, runroot: Path) -> tuple[str, ...]:
        return ("--root", str(root), "--runroot", str(runroot))

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
        arguments = [*self._storage(root, runroot), "rm"]
        if force:
            arguments.append("--force")
        arguments.append(name)
        self._run(arguments, timeout_seconds=120, operation=OperationKind.WRITE)
