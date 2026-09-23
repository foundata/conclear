"""Shared command construction for external tool adapters."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.process import (
    CommandRequest,
    OperationKind,
    ProcessResult,
)
from conclear.tool_images import ImageBackedTool, Tool

_MOUNT_ROOT = "/conclear"


def prepare_new_layout_path(layout_path: Path) -> None:
    """Require an absent OCI-layout destination below an existing regular directory.

    Tools that write `oci:` layouts neither create missing parents nor refuse an
    existing layout, so every adapter that exports one applies the same
    fail-closed preparation before the tool runs.
    """
    try:
        layout_path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise OperationalError(
            f"Unable to inspect output layout {layout_path}"
        ) from exc
    else:
        raise InvalidInvocationError(f"Output layout already exists: {layout_path}")
    try:
        layout_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not layout_path.parent.is_dir() or layout_path.parent.is_symlink():
            raise InvalidInvocationError(
                f"Output layout parent is not a regular directory: {layout_path.parent}"
            )
    except OSError as exc:
        raise OperationalError(
            f"Unable to create output layout parent {layout_path.parent}"
        ) from exc


class Runner(Protocol):
    """Narrow process runner boundary used by tool adapters."""

    def run(self, request: CommandRequest) -> ProcessResult:
        """Execute one fully specified external process."""
        ...


@dataclass(frozen=True, slots=True)
class _Mount:
    source: Path
    target: str
    writable: bool


class ToolAdapter:
    """Execute one immutable resolved tool through the central runner.

    A tool that runs from its pinned image sees only what the adapter mounts.
    Adapters therefore pass every path through `_path`, which returns the host
    path for a host executable and, for an image, a container path backed by a
    bind mount that the next `_run` creates. Paths registered but never run are
    dropped by that `_run`, so a failed argument construction leaves nothing
    behind for the call after it.
    """

    def __init__(
        self,
        *,
        tool: Tool,
        runner: Runner,
        environment: Mapping[str, str],
        log_directory: Path,
    ) -> None:
        """Bind the adapter to a run-owned environment and log directory."""
        self._tool = tool
        self._runner = runner
        self._environment = dict(environment)
        self._log_directory = log_directory
        self._sequence = 0
        self._mounts: dict[Path, _Mount] = {}

    def _path(
        self, path: Path, *, writable: bool = False, name: str | None = None
    ) -> str:
        """Return ``path`` as the tool will see it.

        For an image the directory itself is mounted when ``path`` is one,
        otherwise its parent, so an output file that does not exist yet has a
        place to appear. A path below a directory already registered reuses
        that mount; asking for write access widens an existing mount.
        """
        absolute = path.absolute()
        if not isinstance(self._tool, ImageBackedTool):
            return str(absolute)
        directory = absolute if absolute.is_dir() else absolute.parent
        for source, mount in self._mounts.items():
            if directory != source and source not in directory.parents:
                continue
            if writable and not mount.writable:
                self._mounts[source] = _Mount(source, mount.target, True)
            below = directory.relative_to(source)
            base = mount.target if below == Path() else f"{mount.target}/{below}"
            return base if absolute.is_dir() else f"{base}/{absolute.name}"
        target = f"{_MOUNT_ROOT}/{name or f'mount{len(self._mounts)}'}"
        if any(mount.target == target for mount in self._mounts.values()):
            raise OperationalError(f"Tool mount name is already taken: {target}")
        self._mounts[directory] = _Mount(directory, target, writable)
        return target if absolute.is_dir() else f"{target}/{absolute.name}"

    def _run(
        self,
        arguments: Sequence[str],
        *,
        operation: OperationKind = OperationKind.READ,
        timeout_seconds: float,
        retries: int = 0,
        extra_environment: Mapping[str, str] | None = None,
        secret_values: tuple[str, ...] = (),
        secret_paths: tuple[Path, ...] = (),
        cwd: Path | None = None,
        stdout_artifact: Path | None = None,
        max_artifact_bytes: int = 128 * 1024 * 1024,
        network: bool = False,
    ) -> ProcessResult:
        self._tool.assert_unchanged()
        self._sequence += 1
        try:
            if isinstance(self._tool, ImageBackedTool):
                argv = self._containerized(
                    self._tool,
                    arguments,
                    extra_environment=extra_environment,
                    secret_paths=secret_paths,
                    cwd=cwd,
                    network=network,
                )
                environment = dict(self._environment)
                request_cwd = None
            else:
                argv = (str(self._tool.path), *arguments)
                environment = dict(self._environment)
                if extra_environment is not None:
                    environment.update(extra_environment)
                request_cwd = cwd
            return self._runner.run(
                CommandRequest(
                    argv=argv,
                    environment=environment,
                    timeout_seconds=timeout_seconds,
                    operation=operation,
                    retries=retries,
                    log_path=(
                        self._log_directory
                        / f"{self._tool.name.value}-{self._sequence:04d}.json"
                    ),
                    secret_values=secret_values,
                    secret_paths=secret_paths,
                    cwd=request_cwd,
                    stdout_artifact=stdout_artifact,
                    max_artifact_bytes=max_artifact_bytes,
                )
            )
        finally:
            self._mounts.clear()

    def _containerized(
        self,
        tool: ImageBackedTool,
        arguments: Sequence[str],
        *,
        extra_environment: Mapping[str, str] | None,
        secret_paths: tuple[Path, ...],
        cwd: Path | None,
        network: bool,
    ) -> tuple[str, ...]:
        """Compose the Podman invocation that runs the tool from its image.

        The container gets a read-only root, no network unless the call asks
        for it, and exactly the mounts the adapter registered. The sanitized
        environment goes to Podman; only the call's extra variables reach the
        tool.
        """
        for secret in secret_paths:
            self._path(secret)
        workdir = None if cwd is None else self._path(cwd)
        argv: list[str] = [
            str(tool.executor.path),
            *tool.store.arguments,
            "run",
            "--rm",
            "--pull",
            "never",
            "--read-only",
        ]
        if not network:
            argv.extend(("--network", "none"))
        if workdir is not None:
            argv.extend(("--workdir", workdir))
        for mount in self._mounts.values():
            argv.extend(
                (
                    "--mount",
                    f"type=bind,src={mount.source},target={mount.target},"
                    f"{'rw' if mount.writable else 'ro'},nosuid,nodev,relabel=private",
                )
            )
        for key, value in (extra_environment or {}).items():
            argv.extend(("--env", f"{key}={value}"))
        argv.extend(
            ("--entrypoint", tool.image.executable, tool.image.pinned_reference)
        )
        argv.extend(arguments)
        return tuple(argv)
