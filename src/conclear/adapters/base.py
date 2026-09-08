"""Shared command construction for external tool adapters."""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.process import (
    CommandRequest,
    OperationKind,
    ProcessResult,
)
from conclear.tools import ResolvedTool


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


class ToolAdapter:
    """Execute one immutable resolved tool through the central runner."""

    def __init__(
        self,
        *,
        tool: ResolvedTool,
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
    ) -> ProcessResult:
        self._tool.assert_unchanged()
        environment = dict(self._environment)
        if extra_environment is not None:
            environment.update(extra_environment)
        self._sequence += 1
        return self._runner.run(
            CommandRequest(
                argv=(str(self._tool.path), *arguments),
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
                cwd=cwd,
                stdout_artifact=stdout_artifact,
                max_artifact_bytes=max_artifact_bytes,
            )
        )
