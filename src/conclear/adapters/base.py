"""Shared command construction for external tool adapters."""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

from conclear.process import (
    CommandRequest,
    OperationKind,
    ProcessResult,
)
from conclear.tools import ResolvedTool


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
            )
        )
