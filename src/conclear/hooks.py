"""Repository hook execution with explicit arguments and documented inputs."""

import os
import shutil
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from conclear.config import HookConfig
from conclear.errors import CommandExecutionError, OperationalError
from conclear.jsonutil import canonical_json_bytes, sha256_bytes, sha256_file
from conclear.path_safety import contained_path
from conclear.process import CommandRequest, ProcessResult


class HookStatus(StrEnum):
    """Stable repository hook outcomes."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class HookObservation:
    """One bounded hook result suitable for qualification evidence."""

    name: str
    status: HookStatus
    required: bool
    executable: str | None
    executable_digest: str | None
    output_digest: str | None

    def to_dict(self) -> dict[str, object]:
        """Return the record representation."""
        return {
            "name": self.name,
            "status": self.status.value,
            "required": self.required,
            "executable": self.executable,
            "executableDigest": self.executable_digest,
            "outputDigest": self.output_digest,
        }


class Runner(Protocol):
    """Narrow process runner boundary for repository hooks."""

    def run(self, request: CommandRequest) -> ProcessResult:
        """Run one fully specified hook process."""
        ...


class HookRunner:
    """Resolve and run repository hooks without command interpolation."""

    def __init__(
        self,
        *,
        runner: Runner,
        environment: dict[str, str],
        source_root: Path,
        log_directory: Path,
    ) -> None:
        """Bind hooks to one isolated source checkout and child environment."""
        self._runner = runner
        self._environment = dict(environment)
        self._source_root = source_root.resolve(strict=True)
        self._log_directory = log_directory

    def run(
        self,
        hook: HookConfig,
        *,
        supplied_environment: dict[str, str],
    ) -> HookObservation:
        """Run one hook or record a missing optional executable as skipped."""
        executable = self._resolve(hook.command[0])
        if executable is None:
            return HookObservation(
                hook.name, HookStatus.SKIPPED, hook.required, None, None, None
            )
        executable_digest = _hash_executable(executable)
        environment = dict(self._environment)
        environment.update(supplied_environment)
        try:
            result = self._runner.run(
                CommandRequest(
                    argv=(str(executable), *hook.command[1:]),
                    environment=environment,
                    timeout_seconds=hook.timeout_seconds,
                    cwd=self._source_root,
                    log_path=self._log_directory / f"hook-{hook.name}.json",
                )
            )
            status = HookStatus.PASSED
            output = {"stdout": result.stdout, "stderr": result.stderr}
        except CommandExecutionError as exc:
            status = HookStatus.FAILED
            output = {"stdout": exc.stdout, "stderr": exc.stderr}
        if _hash_executable(executable) != executable_digest:
            raise OperationalError(
                f"Repository hook executable changed during execution: {executable}"
            )
        return HookObservation(
            name=hook.name,
            status=status,
            required=hook.required,
            executable=hook.command[0],
            executable_digest=executable_digest,
            output_digest=sha256_bytes(canonical_json_bytes(output)),
        )

    def _resolve(self, value: str) -> Path | None:
        if "/" in value:
            # A missing optional hook is skipped, not rejected, so the path
            # is confined first and only then checked for existence.
            path = contained_path(self._source_root, value, must_exist=False)
            return path if _is_executable(path) else None
        found = shutil.which(value, path=self._environment.get("PATH", ""))
        if found is None:
            return None
        path = Path(found).resolve(strict=True)
        return path if _is_executable(path) else None


def _is_executable(path: Path) -> bool:
    try:
        file_stat = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(file_stat.st_mode) and os.access(path, os.X_OK)


def _hash_executable(path: Path) -> str:
    return sha256_file(path)
