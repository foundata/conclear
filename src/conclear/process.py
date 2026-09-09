"""Centralized, bounded external process execution."""

import os
import re
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, cast

from conclear.errors import (
    CommandExecutionError,
    CommandTimeoutError,
    OperationalError,
)
from conclear.jsonutil import atomic_write_json

_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_SENSITIVE_FLAG = re.compile(
    r"^(?:--?(?:password|passphrase|token|secret|auth|authfile|key))(?:=|$)",
    re.IGNORECASE,
)
_AUTHORIZATION = re.compile(
    r"(?im)^(?P<label>authorization\s*:\s*)(?:bearer|basic)\s+\S+"
)
_URL_SECRET = re.compile(
    r"(?i)(?P<label>[?&](?:access_token|password|secret|token)=)[^&#\s]+"
)
_URL_USERINFO = re.compile(r"(?i)(?P<scheme>\b[a-z][a-z0-9+.-]*://)[^/@\s]+@")


class OperationKind(StrEnum):
    """Retry classification for an external operation."""

    READ = "read"
    WRITE = "write"


@dataclass(frozen=True, slots=True)
class ProcessEnvironment:
    """Run-owned paths used to construct a sanitized child environment."""

    home: Path
    config_home: Path
    cache_home: Path
    state_home: Path
    runtime_dir: Path

    def values(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        """Return an allowlisted environment with the caller's executable search path."""
        environment = {
            "PATH": os.environ.get("PATH") or _DEFAULT_PATH,
            "HOME": str(self.home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "XDG_CONFIG_HOME": str(self.config_home),
            "XDG_CACHE_HOME": str(self.cache_home),
            "XDG_STATE_HOME": str(self.state_home),
            "XDG_RUNTIME_DIR": str(self.runtime_dir),
        }
        if extra is not None:
            for key, value in extra.items():
                if key in environment:
                    raise OperationalError(
                        f"Child environment cannot override sanitized variable: {key}"
                    )
                if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
                    raise OperationalError(f"Invalid child environment name: {key}")
                if "\x00" in value:
                    raise OperationalError(
                        f"Child environment value for {key} contains NUL"
                    )
                environment[key] = value
        return environment


@dataclass(frozen=True, slots=True)
class CommandRequest:
    """One fully specified external process invocation."""

    argv: tuple[str, ...]
    environment: Mapping[str, str]
    timeout_seconds: float
    cwd: Path | None = None
    operation: OperationKind = OperationKind.READ
    retries: int = 0
    max_output_bytes: int = 1024 * 1024
    termination_grace_seconds: float = 2.0
    log_path: Path | None = None
    secret_values: tuple[str, ...] = ()
    secret_paths: tuple[Path, ...] = ()
    stdout_artifact: Path | None = None
    max_artifact_bytes: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        """Reject unsafe or unbounded execution specifications."""
        if not self.argv:
            raise OperationalError("Command argument array cannot be empty")
        executable = Path(self.argv[0])
        if not executable.is_absolute():
            raise OperationalError("External executable path must be absolute")
        if any("\x00" in argument for argument in self.argv):
            raise OperationalError("Command arguments cannot contain NUL")
        if self.timeout_seconds <= 0 or self.termination_grace_seconds <= 0:
            raise OperationalError("Command timeouts must be positive")
        if self.retries < 0 or self.retries > 3:
            raise OperationalError(
                "External command retries must be between zero and three"
            )
        if self.operation is OperationKind.WRITE and self.retries:
            raise OperationalError("Registry and signing writes cannot retry blindly")
        if self.max_output_bytes < 1024:
            raise OperationalError("Captured output bound is too small")
        if self.stdout_artifact is not None and (
            not self.stdout_artifact.is_absolute() or self.max_artifact_bytes < 1024
        ):
            raise OperationalError(
                "Machine output needs an absolute path and size bound"
            )


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Redacted observation from one successful external command."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    attempts: int
    stdout_truncated: bool
    stderr_truncated: bool


class Redactor:
    """Redact known secrets and common credential-bearing syntax."""

    def __init__(
        self,
        *,
        secret_values: Sequence[str] = (),
        secret_paths: Sequence[Path] = (),
    ) -> None:
        """Create a redactor without retaining empty replacement values."""
        self._values = tuple(
            sorted(
                {
                    value
                    for value in (*secret_values, *(str(path) for path in secret_paths))
                    if value
                },
                key=len,
                reverse=True,
            )
        )

    def text(self, value: str) -> str:
        """Return text with known and structured credentials removed."""
        redacted = value
        for secret in self._values:
            redacted = redacted.replace(secret, "[REDACTED]")
        redacted = _AUTHORIZATION.sub(r"\g<label>[REDACTED]", redacted)
        redacted = _URL_SECRET.sub(r"\g<label>[REDACTED]", redacted)
        return _URL_USERINFO.sub(r"\g<scheme>[REDACTED]@", redacted)

    def argv(self, arguments: Sequence[str]) -> tuple[str, ...]:
        """Redact sensitive flag values while preserving argument boundaries."""
        output: list[str] = []
        redact_next = False
        for argument in arguments:
            if redact_next:
                output.append("[REDACTED]")
                redact_next = False
                continue
            if _SENSITIVE_FLAG.match(argument):
                flag, separator, _value = argument.partition("=")
                if separator:
                    output.append(f"{flag}=[REDACTED]")
                else:
                    output.append(argument)
                    redact_next = True
                continue
            output.append(self.text(argument))
        return tuple(output)


class ProcessRunner:
    """Execute child process groups with bounded cleanup and output capture."""

    def __init__(self, *, monotonic: Callable[[], float] = time.monotonic) -> None:
        """Create a runner with an injectable monotonic clock."""
        self._monotonic = monotonic

    def run(self, request: CommandRequest) -> ProcessResult:
        """Run a command, retrying only explicitly classified read operations."""
        with _stdout_artifact(request.stdout_artifact) as artifact:
            return self._run_attempts(request, artifact)

    def _run_attempts(
        self, request: CommandRequest, artifact: BinaryIO | None
    ) -> ProcessResult:
        redactor = Redactor(
            secret_values=request.secret_values,
            secret_paths=request.secret_paths,
        )
        attempts = request.retries + 1
        last_failure: CommandExecutionError | CommandTimeoutError | None = None
        for attempt in range(1, attempts + 1):
            if artifact is not None:
                artifact.seek(0)
                artifact.truncate()
            try:
                result = self._run_once(request, redactor, attempt, artifact)
            except (CommandExecutionError, CommandTimeoutError) as exc:
                last_failure = exc
                if attempt == attempts:
                    raise
            else:
                self._write_log(request, result)
                return result
        if last_failure is None:  # pragma: no cover - loop invariant
            raise OperationalError(
                "Process retry loop completed without an observation"
            )
        raise last_failure

    def _run_once(
        self,
        request: CommandRequest,
        redactor: Redactor,
        attempt: int,
        artifact: BinaryIO | None,
    ) -> ProcessResult:
        start = self._monotonic()
        try:
            process = subprocess.Popen(
                request.argv,
                cwd=request.cwd,
                env=dict(request.environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            raise CommandExecutionError(
                f"Unable to start external command {redactor.argv(request.argv)[0]}"
            ) from exc
        if process.stdout is None or process.stderr is None:  # pragma: no cover
            self._terminate(process, request.termination_grace_seconds)
            raise OperationalError("Process pipes were not created")
        stdout_stream = cast(BinaryIO, process.stdout)
        stderr_stream = cast(BinaryIO, process.stderr)
        stdout = _BoundedCapture(
            stdout_stream,
            request.max_output_bytes,
            artifact,
            request.max_artifact_bytes,
        )
        stderr = _BoundedCapture(stderr_stream, request.max_output_bytes)
        stdout.start()
        stderr.start()
        timed_out = False
        try:
            process.wait(timeout=request.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate(process, request.termination_grace_seconds)
        except BaseException:
            self._terminate(process, request.termination_grace_seconds)
            raise
        finally:
            _finish_capture(stdout_stream, stdout, request.termination_grace_seconds)
            _finish_capture(stderr_stream, stderr, request.termination_grace_seconds)
        duration = max(0.0, self._monotonic() - start)
        redacted_argv = redactor.argv(request.argv)
        stdout_text = redactor.text(stdout.text())
        stderr_text = redactor.text(stderr.text())
        if timed_out:
            timeout_failure = CommandTimeoutError(
                f"External command timed out after {request.timeout_seconds:g}s: "
                f"{redacted_argv[0]}",
                stdout=stdout_text,
                stderr=stderr_text,
            )
            self._write_failure_log_best_effort(
                request,
                redacted_argv,
                stdout_text,
                stderr_text,
                duration,
                attempt,
                "timeout",
            )
            raise timeout_failure
        if process.returncode != 0:
            detail = stderr_text.strip() or stdout_text.strip()
            suffix = f": {detail}" if detail else ""
            execution_failure = CommandExecutionError(
                f"External command failed with status {process.returncode}: "
                f"{redacted_argv[0]}{suffix}",
                returncode=process.returncode,
                stdout=stdout_text,
                stderr=stderr_text,
            )
            self._write_failure_log_best_effort(
                request,
                redacted_argv,
                stdout_text,
                stderr_text,
                duration,
                attempt,
                "failure",
            )
            raise execution_failure
        if artifact is not None:
            if stdout.alive or not stdout.complete:
                raise OperationalError("Machine output capture did not complete")
            if stdout.artifact_error is not None:
                raise OperationalError(stdout.artifact_error)
            artifact.flush()
        return ProcessResult(
            argv=redacted_argv,
            returncode=process.returncode,
            stdout=stdout_text,
            stderr=stderr_text,
            duration_seconds=duration,
            attempts=attempt,
            stdout_truncated=stdout.truncated,
            stderr_truncated=stderr.truncated,
        )

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes], grace_seconds: float) -> None:
        _signal_group(process.pid, signal.SIGTERM)
        _wait_best_effort(process, grace_seconds)
        # The group can outlive its leader, so always complete the group cleanup.
        _signal_group(process.pid, signal.SIGKILL)
        _wait_best_effort(process, grace_seconds)

    @staticmethod
    def _write_log(request: CommandRequest, result: ProcessResult) -> None:
        if request.log_path is None:
            return
        atomic_write_json(
            request.log_path,
            {
                "schemaVersion": 1,
                "argv": list(result.argv),
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "durationSeconds": result.duration_seconds,
                "attempts": result.attempts,
                "stdoutTruncated": result.stdout_truncated,
                "stderrTruncated": result.stderr_truncated,
            },
        )

    @staticmethod
    def _write_failure_log(
        request: CommandRequest,
        argv: tuple[str, ...],
        stdout: str,
        stderr: str,
        duration: float,
        attempt: int,
        outcome: str,
    ) -> None:
        if request.log_path is None:
            return
        atomic_write_json(
            request.log_path,
            {
                "schemaVersion": 1,
                "argv": list(argv),
                "outcome": outcome,
                "stdout": stdout,
                "stderr": stderr,
                "durationSeconds": duration,
                "attempts": attempt,
            },
        )

    @classmethod
    def _write_failure_log_best_effort(
        cls,
        request: CommandRequest,
        argv: tuple[str, ...],
        stdout: str,
        stderr: str,
        duration: float,
        attempt: int,
        outcome: str,
    ) -> None:
        try:
            cls._write_failure_log(
                request,
                argv,
                stdout,
                stderr,
                duration,
                attempt,
                outcome,
            )
        except (OSError, OperationalError):
            return


class _BoundedCapture:
    def __init__(
        self,
        stream: BinaryIO,
        limit: int,
        artifact: BinaryIO | None = None,
        artifact_limit: int = 0,
    ) -> None:
        self._stream = stream
        self._limit = limit
        self._content = bytearray()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self.truncated = False
        self.complete = False
        self.artifact_error: str | None = None
        self._artifact = artifact
        self._artifact_limit = artifact_limit
        self._artifact_bytes = 0

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)

    @property
    def alive(self) -> bool:
        return self._thread.is_alive()

    def text(self) -> str:
        return self._content.decode("utf-8", errors="replace")

    def _drain(self) -> None:
        try:
            while chunk := self._stream.read(65536):
                remaining = self._limit - len(self._content)
                if remaining > 0:
                    self._content.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.truncated = True
                self._write_artifact(chunk)
            self.complete = True
        except (OSError, ValueError):
            return

    def _write_artifact(self, chunk: bytes) -> None:
        if self._artifact is None or self.artifact_error is not None:
            return
        self._artifact_bytes += len(chunk)
        if self._artifact_bytes > self._artifact_limit:
            self.artifact_error = (
                f"Machine output exceeds the {self._artifact_limit}-byte size limit"
            )
            return
        try:
            self._artifact.write(chunk)
        except (OSError, ValueError):
            self.artifact_error = "Unable to write machine output"


@contextmanager
def _stdout_artifact(path: Path | None) -> Iterator[BinaryIO | None]:
    """Keep raw machine output separate from redacted, bounded diagnostics."""
    if path is None:
        yield None
        return
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
        )
    except OSError as exc:
        raise OperationalError(
            "Unable to create exclusive machine output file"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            yield stream
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _finish_capture(stream: BinaryIO, capture: _BoundedCapture, timeout: float) -> None:
    capture.join(timeout)
    if capture.alive:
        try:
            os.close(stream.fileno())
        except (OSError, ValueError):
            pass
        capture.join(timeout)
        return
    try:
        stream.close()
    except (OSError, ValueError):
        pass


def _signal_group(process_group: int, signal_number: signal.Signals) -> None:
    try:
        os.killpg(process_group, signal_number)
    except OSError:
        return


def _wait_best_effort(process: subprocess.Popen[bytes], timeout: float) -> None:
    try:
        process.wait(timeout=timeout)
    except BaseException:
        return


def command_array(arguments: Sequence[str]) -> tuple[str, ...]:
    """Convert an argument sequence while explicitly rejecting shell interpolation."""
    if isinstance(arguments, str):
        raise OperationalError("External commands must be argument arrays")
    return tuple(arguments)
