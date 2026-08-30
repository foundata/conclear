import io
import subprocess
from pathlib import Path
from typing import Any

import pytest

from conclear.errors import (
    CommandExecutionError,
    CommandTimeoutError,
    RuleRejectionError,
)
from conclear.process import (
    CommandRequest,
    OperationKind,
    ProcessEnvironment,
    ProcessResult,
    ProcessRunner,
    Redactor,
    command_array,
)
from conclear.tools import ToolName, ToolResolver


class FakeProcess:
    def __init__(
        self,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        timeout_once: bool = False,
    ) -> None:
        self.pid = 4321
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode: int | None = None
        self._final_returncode = returncode
        self._timeout_once = timeout_once

    def wait(self, timeout: float | None = None) -> int:
        if self._timeout_once:
            self._timeout_once = False
            raise subprocess.TimeoutExpired("fake", 0 if timeout is None else timeout)
        self.returncode = self._final_returncode
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode


def request(tmp_path: Path, **changes: Any) -> CommandRequest:
    values: dict[str, Any] = {
        "argv": ("/usr/bin/example", "--version"),
        "environment": {"PATH": "/usr/bin"},
        "timeout_seconds": 10,
        "log_path": tmp_path / "command.json",
    }
    values.update(changes)
    return CommandRequest(**values)


def test_process_environment_does_not_inherit_ambient_secrets(tmp_path: Path) -> None:
    environment = ProcessEnvironment(
        home=tmp_path / "home",
        config_home=tmp_path / "config",
        cache_home=tmp_path / "cache",
        state_home=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
    ).values({"COSIGN_PASSWORD": "secret"})

    assert set(environment) == {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "COSIGN_PASSWORD",
    }


def test_redactor_handles_flags_headers_urls_and_known_paths(tmp_path: Path) -> None:
    redactor = Redactor(secret_values=("top-secret",), secret_paths=(tmp_path,))
    arguments = redactor.argv(
        ("tool", "--password", "top-secret", f"--authfile={tmp_path}")
    )
    output = redactor.text(
        "Authorization: Bearer token\nhttps://x.invalid/?access_token=value"
    )

    assert arguments == (
        "tool",
        "--password",
        "[REDACTED]",
        "--authfile=[REDACTED]",
    )
    assert output == (
        "Authorization: [REDACTED]\nhttps://x.invalid/?access_token=[REDACTED]"
    )


def test_process_runner_captures_bounded_redacted_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = FakeProcess(stdout=b"secret-" + b"x" * 4096)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    result = ProcessRunner(monotonic=iter((1.0, 2.5)).__next__).run(
        request(
            tmp_path,
            max_output_bytes=1024,
            secret_values=("secret",),
        )
    )

    assert result.returncode == 0
    assert result.duration_seconds == 1.5
    assert result.stdout.startswith("[REDACTED]")
    assert result.stdout_truncated
    assert "secret" not in (tmp_path / "command.json").read_text()


def test_process_runner_terminates_timed_out_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = FakeProcess(timeout_once=True)
    signals: list[int] = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        "conclear.process.os.killpg",
        lambda _pid, signal_number: signals.append(signal_number),
    )

    with pytest.raises(CommandTimeoutError, match="timed out"):
        ProcessRunner(monotonic=iter((1.0, 3.0)).__next__).run(request(tmp_path))

    assert signals
    assert process.returncode == 0


def test_process_runner_retries_reads_but_rejects_write_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    processes = iter(
        (
            FakeProcess(stderr=b"temporary token=secret", returncode=1),
            FakeProcess(stdout=b"ok"),
        )
    )
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: next(processes))
    result = ProcessRunner(monotonic=iter((1.0, 2.0, 3.0, 4.0)).__next__).run(
        request(tmp_path, retries=1, secret_values=("secret",))
    )
    assert result.attempts == 2

    with pytest.raises(ValueError, match="cannot retry blindly"):
        request(tmp_path, retries=1, operation=OperationKind.WRITE)


def test_process_runner_classifies_nonzero_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = FakeProcess(stderr=b"bad", returncode=8)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(CommandExecutionError, match="status 8"):
        ProcessRunner(monotonic=iter((1.0, 2.0)).__next__).run(request(tmp_path))


def test_command_array_rejects_shell_strings() -> None:
    with pytest.raises(TypeError, match="argument arrays"):
        command_array("echo unsafe")


class FakeRunner:
    def __init__(self, output: str) -> None:
        self.output = output

    def run(self, request: CommandRequest) -> ProcessResult:
        return ProcessResult(
            argv=request.argv,
            returncode=0,
            stdout=self.output,
            stderr="",
            duration_seconds=0,
            attempts=1,
            stdout_truncated=False,
            stderr_truncated=False,
        )


def test_tool_resolver_records_supported_executable_identity(tmp_path: Path) -> None:
    executable = tmp_path / "cosign"
    executable.write_bytes(b"executable")
    executable.chmod(0o700)
    resolver = ToolResolver(
        runner=FakeRunner("GitVersion: v3.1.3"),
        locator=lambda _name: str(executable),
    )

    tool = resolver.resolve(ToolName.COSIGN, environment={"PATH": "/usr/bin"})

    assert tool.version == "3.1.3"
    assert tool.executable_digest.startswith("sha256:")
    assert tool.path.is_absolute()


def test_tool_resolver_rejects_unsupported_version(tmp_path: Path) -> None:
    executable = tmp_path / "cosign"
    executable.write_bytes(b"executable")
    executable.chmod(0o700)
    resolver = ToolResolver(
        runner=FakeRunner("GitVersion: v3.1.2"),
        locator=lambda _name: str(executable),
    )

    with pytest.raises(RuleRejectionError, match=r"Unsupported cosign version 3\.1\.2"):
        resolver.resolve(ToolName.COSIGN, environment={"PATH": "/usr/bin"})
