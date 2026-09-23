import io
import logging
import signal
import subprocess
from pathlib import Path
from typing import Any, override

import pytest

from conclear import narration
from conclear.errors import (
    CommandExecutionError,
    CommandTimeoutError,
    OperationalError,
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


class InterruptedProcess(FakeProcess):
    def __init__(self) -> None:
        super().__init__()
        self._waits = 0

    @override
    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self._waits += 1
        if self._waits == 1:
            raise KeyboardInterrupt
        self.returncode = 0
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


def test_process_environment_does_not_inherit_ambient_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QUAY_TOKEN", "ambient-secret")
    monkeypatch.setenv("TRIVY_CONFIG", "/ambient/trivy.yaml")
    monkeypatch.setenv("LD_PRELOAD", "/ambient/library.so")
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


@pytest.mark.parametrize(
    "search_path",
    [None, "", "/home/example/.local/bin:/usr/bin", ":./tools:", " ", "/missing"],
)
def test_process_environment_preserves_path_with_an_empty_or_unset_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, search_path: str | None
) -> None:
    if search_path is None:
        monkeypatch.delenv("PATH", raising=False)
    else:
        monkeypatch.setenv("PATH", search_path)

    environment = ProcessEnvironment(
        home=tmp_path / "home",
        config_home=tmp_path / "config",
        cache_home=tmp_path / "cache",
        state_home=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
    ).values()

    expected = (
        search_path or "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )
    assert environment["PATH"] == expected


def test_process_environment_rejects_sanitized_variable_override(
    tmp_path: Path,
) -> None:
    process_environment = ProcessEnvironment(
        home=tmp_path / "home",
        config_home=tmp_path / "config",
        cache_home=tmp_path / "cache",
        state_home=tmp_path / "state",
        runtime_dir=tmp_path / "runtime",
    )

    with pytest.raises(OperationalError, match=r"cannot override.*PATH"):
        process_environment.values({"PATH": str(tmp_path / "untrusted")})


def test_redactor_handles_flags_headers_urls_and_known_paths(tmp_path: Path) -> None:
    redactor = Redactor(secret_values=("top-secret",), secret_paths=(tmp_path,))
    arguments = redactor.argv(
        ("tool", "--password", "top-secret", f"--authfile={tmp_path}")
    )
    output = redactor.text(
        "Authorization: Bearer token\n"
        "https://x.invalid/?access_token=value\n"
        "https://user:password@registry.invalid/image\n"
        "https://registry.invalid/path@digest"
    )

    assert arguments == (
        "tool",
        "--password",
        "[REDACTED]",
        "--authfile=[REDACTED]",
    )
    assert output == (
        "Authorization: [REDACTED]\n"
        "https://x.invalid/?access_token=[REDACTED]\n"
        "https://[REDACTED]@registry.invalid/image\n"
        "https://registry.invalid/path@digest"
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


def test_machine_output_is_complete_private_and_not_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = (
        b'{"secret":"keep-these-bytes","padding":"' + b"x" * (2 * 1024 * 1024) + b'"}'
    )
    monkeypatch.setattr(
        subprocess, "Popen", lambda *args, **kwargs: FakeProcess(stdout=content)
    )
    output = tmp_path / "response.json"

    result = ProcessRunner().run(
        request(tmp_path, stdout_artifact=output, secret_values=("keep-these-bytes",))
    )

    assert output.read_bytes() == content
    assert output.stat().st_mode & 0o777 == 0o600
    assert result.stdout_truncated
    assert "keep-these-bytes" not in result.stdout
    assert "keep-these-bytes" not in (tmp_path / "command.json").read_text()


def test_machine_output_overflow_fails_without_leaving_partial_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        subprocess, "Popen", lambda *args, **kwargs: FakeProcess(stdout=b"x" * 2049)
    )
    output = tmp_path / "response.json"

    with pytest.raises(OperationalError, match="Machine output exceeds the 2048-byte"):
        ProcessRunner().run(
            request(tmp_path, stdout_artifact=output, max_artifact_bytes=2048)
        )

    assert not output.exists()


def test_machine_output_retry_discards_failed_attempt_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    processes = iter(
        (FakeProcess(stdout=b"failed", returncode=1), FakeProcess(stdout=b"ok"))
    )
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: next(processes))
    output = tmp_path / "response.json"

    result = ProcessRunner().run(request(tmp_path, stdout_artifact=output, retries=1))

    assert result.attempts == 2
    assert output.read_bytes() == b"ok"


def test_machine_output_never_replaces_existing_file(tmp_path: Path) -> None:
    output = tmp_path / "response.json"
    output.write_text("protected")

    with pytest.raises(OperationalError, match="exclusive machine output"):
        ProcessRunner().run(request(tmp_path, stdout_artifact=output))

    assert output.read_text() == "protected"


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

    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert process.returncode == 0


def test_process_runner_preserves_interruption_during_group_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = InterruptedProcess()
    signals: list[int] = []
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        "conclear.process.os.killpg",
        lambda _pid, signal_number: signals.append(signal_number),
    )

    with pytest.raises(KeyboardInterrupt):
        ProcessRunner().run(request(tmp_path))

    assert signals == [signal.SIGTERM, signal.SIGKILL]


def test_process_runner_preserves_timeout_when_cleanup_operations_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = FakeProcess(timeout_once=True)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        "conclear.process.os.killpg",
        lambda _pid, _signal_number: (_ for _ in ()).throw(PermissionError()),
    )
    monkeypatch.setattr(
        "conclear.process.atomic_write_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()),
    )

    with pytest.raises(CommandTimeoutError, match="timed out"):
        ProcessRunner(monotonic=iter((1.0, 3.0)).__next__).run(request(tmp_path))


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

    with pytest.raises(OperationalError, match="cannot retry blindly"):
        request(tmp_path, retries=1, operation=OperationKind.WRITE)


def test_process_runner_classifies_nonzero_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = FakeProcess(stderr=b"bad", returncode=8)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(CommandExecutionError, match="status 8"):
        ProcessRunner(monotonic=iter((1.0, 2.0)).__next__).run(request(tmp_path))


def test_command_array_rejects_shell_strings() -> None:
    with pytest.raises(OperationalError, match="argument arrays"):
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
    searches: list[tuple[str, str]] = []

    def locate(name: str, search_path: str) -> str:
        searches.append((name, search_path))
        return str(executable)

    resolver = ToolResolver(
        runner=FakeRunner("GitVersion: v3.1.3"),
        locator=locate,
    )

    tool = resolver.resolve(ToolName.COSIGN, environment={"PATH": "/usr/bin"})

    assert tool.version == "3.1.3"
    assert tool.executable_digest.startswith("sha256:")
    assert tool.path.is_absolute()
    assert searches == [("cosign", "/usr/bin")]


def test_tool_resolver_rejects_unsupported_version(tmp_path: Path) -> None:
    executable = tmp_path / "cosign"
    executable.write_bytes(b"executable")
    executable.chmod(0o700)
    resolver = ToolResolver(
        runner=FakeRunner("GitVersion: v3.1.2"),
        locator=lambda _name, _search_path: str(executable),
    )

    with pytest.raises(
        RuleRejectionError, match=r"Unsupported cosign version 3\.1\.2"
    ) as failure:
        resolver.resolve(ToolName.COSIGN, environment={"PATH": "/usr/bin"})
    assert failure.value.code == "CC0301"
    assert "accepted 3.1.3 <= version < 4.0.0" in str(failure.value)
    assert "excluded: none" in str(failure.value)
    assert "real-tool tested (not the only accepted versions): 3.1.3" in str(
        failure.value
    )


def test_process_runner_narrates_each_attempt_with_the_redacted_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The story shows what really ran, so it must be the redacted line the
    # evidence log records, never the raw one.
    processes = iter(
        (FakeProcess(stderr=b"busy", returncode=1), FakeProcess(stdout=b"ok"))
    )
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: next(processes))
    caplog.set_level(logging.INFO, logger="conclear.process")

    ProcessRunner(monotonic=iter((1.0, 2.0, 3.0, 4.0)).__next__).run(
        request(
            tmp_path,
            argv=("/usr/bin/skopeo", "login", "--password", "hunter2", "r.invalid"),
            retries=1,
            cwd=tmp_path,
        )
    )

    echoed = [
        record.getMessage()
        for record in caplog.records
        if getattr(record, narration.COMMAND, False)
    ]
    assert echoed == ["skopeo login --password '[REDACTED]' r.invalid"] * 2
    phases = [
        record.getMessage()
        for record in caplog.records
        if not getattr(record, narration.COMMAND, False)
    ]
    assert phases == [
        f"Running in {tmp_path}",
        "Retrying skopeo (attempt 2)",
        f"Running in {tmp_path}",
    ]
    assert "hunter2" not in caplog.text
