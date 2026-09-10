import hashlib
import socket
from pathlib import Path
from typing import cast

import pytest

from conclear.errors import OperationalError, RuleRejectionError
from conclear.process import CommandRequest, ProcessResult, ProcessRunner
from conclear.runtime import ApplicationRuntime
from conclear.tools import ResolvedTool, ToolName, ToolResolver


@pytest.mark.parametrize("order", [("local", "system"), ("system", "local")])
def test_runtime_discovers_tools_in_caller_path_order_and_passes_it_to_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, order: tuple[str, str]
) -> None:
    directories = [tmp_path / name for name in order]
    for directory in directories:
        directory.mkdir()
        executable = directory / "git"
        executable.write_bytes(b"test executable")
        executable.chmod(0o700)
    search_path = ":".join(str(directory) for directory in directories)
    monkeypatch.setenv("PATH", search_path)
    requests: list[CommandRequest] = []

    def observe(_runner: ProcessRunner, request: CommandRequest) -> ProcessResult:
        requests.append(request)
        return ProcessResult(
            request.argv, 0, "git version 2.43.0", "", 0.0, 1, False, False
        )

    monkeypatch.setattr(ProcessRunner, "run", observe)
    runtime = ApplicationRuntime.create(tmp_path / "environment", names=(ToolName.GIT,))

    assert runtime.tools[ToolName.GIT].path == directories[0] / "git"
    assert runtime.environment["PATH"] == search_path
    assert len(requests) == 1
    assert requests[0].argv == (str(directories[0] / "git"), "--version")
    assert requests[0].environment["PATH"] == search_path
    runtime.assert_unchanged()


def test_runtime_does_not_fall_back_when_a_nonempty_path_has_no_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "missing"))

    with pytest.raises(OperationalError, match="Required tool is unavailable: git"):
        ApplicationRuntime.create(tmp_path / "environment", names=(ToolName.GIT,))


def test_runtime_reuses_adapter_instances_for_monotonic_evidence_logs(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "git"
    executable.write_bytes(b"test executable")
    executable.chmod(0o700)
    runtime = ApplicationRuntime(
        root=tmp_path,
        environment={"PATH": "/usr/bin", "HOME": str(tmp_path)},
        runner=ProcessRunner(),
        tools={
            ToolName.GIT: ResolvedTool(
                name=ToolName.GIT,
                path=executable,
                version="test",
                executable_digest="sha256:"
                + hashlib.sha256(b"test executable").hexdigest(),
                reported_version="test",
            )
        },
    )

    assert runtime.git() is runtime.git()


class _Resolver:
    """Resolve fake tools; fail the ones named in `broken`."""

    def __init__(self, broken: dict[ToolName, Exception], root: Path) -> None:
        self.broken = broken
        self.root = root
        self.requested: list[ToolName] = []

    def resolve(self, name: ToolName, *, environment: dict[str, str]) -> ResolvedTool:
        self.requested.append(name)
        failure = self.broken.get(name)
        if failure is not None:
            raise failure
        executable = self.root / name.value
        executable.write_bytes(name.value.encode())
        return ResolvedTool(
            name=name,
            path=executable,
            version="1.0.0",
            executable_digest="sha256:"
            + hashlib.sha256(name.value.encode()).hexdigest(),
            reported_version="1.0.0",
        )

    def resolve_all(
        self, *, environment: dict[str, str], names: tuple[ToolName, ...]
    ) -> tuple[ResolvedTool, ...]:
        return tuple(self.resolve(name, environment=environment) for name in names)


def test_create_resolves_exactly_the_requested_tools(tmp_path: Path) -> None:
    resolver = _Resolver({}, tmp_path)

    runtime = ApplicationRuntime.create(
        tmp_path / "environment",
        names=(ToolName.GIT, ToolName.SKOPEO),
        resolver=cast(ToolResolver, resolver),
    )

    assert resolver.requested == [ToolName.GIT, ToolName.SKOPEO]
    assert tuple(runtime.tools) == (ToolName.GIT, ToolName.SKOPEO)
    assert [item.name for item in runtime.identities] == ["git", "skopeo"]
    with pytest.raises(OperationalError, match="did not resolve cosign"):
        runtime.cosign()


def test_diagnose_reports_every_failure_and_keeps_resolved_tools(
    tmp_path: Path,
) -> None:
    resolver = _Resolver(
        {
            ToolName.COSIGN: OperationalError("Required tool is unavailable: cosign"),
            ToolName.TRIVY: RuleRejectionError(
                "Unsupported trivy version 0.1.0; supported: 0.69.3", code="CC0301"
            ),
        },
        tmp_path,
    )

    runtime, problems = ApplicationRuntime.diagnose(
        tmp_path / "environment",
        names=(ToolName.GIT, ToolName.TRIVY, ToolName.COSIGN, ToolName.GIT),
        resolver=cast(ToolResolver, resolver),
    )

    assert resolver.requested == [ToolName.GIT, ToolName.TRIVY, ToolName.COSIGN]
    assert tuple(runtime.tools) == (ToolName.GIT,)
    assert [problem.message for problem in problems] == [
        "trivy: Unsupported trivy version 0.1.0; supported: 0.69.3",
        "cosign: Required tool is unavailable: cosign",
    ]
    assert isinstance(problems[0].failure, RuleRejectionError)


def test_container_tools_use_login_runtime_and_command_close_removes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    login_runtime = tmp_path / "login-runtime"
    login_runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(login_runtime))
    runtime = ApplicationRuntime.create(
        tmp_path / "environment",
        names=(ToolName.PODMAN,),
        resolver=cast(ToolResolver, _Resolver({}, tmp_path)),
    )
    path = Path(runtime.environment["XDG_RUNTIME_DIR"])
    assert path.parent == login_runtime
    assert path.is_dir()
    runtime.close()
    assert not path.exists()
    assert login_runtime.is_dir()


@pytest.mark.parametrize("tool", [ToolName.BUILDAH, ToolName.PODMAN, ToolName.GIT])
def test_only_container_tools_receive_the_local_login_bus(
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    tool: ToolName,
) -> None:
    login_runtime = tmp_path_factory.mktemp("bus")
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(login_runtime))
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "tcp:host=untrusted,port=1234")
    with socket.socket(socket.AF_UNIX) as bus:
        bus.bind(str(login_runtime / "bus"))
        runtime = ApplicationRuntime.create(
            tmp_path / "environment",
            names=(tool,),
            resolver=cast(ToolResolver, _Resolver({}, tmp_path)),
        )
        if tool is ToolName.GIT:
            assert "DBUS_SESSION_BUS_ADDRESS" not in runtime.environment
        else:
            assert runtime.environment["DBUS_SESSION_BUS_ADDRESS"] == (
                f"unix:path={login_runtime}/bus"
            )
        runtime.close()
        assert (login_runtime / "bus").is_socket()


def test_tool_resolution_failure_removes_command_runtime_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    login_runtime = tmp_path / "login-runtime"
    login_runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(login_runtime))
    with pytest.raises(OperationalError, match="unavailable"):
        ApplicationRuntime.create(
            tmp_path / "environment",
            names=(ToolName.PODMAN,),
            resolver=cast(
                ToolResolver,
                _Resolver({ToolName.PODMAN: OperationalError("unavailable")}, tmp_path),
            ),
        )
    assert not tuple(login_runtime.iterdir())
