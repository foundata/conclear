import hashlib
import socket
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

import conclear.runtime as runtime_module
from conclear.errors import OperationalError, RuleRejectionError
from conclear.process import CommandRequest, ProcessResult, ProcessRunner
from conclear.runtime import ApplicationRuntime
from conclear.tool_images import ImageBackedTool, ToolImageStore
from conclear.tools import (
    SUPPORTED_TOOLS,
    ResolvedTool,
    Runner,
    ToolName,
    ToolResolver,
)
from conclear.workspace import ResourceKind, ResourceStatus, RunWorkspace


class _Ids:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


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

    assert runtime.executable(ToolName.GIT).path == directories[0] / "git"
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


class _InspectRunner:
    """Answer the image recheck with the pinned digest; nothing else runs."""

    def __init__(self, digest: str) -> None:
        self.digest = digest

    def run(self, request: CommandRequest) -> ProcessResult:
        assert "inspect" in request.argv, request.argv
        return ProcessResult(
            request.argv, 0, self.digest + "\n", "", 0.0, 1, False, False
        )


class _ImageFactory:
    """Stand in for the image resolver and record what the runtime handed over."""

    def __init__(self, broken: dict[ToolName, Exception] | None = None) -> None:
        self.broken = broken or {}
        self.calls: list[dict[str, object]] = []
        self.resolved: list[ToolName] = []

    def __call__(
        self,
        *,
        runner: Runner,
        store: ToolImageStore,
        podman: ResolvedTool,
        cosign: ResolvedTool | None,
    ) -> "_ImageFactory":
        self.calls.append({"store": store, "podman": podman, "cosign": cosign})
        self.store = store
        self.podman = podman
        return self

    def resolve(
        self, name: ToolName, *, environment: Mapping[str, str]
    ) -> ImageBackedTool:
        self.resolved.append(name)
        failure = self.broken.get(name)
        if failure is not None:
            raise failure
        image = SUPPORTED_TOOLS[name].image
        assert image is not None
        return ImageBackedTool(
            name=name,
            image=image,
            version=str(image.version),
            reported_version="test",
            manifest_digest="sha256:" + "2" * 64,
            executor=self.podman,
            store=self.store,
            runner=_InspectRunner(image.digest),
            environment=environment,
        )


def test_a_tool_selected_to_run_from_its_image_adds_podman_to_the_host_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "login-runtime"))
    (tmp_path / "login-runtime").mkdir(mode=0o700)
    monkeypatch.setattr(runtime_module, "reset_store", lambda *arguments: None)
    resolver = _Resolver({}, tmp_path)
    factory = _ImageFactory()

    runtime = ApplicationRuntime.create(
        tmp_path / "environment",
        names=(ToolName.GIT, ToolName.HADOLINT),
        resolver=cast(ToolResolver, resolver),
        images=frozenset({ToolName.HADOLINT}),
        image_resolver=factory,
    )

    assert resolver.requested == [ToolName.GIT, ToolName.PODMAN]
    assert tuple(runtime.tools) == (ToolName.GIT, ToolName.PODMAN, ToolName.HADOLINT)
    assert isinstance(runtime.tools[ToolName.HADOLINT], ImageBackedTool)
    assert factory.resolved == [ToolName.HADOLINT]
    (call,) = factory.calls
    assert call["podman"] is runtime.tools[ToolName.PODMAN]
    assert call["cosign"] is None
    store = cast(ToolImageStore, call["store"])
    assert store.root == tmp_path / "environment" / "tool-images" / "root"
    assert runtime.tool_image_store == store
    assert [item.name for item in runtime.identities] == ["git", "hadolint", "podman"]
    assert runtime.identities[1].to_dict()["imageDigest"]
    runtime.assert_unchanged()
    runtime.close()


def test_a_signed_image_adds_cosign_and_an_unused_selection_adds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "login-runtime"))
    (tmp_path / "login-runtime").mkdir(mode=0o700)
    resolver = _Resolver({}, tmp_path)
    factory = _ImageFactory()

    runtime = ApplicationRuntime.create(
        tmp_path / "environment",
        names=(ToolName.TRIVY,),
        resolver=cast(ToolResolver, resolver),
        images=frozenset({ToolName.TRIVY, ToolName.HADOLINT}),
        image_resolver=factory,
    )

    assert resolver.requested == [ToolName.PODMAN, ToolName.COSIGN]
    assert tuple(runtime.tools) == (ToolName.PODMAN, ToolName.COSIGN, ToolName.TRIVY)
    assert factory.calls[0]["cosign"] is runtime.tools[ToolName.COSIGN]
    assert factory.resolved == [ToolName.TRIVY]

    plain = _Resolver({}, tmp_path / "plain")
    (tmp_path / "plain").mkdir()
    unaffected = ApplicationRuntime.create(
        tmp_path / "plain-environment",
        names=(ToolName.GIT,),
        resolver=cast(ToolResolver, plain),
        images=frozenset({ToolName.TRIVY}),
        image_resolver=_ImageFactory(),
    )
    assert plain.requested == [ToolName.GIT]
    assert unaffected.tool_image_store is None


def test_the_selection_defaults_to_the_environment_switch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "login-runtime"))
    (tmp_path / "login-runtime").mkdir(mode=0o700)
    monkeypatch.setenv("CONCLEAR_TOOL_IMAGES", "hadolint")

    runtime = ApplicationRuntime.create(
        tmp_path / "environment",
        names=(ToolName.HADOLINT,),
        resolver=cast(ToolResolver, _Resolver({}, tmp_path)),
        image_resolver=_ImageFactory(),
    )

    assert isinstance(runtime.tools[ToolName.HADOLINT], ImageBackedTool)


def test_diagnose_reports_image_failures_beside_host_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "login-runtime"))
    (tmp_path / "login-runtime").mkdir(mode=0o700)
    factory = _ImageFactory({ToolName.HADOLINT: OperationalError("pull failed")})

    runtime, problems = ApplicationRuntime.diagnose(
        tmp_path / "environment",
        names=(ToolName.GIT, ToolName.HADOLINT, ToolName.TRIVY),
        resolver=cast(ToolResolver, _Resolver({}, tmp_path)),
        images=frozenset({ToolName.HADOLINT, ToolName.TRIVY}),
        image_resolver=factory,
    )

    assert tuple(runtime.tools) == (
        ToolName.GIT,
        ToolName.PODMAN,
        ToolName.COSIGN,
        ToolName.TRIVY,
    )
    assert [problem.message for problem in problems] == ["hadolint: pull failed"]


def test_diagnose_blames_every_image_when_podman_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "login-runtime"))
    (tmp_path / "login-runtime").mkdir(mode=0o700)

    runtime, problems = ApplicationRuntime.diagnose(
        tmp_path / "environment",
        names=(ToolName.HADOLINT,),
        resolver=cast(
            ToolResolver,
            _Resolver({ToolName.PODMAN: OperationalError("unavailable")}, tmp_path),
        ),
        images=frozenset({ToolName.HADOLINT}),
        image_resolver=_ImageFactory(),
    )

    assert tuple(runtime.tools) == ()
    assert [problem.message for problem in problems] == [
        "podman: unavailable",
        "hadolint: Running hadolint from an image requires the podman executable",
    ]


def _login_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "login-runtime"))
    (tmp_path / "login-runtime").mkdir(mode=0o700)


def test_releasing_tool_images_resets_the_store_and_removes_its_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _login_runtime(tmp_path, monkeypatch)
    resets: list[tuple[Path, ToolImageStore]] = []
    monkeypatch.setattr(
        runtime_module,
        "reset_store",
        lambda runner, environment, podman, store: resets.append((podman.path, store)),
    )
    runtime = ApplicationRuntime.create(
        tmp_path / "environment",
        names=(ToolName.HADOLINT,),
        resolver=cast(ToolResolver, _Resolver({}, tmp_path)),
        images=frozenset({ToolName.HADOLINT}),
        image_resolver=_ImageFactory(),
    )
    store_directory = tmp_path / "environment" / "tool-images"
    assert store_directory.is_dir()

    runtime.close()

    assert resets == [
        (
            tmp_path / "podman",
            ToolImageStore(store_directory / "root", store_directory / "runroot"),
        )
    ]
    assert not store_directory.exists()
    runtime.release_tool_images()
    assert len(resets) == 1


def test_a_failed_image_resolution_releases_a_command_scoped_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _login_runtime(tmp_path, monkeypatch)
    resets: list[Path] = []
    monkeypatch.setattr(
        runtime_module,
        "reset_store",
        lambda runner, environment, podman, store: resets.append(store.root),
    )

    with pytest.raises(OperationalError, match="pull failed"):
        ApplicationRuntime.create(
            tmp_path / "environment",
            names=(ToolName.HADOLINT,),
            resolver=cast(ToolResolver, _Resolver({}, tmp_path)),
            images=frozenset({ToolName.HADOLINT}),
            image_resolver=_ImageFactory(
                {ToolName.HADOLINT: OperationalError("pull failed")}
            ),
        )

    assert resets == [tmp_path / "environment" / "tool-images" / "root"]
    assert not (tmp_path / "environment" / "tool-images").exists()


def test_a_run_workspace_journals_its_tool_image_store_for_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _login_runtime(tmp_path, monkeypatch)
    run = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={"source": "b" * 40},
        id_factory=_Ids(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )

    ApplicationRuntime.create(
        run.root / "environment",
        names=(ToolName.HADOLINT,),
        resolver=cast(ToolResolver, _Resolver({}, tmp_path)),
        journal=run.journal,
        images=frozenset({ToolName.HADOLINT}),
        image_resolver=_ImageFactory(),
    )

    (entry,) = [
        item
        for item in run.journal.entries()
        if item.kind is ResourceKind.TOOL_IMAGE_STORE
    ]
    assert entry.identifier == str(run.root / "environment" / "tool-images")
    assert entry.status is ResourceStatus.CREATED
    assert entry.ephemeral is True
    assert (run.root / "environment" / "tool-images").is_dir()

    (tmp_path / "failing").mkdir()
    failing = RunWorkspace.create(
        state_home=tmp_path / "state-failing",
        immutable_inputs={"source": "b" * 40},
        id_factory=_Ids(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(OperationalError, match="pull failed"):
        ApplicationRuntime.create(
            failing.root / "environment",
            names=(ToolName.HADOLINT,),
            resolver=cast(ToolResolver, _Resolver({}, tmp_path / "failing")),
            journal=failing.journal,
            images=frozenset({ToolName.HADOLINT}),
            image_resolver=_ImageFactory(
                {ToolName.HADOLINT: OperationalError("pull failed")}
            ),
        )
    (failed,) = [
        item
        for item in failing.journal.entries()
        if item.kind is ResourceKind.TOOL_IMAGE_STORE
    ]
    assert failed.status is ResourceStatus.FAILED
