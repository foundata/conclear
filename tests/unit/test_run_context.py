import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import conclear.services.run_context as run_context_module
from conclear.adapters.git import SourceObservation
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.jsonutil import sha256_bytes
from conclear.services.run_context import create_source_run, open_source_run
from conclear.tools import ToolName
from conclear.workspace import ResourceStatus, RunState, RunWorkspace

REVISION = "b" * 40


class FixedIdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


@dataclass(frozen=True)
class FakeTool:
    name: ToolName
    version: str
    executable_digest: str


class FakeGit:
    def __init__(self, source_root: Path) -> None:
        self.source_root = source_root
        self.remote_url = "https://github.com/example/app.git"
        self.revision = REVISION
        self.config_override: str | None = None
        self.fail_worktree = False
        self.observe_calls: list[tuple[Path, str]] = []

    def observe(self, repository: Path, selector: str) -> SourceObservation:
        self.observe_calls.append((repository, selector))
        return SourceObservation(
            self.revision, self.remote_url, datetime(2026, 1, 1, tzinfo=UTC)
        )

    def read_text(self, repository: Path, revision: str, relative_path: str) -> str:
        assert revision == self.revision
        if self.config_override is not None:
            return self.config_override
        return (self.source_root / relative_path).read_text(encoding="utf-8")

    def create_worktree(
        self, repository: Path, destination: Path, revision: str
    ) -> None:
        assert revision == self.revision
        if self.fail_worktree:
            raise OperationalError("injected worktree failure")
        shutil.copytree(self.source_root, destination)

    def remove_worktree(self, repository: Path, destination: Path) -> None:
        shutil.rmtree(destination)


class FakeRuntime:
    def __init__(self, git: FakeGit, names: tuple[ToolName, ...], digest: str) -> None:
        self._git = git
        self.tools = {
            name: FakeTool(name, "1.0.0", digest) for name in dict.fromkeys(names)
        }

    def git(self) -> FakeGit:
        return self._git


@pytest.fixture
def source(
    repository_factory: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, FakeGit, dict[str, str]]:
    root = repository_factory()
    git = FakeGit(root)
    settings = {"digest": "sha256:" + "1" * 64}

    class Runtime:
        @classmethod
        def create(cls, path: Path, *, names: tuple[ToolName, ...]) -> FakeRuntime:
            return FakeRuntime(git, names, settings["digest"])

    monkeypatch.setattr(run_context_module, "ApplicationRuntime", Runtime)
    return root, git, settings


def create(root: Path, tmp_path: Path, **overrides: Any) -> Any:
    arguments: dict[str, Any] = {
        "source_root": root,
        "selector": "v1.2.3",
        "image_id": "app",
        "version": "1.2.3",
        "state_home": tmp_path / "state",
        "names": (ToolName.BUILDAH,),
        "id_factory": FixedIdFactory(),
        "now": datetime(2026, 1, 1, tzinfo=UTC),
    }
    arguments.update(overrides)
    return create_source_run(**arguments)


def test_source_run_binds_observed_identity_and_worktree_ownership(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, git, _ = source

    run = create(root, tmp_path)

    inputs = run.workspace.load().immutable_inputs
    assert inputs["sourceRevision"] == REVISION
    assert inputs["sourceRepository"] == "https://github.com/example/app"
    assert inputs["configurationDigest"] == sha256_bytes(
        (root / "conclear.toml").read_bytes()
    )
    assert inputs["tool.git"] == "1.0.0@sha256:" + "1" * 64
    assert inputs["tool.buildah"] == "1.0.0@sha256:" + "1" * 64
    assert run.source.repository == "https://github.com/example/app"
    assert run.source.revision == REVISION
    assert run.repository.path == (run.workspace.root / "source" / "conclear.toml")
    entry = next(iter(run.workspace.journal.entries()))
    assert entry.resource_id == "source-worktree"
    assert entry.status is ResourceStatus.CREATED
    assert entry.metadata == {"repository": str(root.resolve())}
    assert git.observe_calls == [(root.resolve(), "v1.2.3")]


def test_source_run_rejects_reserved_additional_inputs_before_creating_a_run(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, _, _ = source

    with pytest.raises(InvalidInvocationError, match="conflict"):
        create(root, tmp_path, additional_inputs={"sourceRevision": "x"})

    assert not (tmp_path / "state" / "conclear" / "runs").exists()


def test_checked_out_configuration_must_match_the_git_object(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, git, _ = source
    git.config_override = (root / "conclear.toml").read_text(encoding="utf-8") + "\n"

    with pytest.raises(OperationalError, match="differs from Git object"):
        create(root, tmp_path)

    workspace = _only_workspace(tmp_path)
    assert workspace.load().state is RunState.INCOMPLETE


def test_observed_origin_must_match_the_configured_project_source(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, git, _ = source
    git.remote_url = "https://github.com/other/app.git"

    with pytest.raises(RuleRejectionError, match="differs from configured") as caught:
        create(root, tmp_path)

    assert caught.value.code == "CC0001"
    assert _only_workspace(tmp_path).load().state is RunState.REJECTED


def test_unknown_image_leaves_an_incomplete_run(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, _, _ = source

    with pytest.raises(InvalidInvocationError, match="Unknown image"):
        create(root, tmp_path, image_id="missing")

    assert _only_workspace(tmp_path).load().state is RunState.INCOMPLETE


def test_failed_worktree_creation_is_journaled_and_incomplete(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, git, _ = source
    git.fail_worktree = True

    with pytest.raises(OperationalError, match="injected worktree failure"):
        create(root, tmp_path)

    workspace = _only_workspace(tmp_path)
    assert workspace.load().state is RunState.INCOMPLETE
    entry = next(iter(workspace.journal.entries()))
    assert entry.status is ResourceStatus.FAILED


def test_reopened_run_revalidates_checkout_configuration_and_tools(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, git, settings = source
    created = create(root, tmp_path)
    state_home = tmp_path / "state"

    reopened = open_source_run(
        state_home=state_home, run_id=created.workspace.run_id, names=(ToolName.PODMAN,)
    )
    assert reopened.source == created.source
    assert (
        reopened.workspace.load().immutable_inputs["tool.podman"].startswith("1.0.0@")
    )
    git.observe_calls.clear()

    settings["digest"] = "sha256:" + "2" * 64
    with pytest.raises(InvalidInvocationError, match="tool identity changed"):
        open_source_run(
            state_home=state_home, run_id=created.workspace.run_id, names=()
        )
    assert git.observe_calls == []
    settings["digest"] = "sha256:" + "1" * 64

    created.workspace.transition(RunState.QUALIFIED)
    with pytest.raises(InvalidInvocationError, match="lacks required immutable tool"):
        open_source_run(
            state_home=state_home,
            run_id=created.workspace.run_id,
            names=(ToolName.TRIVY,),
        )

    git.revision = "c" * 40
    with pytest.raises(InvalidInvocationError, match="checkout changed"):
        open_source_run(
            state_home=state_home, run_id=created.workspace.run_id, names=()
        )
    git.revision = REVISION

    worktree = created.workspace.root / "source"
    config = worktree / "conclear.toml"
    original = config.read_bytes()
    config.write_bytes(original + b"\n")
    with pytest.raises(InvalidInvocationError, match="configuration changed"):
        open_source_run(
            state_home=state_home, run_id=created.workspace.run_id, names=()
        )
    config.write_bytes(original)

    created.workspace.journal.update("source-worktree", ResourceStatus.REMOVED)
    with pytest.raises(InvalidInvocationError, match="ownership is not established"):
        open_source_run(
            state_home=state_home, run_id=created.workspace.run_id, names=()
        )

    shutil.rmtree(worktree)
    worktree.symlink_to(root, target_is_directory=True)
    with pytest.raises(InvalidInvocationError, match="not a directory"):
        open_source_run(
            state_home=state_home, run_id=created.workspace.run_id, names=()
        )
    worktree.unlink()
    with pytest.raises(InvalidInvocationError, match="unavailable"):
        open_source_run(
            state_home=state_home, run_id=created.workspace.run_id, names=()
        )


def _only_workspace(tmp_path: Path) -> Any:
    runs = tmp_path / "state" / "conclear" / "runs"
    (run_directory,) = [item for item in runs.iterdir() if item.is_dir()]
    return RunWorkspace.open(state_home=tmp_path / "state", run_id=run_directory.name)
