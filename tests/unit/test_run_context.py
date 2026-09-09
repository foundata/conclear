import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import conclear.commands.local as local_commands
import conclear.services.run_context as run_context_module
from conclear.adapters.git import SourceObservation
from conclear.cli import main
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
    failed_run_id,
)
from conclear.jsonutil import sha256_bytes
from conclear.services.cleanup import cleanup_run
from conclear.services.run_context import create_source_run, open_source_run
from conclear.tools import ToolName
from conclear.workspace import ResourceStatus, RunState, RunWorkspace
from tests.unit.test_config import _image_text

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


class NoStorage:
    """Cleanup boundary for a run that never created Buildah storage."""

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        raise AssertionError("no storage was created")


class NoRuntime:
    """Cleanup boundary for a run that never created a container."""

    def remove(
        self, *, root: Path, runroot: Path, name: str, force: bool = False
    ) -> None:
        raise AssertionError("no container was created")

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        raise AssertionError("no storage was created")


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


def test_source_run_records_inferred_release_image(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, _, _ = source
    run = create(root, tmp_path, image_id=None)
    assert run.workspace.load().immutable_inputs["image"] == "app"


@pytest.mark.parametrize("version", [None, "stable"])
def test_source_run_rejects_missing_version_or_moving_tag_collision_before_build_tools(
    source: tuple[Path, FakeGit, dict[str, str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: str | None,
) -> None:
    root, git, settings = source
    resolved: list[ToolName] = []

    class Runtime:
        @classmethod
        def create(cls, path: Path, *, names: tuple[ToolName, ...]) -> FakeRuntime:
            resolved.extend(names)
            assert names == (ToolName.GIT,)
            return FakeRuntime(git, names, settings["digest"])

    monkeypatch.setattr(run_context_module, "ApplicationRuntime", Runtime)
    with pytest.raises(InvalidInvocationError):
        create(root, tmp_path, version=version)
    assert resolved == [ToolName.GIT, ToolName.GIT]


def test_source_run_rejects_reserved_additional_inputs_before_creating_a_run(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, _, _ = source

    with pytest.raises(InvalidInvocationError, match="conflict") as caught:
        create(root, tmp_path, additional_inputs={"sourceRevision": "x"})

    assert failed_run_id(caught.value) is None
    assert not (tmp_path / "state" / "conclear" / "runs").exists()


def test_failure_before_workspace_creation_names_no_run(
    source: tuple[Path, FakeGit, dict[str, str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, git, _ = source

    def observe(repository: Path, selector: str) -> SourceObservation:
        raise OperationalError("git is unavailable")

    monkeypatch.setattr(git, "observe", observe)

    with pytest.raises(OperationalError, match="git is unavailable") as caught:
        create(root, tmp_path)

    assert failed_run_id(caught.value) is None
    assert not (tmp_path / "state" / "conclear" / "runs").exists()


def test_checked_out_configuration_must_match_the_git_object(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, git, _ = source
    git.config_override = (root / "conclear.toml").read_text(encoding="utf-8") + "\n"

    with pytest.raises(OperationalError, match="differs from Git object") as caught:
        create(root, tmp_path)

    workspace = _only_workspace(tmp_path)
    assert workspace.load().state is RunState.INCOMPLETE
    assert failed_run_id(caught.value) == workspace.run_id
    _assert_cleanup_resolves_every_resource(workspace, git)


def test_observed_origin_must_match_the_configured_project_source(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, git, _ = source
    git.remote_url = "https://github.com/other/app.git"

    with pytest.raises(RuleRejectionError, match="differs from configured") as caught:
        create(root, tmp_path)

    assert caught.value.code == "CC0001"
    workspace = _only_workspace(tmp_path)
    assert workspace.load().state is RunState.REJECTED
    assert failed_run_id(caught.value) == workspace.run_id
    _assert_cleanup_resolves_every_resource(workspace, git)


def test_unknown_image_leaves_an_incomplete_run(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, git, _ = source

    with pytest.raises(InvalidInvocationError, match="Unknown image") as caught:
        create(root, tmp_path, image_id="missing")

    workspace = _only_workspace(tmp_path)
    assert workspace.load().state is RunState.INCOMPLETE
    assert failed_run_id(caught.value) == workspace.run_id
    _assert_cleanup_resolves_every_resource(workspace, git)


def test_test_only_image_cannot_start_a_run(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, git, _ = source
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8").replace(
        "[images.release]",
        '[images.test]\ndependencies = ["helper"]\n\n[images.release]',
    )
    path.write_text(content + _image_text("helper", releasable=False), encoding="utf-8")

    with pytest.raises(InvalidInvocationError, match="helper is test-only") as caught:
        create(root, tmp_path, image_id="helper")

    workspace = _only_workspace(tmp_path)
    assert workspace.load().state is RunState.INCOMPLETE
    assert failed_run_id(caught.value) == workspace.run_id
    _assert_cleanup_resolves_every_resource(workspace, git)


def test_failed_worktree_creation_is_journaled_and_incomplete(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    root, git, _ = source
    git.fail_worktree = True

    with pytest.raises(OperationalError, match="injected worktree failure") as caught:
        create(root, tmp_path)

    workspace = _only_workspace(tmp_path)
    assert workspace.load().state is RunState.INCOMPLETE
    entry = next(iter(workspace.journal.entries()))
    assert entry.status is ResourceStatus.FAILED
    assert failed_run_id(caught.value) == workspace.run_id
    # The worktree never materialized, so cleanup resolves the failed entry
    # without asking Git to remove a directory that does not exist.
    _assert_cleanup_resolves_every_resource(workspace, git)


def test_tool_resolution_failure_after_workspace_creation_names_the_run(
    source: tuple[Path, FakeGit, dict[str, str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, git, settings = source

    class Runtime:
        @classmethod
        def create(cls, path: Path, *, names: tuple[ToolName, ...]) -> FakeRuntime:
            if ToolName.BUILDAH in names:
                raise OperationalError("buildah is unavailable")
            return FakeRuntime(git, names, settings["digest"])

    monkeypatch.setattr(run_context_module, "ApplicationRuntime", Runtime)

    with pytest.raises(OperationalError, match="buildah is unavailable") as caught:
        create(root, tmp_path)

    workspace = _only_workspace(tmp_path)
    assert workspace.load().state is RunState.INCOMPLETE
    assert failed_run_id(caught.value) == workspace.run_id
    assert [entry.resource_id for entry in workspace.journal.entries()] == [
        "source-worktree"
    ]
    _assert_cleanup_resolves_every_resource(workspace, git)
    _assert_cleanup_resolves_every_resource(workspace, git)


def test_build_names_the_run_when_source_isolation_fails(
    source: tuple[Path, FakeGit, dict[str, str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, git, _ = source
    git.fail_worktree = True
    monkeypatch.setattr(local_commands, "state_home", lambda: tmp_path / "state")

    code = main(
        [
            "build",
            "--source",
            str(root),
            "--revision",
            "v1.2.3",
            "--image",
            "app",
            "--platform",
            "linux/amd64",
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    workspace = _only_workspace(tmp_path)
    assert code == 1
    value = json.loads(captured.out)
    assert (value["status"], value["data"]) == (
        "operationalFailure",
        {"runId": workspace.run_id},
    )
    assert f"conclear cleanup {workspace.run_id}" in captured.err
    assert workspace.load().state is RunState.INCOMPLETE


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
    later_phase = open_source_run(
        state_home=state_home,
        run_id=created.workspace.run_id,
        names=(ToolName.TRIVY,),
    )
    assert (
        later_phase.workspace.load().immutable_inputs["tool.trivy"].startswith("1.0.0@")
    )
    settings["digest"] = "sha256:" + "3" * 64
    with pytest.raises(InvalidInvocationError, match="tool identity changed"):
        open_source_run(
            state_home=state_home,
            run_id=created.workspace.run_id,
            names=(ToolName.TRIVY,),
        )
    settings["digest"] = "sha256:" + "1" * 64

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


def _assert_cleanup_resolves_every_resource(workspace: Any, git: FakeGit) -> None:
    cleanup_run(
        workspace,
        buildah=NoStorage(),
        podman=NoRuntime(),
        registry_control=None,
        git=git,
    )
    assert not [
        entry
        for entry in workspace.journal.entries()
        if entry.status
        in {
            ResourceStatus.PLANNED,
            ResourceStatus.CREATED,
            ResourceStatus.FAILED,
        }
    ]


def _only_workspace(tmp_path: Path) -> Any:
    runs = tmp_path / "state" / "conclear" / "runs"
    (run_directory,) = [item for item in runs.iterdir() if item.is_dir()]
    return RunWorkspace.open(state_home=tmp_path / "state", run_id=run_directory.name)


def test_a_later_phase_pins_a_tool_at_first_use_and_a_finished_run_refuses_new_tools(
    source: tuple[Path, FakeGit, dict[str, str]], tmp_path: Path
) -> None:
    """A coordinator run created by `assemble` records only Git; `publish` adds Skopeo."""
    root, _git, settings = source
    created = create(root, tmp_path, names=())
    state_home = tmp_path / "state"
    assert [
        key
        for key in created.workspace.load().immutable_inputs
        if key.startswith("tool.")
    ] == ["tool.git"]
    for state in (RunState.QUALIFIED, RunState.ASSEMBLED):
        created.workspace.transition(state)

    publish_phase = open_source_run(
        state_home=state_home,
        run_id=created.workspace.run_id,
        names=(ToolName.SKOPEO,),
    )
    inputs = publish_phase.workspace.load().immutable_inputs
    assert inputs["tool.skopeo"] == "1.0.0@sha256:" + "1" * 64

    settings["digest"] = "sha256:" + "2" * 64
    with pytest.raises(
        InvalidInvocationError, match=r"tool identity changed: tool\.git"
    ):
        open_source_run(
            state_home=state_home,
            run_id=created.workspace.run_id,
            names=(ToolName.SKOPEO, ToolName.COSIGN),
        )
    settings["digest"] = "sha256:" + "1" * 64

    created.workspace.transition(RunState.REJECTED)
    with pytest.raises(InvalidInvocationError, match="finished run"):
        open_source_run(
            state_home=state_home,
            run_id=created.workspace.run_id,
            names=(ToolName.COSIGN,),
        )
    assert "tool.cosign" not in created.workspace.load().immutable_inputs
