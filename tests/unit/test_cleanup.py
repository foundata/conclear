import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conclear.config import TestConfig as RuntimeTestConfig
from conclear.config import TestLaunchConfig as RuntimeTestLaunchConfig
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.registry_control import TagObservation
from conclear.services.cleanup import cleanup_run, retire_run
from conclear.test_inputs import materialize_test_inputs
from conclear.values import Digest, OCIReference
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
)


class IdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


class FakeBuildah:
    def __init__(self) -> None:
        self.removed: list[tuple[Path, Path]] = []

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        self.removed.append((root, runroot))


class FakePodman:
    def __init__(self) -> None:
        self.removed: list[str] = []
        self.reset: list[tuple[Path, Path]] = []
        self.mapped_removals: list[tuple[Path, Path]] = []

    def remove(
        self, *, root: Path, runroot: Path, name: str, force: bool = False
    ) -> None:
        del root, runroot
        assert force
        self.removed.append(name)

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        self.reset.append((root, runroot))

    def remove_mapped_tree(self, path: Path, *, storage: Path) -> None:
        self.mapped_removals.append((path, storage))
        shutil.rmtree(path, ignore_errors=True)


class FakeRegistryControl:
    def __init__(self, tag: TagObservation | None) -> None:
        self.tag = tag
        self.deleted: list[str] = []

    def observe_tag(self, repository: OCIReference, tag: str) -> TagObservation | None:
        assert repository.tag is None
        del tag
        return self.tag

    def remove_tag(self, repository: OCIReference, tag: str) -> None:
        assert repository.tag is None
        if self.tag is not None and self.tag.immutable:
            raise OperationalError("immutable tags cannot be deleted")
        self.deleted.append(tag)
        self.tag = None

    def ensure_tag_mutable(self, repository: OCIReference, tag: str) -> TagObservation:
        assert repository.tag is None
        assert self.tag is not None
        assert self.tag.name == tag
        self.tag = TagObservation(
            self.tag.name,
            self.tag.digest,
            self.tag.expiration,
            False,
        )
        return self.tag


def workspace(tmp_path: Path) -> RunWorkspace:
    return RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={"source": "b" * 40},
        id_factory=IdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_cleanup_removes_only_journaled_ephemeral_resources(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    owned = run.root / "layouts" / "owned"
    owned.mkdir(parents=True)
    durable = run.root / "records" / "retained.json"
    durable.write_text("retained", encoding="utf-8")
    run.journal.plan(
        resource_id="owned",
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(owned),
        ephemeral=True,
    )
    run.journal.update("owned", ResourceStatus.CREATED)
    run.journal.plan(
        resource_id="durable",
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(durable),
        ephemeral=False,
    )
    run.journal.update("durable", ResourceStatus.CREATED)

    result = cleanup_run(
        run,
        buildah=FakeBuildah(),
        podman=FakePodman(),
        registry_control=None,
    )

    assert result.removed == ("owned",)
    assert not owned.exists()
    assert durable.is_file()


def test_cleanup_removes_container_and_isolated_podman_storage(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    storage = run.root / "podman" / "linux-amd64" / "root"
    storage.mkdir(parents=True)
    runroot = storage.parent / "runroot"
    runroot.mkdir()
    run.journal.plan(
        resource_id="podman-linux-amd64",
        kind=ResourceKind.PODMAN_IMPORT,
        identifier="owned-container",
        ephemeral=True,
        metadata={"storageRoot": str(storage)},
    )
    run.journal.update("podman-linux-amd64", ResourceStatus.CREATED)
    podman = FakePodman()

    result = cleanup_run(
        run,
        buildah=FakeBuildah(),
        podman=podman,
        registry_control=None,
    )

    assert result.removed == ("podman-linux-amd64",)
    assert podman.removed == ["owned-container"]
    assert podman.reset == [(storage, runroot)]
    assert not storage.parent.exists()


def test_cleanup_removes_preparation_without_resetting_shared_storage(
    tmp_path: Path,
) -> None:
    run = workspace(tmp_path)
    storage = run.root / "podman" / "linux-amd64" / "root"
    storage.mkdir(parents=True)
    runroot = storage.parent / "runroot"
    runroot.mkdir()
    run.journal.plan(
        resource_id="preparation",
        kind=ResourceKind.PODMAN_IMPORT,
        identifier="owned-preparation",
        ephemeral=True,
        metadata={"storageRoot": str(storage), "resetStorage": False},
    )
    run.journal.update("preparation", ResourceStatus.CREATED)
    podman = FakePodman()

    result = cleanup_run(
        run,
        buildah=FakeBuildah(),
        podman=podman,
        registry_control=None,
    )

    assert result.removed == ("preparation",)
    assert podman.removed == ["owned-preparation"]
    assert not podman.reset
    assert storage.is_dir()


def test_cleanup_requires_run_marker_for_test_input_tree(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    root = run.root / "reports" / "test-inputs"
    test = RuntimeTestConfig(
        fixtures=(),
        outputs=(),
        preparations=(),
        launch=RuntimeTestLaunchConfig((), (), (), 0),
    )
    materialize_test_inputs(root, run_id=run.run_id, test=test)
    run.journal.plan(
        resource_id="test-inputs",
        kind=ResourceKind.TEST_INPUTS,
        identifier=str(root),
        ephemeral=True,
    )
    run.journal.update("test-inputs", ResourceStatus.CREATED)

    result = cleanup_run(
        run,
        buildah=FakeBuildah(),
        podman=FakePodman(),
        registry_control=None,
    )

    assert result.removed == ("test-inputs",)
    assert not root.exists()


def test_cleanup_closes_planned_test_inputs_that_were_never_created(
    tmp_path: Path,
) -> None:
    run = workspace(tmp_path)
    root = run.root / "reports" / "test-inputs"
    run.journal.plan(
        resource_id="test-inputs",
        kind=ResourceKind.TEST_INPUTS,
        identifier=str(root),
        ephemeral=True,
    )

    result = cleanup_run(
        run,
        buildah=FakeBuildah(),
        podman=FakePodman(),
        registry_control=None,
    )

    assert result.removed == ("test-inputs",)
    assert run.journal.entries()[0].status is ResourceStatus.REMOVED


def test_cleanup_refuses_candidate_when_recorded_digest_changed(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    expected = Digest("sha256:" + "a" * 64)
    changed = Digest("sha256:" + "b" * 64)
    reference = OCIReference.parse("quay.io/example/app:candidate")
    run.journal.plan(
        resource_id="candidate",
        kind=ResourceKind.CANDIDATE_REFERENCE,
        identifier=str(reference),
        ephemeral=True,
        metadata={"digest": str(expected)},
    )
    run.journal.update("candidate", ResourceStatus.CREATED)
    registry_control = FakeRegistryControl(
        TagObservation("candidate", changed, None, False)
    )

    with pytest.raises(OperationalError, match="unowned digest"):
        cleanup_run(
            run,
            buildah=FakeBuildah(),
            podman=FakePodman(),
            registry_control=registry_control,
        )

    assert registry_control.deleted == []
    assert run.journal.entries()[0].status is ResourceStatus.CREATED


def test_cleanup_lifts_owned_candidate_immutability_before_deletion(
    tmp_path: Path,
) -> None:
    run = workspace(tmp_path)
    expected = Digest("sha256:" + "a" * 64)
    reference = OCIReference.parse("quay.io/example/app:candidate")
    run.journal.plan(
        resource_id="candidate",
        kind=ResourceKind.CANDIDATE_REFERENCE,
        identifier=str(reference),
        ephemeral=True,
        metadata={"digest": str(expected)},
    )
    run.journal.update("candidate", ResourceStatus.CREATED)
    registry_control = FakeRegistryControl(
        TagObservation("candidate", expected, None, True)
    )

    result = cleanup_run(
        run,
        buildah=FakeBuildah(),
        podman=FakePodman(),
        registry_control=registry_control,
    )

    assert result.removed == ("candidate",)
    assert registry_control.deleted == ["candidate"]
    assert run.journal.entries()[0].status is ResourceStatus.REMOVED


def test_cleanup_unlinks_owned_symlink_without_following_it(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker"
    marker.write_text("keep", encoding="utf-8")
    link = run.root / "layouts" / "link"
    link.symlink_to(outside, target_is_directory=True)
    run.journal.plan(
        resource_id="link",
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(link),
        ephemeral=True,
    )
    run.journal.update("link", ResourceStatus.CREATED)

    cleanup_run(
        run,
        buildah=FakeBuildah(),
        podman=FakePodman(),
        registry_control=None,
    )

    assert not link.exists()
    assert marker.read_text(encoding="utf-8") == "keep"


def test_cleanup_can_reserve_ambiguous_candidate_for_resume(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    reference = OCIReference.parse("quay.io/example/app:candidate")
    run.journal.plan(
        resource_id="candidate",
        kind=ResourceKind.CANDIDATE_REFERENCE,
        identifier=str(reference),
        ephemeral=True,
    )
    run.journal.update("candidate", ResourceStatus.FAILED)

    result = cleanup_run(
        run,
        buildah=FakeBuildah(),
        podman=FakePodman(),
        registry_control=FakeRegistryControl(None),
        statuses=frozenset({ResourceStatus.FAILED}),
        excluded_kinds=frozenset({ResourceKind.CANDIDATE_REFERENCE}),
    )

    assert result.removed == ()
    assert result.retained == ("candidate",)
    assert run.journal.entries()[0].status is ResourceStatus.FAILED


def test_cleanup_preserves_explicitly_revalidated_resource(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    layout = run.root / "layouts" / "accepted"
    layout.mkdir(parents=True)
    run.journal.plan(
        resource_id="layout-linux-amd64",
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(layout),
        ephemeral=True,
    )
    run.journal.update("layout-linux-amd64", ResourceStatus.CREATED)

    result = cleanup_run(
        run,
        buildah=FakeBuildah(),
        podman=FakePodman(),
        registry_control=None,
        excluded_resource_ids=frozenset({"layout-linux-amd64"}),
    )

    assert result.retained == ("layout-linux-amd64",)
    assert layout.is_dir()


def test_retire_removes_the_directory_of_a_terminal_run(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    run.transition(RunState.COMPLETED, now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC))
    assert run.root.is_dir()

    removed = retire_run(run, state_home=tmp_path / "state")

    assert removed == run.root.resolve()
    assert not run.root.exists()


def test_retire_refuses_a_release_that_could_still_resume(tmp_path: Path) -> None:
    run = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={"sourceRevision": "b" * 40, "version": "1.0.0"},
        id_factory=IdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    for state in (RunState.CREATED, RunState.INCOMPLETE):
        if state is not RunState.CREATED:
            run.transition(state, now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC))
        with pytest.raises(InvalidInvocationError, match="could still resume"):
            retire_run(run, state_home=tmp_path / "state")
        assert run.root.is_dir()


def test_retire_accepts_an_interrupted_run_that_is_not_a_release(
    tmp_path: Path,
) -> None:
    running = workspace(tmp_path)
    with pytest.raises(InvalidInvocationError, match="could still resume"):
        retire_run(running, state_home=tmp_path / "state")
    assert running.root.is_dir()

    running.transition(RunState.INCOMPLETE, now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC))
    removed = retire_run(running, state_home=tmp_path / "state")

    assert removed == running.root.resolve()
    assert not running.root.exists()


def test_retire_refuses_a_workspace_outside_the_state_home(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    run.transition(RunState.REJECTED, now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC))

    with pytest.raises(OperationalError, match="Refusing to retire"):
        retire_run(run, state_home=tmp_path / "elsewhere")
    assert run.root.is_dir()


def test_retire_accepts_a_qualification_without_a_release_profile(
    tmp_path: Path,
) -> None:
    run = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={"sourceRevision": "b" * 40, "profile": "none"},
        id_factory=IdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    run.transition(RunState.QUALIFIED, now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC))

    removed = retire_run(run, state_home=tmp_path / "state")

    assert removed == run.root.resolve()
    assert not run.root.exists()


def _release_run_with_window(tmp_path: Path, expires_at: str) -> RunWorkspace:
    run = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={"sourceRevision": "b" * 40, "profile": "foundata"},
        id_factory=IdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    run.transition(RunState.QUALIFIED, now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC))
    records = run.root / "records"
    records.mkdir(exist_ok=True)
    (records / "platform-qualification-linux-amd64.json").write_text(
        json.dumps(
            {
                "payload": {
                    "qualificationWindow": {
                        "startedAt": "2026-01-01T00:00:00Z",
                        "expiresAt": expires_at,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return run


def test_retire_accepts_a_release_whose_qualification_window_expired(
    tmp_path: Path,
) -> None:
    run = _release_run_with_window(tmp_path, "2026-01-03T00:00:00Z")

    with pytest.raises(InvalidInvocationError, match="until its qualification"):
        retire_run(
            run,
            state_home=tmp_path / "state",
            now=datetime(2026, 1, 2, tzinfo=UTC),
        )
    assert run.root.is_dir()

    removed = retire_run(
        run, state_home=tmp_path / "state", now=datetime(2026, 1, 3, tzinfo=UTC)
    )

    assert removed == run.root.resolve()
    assert not run.root.exists()


def test_abandon_retires_a_release_that_could_still_resume(tmp_path: Path) -> None:
    run = _release_run_with_window(tmp_path, "2026-01-03T00:00:00Z")

    removed = retire_run(
        run,
        state_home=tmp_path / "state",
        now=datetime(2026, 1, 2, tzinfo=UTC),
        abandon=True,
    )

    assert removed == run.root.resolve()
    assert not run.root.exists()


def _planned_hook_scratch(run: RunWorkspace) -> Path:
    scratch = run.root / "hook-scratch" / "app" / "linux-amd64"
    scratch.mkdir(parents=True)
    (scratch / "store").mkdir()
    (scratch / "store" / "layer").write_text("hook litter", encoding="utf-8")
    run.journal.plan(
        resource_id="hook-scratch-app-linux-amd64",
        kind=ResourceKind.HOOK_SCRATCH,
        identifier=str(scratch),
        ephemeral=True,
    )
    run.journal.update("hook-scratch-app-linux-amd64", ResourceStatus.CREATED)
    return scratch


def test_cleanup_removes_hook_scratch_plainly_when_it_can(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    scratch = _planned_hook_scratch(run)
    podman = FakePodman()

    result = cleanup_run(
        run, buildah=FakeBuildah(), podman=podman, registry_control=None
    )

    assert result.removed == ("hook-scratch-app-linux-amd64",)
    assert not scratch.exists()
    assert podman.mapped_removals == []


def test_cleanup_removes_blocked_hook_scratch_through_the_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = workspace(tmp_path)
    scratch = _planned_hook_scratch(run)
    real_rmtree = shutil.rmtree

    def refuse_scratch(path: Path, *args: Any, **kwargs: Any) -> None:
        if path == scratch and not kwargs.get("ignore_errors"):
            raise PermissionError(13, "Permission denied", str(scratch / "store"))
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", refuse_scratch)
    monkeypatch.setattr("conclear.hook_scratch.active_mounts_below", lambda *a, **k: ())
    podman = FakePodman()

    result = cleanup_run(
        run, buildah=FakeBuildah(), podman=podman, registry_control=None
    )

    assert result.removed == ("hook-scratch-app-linux-amd64",)
    assert podman.mapped_removals == [(scratch, run.root / "hook-scratch" / ".unshare")]
    assert not scratch.exists()
    assert not (run.root / "hook-scratch" / ".unshare").exists()


@pytest.mark.skipif(os.getuid() == 0, reason="root ignores directory permissions")
def test_retire_names_what_it_cannot_remove_and_stays_retryable(
    tmp_path: Path,
) -> None:
    run = workspace(tmp_path)
    run.transition(RunState.COMPLETED, now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC))
    (run.root / "records" / "result.json").write_text("{}", encoding="utf-8")
    (run.root / "layouts" / "linux-amd64").mkdir(parents=True)
    litter = run.root / "checkout" / ".pytest" / "podman-root" / "layer"
    litter.mkdir(parents=True)
    blocked = litter / "root-mapped"
    blocked.write_text("subordinate uid", encoding="utf-8")
    # A read-only parent blocks the unlink the way a subordinate owner would.
    litter.chmod(0o500)
    try:
        with pytest.raises(OperationalError, match="retired only partially") as caught:
            retire_run(run, state_home=tmp_path / "state")
    finally:
        litter.chmod(0o700)

    message = str(caught.value)
    assert str(blocked) in message
    assert "podman unshare rm -rf" in message
    # The blocked file is named first, not the directories that failed after it.
    assert message.split("cannot remove ", 1)[1].startswith(str(blocked))
    assert not (run.root / "layouts").exists()
    assert (run.root / "run.json").is_file()
    assert (run.root / "records" / "result.json").is_file()
    assert run.load().state is RunState.COMPLETED

    removed = retire_run(run, state_home=tmp_path / "state")

    assert removed == run.root.resolve()
    assert not run.root.exists()


def test_binding_after_an_interruption_keeps_the_run_openable(tmp_path: Path) -> None:
    """Tool identities bound while a failure unwinds must keep the resume marker."""
    run = workspace(tmp_path)
    run.transition(RunState.INCOMPLETE, now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC))
    run.bind_tool_identities(
        {"tool.skopeo": "1.20.0@sha256:" + "c" * 64},
        now=datetime(2026, 1, 1, 0, 2, tzinfo=UTC),
    )

    reopened = RunWorkspace.open(state_home=tmp_path / "state", run_id=run.run_id)
    snapshot = reopened.load()

    assert snapshot.state is RunState.INCOMPLETE
    assert snapshot.resume_state is RunState.CREATED
    assert "tool.skopeo" in snapshot.immutable_inputs
    assert retire_run(reopened, state_home=tmp_path / "state") == run.root.resolve()


def test_cleanup_resets_and_removes_a_tool_image_store(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    store = run.root / "environment" / "tool-images"
    (store / "root").mkdir(parents=True)
    (store / "runroot").mkdir()
    run.journal.plan(
        resource_id="tool-images",
        kind=ResourceKind.TOOL_IMAGE_STORE,
        identifier=str(store),
        ephemeral=True,
    )
    run.journal.update("tool-images", ResourceStatus.CREATED)
    podman = FakePodman()

    result = cleanup_run(
        run,
        buildah=FakeBuildah(),
        podman=podman,
        registry_control=None,
    )

    assert result.removed == ("tool-images",)
    assert podman.reset == [(store / "root", store / "runroot")]
    assert not store.exists()
