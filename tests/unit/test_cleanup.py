from datetime import UTC, datetime
from pathlib import Path

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

    def remove(
        self, *, root: Path, runroot: Path, name: str, force: bool = False
    ) -> None:
        del root, runroot
        assert force
        self.removed.append(name)

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        self.reset.append((root, runroot))


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


def test_retire_refuses_a_run_that_could_still_resume(tmp_path: Path) -> None:
    run = workspace(tmp_path)

    with pytest.raises(InvalidInvocationError, match="only promoted, completed"):
        retire_run(run, state_home=tmp_path / "state")
    assert run.root.is_dir()


def test_retire_refuses_a_workspace_outside_the_state_home(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    run.transition(RunState.REJECTED, now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC))

    with pytest.raises(OperationalError, match="Refusing to retire"):
        retire_run(run, state_home=tmp_path / "elsewhere")
    assert run.root.is_dir()
