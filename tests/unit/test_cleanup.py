from datetime import UTC, datetime
from pathlib import Path

import pytest

from conclear.errors import OperationalError
from conclear.registry_control import TagObservation
from conclear.services.cleanup import cleanup_run
from conclear.values import Digest, OCIReference
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
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
