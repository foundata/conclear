from datetime import UTC, datetime
from pathlib import Path

import pytest

from conclear.adapters.quay import QuayTagObservation
from conclear.errors import OperationalError
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

    def remove(
        self, *, root: Path, runroot: Path, name: str, force: bool = False
    ) -> None:
        del root, runroot
        assert force
        self.removed.append(name)


class FakeQuay:
    def __init__(self, tag: QuayTagObservation | None) -> None:
        self.tag = tag
        self.deleted: list[str] = []

    def get_tag(self, repository: OCIReference, tag: str) -> QuayTagObservation | None:
        assert repository.tag is None
        del tag
        return self.tag

    def delete_tag(self, repository: OCIReference, tag: str) -> None:
        assert repository.tag is None
        self.deleted.append(tag)
        self.tag = None


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
        quay=None,
    )

    assert result.removed == ("owned",)
    assert not owned.exists()
    assert durable.is_file()


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
    quay = FakeQuay(QuayTagObservation("candidate", changed, None, False))

    with pytest.raises(OperationalError, match="unowned digest"):
        cleanup_run(
            run,
            buildah=FakeBuildah(),
            podman=FakePodman(),
            quay=quay,
        )

    assert quay.deleted == []
    assert run.journal.entries()[0].status is ResourceStatus.CREATED


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
        quay=None,
    )

    assert not link.exists()
    assert marker.read_text(encoding="utf-8") == "keep"
