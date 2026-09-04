"""Cleanup refuses every resource whose ownership the journal cannot establish."""

from datetime import UTC, datetime
from pathlib import Path
from typing import override

import pytest

from conclear.errors import OperationalError
from conclear.registry_control import TagObservation
from conclear.services.cleanup import CleanupResult, cleanup_run
from conclear.values import Digest, OCIReference
from conclear.workspace import ResourceKind, ResourceStatus, RunWorkspace
from tests.unit.test_cleanup import FakeBuildah, FakePodman, FakeRegistryControl

DIGEST = Digest("sha256:" + "a" * 64)
CANDIDATE = "quay.io/example/app:1.2.3-candidate.01arz3ndektsv4rrffq69g5fav.gbbbbbbbb"


class FixedIdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


class FakeGit:
    def __init__(self) -> None:
        self.removed: list[tuple[Path, Path]] = []

    def remove_worktree(self, repository: Path, destination: Path) -> None:
        self.removed.append((repository, destination))


def workspace(tmp_path: Path, source_root: Path | None = None) -> RunWorkspace:
    inputs = {"sourceRevision": "b" * 40}
    if source_root is not None:
        inputs["sourceRoot"] = str(source_root)
    return RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs=inputs,
        id_factory=FixedIdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )


def plan(
    run: RunWorkspace,
    resource_id: str,
    kind: ResourceKind,
    identifier: str,
    *,
    metadata: dict[str, object] | None = None,
    status: ResourceStatus = ResourceStatus.CREATED,
) -> None:
    run.journal.plan(
        resource_id=resource_id,
        kind=kind,
        identifier=identifier,
        ephemeral=True,
        metadata=metadata,
    )
    if status is not ResourceStatus.PLANNED:
        run.journal.update(resource_id, status)


def run_cleanup(run: RunWorkspace, **overrides: object) -> CleanupResult:
    arguments: dict[str, object] = {
        "buildah": FakeBuildah(),
        "podman": FakePodman(),
        "registry_control": None,
    }
    arguments.update(overrides)
    return cleanup_run(run, **arguments)  # type: ignore[arg-type]


def status_of(run: RunWorkspace, resource_id: str) -> ResourceStatus:
    return next(
        entry.status
        for entry in run.journal.entries()
        if entry.resource_id == resource_id
    )


def test_paths_outside_the_workspace_or_at_its_root_are_never_removed(
    tmp_path: Path,
) -> None:
    run = workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("keep\n", encoding="utf-8")
    plan(run, "outside", ResourceKind.LOCAL_PATH, str(outside))
    plan(run, "root", ResourceKind.LOCAL_PATH, str(run.root))

    with pytest.raises(OperationalError, match="incomplete") as caught:
        run_cleanup(run)

    assert "outside the run workspace" in str(caught.value)
    assert "cannot remove the workspace root" in str(caught.value)
    assert outside.exists()
    assert run.root.is_dir()
    assert status_of(run, "outside") is ResourceStatus.CREATED
    assert status_of(run, "root") is ResourceStatus.CREATED


def test_journaled_paths_crossing_a_symbolic_link_are_refused(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    target = tmp_path / "real"
    target.mkdir()
    (target / "payload").write_text("keep\n", encoding="utf-8")
    (run.root / "link").symlink_to(target, target_is_directory=True)
    plan(run, "crossing", ResourceKind.LOCAL_PATH, str(run.root / "link" / "payload"))

    with pytest.raises(OperationalError, match="crosses a symbolic link"):
        run_cleanup(run)

    assert (target / "payload").exists()


def test_worktree_cleanup_requires_git_and_a_run_owned_repository(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    run = workspace(tmp_path, source_root)
    worktree = run.root / "source"
    worktree.mkdir()
    plan(
        run,
        "source-worktree",
        ResourceKind.GIT_WORKTREE,
        str(worktree),
        metadata={"repository": str(source_root)},
    )

    with pytest.raises(OperationalError, match="requires Git"):
        run_cleanup(run)

    other = tmp_path / "other"
    other.mkdir()
    run.journal.update(
        "source-worktree", ResourceStatus.CREATED, metadata={"repository": str(other)}
    )
    git = FakeGit()
    with pytest.raises(OperationalError, match="not run-owned"):
        run_cleanup(run, git=git)
    assert git.removed == []

    run.journal.update(
        "source-worktree", ResourceStatus.CREATED, metadata={"repository": 5}
    )
    with pytest.raises(OperationalError, match="no source repository"):
        run_cleanup(run, git=git)

    run.journal.update(
        "source-worktree",
        ResourceStatus.CREATED,
        metadata={"repository": str(source_root)},
    )
    result = run_cleanup(run, git=git)
    assert result.removed == ("source-worktree",)
    assert git.removed == [(source_root.resolve(), worktree)]
    assert status_of(run, "source-worktree") is ResourceStatus.REMOVED


def test_buildah_storage_is_reset_and_removed(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    storage = run.root / "buildah" / "app"
    (storage / "root").mkdir(parents=True)
    plan(run, "buildah-app", ResourceKind.BUILDAH_STORAGE, str(storage))
    buildah = FakeBuildah()

    run_cleanup(run, buildah=buildah)

    assert buildah.removed == [(storage / "root", storage / "runroot")]
    assert not storage.exists()
    assert status_of(run, "buildah-app") is ResourceStatus.REMOVED


def test_candidate_cleanup_requires_credentials_and_an_owned_digest(
    tmp_path: Path,
) -> None:
    run = workspace(tmp_path)
    plan(
        run,
        "candidate",
        ResourceKind.CANDIDATE_REFERENCE,
        CANDIDATE,
        metadata={"digest": str(DIGEST)},
    )
    with pytest.raises(OperationalError, match="requires registry credentials"):
        run_cleanup(run)

    run.journal.update("candidate", ResourceStatus.CREATED, metadata={"digest": None})
    control = FakeRegistryControl(TagObservation("tag", DIGEST, None, False))
    with pytest.raises(OperationalError, match="ownership is uncertain"):
        run_cleanup(run, registry_control=control)
    assert control.deleted == []

    run.journal.update(
        "candidate", ResourceStatus.CREATED, metadata={"digest": str(DIGEST)}
    )
    other = FakeRegistryControl(
        TagObservation("tag", Digest("sha256:" + "9" * 64), None, False)
    )
    with pytest.raises(OperationalError, match="unowned digest"):
        run_cleanup(run, registry_control=other)
    assert other.deleted == []

    absent = FakeRegistryControl(None)
    result = run_cleanup(run, registry_control=absent)
    assert result.removed == ("candidate",)
    assert absent.deleted == []


def test_malformed_candidate_identifiers_are_never_deleted(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    plan(
        run,
        "candidate",
        ResourceKind.CANDIDATE_REFERENCE,
        "quay.io/example/app:1.2.3@" + str(DIGEST),
        metadata={"digest": str(DIGEST)},
    )
    control = FakeRegistryControl(TagObservation("1.2.3", DIGEST, None, False))

    with pytest.raises(OperationalError, match="malformed"):
        run_cleanup(run, registry_control=control)

    assert control.deleted == []


def test_candidate_immutability_lift_must_keep_the_owned_digest(
    tmp_path: Path,
) -> None:
    run = workspace(tmp_path)
    plan(
        run,
        "candidate",
        ResourceKind.CANDIDATE_REFERENCE,
        CANDIDATE,
        metadata={"digest": str(DIGEST)},
    )

    class SwappingControl(FakeRegistryControl):
        @override
        def ensure_tag_mutable(
            self, repository: OCIReference, tag: str
        ) -> TagObservation:
            self.tag = TagObservation(tag, Digest("sha256:" + "8" * 64), None, False)
            return self.tag

    control = SwappingControl(TagObservation("tag", DIGEST, None, True))
    with pytest.raises(OperationalError, match="changed while removing immutability"):
        run_cleanup(run, registry_control=control)
    assert control.deleted == []


def test_status_filters_and_exclusions_retain_resources(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    created = run.root / "created"
    created.write_text("x", encoding="utf-8")
    failed = run.root / "failed"
    failed.write_text("x", encoding="utf-8")
    plan(run, "created", ResourceKind.LOCAL_PATH, str(created))
    plan(
        run,
        "failed",
        ResourceKind.LOCAL_PATH,
        str(failed),
        status=ResourceStatus.FAILED,
    )
    plan(run, "signature", ResourceKind.SIGNATURE, "quay.io/example/app@" + str(DIGEST))

    result = run_cleanup(
        run,
        statuses=frozenset({ResourceStatus.CREATED}),
        excluded_resource_ids=frozenset({"created"}),
        excluded_kinds=frozenset({ResourceKind.SIGNATURE}),
    )

    assert result.removed == ()
    assert set(result.retained) == {"created", "signature"}
    assert created.exists() and failed.exists()

    result = run_cleanup(run)
    assert result.removed == ("created", "failed")
    assert result.retained == ("signature",)
    assert not created.exists() and not failed.exists()
    assert status_of(run, "signature") is ResourceStatus.CREATED


def test_podman_import_without_storage_metadata_is_retained(tmp_path: Path) -> None:
    run = workspace(tmp_path)
    plan(run, "podman-app", ResourceKind.PODMAN_IMPORT, "cc-container")

    with pytest.raises(OperationalError, match="has no storageRoot"):
        run_cleanup(run)

    assert status_of(run, "podman-app") is ResourceStatus.CREATED
