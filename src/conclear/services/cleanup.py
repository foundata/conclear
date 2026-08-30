"""Ownership-journal-driven release-run cleanup."""

import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from conclear.adapters.quay import QuayTagObservation
from conclear.errors import OperationalError
from conclear.values import Digest, OCIReference
from conclear.workspace import (
    ResourceEntry,
    ResourceKind,
    ResourceStatus,
    RunWorkspace,
)


class BuildStorage(Protocol):
    """Run-owned Buildah storage cleanup boundary."""

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        """Remove content from one isolated storage root."""
        ...


class RuntimeStorage(Protocol):
    """Run-owned Podman resource cleanup boundary."""

    def remove(
        self, *, root: Path, runroot: Path, name: str, force: bool = False
    ) -> None:
        """Remove one isolated runtime container."""
        ...


class CandidateRegistry(Protocol):
    """Candidate tag cleanup boundary."""

    def get_tag(self, repository: OCIReference, tag: str) -> QuayTagObservation | None:
        """Observe one exact candidate tag."""
        ...

    def delete_tag(self, repository: OCIReference, tag: str) -> None:
        """Delete and verify one candidate tag."""
        ...


@dataclass(frozen=True, slots=True)
class CleanupResult:
    """Resources removed or deliberately retained by cleanup."""

    removed: tuple[str, ...]
    retained: tuple[str, ...]


def cleanup_run(
    workspace: RunWorkspace,
    *,
    buildah: BuildStorage,
    podman: RuntimeStorage,
    quay: CandidateRegistry | None,
) -> CleanupResult:
    """Remove only ephemeral resources whose ownership is established by the run."""
    removed: list[str] = []
    retained: list[str] = []
    failures: list[str] = []
    for entry in workspace.journal.cleanup_candidates():
        try:
            did_remove = _cleanup_entry(
                workspace, entry, buildah=buildah, podman=podman, quay=quay
            )
        except Exception as exc:
            failures.append(f"{entry.resource_id}: {exc}")
            retained.append(entry.resource_id)
            continue
        if did_remove:
            workspace.journal.update(entry.resource_id, ResourceStatus.REMOVED)
            removed.append(entry.resource_id)
        else:
            retained.append(entry.resource_id)
    if failures:
        raise OperationalError("Cleanup was incomplete: " + "; ".join(failures))
    return CleanupResult(tuple(removed), tuple(retained))


def _cleanup_entry(
    workspace: RunWorkspace,
    entry: ResourceEntry,
    *,
    buildah: BuildStorage,
    podman: RuntimeStorage,
    quay: CandidateRegistry | None,
) -> bool:
    if entry.kind is ResourceKind.LOCAL_PATH:
        path = _owned_path(workspace, entry.identifier)
        _remove_local(path)
        return True
    if entry.kind is ResourceKind.BUILDAH_STORAGE:
        root = _owned_path(workspace, entry.identifier)
        buildah.remove_storage(root=root / "root", runroot=root / "runroot")
        _remove_local(root)
        return True
    if entry.kind is ResourceKind.PODMAN_IMPORT:
        storage = _metadata_path(workspace, entry, "storageRoot")
        podman.remove(
            root=storage,
            runroot=storage.parent / "runroot",
            name=entry.identifier,
            force=True,
        )
        _remove_local(storage.parent)
        return True
    if entry.kind is ResourceKind.CANDIDATE_REFERENCE:
        if quay is None:
            raise OperationalError("Candidate cleanup requires Quay credentials")
        reference = OCIReference.parse(entry.identifier, require_tag=True)
        if reference.digest is not None or reference.tag is None:
            raise OperationalError("Journaled candidate reference is malformed")
        expected_value = entry.metadata.get("digest")
        if not isinstance(expected_value, str):
            raise OperationalError(
                "Candidate ownership is uncertain because no digest was recorded"
            )
        expected = Digest(expected_value)
        repository = OCIReference(reference.registry, reference.repository)
        observed = quay.get_tag(repository, reference.tag)
        if observed is None:
            return True
        if observed.digest != expected:
            raise OperationalError("Candidate now names an unowned digest")
        quay.delete_tag(repository, reference.tag)
        return True
    return False


def _owned_path(workspace: RunWorkspace, value: str) -> Path:
    path = Path(value)
    try:
        relative = path.relative_to(workspace.root)
    except ValueError as exc:
        raise OperationalError("Journaled path is outside the run workspace") from exc
    if not relative.parts:
        raise OperationalError("Cleanup cannot remove the workspace root")
    current = workspace.root
    for component in relative.parts[:-1]:
        current = current / component
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise OperationalError("Journaled path crosses a symbolic link")
        except FileNotFoundError:
            break
        except OSError as exc:
            raise OperationalError("Unable to inspect journaled path") from exc
    return path


def _metadata_path(workspace: RunWorkspace, entry: ResourceEntry, name: str) -> Path:
    value = entry.metadata.get(name)
    if not isinstance(value, str):
        raise OperationalError(f"Journaled resource has no {name}")
    return _owned_path(workspace, value)


def _remove_local(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OperationalError(f"Unable to inspect owned path {path}") from exc
    try:
        if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
            shutil.rmtree(path)
        else:
            path.unlink()
    except OSError as exc:
        raise OperationalError(f"Unable to remove owned path {path}") from exc
