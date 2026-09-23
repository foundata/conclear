"""Ownership-journal-driven release-run cleanup."""

import shutil
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from conclear.errors import ConClearError, InvalidInvocationError, OperationalError
from conclear.freshness import QualificationWindow
from conclear.hook_scratch import UNSHARE_STORAGE_NAME, remove_hook_scratch
from conclear.jsonutil import load_json
from conclear.records import format_timestamp, utc_now
from conclear.registry_control import TagObservation
from conclear.runtime_directory import remove_runtime_directory
from conclear.test_inputs import remove_materialized_test_inputs
from conclear.values import Digest, OCIReference
from conclear.workspace import (
    TERMINAL_STATES,
    ResourceEntry,
    ResourceKind,
    ResourceStatus,
    RunSnapshot,
    RunState,
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

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        """Reset one isolated run-owned Podman storage root."""
        ...

    def remove_mapped_tree(self, path: Path, *, storage: Path) -> None:
        """Remove one run-owned tree inside the rootless user namespace."""
        ...


class CandidateRegistry(Protocol):
    """Candidate tag cleanup boundary."""

    def observe_tag(self, repository: OCIReference, tag: str) -> TagObservation | None:
        """Observe one exact candidate tag."""
        ...

    def remove_tag(self, repository: OCIReference, tag: str) -> None:
        """Delete and verify one candidate tag."""
        ...

    def ensure_tag_mutable(self, repository: OCIReference, tag: str) -> TagObservation:
        """Disable and verify candidate immutability before deletion."""
        ...


class SourceWorktree(Protocol):
    """Git worktree cleanup boundary."""

    def remove_worktree(self, repository: Path, destination: Path) -> None:
        """Remove one detached worktree through Git."""
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
    registry_control: CandidateRegistry | None,
    git: SourceWorktree | None = None,
    statuses: frozenset[ResourceStatus] | None = None,
    excluded_kinds: frozenset[ResourceKind] | None = None,
    excluded_resource_ids: frozenset[str] | None = None,
) -> CleanupResult:
    """Remove only ephemeral resources whose ownership is established by the run."""
    removed: list[str] = []
    retained: list[str] = []
    failures: list[str] = []
    selected_statuses = statuses or frozenset(
        {ResourceStatus.PLANNED, ResourceStatus.CREATED, ResourceStatus.FAILED}
    )
    exclusions = excluded_kinds or frozenset()
    excluded_ids = excluded_resource_ids or frozenset()
    # Podman and Buildah may still need sockets and namespaces while cleaning up.
    candidates = sorted(
        workspace.journal.cleanup_candidates(),
        key=lambda entry: entry.kind is ResourceKind.RUNTIME_DIRECTORY,
    )
    for entry in candidates:
        if entry.status not in selected_statuses:
            continue
        if entry.kind in exclusions or entry.resource_id in excluded_ids:
            retained.append(entry.resource_id)
            continue
        if entry.kind is ResourceKind.RUNTIME_DIRECTORY and failures:
            retained.append(entry.resource_id)
            continue
        try:
            did_remove = _cleanup_entry(
                workspace,
                entry,
                buildah=buildah,
                podman=podman,
                registry_control=registry_control,
                git=git,
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
    registry_control: CandidateRegistry | None,
    git: SourceWorktree | None,
) -> bool:
    if entry.kind is ResourceKind.RUNTIME_DIRECTORY:
        owner = _owned_path(workspace, entry.identifier)
        if owner != workspace.root / "environment":
            raise OperationalError("Journaled runtime environment is not run-owned")
        expected_directory = entry.metadata.get("runtimeDirectory")
        if not isinstance(expected_directory, str) or not remove_runtime_directory(
            owner, expected_directory=expected_directory
        ):
            raise OperationalError(
                "Journaled runtime directory has no ownership record"
            )
        return True
    if entry.kind is ResourceKind.LOCAL_PATH:
        path = _owned_path(workspace, entry.identifier)
        _remove_local(path)
        return True
    if entry.kind is ResourceKind.GIT_WORKTREE:
        if git is None:
            raise OperationalError("Worktree cleanup requires Git")
        destination = _owned_path(workspace, entry.identifier)
        repository_value = entry.metadata.get("repository")
        if not isinstance(repository_value, str):
            raise OperationalError("Journaled worktree has no source repository")
        repository = Path(repository_value).resolve(strict=True)
        expected_source = workspace.load().immutable_inputs.get("sourceRoot")
        if expected_source is None or repository != Path(expected_source):
            raise OperationalError("Journaled worktree repository is not run-owned")
        try:
            destination.lstat()
        except FileNotFoundError:
            # A worktree whose creation failed never materialized, so Git has
            # nothing to remove and the failed entry is resolved.
            return True
        git.remove_worktree(repository, destination)
        return True
    if entry.kind is ResourceKind.BUILDAH_STORAGE:
        root = _owned_path(workspace, entry.identifier)
        buildah.remove_storage(root=root / "root", runroot=root / "runroot")
        _remove_local(root)
        return True
    if entry.kind is ResourceKind.TOOL_IMAGE_STORE:
        root = _owned_path(workspace, entry.identifier)
        podman.remove_storage(root=root / "root", runroot=root / "runroot")
        _remove_local(root)
        return True
    if entry.kind is ResourceKind.TEST_INPUTS:
        path = _owned_path(workspace, entry.identifier)
        remove_materialized_test_inputs(path, run_id=workspace.run_id)
        return True
    if entry.kind is ResourceKind.HOOK_SCRATCH:
        path = _owned_path(workspace, entry.identifier)
        remove_hook_scratch(
            path,
            runtime=podman,
            storage=workspace.root / "hook-scratch" / UNSHARE_STORAGE_NAME,
        )
        return True
    if entry.kind is ResourceKind.PODMAN_IMPORT:
        storage = _metadata_path(workspace, entry, "storageRoot")
        runroot = storage.parent / "runroot"
        podman.remove(
            root=storage,
            runroot=runroot,
            name=entry.identifier,
            force=True,
        )
        if entry.metadata.get("resetStorage", True) is True:
            podman.remove_storage(root=storage, runroot=runroot)
            _remove_local(storage.parent)
        return True
    if entry.kind is ResourceKind.CANDIDATE_REFERENCE:
        if registry_control is None:
            raise OperationalError("Candidate cleanup requires registry credentials")
        reference = OCIReference.parse(entry.identifier, require_tag=True)
        if reference.digest is not None or reference.tag is None:
            raise OperationalError("Journaled candidate reference is malformed")
        expected_value = entry.metadata.get("digest")
        if not isinstance(expected_value, str):
            raise OperationalError(
                "Candidate ownership is uncertain because no digest was recorded"
            )
        expected = Digest(expected_value)
        candidate_repository = OCIReference(reference.registry, reference.repository)
        observed = registry_control.observe_tag(candidate_repository, reference.tag)
        if observed is None:
            return True
        if observed.digest != expected:
            raise OperationalError("Candidate now names an unowned digest")
        if observed.immutable:
            observed = registry_control.ensure_tag_mutable(
                candidate_repository, reference.tag
            )
            if observed.digest != expected:
                raise OperationalError("Candidate changed while removing immutability")
        registry_control.remove_tag(candidate_repository, reference.tag)
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


def workspace_size_bytes(root: Path) -> int:
    """Return the size of a run workspace without following symbolic links."""
    total = 0
    for path in root.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def qualification_expiry(root: Path) -> datetime | None:
    """Return the latest recorded qualification expiry of a run, if any.

    Platform qualifications and assembled candidates record the window that
    bounds every later release step; after it no phase can continue (CC0505).
    """
    latest: datetime | None = None
    records = root / "records"
    if not records.is_dir():
        return None
    for path in sorted(records.glob("*.json")):
        try:
            value = load_json(path)
        except ConClearError:
            continue
        if not isinstance(value, dict):
            continue
        payload = value.get("payload")
        window = (
            payload.get("qualificationWindow") if isinstance(payload, dict) else None
        )
        if not isinstance(window, dict):
            continue
        try:
            expiry = QualificationWindow.from_dict(window).expires_at
        except ConClearError:
            continue
        if latest is None or expiry > latest:
            latest = expiry
    return latest


def retirable(snapshot: RunSnapshot, *, root: Path, now: datetime) -> bool:
    """Return whether a run is dead and may therefore be retired.

    A run is dead when it is terminal (promoted, completed, rejected), when it
    has nothing to resume (an interrupted rescan, or a qualification that was
    never bound to a release profile), or when its recorded qualification
    window has expired, because no release phase may continue after that.
    """
    if snapshot.state in TERMINAL_STATES:
        return True
    inputs = snapshot.immutable_inputs
    if inputs.get("profile") == "none":
        return True
    if snapshot.state is RunState.INCOMPLETE and "sourceRevision" not in inputs:
        return True
    expiry = qualification_expiry(root)
    return expiry is not None and now >= expiry


def retire_run(
    workspace: RunWorkspace,
    *,
    state_home: Path,
    now: datetime | None = None,
    abandon: bool = False,
) -> Path:
    """Delete the whole workspace of a dead run, or of an abandoned one.

    Layouts and records stay after ordinary cleanup because an interrupted
    release needs them to resume. Once a run is dead (see `retirable`) its
    directory is only disk usage after its archive is safely retained; with
    `abandon` the operator declares a live run dead. The caller is responsible
    for the retention judgement.
    """
    snapshot = workspace.load()
    current = utc_now() if now is None else now
    if not abandon and not retirable(snapshot, root=workspace.root, now=current):
        expiry = qualification_expiry(workspace.root)
        until = (
            f" until its qualification expires at {format_timestamp(expiry)}"
            if expiry is not None
            else ""
        )
        raise InvalidInvocationError(
            f"Run {workspace.run_id} is {snapshot.state.value} and could still "
            f"resume{until}; retire it with --abandon to give it up"
        )
    runs = (state_home / "conclear" / "runs").resolve()
    root = workspace.root.resolve()
    if root.parent != runs or root.name != workspace.run_id:
        raise OperationalError(f"Refusing to retire a workspace outside {runs}")
    _remove_run_directory(root)
    return root


RETIRE_LAST = ("records", "run.json", "resources.json", "resources.lock")


def _remove_run_directory(root: Path) -> None:
    """Remove a run directory so that a blocked removal stays retryable.

    Everything else goes before the state and records that `retire_run` needs
    to judge the run again. Content this user cannot unlink, such as files a
    repository hook left outside its scratch directory, is named exactly; the
    run stays openable and the next attempt continues where this one stopped.
    """
    remaining = _remove_children(
        root, exclude=frozenset(RETIRE_LAST), label="Run directory"
    )
    if remaining:
        raise OperationalError(
            f"Run directory {root} was retired only partially; this user cannot "
            f"remove {_describe_paths(remaining)}. A repository hook may have "
            "written it outside its scratch directory. Remove it with "
            f"`podman unshare rm -rf -- <path>` after checking that nothing is "
            "mounted below it, then rerun cleanup --retire"
        )
    remaining = _remove_children(root, exclude=frozenset(), label="Run directory")
    if remaining:
        raise OperationalError(
            f"Unable to remove run state below {root}: {_describe_paths(remaining)}"
        )
    try:
        root.rmdir()
    except OSError as exc:
        raise OperationalError(f"Unable to remove run directory {root}") from exc


def _remove_children(root: Path, *, exclude: frozenset[str], label: str) -> list[Path]:
    failed: list[Path] = []

    def record(_function: object, path: str | Path, _exc: BaseException) -> None:
        failed.append(Path(path))

    try:
        children = sorted(root.iterdir())
    except OSError as exc:
        raise OperationalError(f"{label} {root} cannot be listed") from exc
    for child in children:
        if child.name in exclude:
            continue
        try:
            mode = child.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError:
            failed.append(child)
            continue
        if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
            shutil.rmtree(child, onexc=record)
        else:
            try:
                child.unlink()
            except FileNotFoundError:
                continue
            except OSError:
                failed.append(child)
    return failed


def _describe_paths(paths: list[Path]) -> str:
    # Deepest first: the blocking file, not the directories that failed after it.
    unique = sorted(set(paths), key=lambda item: (-len(item.parts), str(item)))
    shown = ", ".join(str(item) for item in unique[:5])
    if len(unique) > 5:
        shown += f" and {len(unique) - 5} more"
    return shown
