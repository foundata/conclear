"""Content binding for the reviewed source tree, independent of Git's index cache.

A run holds the reviewed commit twice: `source/` is an export of its tracked
tree and is the only source that builds, evidence and archives read; `checkout/`
is the Git worktree that repository hooks run in. The export is bound by
content digest and must never change. The checkout must keep every tracked
file's bytes, mode and link target, but tools that hooks run may write
untracked files there, because nothing later in the run reads them.
"""

import os
import stat
from pathlib import Path

from conclear.context import MAX_CONTEXT_DEPTH, MAX_CONTEXT_PATHS
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import canonical_json_bytes, sha256_bytes, sha256_file
from conclear.workspace import ResourceKind, ResourceStatus, RunWorkspace

EXPORT_DIRECTORY = "source"
CHECKOUT_DIRECTORY = "checkout"
CHECKOUT_RESOURCE = "source-worktree"


def source_tree_digest(root: Path) -> str:
    """Hash every regular file and symbolic link below the root.

    Directories carry no reviewed content and Git does not track their modes,
    so only files and links count. Symlink targets and file modes are included,
    but symlinks are never followed. Git index flags and clean filters cannot
    hide byte changes from this observation.
    """
    return sha256_bytes(canonical_json_bytes(source_tree_entries(root)))


def source_tree_entries(root: Path) -> list[dict[str, object]]:
    """Describe file bytes, modes and links without following symbolic links."""
    if root.is_symlink() or not root.is_dir():
        raise InvalidInvocationError("Source checkout is not a regular directory")
    entries: list[dict[str, object]] = []
    try:
        for directory, directories, files in os.walk(
            root, followlinks=False, onerror=_walk_error
        ):
            parent = Path(directory)
            relative_parent = parent.relative_to(root)
            if len(relative_parent.parts) > MAX_CONTEXT_DEPTH:
                raise InvalidInvocationError("Source checkout exceeds the depth limit")
            if parent == root:
                directories[:] = [name for name in directories if name != ".git"]
                files = [name for name in files if name != ".git"]
            for name in sorted((*directories, *files)):
                if len(entries) >= MAX_CONTEXT_PATHS:
                    raise InvalidInvocationError(
                        "Source checkout exceeds the path-count limit"
                    )
                path = parent / name
                if path.is_dir() and not path.is_symlink():
                    continue
                entries.append(_entry(root, path))
    except OSError as exc:
        raise OperationalError("Unable to hash source checkout") from exc
    return sorted(entries, key=lambda entry: str(entry["path"]))


def tracked_entries(
    root: Path, reference: list[dict[str, object]]
) -> list[dict[str, object]]:
    """Describe the reference paths as they exist below another root.

    Paths the reference does not list are not inspected, so files that hooks
    write into a checkout are invisible here; a missing or changed tracked path
    still produces a different entry list.
    """
    entries: list[dict[str, object]] = []
    try:
        for item in reference:
            relative = str(item["path"])
            path = root.joinpath(*relative.split("/"))
            try:
                path.lstat()
            except FileNotFoundError:
                entries.append({"path": relative, "missing": True})
                continue
            entries.append(_entry(root, path))
    except OSError as exc:
        raise OperationalError("Unable to hash source checkout") from exc
    return sorted(entries, key=lambda entry: str(entry["path"]))


def require_source_integrity(workspace: RunWorkspace, export: Path) -> None:
    """Reject a changed export or a checkout whose tracked content changed.

    Neither tree is repaired. The export, the tree that builds and evidence
    read, must match its bound digest exactly. The Git checkout, when the run
    journals one, must present every exported path with identical bytes, mode
    and link target; untracked additions there are tolerated because builds and
    archives never read them.
    """
    expected = workspace.load().immutable_inputs.get("sourceTreeDigest")
    if expected is None:
        raise InvalidInvocationError(
            "Run lacks source content binding; start a new run"
        )
    entries = source_tree_entries(export)
    if sha256_bytes(canonical_json_bytes(entries)) != expected:
        raise InvalidInvocationError("Workspace source content changed")
    checkout = journaled_checkout(workspace)
    if checkout is None:
        return
    if (
        sha256_bytes(canonical_json_bytes(tracked_entries(checkout, entries)))
        != expected
    ):
        raise InvalidInvocationError("Workspace checkout content changed")


def journaled_checkout(workspace: RunWorkspace) -> Path | None:
    """Return the run's created Git checkout, or None when the run has none."""
    for entry in workspace.journal.entries():
        if (
            entry.resource_id == CHECKOUT_RESOURCE
            and entry.kind is ResourceKind.GIT_WORKTREE
            and entry.status is ResourceStatus.CREATED
        ):
            return Path(entry.identifier)
    return None


def _entry(root: Path, path: Path) -> dict[str, object]:
    before = path.lstat()
    entry: dict[str, object] = {
        "path": path.relative_to(root).as_posix(),
        "mode": before.st_mode,
    }
    if stat.S_ISLNK(before.st_mode):
        entry["target"] = str(path.readlink())
    elif stat.S_ISREG(before.st_mode):
        entry["digest"] = sha256_file(path)
    else:
        raise InvalidInvocationError("Source checkout contains a special file")
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise InvalidInvocationError("Source checkout changed while hashing")
    return entry


def _walk_error(error: OSError) -> None:
    raise error
