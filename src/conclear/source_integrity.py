"""Content binding for a detached source tree, independent of Git's index cache."""

import os
import stat
from pathlib import Path

from conclear.context import MAX_CONTEXT_DEPTH, MAX_CONTEXT_PATHS
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import canonical_json_bytes, sha256_bytes, sha256_file
from conclear.workspace import RunWorkspace


def source_tree_digest(root: Path) -> str:
    """Hash all checkout paths and bytes, excluding only the root Git control entry.

    Ignore files do not apply. Symlink targets and directory modes are included,
    but symlinks are never followed. Git index flags and clean filters cannot
    hide byte changes from this observation.
    """
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
                before = path.lstat()
                entry: dict[str, object] = {
                    "path": path.relative_to(root).as_posix(),
                    "mode": before.st_mode,
                }
                if stat.S_ISLNK(before.st_mode):
                    entry["target"] = str(path.readlink())
                elif stat.S_ISREG(before.st_mode):
                    entry["digest"] = sha256_file(path)
                elif not stat.S_ISDIR(before.st_mode):
                    raise InvalidInvocationError(
                        "Source checkout contains a special file"
                    )
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
                    raise InvalidInvocationError(
                        "Source checkout changed while hashing"
                    )
                entries.append(entry)
    except OSError as exc:
        raise OperationalError("Unable to hash source checkout") from exc
    return sha256_bytes(
        canonical_json_bytes(sorted(entries, key=lambda entry: str(entry["path"])))
    )


def require_source_integrity(workspace: RunWorkspace, root: Path) -> None:
    """Reject missing or changed source bindings without repairing the checkout."""
    expected = workspace.load().immutable_inputs.get("sourceTreeDigest")
    if expected is None:
        raise InvalidInvocationError(
            "Run lacks source content binding; start a new run"
        )
    if source_tree_digest(root) != expected:
        raise InvalidInvocationError("Workspace source content changed")


def _walk_error(error: OSError) -> None:
    raise error
