"""Run-owned scratch space for repository hooks and its removal."""

import shutil
import stat
from pathlib import Path
from typing import Protocol

from conclear.errors import OperationalError

MOUNTINFO_PATH = Path("/proc/self/mountinfo")
UNSHARE_STORAGE_NAME = ".unshare"


class MappedTreeRemover(Protocol):
    """Removal of content owned by the container user namespace."""

    def remove_mapped_tree(self, path: Path, *, storage: Path) -> None:
        """Remove one tree inside the rootless user namespace."""
        ...


def hook_scratch_root(workspace_root: Path, image_id: str, platform_key: str) -> Path:
    """Return the scratch directory of one image's platform test session."""
    return workspace_root / "hook-scratch" / image_id / platform_key


def create_hook_scratch(path: Path) -> None:
    """Create one empty private scratch directory for the hooks of a session."""
    try:
        path.parent.parent.mkdir(mode=0o700, exist_ok=True)
        path.parent.mkdir(mode=0o700, exist_ok=True)
        path.mkdir(mode=0o700, exist_ok=False)
    except OSError as exc:
        raise OperationalError(
            f"Unable to create hook scratch directory {path}"
        ) from exc


def active_mounts_below(
    path: Path, *, mountinfo: Path = MOUNTINFO_PATH
) -> tuple[str, ...]:
    """Return the mount points at or below a path in this mount namespace.

    A child created by `podman unshare` inherits these mounts, so a recursive
    removal there would descend into them.
    """
    try:
        lines = mountinfo.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise OperationalError(f"Unable to read {mountinfo}") from exc
    root = str(path)
    prefix = root.rstrip("/") + "/"
    found: list[str] = []
    for line in lines:
        fields = line.split(" ")
        if len(fields) < 5:
            continue
        point = _unescape_mountinfo(fields[4])
        if point == root or point.startswith(prefix):
            found.append(point)
    return tuple(sorted(set(found)))


def remove_hook_scratch(
    path: Path, *, runtime: MappedTreeRemover, storage: Path
) -> None:
    """Remove a hook scratch directory, through the user namespace if needed.

    Hooks own the content: a rootless container store left behind holds files
    owned by subordinate user IDs that this user cannot unlink directly. The
    plain removal runs first; only what it cannot remove is deleted inside the
    container user namespace, and never while a mount is active below the path.
    `storage` names a throwaway Podman storage location for that step.
    """
    try:
        value = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OperationalError(f"Unable to inspect hook scratch {path}") from exc
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
        raise OperationalError(f"Hook scratch is not a directory: {path}")
    try:
        shutil.rmtree(path)
    except OSError:
        pass
    else:
        return
    mounts = active_mounts_below(path)
    if mounts:
        raise OperationalError(
            f"Hook scratch {path} has active mounts below it: {', '.join(mounts)}; "
            "unmount them, then rerun cleanup"
        )
    try:
        runtime.remove_mapped_tree(path, storage=storage)
    finally:
        _remove_plain(storage)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OperationalError(f"Unable to inspect hook scratch {path}") from exc
    raise OperationalError(
        f"Hook scratch {path} is still present after removal in the container "
        "user namespace"
    )


def _remove_plain(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OperationalError(f"Unable to remove {path}") from exc


def _unescape_mountinfo(value: str) -> str:
    """Decode the octal escapes the kernel uses for spaces, tabs and backslashes."""
    result: list[str] = []
    index = 0
    while index < len(value):
        digits = value[index + 1 : index + 4]
        if value[index] == "\\" and len(digits) == 3 and digits.isdigit():
            result.append(chr(int(digits, 8)))
            index += 4
            continue
        result.append(value[index])
        index += 1
    return "".join(result)
