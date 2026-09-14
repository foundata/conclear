"""Set-ID executable inventory of an image's merged filesystem.

The inventory reads layer archives from a validated OCI layout in order and
applies them like a runtime would: later entries replace earlier ones, `.wh.`
markers remove lower content and `.wh..wh..opq` hides every lower child of a
directory. Only tar headers are read; no image program runs and no content is
extracted. The result names every regular executable carrying a set-user-ID or
set-group-ID bit, with hard-link aliases grouped, and set-group-ID directories
separately because they grant no privilege.
"""

import gzip
import stat
import tarfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, cast

from conclear.errors import OperationalError
from conclear.oci import Descriptor
from conclear.presentation import Finding

OCI_LAYER_TAR = "application/vnd.oci.image.layer.v1.tar"
OCI_LAYER_GZIP = OCI_LAYER_TAR + "+gzip"
OCI_LAYER_ZSTD = OCI_LAYER_TAR + "+zstd"
DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MAX_LAYER_ENTRIES = 2_000_000
MAX_SYMLINK_DEPTH = 40
WHITEOUT_PREFIX = ".wh."
OPAQUE_WHITEOUT = ".wh..wh..opq"
SETID_BITS = stat.S_ISUID | stat.S_ISGID
EXECUTE_BITS = 0o111
CHECK_ID = "CC0406"


@dataclass(frozen=True, slots=True)
class SetIDExecutable:
    """One set-ID executable with every hard-link alias that shares its inode."""

    path: str
    mode: int
    uid: int
    gid: int
    aliases: tuple[str, ...] = ()

    @property
    def paths(self) -> frozenset[str]:
        """Return the path and all of its aliases."""
        return frozenset((self.path, *self.aliases))

    def to_dict(self) -> dict[str, object]:
        """Return the record representation with an octal mode."""
        return {
            "path": self.path,
            "mode": f"{self.mode & 0o7777:05o}",
            "uid": self.uid,
            "gid": self.gid,
            "aliases": list(self.aliases),
        }


@dataclass(frozen=True, slots=True)
class SetIDInventory:
    """Set-ID executables and set-group-ID directories of a merged filesystem."""

    executables: tuple[SetIDExecutable, ...]
    setgid_directories: tuple[str, ...]
    symlinks: dict[str, str]

    def resolve(self, path: str) -> str | None:
        """Resolve a path through the image's symbolic links, or return None."""
        return _resolve(self.symlinks, path)

    def to_dict(self) -> dict[str, object]:
        """Return the non-secret record representation."""
        return {
            "executables": [item.to_dict() for item in self.executables],
            "setgidDirectories": list(self.setgid_directories),
        }


@dataclass(slots=True)
class _Entry:
    kind: str
    mode: int
    uid: int
    gid: int
    target: str | None
    inode: int


def inventory_setid(layout_path: Path, layers: Sequence[Descriptor]) -> SetIDInventory:
    """Inventory set-ID files of the filesystem the ordered layers produce."""
    entries: dict[str, _Entry] = {}
    inode = 0
    for layer in layers:
        members = _layer_members(layout_path, layer)
        whiteouts: list[str] = []
        additions: list[tarfile.TarInfo] = []
        for member in members:
            path = _normalized(member.name)
            if PurePosixPath(path).name.startswith(WHITEOUT_PREFIX):
                whiteouts.append(path)
            else:
                additions.append(member)
        for path in whiteouts:
            name = PurePosixPath(path).name
            parent = str(PurePosixPath(path).parent)
            if name == OPAQUE_WHITEOUT:
                _remove_children(entries, parent)
            else:
                _remove_subtree(
                    entries, str(PurePosixPath(parent) / name[len(WHITEOUT_PREFIX) :])
                )
        for member in additions:
            path = _normalized(member.name)
            previous = entries.get(path)
            if previous is not None and previous.kind == "dir" and not member.isdir():
                _remove_children(entries, path)
            if member.islnk():
                target = _normalized(member.linkname)
                linked = entries.get(target)
                if linked is None or linked.kind != "file":
                    raise OperationalError(
                        f"Layer {layer.digest} hard-links {path} to an unknown file"
                    )
                entries[path] = _Entry(
                    "file", linked.mode, linked.uid, linked.gid, None, linked.inode
                )
                continue
            if member.isdir():
                kind = "dir"
            elif member.issym():
                kind = "symlink"
            elif member.isreg():
                kind = "file"
            else:
                kind = "other"
            inode += 1
            entries[path] = _Entry(
                kind,
                member.mode,
                member.uid,
                member.gid,
                member.linkname if kind == "symlink" else None,
                inode,
            )
    return _summarize(entries)


def setid_findings(
    inventory: SetIDInventory, declared_paths: Iterable[str]
) -> tuple[Finding, ...]:
    """Compare the inventory with the declared set-ID paths."""
    findings: list[Finding] = []
    declared = tuple(dict.fromkeys(declared_paths))
    resolved: dict[str, str | None] = {
        path: inventory.resolve(path) for path in declared
    }
    approved = {value for value in resolved.values() if value is not None}
    for executable in inventory.executables:
        if executable.paths & approved:
            continue
        aliases = (
            f" (also {', '.join(executable.aliases)})" if executable.aliases else ""
        )
        findings.append(
            Finding(
                CHECK_ID,
                "error",
                f"Undeclared set-ID executable {executable.path}{aliases} with mode "
                f"{executable.mode & 0o7777:05o} owned by {executable.uid}:{executable.gid}; "
                "declare it under setid_requirements or strip the bit",
                location=executable.path,
            )
        )
    inventoried = {path for item in inventory.executables for path in item.paths}
    for path in declared:
        target = resolved[path]
        if target is None or target not in inventoried:
            findings.append(
                Finding(
                    CHECK_ID,
                    "error",
                    f"Declared set-ID path {path} is not a set-ID executable in the "
                    "image; remove the stale declaration",
                    location=path,
                )
            )
    return tuple(findings)


def _layer_members(layout_path: Path, layer: Descriptor) -> list[tarfile.TarInfo]:
    blob = layout_path / "blobs" / "sha256" / layer.digest.encoded
    if layer.media_type in {OCI_LAYER_GZIP, DOCKER_LAYER_GZIP}:
        compressed = True
    elif layer.media_type == OCI_LAYER_TAR:
        compressed = False
    else:
        raise OperationalError(
            f"Layer {layer.digest} uses unsupported media type {layer.media_type}"
        )
    members: list[tarfile.TarInfo] = []
    try:
        stream = cast(
            IO[bytes], gzip.open(blob, "rb") if compressed else blob.open("rb")
        )
        with stream, tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                members.append(member)
                if len(members) > MAX_LAYER_ENTRIES:
                    raise OperationalError(
                        f"Layer {layer.digest} exceeds the entry limit"
                    )
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise OperationalError(f"Unable to read layer {layer.digest}") from exc
    return members


def _normalized(name: str) -> str:
    parts: list[str] = []
    for part in PurePosixPath(name).parts:
        if part in {"", ".", "/"}:
            continue
        if part == "..":
            raise OperationalError(f"Layer entry escapes the filesystem root: {name}")
        parts.append(part)
    return "/" + "/".join(parts)


def _remove_children(entries: dict[str, _Entry], directory: str) -> None:
    prefix = directory.rstrip("/") + "/"
    for path in [item for item in entries if item.startswith(prefix)]:
        del entries[path]


def _remove_subtree(entries: dict[str, _Entry], path: str) -> None:
    entries.pop(path, None)
    _remove_children(entries, path)


def _summarize(entries: dict[str, _Entry]) -> SetIDInventory:
    groups: dict[int, list[str]] = {}
    for path, entry in entries.items():
        if (
            entry.kind == "file"
            and entry.mode & SETID_BITS
            and entry.mode & EXECUTE_BITS
        ):
            groups.setdefault(entry.inode, []).append(path)
    executables = []
    for paths in groups.values():
        ordered = sorted(paths)
        entry = entries[ordered[0]]
        executables.append(
            SetIDExecutable(
                ordered[0], entry.mode, entry.uid, entry.gid, tuple(ordered[1:])
            )
        )
    setgid_directories = tuple(
        sorted(
            path
            for path, entry in entries.items()
            if entry.kind == "dir" and entry.mode & stat.S_ISGID
        )
    )
    symlinks = {
        path: entry.target
        for path, entry in entries.items()
        if entry.kind == "symlink" and entry.target is not None
    }
    return SetIDInventory(
        tuple(sorted(executables, key=lambda item: item.path)),
        setgid_directories,
        symlinks,
    )


def _resolve(symlinks: dict[str, str], path: str) -> str | None:
    current = PurePosixPath("/")
    pending = list(PurePosixPath(_normalized(path)).parts[1:])
    hops = 0
    while pending:
        part = pending.pop(0)
        candidate = str(current / part)
        target = symlinks.get(candidate)
        if target is None:
            current = current / part
            continue
        hops += 1
        if hops > MAX_SYMLINK_DEPTH:
            return None
        base = PurePosixPath("/") if target.startswith("/") else current
        try:
            pending = [
                *PurePosixPath(_normalized(str(base / target))).parts[1:],
                *pending,
            ]
        except OperationalError:
            return None
        current = PurePosixPath("/")
    return str(current)
