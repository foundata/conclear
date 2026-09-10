"""Preserve source bytes and lexical links without putting links in the outer tar."""

import shutil
import stat
from pathlib import Path

from conclear.archive import member_path
from conclear.errors import InvalidInvocationError
from conclear.jsonutil import canonical_json_bytes, load_json, sha256_bytes, sha256_file
from conclear.parsing import Narrower
from conclear.source_integrity import source_tree_digest, source_tree_entries

_narrow = Narrower(InvalidInvocationError)
SOURCE_MANIFEST = "source-tree.json"


def collect_source(
    root: Path, *, expected_digest: str | None = None
) -> dict[str, Path | bytes]:
    """Select the complete source checkout except its root Git control entry."""
    entries = source_tree_entries(root)
    content = canonical_json_bytes(entries)
    if expected_digest is not None and sha256_bytes(content) != expected_digest:
        raise InvalidInvocationError("Source changed before archive creation")
    sources: dict[str, Path | bytes] = {SOURCE_MANIFEST: content}
    for entry in entries:
        name = _narrow.string_value(entry["path"], "source path")
        member_path(name)
        if name == ".git" or name.startswith(".git/"):
            raise InvalidInvocationError("Archive source contains Git control data")
        if "digest" in entry:
            sources[f"source/{name}"] = root / name
    return sources


def restore_source(root: Path, destination: Path) -> None:
    """Restore checked source into a new directory, preserving modes and safe links.

    Link text lives in the source inventory; the outer archive contains only
    regular files. Links are created last and must resolve within the restored
    tree before configuration parsing may use them.
    """
    entries = _narrow.array_value(load_json(root / SOURCE_MANIFEST), "source inventory")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    modes: list[tuple[Path, int]] = []
    links: list[tuple[Path, str]] = []
    names: set[str] = set()
    for raw in entries:
        entry = _narrow.object_value(raw, "source entry")
        name = _narrow.string_value(entry.get("path"), "source path")
        path = member_path(name)
        if path.parts[0] == ".git" or name in names:
            raise InvalidInvocationError(
                "Source contains duplicate or Git control paths"
            )
        names.add(name)
        mode = _narrow.integer_value(entry.get("mode"), "source mode")
        if mode < 0 or stat.S_IMODE(mode) & ~0o777:
            raise InvalidInvocationError("Source contains unsafe mode bits")
        target = destination.joinpath(*path.parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if stat.S_ISDIR(mode) and set(entry) == {"path", "mode"}:
            target.mkdir(mode=0o700, exist_ok=True)
            modes.append((target, stat.S_IMODE(mode)))
        elif stat.S_ISREG(mode) and set(entry) == {"path", "mode", "digest"}:
            source = root / "source" / name
            if sha256_file(source) != entry["digest"]:
                raise InvalidInvocationError("Archived source bytes changed")
            with source.open("rb") as incoming, target.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            target.chmod(stat.S_IMODE(mode))
        elif stat.S_ISLNK(mode) and set(entry) == {"path", "mode", "target"}:
            link = _narrow.string_value(entry["target"], "source link")
            if Path(link).is_absolute() or "\x00" in link:
                raise InvalidInvocationError("Archived source link is not contained")
            links.append((target, link))
        else:
            raise InvalidInvocationError("Malformed source inventory entry")
    for target, link in links:
        target.symlink_to(link)
    for target, _link in links:
        try:
            if not target.resolve().is_relative_to(destination.resolve()):
                raise InvalidInvocationError("Archived source link escapes the source")
        except (OSError, RuntimeError) as exc:
            raise InvalidInvocationError(
                "Archived source contains a cyclic link"
            ) from exc
    for target, mode in reversed(modes):
        target.chmod(mode)
    if source_tree_digest(destination) != sha256_bytes(canonical_json_bytes(entries)):
        raise InvalidInvocationError(
            "Restored source inventory differs from the archive"
        )


def copy_source(root: Path, destination: Path) -> str:
    """Snapshot a live source tree for a later rescan archive retry."""
    expected = source_tree_digest(root)
    shutil.copytree(
        root,
        destination,
        symlinks=True,
        ignore=lambda directory, names: (
            {".git"} if Path(directory) == root and ".git" in names else set()
        ),
    )
    if (
        source_tree_digest(destination) != expected
        or source_tree_digest(root) != expected
    ):
        raise InvalidInvocationError("Rescan source changed while copying")
    return expected
