"""Deterministic, containment-safe build context hashing."""

import fnmatch
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import canonical_json_bytes, sha256_bytes


@dataclass(frozen=True, slots=True)
class ContextEntry:
    """One regular file included in a build context."""

    path: str
    mode: int
    size: int
    digest: str

    def to_dict(self) -> dict[str, object]:
        """Return the deterministic context manifest entry."""
        return {
            "path": self.path,
            "mode": self.mode,
            "size": self.size,
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class ContextObservation:
    """Exact regular files and aggregate digest entering a build."""

    root: Path
    entries: tuple[ContextEntry, ...]
    digest: str


@dataclass(frozen=True, slots=True)
class IgnoreRule:
    """One ordered `.containerignore` rule."""

    pattern: str
    include: bool
    directory_only: bool
    anchored: bool

    def matches(self, relative: PurePosixPath, *, is_directory: bool) -> bool:
        """Return whether this rule applies to a normalized relative path."""
        if self.directory_only and not is_directory:
            return False
        path = relative.as_posix()
        pattern = self.pattern
        if self.anchored:
            return fnmatch.fnmatchcase(path, pattern)
        if "/" in pattern:
            return fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(
                path, f"**/{pattern}"
            )
        return any(fnmatch.fnmatchcase(part, pattern) for part in relative.parts)


def hash_build_context(root: Path) -> ContextObservation:
    """Hash all non-ignored regular files without following symlinks."""
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise InvalidInvocationError(f"Build context does not exist: {root}") from exc
    if not resolved_root.is_dir():
        raise InvalidInvocationError(f"Build context is not a directory: {root}")
    rules = _load_ignore_rules(resolved_root / ".containerignore")
    entries: list[ContextEntry] = []
    _walk_context(resolved_root, PurePosixPath(), rules, entries)
    entries.sort(key=lambda item: item.path)
    manifest = {
        "schemaVersion": 1,
        "entries": [entry.to_dict() for entry in entries],
    }
    return ContextObservation(
        root=resolved_root,
        entries=tuple(entries),
        digest=sha256_bytes(canonical_json_bytes(manifest)),
    )


def _walk_context(
    root: Path,
    relative_directory: PurePosixPath,
    rules: tuple[IgnoreRule, ...],
    entries: list[ContextEntry],
) -> None:
    directory = root.joinpath(*relative_directory.parts)
    try:
        children = sorted(os.scandir(directory), key=lambda item: item.name)
    except OSError as exc:
        raise OperationalError(
            f"Unable to enumerate build context {directory}"
        ) from exc
    for child in children:
        relative = relative_directory / child.name
        try:
            child_stat = child.stat(follow_symlinks=False)
        except OSError as exc:
            raise OperationalError(
                f"Unable to inspect build context path {relative}"
            ) from exc
        is_directory = stat.S_ISDIR(child_stat.st_mode)
        if _ignored(relative, is_directory=is_directory, rules=rules):
            continue
        if stat.S_ISLNK(child_stat.st_mode):
            raise InvalidInvocationError(
                f"Build context contains a non-ignored symbolic link: {relative}"
            )
        if is_directory:
            _walk_context(root, relative, rules, entries)
            continue
        if not stat.S_ISREG(child_stat.st_mode):
            raise InvalidInvocationError(
                f"Build context contains a non-regular path: {relative}"
            )
        path = root.joinpath(*relative.parts)
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise OperationalError(
                f"Unable to read build context path {relative}"
            ) from exc
        if len(content) != child_stat.st_size:
            raise OperationalError(
                f"Build context path changed while hashing: {relative}"
            )
        entries.append(
            ContextEntry(
                path=relative.as_posix(),
                mode=stat.S_IMODE(child_stat.st_mode),
                size=len(content),
                digest=sha256_bytes(content),
            )
        )


def _load_ignore_rules(path: Path) -> tuple[IgnoreRule, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise InvalidInvocationError(f"Unable to read required {path}") from exc
    rules: list[IgnoreRule] = []
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        include = value.startswith("!")
        if include:
            value = value[1:]
        anchored = value.startswith("/")
        value = value.removeprefix("/")
        directory_only = value.endswith("/")
        value = value.removesuffix("/")
        if not value or "\\" in value or any(part == ".." for part in value.split("/")):
            raise InvalidInvocationError(f"Unsafe .containerignore rule: {line}")
        rules.append(IgnoreRule(value, include, directory_only, anchored))
    return tuple(rules)


def _ignored(
    relative: PurePosixPath,
    *,
    is_directory: bool,
    rules: tuple[IgnoreRule, ...],
) -> bool:
    ignored = False
    for rule in rules:
        if rule.matches(relative, is_directory=is_directory):
            ignored = not rule.include
    return ignored
