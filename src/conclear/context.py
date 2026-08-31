"""Deterministic, containment-safe build context hashing."""

import fnmatch
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.fileio import read_regular_file
from conclear.jsonutil import canonical_json_bytes, sha256_bytes

MAX_CONTAINERIGNORE_BYTES = 1024 * 1024
MAX_CONTEXT_PATHS = 100_000
MAX_CONTEXT_DEPTH = 128


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
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        root_descriptor = os.open(resolved_root, flags)
    except OSError as exc:
        raise OperationalError(f"Unable to open build context {resolved_root}") from exc
    entries: list[ContextEntry] = []
    paths_seen = [0]
    try:
        _walk_context(
            root_descriptor,
            PurePosixPath(),
            rules,
            entries,
            paths_seen,
        )
    finally:
        os.close(root_descriptor)
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
    directory_descriptor: int,
    relative_directory: PurePosixPath,
    rules: tuple[IgnoreRule, ...],
    entries: list[ContextEntry],
    paths_seen: list[int],
) -> None:
    try:
        with os.scandir(directory_descriptor) as iterator:
            children = []
            for child in iterator:
                paths_seen[0] += 1
                if paths_seen[0] > MAX_CONTEXT_PATHS:
                    raise InvalidInvocationError(
                        "Build context exceeds the path-count limit"
                    )
                children.append(child)
        children.sort(key=lambda item: item.name)
    except OSError as exc:
        raise OperationalError(
            f"Unable to enumerate build context {relative_directory}"
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
            if len(relative.parts) > MAX_CONTEXT_DEPTH:
                raise InvalidInvocationError("Build context exceeds the depth limit")
            child_descriptor = _open_observed_directory(
                directory_descriptor,
                child.name,
                child_stat,
                relative,
            )
            try:
                _walk_context(
                    child_descriptor,
                    relative,
                    rules,
                    entries,
                    paths_seen,
                )
            finally:
                os.close(child_descriptor)
            continue
        if not stat.S_ISREG(child_stat.st_mode):
            raise InvalidInvocationError(
                f"Build context contains a non-regular path: {relative}"
            )
        size, digest = _hash_observed_file(
            directory_descriptor,
            child.name,
            child_stat,
            relative,
        )
        entries.append(
            ContextEntry(
                path=relative.as_posix(),
                mode=stat.S_IMODE(child_stat.st_mode),
                size=size,
                digest=digest,
            )
        )


def _load_ignore_rules(path: Path) -> tuple[IgnoreRule, ...]:
    try:
        lines = (
            read_regular_file(
                path,
                maximum_bytes=MAX_CONTAINERIGNORE_BYTES,
                label="required .containerignore",
            )
            .decode("utf-8")
            .splitlines()
        )
    except UnicodeError as exc:
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


def _open_observed_directory(
    parent_descriptor: int,
    name: str,
    observed: os.stat_result,
    relative: PurePosixPath,
) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise OperationalError(
            f"Unable to open build context directory {relative}"
        ) from exc
    if not _same_observation(observed, opened) or not stat.S_ISDIR(opened.st_mode):
        os.close(descriptor)
        raise OperationalError(
            f"Build context directory changed while hashing: {relative}"
        )
    return descriptor


def _hash_observed_file(
    parent_descriptor: int,
    name: str,
    observed: os.stat_result,
    relative: PurePosixPath,
) -> tuple[int, str]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        if not _same_observation(observed, opened) or not stat.S_ISREG(opened.st_mode):
            raise OperationalError(
                f"Build context path changed while hashing: {relative}"
            )
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
        finished = os.fstat(descriptor)
        if not _same_observation(opened, finished) or size != opened.st_size:
            raise OperationalError(
                f"Build context path changed while hashing: {relative}"
            )
        return size, f"sha256:{digest.hexdigest()}"
    except OSError as exc:
        raise OperationalError(f"Unable to read build context path {relative}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _same_observation(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and first.st_mode == second.st_mode
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


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
