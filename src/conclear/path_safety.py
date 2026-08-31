"""Filesystem containment and safe archive extraction."""

import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from conclear.errors import InvalidInvocationError, OperationalError

MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_CONTENT_BYTES = 16 * 1024 * 1024 * 1024


def contained_path(root: Path, untrusted: str, *, must_exist: bool = True) -> Path:
    """Resolve a repository path without allowing traversal or symlink escape."""
    candidate_path = Path(untrusted)
    if candidate_path.is_absolute() or "\x00" in untrusted:
        raise InvalidInvocationError(
            f"Path must be relative to the source root: {untrusted}"
        )
    if any(part in {"", ".", ".."} for part in candidate_path.parts):
        raise InvalidInvocationError(f"Path contains an unsafe component: {untrusted}")
    try:
        resolved_root = root.resolve(strict=True)
        resolved_candidate = (resolved_root / candidate_path).resolve(strict=must_exist)
        resolved_candidate.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise InvalidInvocationError(
            f"Path escapes or cannot be resolved below the source root: {untrusted}"
        ) from exc
    return resolved_candidate


def _safe_archive_target(root: Path, member_name: str) -> Path:
    if "\x00" in member_name or "\\" in member_name:
        raise InvalidInvocationError(f"Unsafe archive member path: {member_name}")
    member = PurePosixPath(member_name)
    if member.is_absolute() or any(part in {"", ".", ".."} for part in member.parts):
        raise InvalidInvocationError(f"Unsafe archive member path: {member_name}")
    target = root.joinpath(*member.parts)
    try:
        target.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as exc:
        raise InvalidInvocationError(
            f"Archive member escapes destination: {member_name}"
        ) from exc
    return target


def extract_tar_safely(archive_path: Path, destination: Path) -> None:
    """Extract regular files and directories from a tar archive without links."""
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            total_size = 0
            names: set[str] = set()
            for member_number, member in enumerate(archive, start=1):
                if member_number > MAX_ARCHIVE_MEMBERS:
                    raise InvalidInvocationError("Tar archive exceeds the member limit")
                if member.name in names:
                    raise InvalidInvocationError(
                        f"Archive contains a duplicate member: {member.name}"
                    )
                names.add(member.name)
                target = _safe_archive_target(destination, member.name)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise InvalidInvocationError(
                        f"Archive member is not a regular file: {member.name}"
                    )
                total_size += member.size
                if total_size > MAX_ARCHIVE_CONTENT_BYTES:
                    raise InvalidInvocationError(
                        "Tar archive exceeds the extracted-content limit"
                    )
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise InvalidInvocationError(
                        f"Unable to read archive member: {member.name}"
                    )
                with source, target.open("xb") as output:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
                target.chmod(stat.S_IMODE(member.mode) & 0o755)
    except (tarfile.TarError, OSError) as exc:
        raise OperationalError(f"Unable to extract tar archive {archive_path}") from exc


def extract_zip_safely(archive_path: Path, destination: Path) -> None:
    """Extract regular files and directories from a ZIP archive without links."""
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        with zipfile.ZipFile(archive_path) as archive:
            total_size = 0
            names: set[str] = set()
            for member_number, member in enumerate(archive.infolist(), start=1):
                if member_number > MAX_ARCHIVE_MEMBERS:
                    raise InvalidInvocationError("ZIP archive exceeds the member limit")
                if member.filename in names:
                    raise InvalidInvocationError(
                        f"Archive contains a duplicate member: {member.filename}"
                    )
                names.add(member.filename)
                target = _safe_archive_target(destination, member.filename)
                unix_mode = member.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    raise InvalidInvocationError(
                        f"Archive member is a symbolic link: {member.filename}"
                    )
                if member.is_dir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                total_size += member.file_size
                if total_size > MAX_ARCHIVE_CONTENT_BYTES:
                    raise InvalidInvocationError(
                        "ZIP archive exceeds the extracted-content limit"
                    )
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("xb") as output:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
                if unix_mode:
                    target.chmod(stat.S_IMODE(unix_mode) & 0o755)
    except (zipfile.BadZipFile, OSError) as exc:
        raise OperationalError(f"Unable to extract ZIP archive {archive_path}") from exc
