"""Bounded, atomic evidence archives with explicit member inventories."""

import io
import os
import stat
import tarfile
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.fileio import read_regular_file
from conclear.jsonutil import canonical_json_bytes, load_json, sha256_bytes, sha256_file
from conclear.parsing import Narrower
from conclear.path_safety import (
    MAX_ARCHIVE_CONTENT_BYTES,
    MAX_ARCHIVE_MEMBERS,
    extract_tar_safely,
)
from conclear.schema import validate_external
from conclear.values import Digest, OCIReference, validate_run_id

_narrow = Narrower(InvalidInvocationError)
MANIFEST = "archive.json"
MAX_MANIFEST_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ArchiveResult:
    """One complete archive, suitable for copying to retained storage."""

    path: Path
    digest: str
    size: int
    manifest_digest: str

    def to_dict(self) -> dict[str, object]:
        """Return the public command-result representation."""
        return {
            "path": str(self.path),
            "digest": self.digest,
            "size": self.size,
            "manifestDigest": self.manifest_digest,
        }


@dataclass(frozen=True, slots=True)
class OpenArchive:
    """A checked archive extracted into a private temporary directory."""

    root: Path
    manifest: dict[str, object]
    result: ArchiveResult

    @property
    def subject(self) -> OCIReference:
        """Return the digest reference declared by the archive."""
        return OCIReference.parse(
            _narrow.string_value(self.manifest.get("subject"), "archive subject"),
            require_digest=True,
        )

    @property
    def kind(self) -> str:
        """Return release or rescan."""
        return _narrow.string_value(self.manifest.get("kind"), "archive kind")


def prepare_archive_directory(directory: Path, *, excluded: tuple[Path, ...]) -> Path:
    """Check writable durable storage before starting a release or rescan."""
    try:
        resolved = directory.expanduser().resolve(strict=True)
        if not resolved.is_dir():
            raise InvalidInvocationError("Archive destination must be a directory")
        for source in excluded:
            if resolved.is_relative_to(source.resolve()):
                raise InvalidInvocationError(
                    "Archive directory must be outside source and ConClear working data"
                )
        with tempfile.TemporaryFile(dir=resolved):
            pass
    except OSError as exc:
        raise InvalidInvocationError(
            "Archive directory must exist and be writable"
        ) from exc
    return resolved


def member_path(value: str) -> PurePosixPath:
    """Validate a canonical, relative archive path."""
    path = PurePosixPath(value)
    if (
        not value
        or not path.parts
        or "\x00" in value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise InvalidInvocationError(f"Unsafe archive member path: {value}")
    return path


def write_archive(
    directory: Path,
    metadata: dict[str, object],
    sources: Mapping[str, Path | bytes],
    *,
    validate: Callable[[OpenArchive], None],
) -> ArchiveResult:
    """Write, reread and atomically publish a private compressed evidence archive.

    Only explicitly selected regular files enter the archive. Publication never
    overwrites a destination; identical retries return the existing archive.
    """
    members: list[dict[str, object]] = []
    total = 0
    for name, source in sorted(sources.items()):
        member_path(name)
        if name == MANIFEST:
            raise InvalidInvocationError("Archive source collides with its manifest")
        if isinstance(source, bytes):
            size, digest = len(source), sha256_bytes(source)
        else:
            info = source.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise InvalidInvocationError("Archive input is not a regular file")
            size, digest = info.st_size, sha256_file(source)
        total += size
        members.append({"path": name, "size": size, "digest": digest})
    if total > MAX_ARCHIVE_CONTENT_BYTES or len(members) >= MAX_ARCHIVE_MEMBERS:
        raise InvalidInvocationError("Evidence exceeds the archive limits")
    manifest = {**metadata, "schemaVersion": 1, "members": members}
    _validate_manifest(manifest)
    content = canonical_json_bytes(manifest)
    if len(content) > MAX_MANIFEST_BYTES:
        raise InvalidInvocationError("Archive manifest exceeds the size limit")
    manifest_digest = sha256_bytes(content)
    name = f"{manifest['kind']}-{manifest['runId']}-{manifest_digest[7:19]}.tar.gz"
    destination = directory / name
    try:
        with tempfile.TemporaryDirectory(
            prefix=".conclear-archive-", dir=directory
        ) as staging:
            temporary = Path(staging) / name
            with temporary.open("xb") as stream:
                temporary.chmod(0o600)
                with tarfile.open(
                    fileobj=stream, mode="w:gz", format=tarfile.PAX_FORMAT
                ) as archive:
                    _add_bytes(archive, MANIFEST, content)
                    for member in members:
                        member_name = str(member["path"])
                        source = sources[member_name]
                        if isinstance(source, bytes):
                            _add_bytes(archive, member_name, source)
                        else:
                            descriptor = os.open(
                                source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                            )
                            with os.fdopen(descriptor, "rb") as incoming:
                                info = os.fstat(incoming.fileno())
                                if (
                                    not stat.S_ISREG(info.st_mode)
                                    or info.st_size != member["size"]
                                ):
                                    raise InvalidInvocationError(
                                        "Archive input changed while writing"
                                    )
                                header = tarfile.TarInfo(member_name)
                                header.size = info.st_size
                                header.mode = 0o600
                                archive.addfile(header, incoming)
                stream.flush()
                os.fsync(stream.fileno())
            with open_archive(temporary) as checked:
                validate(checked)
                if checked.result.manifest_digest != manifest_digest:
                    raise OperationalError("Archive verification changed its manifest")
                result = checked.result
            try:
                os.link(temporary, destination)
            except FileExistsError:
                with open_archive(destination) as previous:
                    validate(previous)
                    if previous.result.manifest_digest != manifest_digest:
                        raise InvalidInvocationError(
                            "Archive destination already contains different evidence"
                        ) from None
                    return previous.result
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return ArchiveResult(
                destination, result.digest, result.size, manifest_digest
            )
    except (OSError, tarfile.TarError) as exc:
        raise OperationalError(
            "Unable to finish evidence archive; retain the run and retry archive create"
        ) from exc


@contextmanager
def open_archive(path: Path) -> Iterator[OpenArchive]:
    """Extract and check every member before exposing any archived data."""
    path = path.expanduser().absolute()
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise InvalidInvocationError("Evidence archive is not a regular file")
        if info.st_size > MAX_ARCHIVE_CONTENT_BYTES:
            raise InvalidInvocationError("Compressed archive exceeds the size limit")
        digest = sha256_file(path)
        with tempfile.TemporaryDirectory(prefix="conclear-archive-") as temporary:
            root = Path(temporary) / "evidence"
            extract_tar_safely(path, root)
            content = read_regular_file(
                root / MANIFEST,
                maximum_bytes=MAX_MANIFEST_BYTES,
                label="archive manifest",
            )
            manifest = _narrow.object_value(
                load_json(root / MANIFEST, maximum_bytes=MAX_MANIFEST_BYTES),
                "archive manifest",
            )
            members = _validate_manifest(manifest)
            observed = {
                item.relative_to(root).as_posix()
                for item in root.rglob("*")
                if item.is_file()
            }
            if observed != {MANIFEST, *members}:
                raise InvalidInvocationError(
                    "Archive contains missing or unlisted files"
                )
            for name, (size, expected_digest) in members.items():
                file = root.joinpath(*member_path(name).parts)
                if file.stat().st_size != size or sha256_file(file) != expected_digest:
                    raise InvalidInvocationError(
                        f"Archive member checksum differs: {name}"
                    )
            if sha256_file(path) != digest:
                raise InvalidInvocationError("Archive changed while reading")
            yield OpenArchive(
                root,
                manifest,
                ArchiveResult(path, digest, info.st_size, sha256_bytes(content)),
            )
    except (OSError, tarfile.TarError) as exc:
        raise OperationalError("Unable to read evidence archive") from exc


def _validate_manifest(value: dict[str, object]) -> dict[str, tuple[int, str]]:
    validate_external(value, "archive.schema.json", label="evidence archive")
    required = {
        "schemaVersion",
        "kind",
        "runId",
        "subject",
        "imageId",
        "members",
        "configurationDigest",
        "recordPath",
        "source",
        "imageLayers",
        "releaseArchiveDigest",
        "signedEvidence",
    }
    if (
        set(value) != required
        or type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != 1
    ):
        raise InvalidInvocationError(
            "Unsupported or malformed evidence archive manifest"
        )
    if value["kind"] not in ("release", "rescan"):
        raise InvalidInvocationError("Unknown evidence archive kind")
    validate_run_id(_narrow.string_value(value["runId"], "archive run id"))
    subject = OCIReference.parse(
        _narrow.string_value(value["subject"], "archive subject"), require_digest=True
    )
    if subject.tag is not None:
        raise InvalidInvocationError("Archive subject must not include a tag")
    _narrow.string_value(value["imageId"], "archive image id")
    Digest(
        _narrow.string_value(
            value["configurationDigest"], "archive configuration digest"
        )
    )
    member_path(_narrow.string_value(value["recordPath"], "archive record path"))
    if type(value["source"]) is not bool or type(value["imageLayers"]) is not bool:
        raise InvalidInvocationError("Archive content flags must be booleans")
    if value["releaseArchiveDigest"] is not None:
        Digest(
            _narrow.string_value(
                value["releaseArchiveDigest"], "release archive digest"
            )
        )
    _narrow.array_value(value["signedEvidence"], "signed evidence")
    members: dict[str, tuple[int, str]] = {}
    total = 0
    for raw in _narrow.array_value(value["members"], "archive members"):
        item = _narrow.object_value(raw, "archive member")
        if set(item) != {"path", "size", "digest"}:
            raise InvalidInvocationError("Archive member declaration is malformed")
        name = _narrow.string_value(item["path"], "archive member path")
        member_path(name)
        size = _narrow.integer_value(item["size"], "archive member size")
        digest = _narrow.string_value(item["digest"], "archive member digest")
        Digest(digest)
        if name == MANIFEST or name in members or size < 0:
            raise InvalidInvocationError("Invalid or repeated archive member")
        total += size
        members[name] = (size, digest)
    if total > MAX_ARCHIVE_CONTENT_BYTES or len(members) >= MAX_ARCHIVE_MEMBERS:
        raise InvalidInvocationError("Archive exceeds its content limits")
    return members


def _add_bytes(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    header = tarfile.TarInfo(name)
    header.size = len(content)
    header.mode = 0o600
    archive.addfile(header, io.BytesIO(content))
