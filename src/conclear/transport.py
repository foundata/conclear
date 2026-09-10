"""Fail-closed export and import of platform qualification transports.

A worker exports one accepted platform qualification as a transport: the
immutable qualification record, its OCI layout and the exact evidence payloads
the record names, plus a schema-validated ``transport.json`` manifest that binds
every member by digest. A coordinator imports a transport only against a digest
the caller obtained independently, verifies every member and installs the
verified copies into its own run workspace before assembly.
"""

import hashlib
import os
import re
import shutil
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import BinaryIO

from conclear.artifacts import qualification_transport
from conclear.config import ReleaseImageConfig, RepositoryConfig
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.fileio import read_regular_file
from conclear.identity import IDENTITY
from conclear.jsonutil import (
    atomic_write_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
)
from conclear.oci import validate_layout
from conclear.parsing import Narrower, json_value
from conclear.path_safety import MAX_ARCHIVE_CONTENT_BYTES, extract_tar_safely
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
    parse_timestamp,
    validate_record,
)
from conclear.services.assembly import (
    QualificationTransport,
    expected_build_arguments,
    verify_dependency_evidence,
)
from conclear.values import Digest, Platform
from conclear.workspace import ResourceKind, ResourceStatus, RunWorkspace

_narrow = Narrower(InvalidInvocationError)

TRANSPORT_RECORD_TYPE = "qualificationTransport"
MANIFEST_NAME = "transport.json"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_TRANSPORT_MEMBERS = 4096
MAX_TRANSPORT_BYTES = MAX_ARCHIVE_CONTENT_BYTES
TRANSPORT_CHECK = "CC0306"

_REPORT_NAME_PATTERN = re.compile(r"^(?:[a-z0-9][a-z0-9-]*\.json|test-outputs\.tar)$")
_BLOB_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class TransportKind(StrEnum):
    """Physical forms of one qualification transport."""

    ARCHIVE = "archive"
    DIRECTORY = "directory"


@dataclass(frozen=True, slots=True)
class TransportMember:
    """One exact regular file inside a transport."""

    path: str
    digest: str
    size: int

    def to_dict(self) -> dict[str, object]:
        """Return the manifest representation."""
        return {"path": self.path, "digest": self.digest, "size": self.size}


@dataclass(frozen=True, slots=True)
class TransportExport:
    """One written transport and the digests its worker must report."""

    path: Path
    kind: TransportKind
    worker_run_id: str
    platform: Platform
    transport_digest: str
    manifest_digest: str
    record_digest: str
    layout_digest: str
    platform_manifest_digest: str
    payload_digests: tuple[str, ...]
    members: tuple[TransportMember, ...]
    total_bytes: int


@dataclass(frozen=True, slots=True)
class ImportedTransport:
    """One verified transport installed into the coordinator workspace."""

    transport: QualificationTransport
    source: Path
    kind: TransportKind
    platform: Platform
    worker_run_id: str
    transport_digest: str
    manifest_digest: str
    record_digest: str


def export_transport(
    workspace: RunWorkspace,
    image: ReleaseImageConfig,
    platform: Platform,
    *,
    destination: Path,
    kind: TransportKind,
    now: datetime,
) -> TransportExport:
    """Write one accepted qualification as a new transport archive or directory.

    The destination must not exist. Only the qualification record, the OCI
    layout and the payload files named by the record are exported; run logs,
    tool environments, container storage, test inputs and secret material are
    never members.

    Raises:
        InvalidInvocationError: If the destination exists or the qualification
            is not an accepted record owned by the workspace.
        OperationalError: If the transport cannot be written.
    """
    owned = qualification_transport(workspace, image, platform)
    record = _narrow.object_value(load_json(owned.record_path), "qualification record")
    run_id = _narrow.string_value(record.get("runId"), "qualification run id")
    source = _narrow.object_value(record.get("source"), "qualification source")
    configuration = _narrow.object_value(
        record.get("repositoryConfiguration"), "qualification configuration"
    )
    tools_value = record.get("tools")
    if not isinstance(tools_value, list):
        raise InvalidInvocationError("Qualification tools are malformed")
    tools = tuple(
        ToolIdentity.from_dict(item, error=InvalidInvocationError)
        for item in tools_value
    )
    payload = _narrow.object_value(record.get("payload"), "qualification payload")
    graph = validate_layout(owned.layout_path, reference=owned.layout_reference)
    key = platform.key
    sources: dict[str, Path] = {
        f"records/platform-qualification-{key}.json": owned.record_path,
        f"layouts/{key}/oci-layout": owned.layout_path / "oci-layout",
        f"layouts/{key}/index.json": owned.layout_path / "index.json",
    }
    for descriptor in graph.descriptors:
        encoded = descriptor.digest.encoded
        sources[f"layouts/{key}/blobs/sha256/{encoded}"] = (
            owned.layout_path / "blobs" / "sha256" / encoded
        )
    report_root = workspace.root / "reports" / image.image_id / key
    sbom_path = workspace.root / "exports" / "sbom" / f"{key}.spdx.json"
    for path in owned.payload_paths:
        if path == sbom_path:
            sources[f"exports/sbom/{key}.spdx.json"] = path
        elif path.parent == report_root and _REPORT_NAME_PATTERN.fullmatch(path.name):
            sources[f"reports/{key}/{path.name}"] = path
        else:
            raise InvalidInvocationError(
                f"Qualification payload is outside the transportable set: {path}"
            )
    members = tuple(
        TransportMember(name, _regular_digest(path), _regular_size(path))
        for name, path in sorted(sources.items())
    )
    total_bytes = sum(member.size for member in members)
    if len(members) > MAX_TRANSPORT_MEMBERS or total_bytes > MAX_TRANSPORT_BYTES:
        raise InvalidInvocationError("Qualification exceeds the transport limits")
    record_digest = sha256_file(owned.record_path)
    manifest = RecordEnvelope(
        record_type=TRANSPORT_RECORD_TYPE,
        created_at=now,
        run_id=run_id,
        source=SourceIdentity(
            _narrow.string_value(source.get("repository"), "source repository"),
            _narrow.string_value(source.get("revision"), "source revision"),
        ),
        configuration_digest=_narrow.string_value(
            configuration.get("sha256"), "configuration digest"
        ),
        tools=tools,
        verdict=Verdict.ACCEPTED,
        payload={
            "imageId": image.image_id,
            "platform": str(platform),
            "qualificationRecordDigest": record_digest,
            "layoutDescriptor": graph.root.to_dict(),
            "manifestDigest": str(graph.manifests[0].descriptor.digest),
            "members": [member.to_dict() for member in members],
            "totalBytes": total_bytes,
        },
    )
    manifest_bytes = manifest.content_bytes()
    manifest_digest = sha256_bytes(manifest_bytes)
    _require_absent(destination)
    if kind is TransportKind.DIRECTORY:
        _write_directory(destination, manifest_bytes, members, sources)
        transport_digest = manifest_digest
    else:
        _write_archive(destination, manifest_bytes, members, sources)
        transport_digest = sha256_file(destination)
    payload_digests = payload.get("payloadDigests")
    return TransportExport(
        path=destination,
        kind=kind,
        worker_run_id=run_id,
        platform=platform,
        transport_digest=transport_digest,
        manifest_digest=manifest_digest,
        record_digest=record_digest,
        layout_digest=str(graph.root.digest),
        platform_manifest_digest=str(graph.manifests[0].descriptor.digest),
        payload_digests=tuple(
            sorted(
                _narrow.string_array_value(
                    payload_digests, "qualification payload digests"
                )
            )
        ),
        members=members,
        total_bytes=total_bytes,
    )


def import_transport(
    source: Path,
    *,
    expected_digest: str,
    workspace: RunWorkspace,
    image: ReleaseImageConfig,
    repository: RepositoryConfig,
    source_time: datetime,
) -> ImportedTransport:
    """Verify one transport against a caller-supplied digest and install it.

    The transport is staged below the coordinator workspace, compared with the
    expected digest before any member is trusted, checked member by member
    against its manifest and its own qualification record, and only then moved
    to the standard workspace locations. Staged content of a failed import is
    retained under a failed journal entry so cleanup can remove it.

    Raises:
        RuleRejectionError: If a digest, member or record does not match.
        InvalidInvocationError: If the transport is malformed or unexpected.
        OperationalError: If the transport cannot be read or installed.
    """
    digest = Digest(expected_digest)
    kind = _transport_kind(source)
    staging = workspace.root / "transports" / digest.encoded[:16]
    resource_id = f"transport-{digest.encoded[:16]}"
    workspace.journal.plan(
        resource_id=resource_id,
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(staging),
        ephemeral=True,
        metadata={"source": str(source), "expectedDigest": str(digest)},
    )
    try:
        if kind is TransportKind.ARCHIVE:
            manifest_bytes = _stage_archive(source, digest, staging)
        else:
            manifest_bytes = _stage_directory(source, digest, staging)
        workspace.journal.update(resource_id, ResourceStatus.CREATED)
        verified = _verify_staging(
            staging,
            manifest_bytes,
            image,
            repository,
            expected_build_arguments(workspace, source_time=source_time),
        )
        transport = _install(workspace, image, verified, transport_digest=str(digest))
        shutil.rmtree(staging)
        workspace.journal.update(resource_id, ResourceStatus.REMOVED)
    except BaseException:
        workspace.journal.update(resource_id, ResourceStatus.FAILED)
        raise
    return ImportedTransport(
        transport=transport,
        source=source,
        kind=kind,
        platform=verified.platform,
        worker_run_id=verified.worker_run_id,
        transport_digest=str(digest),
        manifest_digest=verified.manifest_digest,
        record_digest=verified.record_digest,
    )


@dataclass(frozen=True, slots=True)
class _VerifiedStaging:
    root: Path
    platform: Platform
    worker_run_id: str
    manifest_digest: str
    record_digest: str
    payload_names: tuple[str, ...]


def _stage_archive(source: Path, digest: Digest, staging: Path) -> bytes:
    size = _regular_size(source)
    if size > MAX_TRANSPORT_BYTES:
        raise InvalidInvocationError("Transport archive exceeds the size limit")
    if sha256_file(source) != str(digest):
        raise RuleRejectionError(
            f"Transport digest mismatch: {source}", code=TRANSPORT_CHECK
        )
    staging.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    extract_tar_safely(source, staging)
    manifest_path = staging / MANIFEST_NAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise InvalidInvocationError(
            f"Transport has no {MANIFEST_NAME} manifest and is not a ConClear "
            f"qualification transport: {source}"
        )
    return read_regular_file(
        manifest_path,
        maximum_bytes=MAX_MANIFEST_BYTES,
        label="transport manifest",
    )


def _stage_directory(source: Path, digest: Digest, staging: Path) -> bytes:
    manifest_bytes = read_regular_file(
        _member_source(source, MANIFEST_NAME),
        maximum_bytes=MAX_MANIFEST_BYTES,
        label="transport manifest",
    )
    if sha256_bytes(manifest_bytes) != str(digest):
        raise RuleRejectionError(
            f"Transport digest mismatch: {source}", code=TRANSPORT_CHECK
        )
    manifest = _parse_manifest(manifest_bytes)
    members = _manifest_members(
        _narrow.object_value(manifest.get("payload"), "transport payload")
    )
    staging.mkdir(mode=0o700, parents=True, exist_ok=False)
    for member in members:
        target = staging.joinpath(*PurePosixPath(member.path).parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _copy_verified(_member_source(source, member.path), target, member)
    atomic_write_bytes(staging / MANIFEST_NAME, manifest_bytes, mode=0o644)
    return manifest_bytes


def _verify_staging(
    staging: Path,
    manifest_bytes: bytes,
    image: ReleaseImageConfig,
    repository: RepositoryConfig,
    expected_arguments: tuple[tuple[str, str], ...],
) -> _VerifiedStaging:
    manifest = _parse_manifest(manifest_bytes)
    ruleset = _narrow.object_value(manifest.get("ruleset"), "transport ruleset")
    if (
        ruleset.get("conclearVersion") != IDENTITY.version
        or ruleset.get("conclearRevision") != IDENTITY.source_revision
    ):
        raise InvalidInvocationError(
            "Transport was not produced by this ConClear build"
        )
    payload = _narrow.object_value(manifest.get("payload"), "transport payload")
    worker_run_id = _narrow.string_value(manifest.get("runId"), "transport run id")
    if payload.get("imageId") != image.image_id:
        raise InvalidInvocationError("Transport belongs to another image")
    platform = Platform.parse(
        _narrow.string_value(payload.get("platform"), "transport platform")
    )
    if not any(platform.semantically_matches(item) for item in image.platforms):
        raise InvalidInvocationError(
            f"Transport platform is not required by {image.image_id}: {platform}"
        )
    members = _manifest_members(payload)
    key = platform.key
    for member in members:
        _require_allowed_member(member.path, key)
    observed = _walk_regular_files(staging)
    expected_paths = {member.path for member in members} | {MANIFEST_NAME}
    if observed != expected_paths:
        unexpected = sorted(observed - expected_paths)
        missing = sorted(expected_paths - observed)
        raise RuleRejectionError(
            "Transport members differ from the manifest; "
            f"unexpected={unexpected}, missing={missing}",
            code=TRANSPORT_CHECK,
        )
    for member in members:
        path = staging.joinpath(*PurePosixPath(member.path).parts)
        if _regular_size(path) != member.size or sha256_file(path) != member.digest:
            raise RuleRejectionError(
                f"Transport member differs from the manifest: {member.path}",
                code=TRANSPORT_CHECK,
            )
    record_path = staging / "records" / f"platform-qualification-{key}.json"
    record_digest = sha256_file(record_path)
    if record_digest != payload.get("qualificationRecordDigest"):
        raise RuleRejectionError(
            "Transported qualification record digest differs from the manifest",
            code=TRANSPORT_CHECK,
        )
    record = _narrow.object_value(load_json(record_path), "transported qualification")
    validate_record(record)
    if record.get("recordType") != "platformQualification":
        raise InvalidInvocationError(
            "Transport does not carry a platform qualification"
        )
    if record.get("verdict") != "accepted":
        raise InvalidInvocationError("Transported qualification is not accepted")
    if record.get("runId") != worker_run_id:
        raise RuleRejectionError(
            "Transported qualification belongs to another worker run",
            code=TRANSPORT_CHECK,
        )
    record_payload = _narrow.object_value(
        record.get("payload"), "qualification payload"
    )
    if record_payload.get("imageId") != image.image_id or not Platform.parse(
        _narrow.string_value(record_payload.get("platform"), "qualification platform")
    ).semantically_matches(platform):
        raise RuleRejectionError(
            "Transported qualification identifies another image or platform",
            code=TRANSPORT_CHECK,
        )
    _verify_dependency_evidence(
        record,
        record_payload,
        image=image,
        repository=repository,
        expected_arguments=expected_arguments,
    )
    graph = validate_layout(staging / "layouts" / key, reference="qualified")
    if payload.get("layoutDescriptor") != graph.root.to_dict():
        raise RuleRejectionError(
            "Transported layout descriptor differs from the manifest",
            code=TRANSPORT_CHECK,
        )
    if len(graph.manifests) != 1 or payload.get("manifestDigest") != str(
        graph.manifests[0].descriptor.digest
    ):
        raise RuleRejectionError(
            "Transported platform manifest differs from the manifest",
            code=TRANSPORT_CHECK,
        )
    expected_blobs = {
        f"layouts/{key}/blobs/sha256/{descriptor.digest.encoded}"
        for descriptor in graph.descriptors
    }
    observed_blobs = {
        member.path
        for member in members
        if member.path.startswith(f"layouts/{key}/blobs/")
    }
    if observed_blobs != expected_blobs:
        raise RuleRejectionError(
            "Transported layout blobs differ from the validated graph",
            code=TRANSPORT_CHECK,
        )
    payload_names = _payload_member_names(record_payload, key)
    evidence_paths = {
        member.path
        for member in members
        if member.path.startswith(("reports/", "exports/"))
    }
    if evidence_paths != set(payload_names):
        raise RuleRejectionError(
            "Transported evidence payloads differ from the qualification record",
            code=TRANSPORT_CHECK,
        )
    return _VerifiedStaging(
        root=staging,
        platform=platform,
        worker_run_id=worker_run_id,
        manifest_digest=sha256_bytes(manifest_bytes),
        record_digest=record_digest,
        payload_names=payload_names,
    )


def _verify_dependency_evidence(
    record: dict[str, object],
    payload: dict[str, object],
    *,
    image: ReleaseImageConfig,
    repository: RepositoryConfig,
    expected_arguments: tuple[tuple[str, str], ...],
) -> None:
    source = _narrow.object_value(record.get("source"), "qualification source")
    try:
        verify_dependency_evidence(
            payload,
            repository=repository,
            image=image,
            platform=Platform.parse(
                _narrow.string_value(payload.get("platform"), "qualification platform")
            ),
            source_revision=_narrow.string_value(
                source.get("revision"), "source revision"
            ),
            record_created_at=parse_timestamp(
                record.get("createdAt"),
                "record creation time",
                error=InvalidInvocationError,
            ),
            payload_digests=tuple(
                _narrow.string_array_value(
                    payload.get("payloadDigests"), "payload digests"
                )
            ),
            expected_arguments=expected_arguments,
        )
    except InvalidInvocationError as exc:
        raise RuleRejectionError(
            f"Transported qualification dependency evidence is rejected: {exc}",
            code=TRANSPORT_CHECK,
        ) from exc


def _install(
    workspace: RunWorkspace,
    image: ReleaseImageConfig,
    verified: _VerifiedStaging,
    *,
    transport_digest: str,
) -> QualificationTransport:
    key = verified.platform.key
    record_destination = (
        workspace.root / "records" / f"platform-qualification-{key}.json"
    )
    if (
        record_destination.exists()
        or (workspace.root / "layouts" / image.image_id / key).exists()
    ):
        raise InvalidInvocationError(
            f"A qualification for {verified.platform} is already imported into this run"
        )
    layout_destination = workspace.root / "layouts" / image.image_id / key
    layout_id = f"layout-{image.image_id}-{key}"
    payload_destinations: list[tuple[Path, Path]] = []
    for name in verified.payload_names:
        parts = PurePosixPath(name).parts
        if parts[0] == "exports":
            destination = workspace.root / "exports" / "sbom" / parts[-1]
        else:
            destination = workspace.root / "reports" / image.image_id / key / parts[-1]
        payload_destinations.append((verified.root.joinpath(*parts), destination))
    for destination in (
        record_destination,
        layout_destination,
        *(destination for _source, destination in payload_destinations),
    ):
        _require_absent(destination)
    workspace.journal.plan(
        resource_id=layout_id,
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(layout_destination),
        ephemeral=True,
        metadata={"transported": True, "workerRunId": verified.worker_run_id},
    )
    try:
        layout_destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        (verified.root / "layouts" / key).replace(layout_destination)
        for source, destination in payload_destinations:
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source.replace(destination)
        (verified.root / "records" / f"platform-qualification-{key}.json").replace(
            record_destination
        )
    except OSError as exc:
        workspace.journal.update(layout_id, ResourceStatus.FAILED)
        raise OperationalError("Unable to install the verified transport") from exc
    workspace.journal.update(layout_id, ResourceStatus.CREATED)
    return QualificationTransport(
        record_path=record_destination,
        layout_path=layout_destination,
        layout_reference="qualified",
        payload_paths=tuple(
            sorted(destination for _source, destination in payload_destinations)
        ),
        transport_digest=transport_digest,
    )


def _payload_member_names(payload: dict[str, object], key: str) -> tuple[str, ...]:
    names = [f"reports/{key}/tests.json", f"exports/sbom/{key}.spdx.json"]
    scans = payload.get("scans")
    if not isinstance(scans, list):
        raise InvalidInvocationError("Qualification scans are malformed")
    for item in scans:
        scan = _narrow.object_value(item, "qualification scan")
        name = _narrow.string_value(scan.get("path"), "scan path")
        if _REPORT_NAME_PATTERN.fullmatch(name) is None:
            raise InvalidInvocationError(f"Qualification scan path is unsafe: {name}")
        names.append(f"reports/{key}/{name}")
    if payload.get("testOutputArchive") is not None:
        output = _narrow.object_value(
            payload["testOutputArchive"], "test output archive"
        )
        if output.get("path") != "test-outputs.tar":
            raise InvalidInvocationError(
                "Qualification test output archive path is unsafe"
            )
        names.append(f"reports/{key}/test-outputs.tar")
    if len(names) != len(set(names)):
        raise InvalidInvocationError("Qualification repeats a payload path")
    return tuple(sorted(names))


def _require_allowed_member(path: str, key: str) -> None:
    parts = PurePosixPath(path).parts
    allowed = False
    if parts == ("records", f"platform-qualification-{key}.json"):
        allowed = True
    elif parts[:2] == ("layouts", key) and (
        parts[2:] in (("oci-layout",), ("index.json",))
        or (
            len(parts) == 5
            and parts[2:4] == ("blobs", "sha256")
            and _BLOB_PATTERN.fullmatch(parts[4]) is not None
        )
    ):
        allowed = True
    elif (
        parts[:2] == ("reports", key)
        and len(parts) == 3
        and _REPORT_NAME_PATTERN.fullmatch(parts[2]) is not None
    ):
        allowed = True
    elif parts == ("exports", "sbom", f"{key}.spdx.json"):
        allowed = True
    if not allowed:
        raise InvalidInvocationError(
            f"Transport member is not part of a platform qualification: {path}",
            code="CC0002",
        )


def _manifest_members(payload: dict[str, object]) -> tuple[TransportMember, ...]:
    raw_members = payload.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        raise InvalidInvocationError("Transport manifest has no members")
    if len(raw_members) > MAX_TRANSPORT_MEMBERS:
        raise InvalidInvocationError("Transport manifest exceeds the member limit")
    members: list[TransportMember] = []
    total = 0
    for raw in raw_members:
        item = _narrow.object_value(raw, "transport member")
        path = _narrow.string_value(item.get("path"), "transport member path")
        _safe_member_path(path)
        size = item.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise InvalidInvocationError("Transport member size is malformed")
        digest = str(
            Digest(_narrow.string_value(item.get("digest"), "transport member digest"))
        )
        total += size
        members.append(TransportMember(path, digest, size))
    if len({member.path for member in members}) != len(members):
        raise InvalidInvocationError("Transport manifest repeats a member path")
    if total > MAX_TRANSPORT_BYTES or payload.get("totalBytes") != total:
        raise InvalidInvocationError("Transport manifest size accounting is invalid")
    return tuple(members)


def _parse_manifest(manifest_bytes: bytes) -> dict[str, object]:
    try:
        text = manifest_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise InvalidInvocationError("Transport manifest is not UTF-8") from exc
    manifest = _narrow.object_value(
        json_value(text, label="Transport manifest"), "transport manifest"
    )
    validate_record(manifest)
    if manifest.get("recordType") != TRANSPORT_RECORD_TYPE:
        raise InvalidInvocationError("Transport manifest has the wrong record type")
    if manifest.get("verdict") != "accepted":
        raise InvalidInvocationError("Transport manifest is not accepted")
    return manifest


def _safe_member_path(path: str) -> PurePosixPath:
    if "\x00" in path or "\\" in path or path.startswith("/"):
        raise InvalidInvocationError(
            f"Unsafe transport member path: {path}", code="CC0002"
        )
    member = PurePosixPath(path)
    if member.is_absolute() or any(part in {"", ".", ".."} for part in member.parts):
        raise InvalidInvocationError(
            f"Unsafe transport member path: {path}", code="CC0002"
        )
    return member


def _member_source(root: Path, path: str) -> Path:
    member = _safe_member_path(path)
    current = root
    for part in member.parts[:-1]:
        current = current / part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise InvalidInvocationError(
                    f"Transport member crosses a symbolic link: {path}", code="CC0002"
                )
        except OSError as exc:
            raise InvalidInvocationError(
                f"Transport member is unavailable: {path}", code="CC0002"
            ) from exc
    return root.joinpath(*member.parts)


def _walk_regular_files(root: Path) -> set[str]:
    observed: set[str] = set()
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        for name in names:
            if stat.S_ISLNK((current / name).lstat().st_mode):
                raise InvalidInvocationError(
                    f"Transport contains a symbolic link: {name}", code="CC0002"
                )
        for name in files:
            path = current / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise InvalidInvocationError(
                    f"Transport member is not a regular file: {name}", code="CC0002"
                )
            if path.lstat().st_nlink != 1:
                raise InvalidInvocationError(
                    f"Transport member is hard-linked: {name}", code="CC0002"
                )
            observed.add(path.relative_to(root).as_posix())
    return observed


def _transport_kind(source: Path) -> TransportKind:
    try:
        mode = source.lstat().st_mode
    except OSError as exc:
        raise InvalidInvocationError(f"Transport is unavailable: {source}") from exc
    if stat.S_ISLNK(mode):
        raise InvalidInvocationError(f"Transport must not be a symbolic link: {source}")
    if stat.S_ISREG(mode):
        return TransportKind.ARCHIVE
    if stat.S_ISDIR(mode):
        return TransportKind.DIRECTORY
    raise InvalidInvocationError(
        f"Transport is neither a file nor a directory: {source}"
    )


def _copy_verified(source: Path, destination: Path, member: TransportMember) -> None:
    try:
        source_mode = source.lstat().st_mode
    except OSError as exc:
        raise InvalidInvocationError(
            f"Transport member is unavailable: {member.path}", code="CC0002"
        ) from exc
    if stat.S_ISLNK(source_mode):
        raise InvalidInvocationError(
            f"Transport member is a symbolic link: {member.path}", code="CC0002"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    digest = hashlib.sha256()
    size = 0
    try:
        descriptor = os.open(source, flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise InvalidInvocationError(
                f"Transport member is not a regular file: {member.path}", code="CC0002"
            )
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        with stream, destination.open("xb") as output:
            while size <= member.size:
                chunk = stream.read(min(1024 * 1024, member.size + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    except OSError as exc:
        raise OperationalError(
            f"Unable to copy transport member {member.path}"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if size != member.size or f"sha256:{digest.hexdigest()}" != member.digest:
        raise RuleRejectionError(
            f"Transport member differs from the manifest: {member.path}",
            code=TRANSPORT_CHECK,
        )
    destination.chmod(0o644)


def _write_directory(
    destination: Path,
    manifest_bytes: bytes,
    members: tuple[TransportMember, ...],
    sources: dict[str, Path],
) -> None:
    try:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise OperationalError(f"Unable to create transport {destination}") from exc
    for member in members:
        target = destination.joinpath(*PurePosixPath(member.path).parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _copy_verified(sources[member.path], target, member)
    atomic_write_bytes(destination / MANIFEST_NAME, manifest_bytes, mode=0o644)


def _write_archive(
    destination: Path,
    manifest_bytes: bytes,
    members: tuple[TransportMember, ...],
    sources: dict[str, Path],
) -> None:
    temporary_path: Path | None = None
    try:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp"
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o644)
        with (
            os.fdopen(descriptor, "wb") as stream,
            tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as tar,
        ):
            tar.addfile(
                _tar_info(MANIFEST_NAME, len(manifest_bytes)),
                _BytesReader(manifest_bytes),
            )
            for member in members:
                with _MemberReader(sources[member.path], member) as reader:
                    tar.addfile(_tar_info(member.path, member.size), reader)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.replace(destination)
        temporary_path = None
    except OSError as exc:
        raise OperationalError(f"Unable to write transport {destination}") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


class _BytesReader:
    """Readable wrapper for one in-memory tar member."""

    def __init__(self, content: bytes) -> None:
        self._content = content
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        """Return the next chunk of the wrapped bytes."""
        if size < 0:
            size = len(self._content) - self._offset
        chunk = self._content[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class _MemberReader:
    """Stream one exact member and refuse content that changed since hashing."""

    def __init__(self, source: Path, member: TransportMember) -> None:
        self._source = source
        self._member = member
        self._digest = hashlib.sha256()
        self._size = 0
        self._stream: BinaryIO | None = None

    def __enter__(self) -> "_MemberReader":
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self._source, flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise InvalidInvocationError(
                f"Transport source is not a regular file: {self._member.path}"
            )
        self._stream = os.fdopen(descriptor, "rb")
        return self

    def read(self, size: int = -1) -> bytes:
        """Return the next chunk while accumulating its digest."""
        if self._stream is None:
            raise OperationalError("Transport member stream is not open")
        limit = self._member.size - self._size
        if limit <= 0:
            return b""
        if size < 0 or size > limit:
            size = limit
        chunk = self._stream.read(size)
        self._size += len(chunk)
        self._digest.update(chunk)
        return chunk

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        stream = self._stream
        self._stream = None
        if stream is not None:
            stream.close()
        if exc_type is None and (
            self._size != self._member.size
            or f"sha256:{self._digest.hexdigest()}" != self._member.digest
        ):
            raise OperationalError(
                f"Transport source changed while exporting: {self._member.path}"
            )


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


def _require_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OperationalError(f"Unable to inspect {path}") from exc
    raise InvalidInvocationError(f"Destination already exists: {path}")


def _regular_size(path: Path) -> int:
    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise InvalidInvocationError(
            f"Transport member is unavailable: {path}"
        ) from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise InvalidInvocationError(f"Transport member is not a regular file: {path}")
    return file_stat.st_size


def _regular_digest(path: Path) -> str:
    _regular_size(path)
    return sha256_file(path)
