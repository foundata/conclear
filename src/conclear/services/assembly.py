"""Qualification transport validation and release-candidate assembly."""

import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from conclear.assembly import (
    AssemblyObservation,
    PlatformLayout,
    assemble_layout,
)
from conclear.config import ImageConfig, RepositoryConfig
from conclear.errors import InvalidInvocationError
from conclear.identity import IDENTITY
from conclear.jsonutil import load_json, sha256_bytes, sha256_file
from conclear.oci import validate_layout
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
    validate_record,
)
from conclear.values import (
    Digest,
    Platform,
    candidate_tag,
    validate_source_revision,
)
from conclear.workspace import RunState, RunWorkspace


@dataclass(frozen=True, slots=True)
class QualificationTransport:
    """One transported qualification, layout and exact payload files."""

    record_path: Path
    layout_path: Path
    layout_reference: str
    payload_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class CandidateResult:
    """One accepted aggregate record and assembled immutable subject."""

    record_path: Path
    record_digest: str
    observation: AssemblyObservation
    candidate_tag: str
    qualification_digests: tuple[str, ...]
    payload_digests: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Qualification:
    run_id: str
    image_id: str
    platform: Platform
    record_digest: str
    payload_digests: tuple[str, ...]
    source: SourceIdentity
    configuration_digest: str
    ruleset: dict[str, object]
    tools: tuple[tuple[str, str], ...]
    database_digest: str
    manifest_digest: Digest
    transport: QualificationTransport


def assemble_candidate(
    transports: tuple[QualificationTransport, ...],
    *,
    repository: RepositoryConfig,
    image: ImageConfig,
    workspace: RunWorkspace,
    version: str | None,
    tools: tuple[ToolIdentity, ...],
    now: datetime,
) -> CandidateResult:
    """Verify every transported byte and assemble exact required platform coverage."""
    qualifications = tuple(_read_qualification(item) for item in transports)
    snapshot = workspace.load()
    recorded_version = snapshot.immutable_inputs.get("version") or None
    if version != recorded_version:
        raise InvalidInvocationError("Assembly version differs from the release run")
    accepted_platforms = {item.platform for item in qualifications}
    required_platforms = set(image.platforms)
    if accepted_platforms != required_platforms:
        missing = sorted(str(item) for item in required_platforms - accepted_platforms)
        unexpected = sorted(
            str(item) for item in accepted_platforms - required_platforms
        )
        raise InvalidInvocationError(
            "Qualification platform coverage mismatch; "
            f"missing={missing}, unexpected={unexpected}"
        )
    if len(qualifications) != len(accepted_platforms):
        raise InvalidInvocationError(
            "Assembly received duplicate platform qualifications"
        )
    first = qualifications[0]
    if any(item.run_id != workspace.run_id for item in qualifications):
        raise InvalidInvocationError("Qualifications belong to another release run")
    if any(item.image_id != image.image_id for item in qualifications):
        raise InvalidInvocationError("Qualifications do not match the selected image")
    if first.source.repository != repository.project.source:
        raise InvalidInvocationError(
            "Qualifications do not match the selected source repository"
        )
    if first.source.revision != snapshot.immutable_inputs.get("sourceRevision"):
        raise InvalidInvocationError(
            "Qualifications do not match the release-run source revision"
        )
    if first.configuration_digest != sha256_bytes(repository.raw_bytes):
        raise InvalidInvocationError(
            "Qualifications do not match the selected repository configuration"
        )
    for item in qualifications[1:]:
        if item.source != first.source:
            raise InvalidInvocationError(
                "Qualifications identify different source commits"
            )
        if item.configuration_digest != first.configuration_digest:
            raise InvalidInvocationError(
                "Qualifications identify different repository configurations"
            )
        if item.ruleset != first.ruleset:
            raise InvalidInvocationError("Qualifications identify different rulesets")
        if item.tools != first.tools:
            raise InvalidInvocationError(
                "Qualifications report different normalized tool versions"
            )
        if item.database_digest != first.database_digest:
            raise InvalidInvocationError(
                "Qualifications use different vulnerability database snapshots"
            )
    tag = candidate_tag(
        version=version,
        run_id=workspace.run_id,
        source_revision=first.source.revision,
    )
    observation = assemble_layout(
        tuple(
            PlatformLayout(
                item.platform,
                item.transport.layout_path,
                item.transport.layout_reference,
            )
            for item in qualifications
        ),
        output_path=workspace.root / "layouts" / image.image_id / "candidate",
        output_reference=tag,
    )
    qualification_digests = tuple(
        item.record_digest
        for item in sorted(qualifications, key=lambda value: value.platform)
    )
    payload_digests = tuple(
        sorted({digest for item in qualifications for digest in item.payload_digests})
    )
    payload: dict[str, object] = {
        "imageId": image.image_id,
        "repository": image.repository.repository_name,
        "requiredPlatforms": [str(item) for item in sorted(image.platforms)],
        "acceptedPlatforms": [str(item) for item in sorted(accepted_platforms)],
        "qualifications": [
            {
                "platform": str(item.platform),
                "recordDigest": item.record_digest,
                "payloadDigests": list(item.payload_digests),
            }
            for item in sorted(qualifications, key=lambda value: value.platform)
        ],
        "platformManifests": {
            str(platform): str(digest)
            for platform, digest in observation.platform_manifests
        },
        "subjectDescriptor": observation.graph.root.to_dict(),
        "candidateTag": tag,
        "candidateNaming": {
            "version": version,
            "runId": workspace.run_id,
            "sourceRevision": first.source.revision,
            "tag": tag,
        },
    }
    record = RecordEnvelope(
        record_type="releaseCandidate",
        created_at=now,
        run_id=workspace.run_id,
        source=first.source,
        configuration_digest=first.configuration_digest,
        tools=tools,
        verdict=Verdict.ACCEPTED,
        payload=payload,
    )
    record_path = workspace.root / "records" / "release-candidate.json"
    record_digest = record.write(record_path)
    workspace.transition(RunState.ASSEMBLED, now=now)
    return CandidateResult(
        record_path,
        record_digest,
        observation,
        tag,
        qualification_digests,
        payload_digests,
    )


def _read_qualification(transport: QualificationTransport) -> _Qualification:
    value = load_json(transport.record_path)
    validate_record(value)
    record = _object(value, "qualification")
    if record.get("recordType") != "platformQualification":
        raise InvalidInvocationError("Assembly input is not a platform qualification")
    if record.get("verdict") != "accepted":
        raise InvalidInvocationError("Assembly input qualification is not accepted")
    payload = _object(record.get("payload"), "qualification payload")
    platform = Platform.parse(
        _string(payload.get("platform"), "qualification platform")
    )
    payload_values = _strings(payload.get("payloadDigests"), "payload digests")
    payload_digests = tuple(sorted(payload_values))
    if len(payload_digests) != len(set(payload_digests)):
        raise InvalidInvocationError("Qualification contains duplicate payload digests")
    actual_payloads = tuple(
        sorted(_hash_transport_path(path) for path in transport.payload_paths)
    )
    if actual_payloads != payload_digests:
        raise InvalidInvocationError(
            f"Transported payload digests do not match qualification for {platform}"
        )
    graph = validate_layout(transport.layout_path, reference=transport.layout_reference)
    if len(graph.manifests) != 1 or graph.manifests[0].platform != platform:
        raise InvalidInvocationError(
            f"Transported layout does not match qualification platform {platform}"
        )
    manifest_digest = Digest(_string(payload.get("manifestDigest"), "manifest digest"))
    if graph.manifests[0].descriptor.digest != manifest_digest:
        raise InvalidInvocationError(
            f"Transported layout manifest differs for {platform}"
        )
    descriptor = _object(payload.get("layoutDescriptor"), "layout descriptor")
    if descriptor.get("digest") != str(graph.root.digest):
        raise InvalidInvocationError(f"Transported layout root differs for {platform}")
    source_value = _object(record.get("source"), "qualification source")
    configuration = _object(
        record.get("repositoryConfiguration"), "qualification configuration"
    )
    ruleset = _object(record.get("ruleset"), "qualification ruleset")
    if (
        ruleset.get("conclearVersion") != IDENTITY.version
        or ruleset.get("conclearRevision") != IDENTITY.source_revision
    ):
        raise InvalidInvocationError(
            "Qualification was not produced by this ConClear build"
        )
    tools_value = record.get("tools")
    if not isinstance(tools_value, list):
        raise InvalidInvocationError("Qualification tools are malformed")
    normalized_tools = []
    for raw_tool in tools_value:
        tool = _object(raw_tool, "qualification tool")
        normalized_tools.append(
            (
                _string(tool.get("name"), "tool name"),
                _string(tool.get("version"), "tool version"),
            )
        )
    if len(normalized_tools) != len({name for name, _version in normalized_tools}):
        raise InvalidInvocationError("Qualification contains duplicate tool identities")
    database_digest = _string(payload.get("databaseDigest"), "database digest")
    Digest(database_digest)
    configuration_digest = _string(configuration.get("sha256"), "configuration digest")
    Digest(configuration_digest)
    return _Qualification(
        run_id=_string(record.get("runId"), "qualification run id"),
        image_id=_string(payload.get("imageId"), "image id"),
        platform=platform,
        record_digest=sha256_file(transport.record_path),
        payload_digests=payload_digests,
        source=SourceIdentity(
            repository=_string(source_value.get("repository"), "source repository"),
            revision=validate_source_revision(
                _string(source_value.get("revision"), "source revision")
            ),
        ),
        configuration_digest=configuration_digest,
        ruleset=ruleset,
        tools=tuple(sorted(normalized_tools)),
        database_digest=database_digest,
        manifest_digest=manifest_digest,
        transport=transport,
    )


def _hash_transport_path(path: Path) -> str:
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise InvalidInvocationError(
            f"Transported payload is unavailable: {path}"
        ) from exc
    if not stat.S_ISREG(path_stat.st_mode):
        raise InvalidInvocationError(f"Transported payload is not regular: {path}")
    return sha256_file(path)


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise InvalidInvocationError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidInvocationError(f"{label} must be a non-empty string")
    return value


def _strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise InvalidInvocationError(f"{label} must be an array of strings")
    return value
