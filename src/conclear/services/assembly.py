"""Qualification transport validation and release-candidate assembly."""

import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from conclear.assembly import (
    AssemblyObservation,
    PlatformLayout,
    assemble_layout,
)
from conclear.config import ImageConfig, RepositoryConfig
from conclear.emulation import validate_execution_observation
from conclear.errors import InvalidInvocationError, OperationalError
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
    OCIReference,
    Platform,
    candidate_tag,
    validate_source_revision,
)
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
)


@dataclass(frozen=True, slots=True)
class QualificationTransport:
    """One qualification, layout and exact payload files ready for assembly.

    A transport owned by the assembling run carries no transport digest and
    must name that run. An imported transport carries the caller-verified
    transport digest and retains its worker run identity.
    """

    record_path: Path
    layout_path: Path
    layout_reference: str
    payload_paths: tuple[Path, ...]
    transport_digest: str | None = None


@dataclass(frozen=True, slots=True)
class CandidateResult:
    """One accepted aggregate record and assembled immutable subject."""

    record_path: Path
    record_digest: str
    observation: AssemblyObservation
    candidate_tag: str
    qualification_digests: tuple[str, ...]
    payload_digests: tuple[str, ...]
    qualification_runs: tuple[tuple[Platform, str], ...] = ()


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
    pin_references: tuple[str, ...]
    pin_resolutions: tuple[tuple[str, str], ...]
    effective_limits: tuple[tuple[str, int], ...]
    image_version: str | None
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
    if any(
        item.transport.transport_digest is None and item.run_id != workspace.run_id
        for item in qualifications
    ):
        raise InvalidInvocationError("Qualifications belong to another release run")
    if any(item.image_id != image.image_id for item in qualifications):
        raise InvalidInvocationError("Qualifications do not match the selected image")
    if any(item.image_version != version for item in qualifications):
        raise InvalidInvocationError(
            "Qualifications were built for another release version"
        )
    expected_pins = tuple(sorted(str(item.reference) for item in image.pins))
    if any(item.pin_references != expected_pins for item in qualifications):
        raise InvalidInvocationError(
            "Qualifications do not match configured external image pins"
        )
    expected_limits = tuple(
        sorted(
            {
                "pinFreshnessSeconds": int(image.limits.pin_freshness.total_seconds()),
                "pinDivergenceSeconds": int(
                    image.limits.pin_divergence.total_seconds()
                ),
            }.items()
        )
    )
    if any(item.effective_limits != expected_limits for item in qualifications):
        raise InvalidInvocationError("Qualifications do not match effective pin limits")
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
                "Qualifications use different vulnerability database snapshots",
                code="CC0505",
            )
        if item.pin_resolutions != first.pin_resolutions:
            raise InvalidInvocationError(
                "Qualifications observed different external image digests"
            )
    tag = candidate_tag(
        version=version,
        run_id=workspace.run_id,
        source_revision=first.source.revision,
    )
    output_path = workspace.root / "layouts" / image.image_id / "candidate"
    layout_id = f"candidate-layout-{image.image_id}"
    workspace.journal.plan(
        resource_id=layout_id,
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(output_path),
        ephemeral=True,
    )
    try:
        observation = assemble_layout(
            tuple(
                PlatformLayout(
                    item.platform,
                    item.transport.layout_path,
                    item.transport.layout_reference,
                )
                for item in qualifications
            ),
            output_path=output_path,
            output_reference=tag,
        )
    except BaseException:
        workspace.journal.update(layout_id, ResourceStatus.FAILED)
        raise
    workspace.journal.update(layout_id, ResourceStatus.CREATED)
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
            _qualification_entry(item)
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
        tuple(
            (item.platform, item.run_id)
            for item in sorted(qualifications, key=lambda value: value.platform)
        ),
    )


def _qualification_entry(item: _Qualification) -> dict[str, object]:
    entry: dict[str, object] = {
        "platform": str(item.platform),
        "runId": item.run_id,
        "recordDigest": item.record_digest,
        "payloadDigests": list(item.payload_digests),
    }
    if item.transport.transport_digest is not None:
        entry["transportDigest"] = item.transport.transport_digest
    return entry


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
    actual_payloads = {_hash_transport_path(path) for path in transport.payload_paths}
    if actual_payloads != set(payload_digests):
        raise InvalidInvocationError(
            f"Transported payload digests do not match qualification for {platform}"
        )
    graph = validate_layout(transport.layout_path, reference=transport.layout_reference)
    if len(graph.manifests) != 1 or not graph.manifests[
        0
    ].platform.semantically_matches(platform):
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
    for name in ("buildExecution", "testExecution"):
        validate_execution_observation(payload.get(name), platform=platform)
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
    record_created_at = _timestamp(record.get("createdAt"), "record creation time")
    pin_references = tuple(
        sorted(_strings(payload.get("externalImages"), "external images"))
    )
    if len(pin_references) != len(set(pin_references)):
        raise InvalidInvocationError("Qualification repeats an external image")
    parsed_references = {
        OCIReference.parse(
            reference,
            require_tag=True,
            require_digest=True,
            allow_localhost=False,
        ): reference
        for reference in pin_references
    }
    limits_value = _object(payload.get("effectiveLimits"), "effective limits")
    effective_limits: list[tuple[str, int]] = []
    for name in ("pinFreshnessSeconds", "pinDivergenceSeconds"):
        item = limits_value.get(name)
        if not isinstance(item, int) or isinstance(item, bool):
            raise InvalidInvocationError("Qualification effective limits are malformed")
        effective_limits.append((name, item))
    limit_map = dict(effective_limits)
    raw_observations = payload.get("pinObservations")
    if not isinstance(raw_observations, list):
        raise InvalidInvocationError("Qualification pin observations are malformed")
    observation_references: set[str] = set()
    pin_resolutions: list[tuple[str, str]] = []
    for raw_observation in raw_observations:
        observation = _object(raw_observation, "pin observation")
        reference_text = _string(
            observation.get("reference"), "pin observation reference"
        )
        reference = OCIReference.parse(
            reference_text,
            require_tag=True,
            require_digest=True,
            allow_localhost=False,
        )
        if reference not in parsed_references:
            raise InvalidInvocationError(
                "Qualification observes an undeclared external image"
            )
        if observation.get("pinnedDigest") != str(reference.digest):
            raise InvalidInvocationError(
                "Qualification pin observation has another pinned digest"
            )
        pinned_digest = reference.digest
        if pinned_digest is None:  # parser invariant
            raise OperationalError("Required pin digest is absent after validation")
        observed_digest = Digest(
            _string(observation.get("observedDigest"), "observed pin digest")
        )
        pin_resolutions.append((reference_text, str(observed_digest)))
        checked_at = _timestamp(observation.get("checkedAt"), "pin observation time")
        age = record_created_at - checked_at
        if age < timedelta(0) or age > timedelta(
            seconds=limit_map["pinFreshnessSeconds"]
        ):
            raise InvalidInvocationError(
                "Qualification pin observation exceeds its freshness limit"
            )
        divergence_value = observation.get("divergenceSince")
        if observed_digest == pinned_digest:
            if divergence_value is not None:
                raise InvalidInvocationError(
                    "Matching pin observation has a divergence timestamp"
                )
        else:
            divergence_since = _timestamp(divergence_value, "pin divergence time")
            divergence_age = checked_at - divergence_since
            if divergence_age < timedelta(0) or divergence_age >= timedelta(
                seconds=limit_map["pinDivergenceSeconds"]
            ):
                raise InvalidInvocationError(
                    "Qualification pin divergence exceeds its effective limit"
                )
        observation_findings = observation.get("findings")
        if not isinstance(observation_findings, list) or any(
            not isinstance(item, dict) for item in observation_findings
        ):
            raise InvalidInvocationError("Qualification pin findings are malformed")
        if any(item.get("severity") == "error" for item in observation_findings):
            raise InvalidInvocationError(
                "Accepted qualification contains a rejecting pin finding"
            )
        observation_references.add(reference_text)
    if observation_references != set(pin_references) or len(raw_observations) != len(
        observation_references
    ):
        raise InvalidInvocationError(
            "Qualification pin observations do not exactly cover external images"
        )
    findings = payload.get("findings")
    if not isinstance(findings, list) or any(
        not isinstance(item, dict) for item in findings
    ):
        raise InvalidInvocationError("Qualification findings are malformed")
    if any(item.get("severity") == "error" for item in findings):
        raise InvalidInvocationError(
            "Accepted qualification contains a rejecting finding"
        )
    configuration_digest = _string(configuration.get("sha256"), "configuration digest")
    Digest(configuration_digest)
    build_arguments = _object(payload.get("buildArguments"), "build arguments")
    image_version = build_arguments.get("IMAGE_VERSION")
    if image_version is not None and not isinstance(image_version, str):
        raise InvalidInvocationError("Qualification image version is malformed")
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
        pin_references=pin_references,
        pin_resolutions=tuple(sorted(pin_resolutions)),
        effective_limits=tuple(sorted(effective_limits)),
        image_version=image_version,
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


def _timestamp(value: object, label: str) -> datetime:
    text = _string(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidInvocationError(f"{label} is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InvalidInvocationError(f"{label} lacks a timezone")
    return parsed.astimezone(UTC)
