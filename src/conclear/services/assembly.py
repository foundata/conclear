"""Qualification transport validation and release-candidate assembly."""

import stat
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from conclear.config import ImageConfig, ReleaseImageConfig, RepositoryConfig
from conclear.emulation import validate_execution_observation
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.identity import IDENTITY
from conclear.jsonutil import load_json, sha256_bytes, sha256_file
from conclear.layout_assembly import (
    AssemblyObservation,
    PlatformLayout,
    assemble_layout,
)
from conclear.oci import validate_layout
from conclear.parsing import Narrower
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
    parse_timestamp,
    validate_record,
)
from conclear.services.qualification_inputs import canonical_build_arguments
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

_narrow = Narrower(InvalidInvocationError)


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
class DependencyEvidence:
    """Platform-independent inputs one qualification recorded for a dependency."""

    image_id: str
    containerfile_digest: str
    context_digest: str
    build_arguments: tuple[tuple[str, str], ...]
    pin_references: tuple[str, ...]
    pin_resolutions: tuple[tuple[str, str], ...]
    effective_limits: tuple[tuple[str, int], ...]


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
    dependencies: tuple[DependencyEvidence, ...]
    build_arguments: tuple[tuple[str, str], ...]
    manifest_digest: Digest
    transport: QualificationTransport


def assemble_candidate(
    transports: tuple[QualificationTransport, ...],
    *,
    repository: RepositoryConfig,
    image: ReleaseImageConfig,
    workspace: RunWorkspace,
    version: str | None,
    source_time: datetime,
    tools: tuple[ToolIdentity, ...],
    now: datetime,
) -> CandidateResult:
    """Verify every transported byte and assemble exact required platform coverage."""
    snapshot = workspace.load()
    recorded_version = snapshot.immutable_inputs.get("version") or None
    if version != recorded_version:
        raise InvalidInvocationError("Assembly version differs from the release run")
    expected_arguments = expected_build_arguments(workspace, source_time=source_time)
    qualifications = tuple(
        _read_qualification(item, expected_arguments=expected_arguments)
        for item in transports
    )
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
    expected_pins = tuple(sorted(str(item.reference) for item in image.pins))
    if any(item.pin_references != expected_pins for item in qualifications):
        raise InvalidInvocationError(
            "Qualifications do not match configured external image pins"
        )
    expected_limits = _expected_limits(image)
    if any(item.effective_limits != expected_limits for item in qualifications):
        raise InvalidInvocationError("Qualifications do not match effective pin limits")
    expected_dependencies = repository.test_dependencies(image.image_id)
    for item in qualifications:
        _require_dependency_evidence(item.dependencies, expected_dependencies)
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
        if item.build_arguments != first.build_arguments:
            raise InvalidInvocationError(
                "Qualifications were built with different build arguments"
            )
        if item.dependencies != first.dependencies:
            raise InvalidInvocationError(
                "Qualifications identify different test dependency inputs"
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


def expected_build_arguments(
    workspace: RunWorkspace, *, source_time: datetime
) -> tuple[tuple[str, str], ...]:
    """Derive the build arguments every record of this run must carry exactly.

    The selected revision and release version come from the run's immutable
    inputs and the commit time from the caller's Git observation of that
    revision; nothing in a record establishes its own build arguments.
    """
    inputs = workspace.load().immutable_inputs
    revision = _narrow.string_value(inputs.get("sourceRevision"), "run source revision")
    version = inputs.get("version") or None
    if version is not None and not isinstance(version, str):
        raise InvalidInvocationError("Run version is malformed")
    return tuple(
        sorted(
            canonical_build_arguments(
                source_revision=revision, source_time=source_time, version=version
            ).items()
        )
    )


def _read_qualification(
    transport: QualificationTransport,
    *,
    expected_arguments: tuple[tuple[str, str], ...],
) -> _Qualification:
    value = load_json(transport.record_path)
    validate_record(value)
    record = _narrow.object_value(value, "qualification")
    if record.get("recordType") != "platformQualification":
        raise InvalidInvocationError("Assembly input is not a platform qualification")
    if record.get("verdict") != "accepted":
        raise InvalidInvocationError("Assembly input qualification is not accepted")
    payload = _narrow.object_value(record.get("payload"), "qualification payload")
    platform = Platform.parse(
        _narrow.string_value(payload.get("platform"), "qualification platform")
    )
    payload_values = _narrow.string_array_value(
        payload.get("payloadDigests"), "payload digests"
    )
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
    manifest_digest = Digest(
        _narrow.string_value(payload.get("manifestDigest"), "manifest digest")
    )
    if graph.manifests[0].descriptor.digest != manifest_digest:
        raise InvalidInvocationError(
            f"Transported layout manifest differs for {platform}"
        )
    descriptor = _narrow.object_value(
        payload.get("layoutDescriptor"), "layout descriptor"
    )
    if descriptor.get("digest") != str(graph.root.digest):
        raise InvalidInvocationError(f"Transported layout root differs for {platform}")
    for name in ("buildExecution", "testExecution"):
        validate_execution_observation(payload.get(name), platform=platform)
    source_value = _narrow.object_value(record.get("source"), "qualification source")
    configuration = _narrow.object_value(
        record.get("repositoryConfiguration"), "qualification configuration"
    )
    ruleset = _narrow.object_value(record.get("ruleset"), "qualification ruleset")
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
        tool = _narrow.object_value(raw_tool, "qualification tool")
        normalized_tools.append(
            (
                _narrow.string_value(tool.get("name"), "tool name"),
                _narrow.string_value(tool.get("version"), "tool version"),
            )
        )
    if len(normalized_tools) != len({name for name, _version in normalized_tools}):
        raise InvalidInvocationError("Qualification contains duplicate tool identities")
    database_digest = _narrow.string_value(
        payload.get("databaseDigest"), "database digest"
    )
    Digest(database_digest)
    record_created_at = parse_timestamp(
        record.get("createdAt"), "record creation time", error=InvalidInvocationError
    )
    pin_references, pin_resolutions, effective_limits = _read_pin_evidence(
        payload, record_created_at=record_created_at, subject="Qualification"
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
    configuration_digest = _narrow.string_value(
        configuration.get("sha256"), "configuration digest"
    )
    Digest(configuration_digest)
    source_revision = validate_source_revision(
        _narrow.string_value(source_value.get("revision"), "source revision")
    )
    build_arguments = _read_build_arguments(
        payload, subject="Qualification", expected=expected_arguments
    )
    dependencies = _read_dependencies(
        payload,
        platform=platform,
        source_revision=source_revision,
        record_created_at=record_created_at,
        payload_digests=payload_digests,
        expected_arguments=expected_arguments,
    )
    return _Qualification(
        run_id=_narrow.string_value(record.get("runId"), "qualification run id"),
        image_id=_narrow.string_value(payload.get("imageId"), "image id"),
        platform=platform,
        record_digest=sha256_file(transport.record_path),
        payload_digests=payload_digests,
        source=SourceIdentity(
            repository=_narrow.string_value(
                source_value.get("repository"), "source repository"
            ),
            revision=source_revision,
        ),
        configuration_digest=configuration_digest,
        ruleset=ruleset,
        tools=tuple(sorted(normalized_tools)),
        database_digest=database_digest,
        pin_references=pin_references,
        pin_resolutions=tuple(sorted(pin_resolutions)),
        effective_limits=tuple(sorted(effective_limits)),
        dependencies=dependencies,
        build_arguments=build_arguments,
        manifest_digest=manifest_digest,
        transport=transport,
    )


def _expected_limits(image: ImageConfig) -> tuple[tuple[str, int], ...]:
    return tuple(
        sorted(
            {
                "pinFreshnessSeconds": int(
                    image.pin_limits.pin_freshness.total_seconds()
                ),
                "pinDivergenceSeconds": int(
                    image.pin_limits.pin_divergence.total_seconds()
                ),
            }.items()
        )
    )


def verify_dependency_evidence(
    payload: dict[str, object],
    *,
    repository: RepositoryConfig,
    image: ReleaseImageConfig,
    platform: Platform,
    source_revision: str,
    record_created_at: datetime,
    payload_digests: tuple[str, ...],
    expected_arguments: tuple[tuple[str, str], ...],
) -> tuple[DependencyEvidence, ...]:
    """Read one qualification's dependency evidence and check it against configuration.

    Transport import and assembly share this check: the recorded dependencies
    must be exactly the configured closure of the qualified image in
    dependency-first order, and each entry must carry that dependency's
    configured pins, its effective pin limits, accepted observations and the
    exact build arguments derived for the run.
    """
    _read_build_arguments(payload, subject="Qualification", expected=expected_arguments)
    evidence = _read_dependencies(
        payload,
        platform=platform,
        source_revision=source_revision,
        record_created_at=record_created_at,
        payload_digests=payload_digests,
        expected_arguments=expected_arguments,
    )
    _require_dependency_evidence(evidence, repository.test_dependencies(image.image_id))
    return evidence


def _require_dependency_evidence(
    dependencies: tuple[DependencyEvidence, ...], expected: tuple[ImageConfig, ...]
) -> None:
    if tuple(value.image_id for value in dependencies) != tuple(
        image.image_id for image in expected
    ):
        raise InvalidInvocationError(
            "Qualifications do not match the configured test dependencies"
        )
    for evidence, configured in zip(dependencies, expected, strict=True):
        if evidence.pin_references != tuple(
            sorted(str(pin.reference) for pin in configured.pins)
        ):
            raise InvalidInvocationError(
                "Qualifications do not match configured external image pins of "
                f"{configured.image_id}"
            )
        if evidence.effective_limits != _expected_limits(configured):
            raise InvalidInvocationError(
                f"Qualifications do not match effective pin limits of {configured.image_id}"
            )


def _read_dependencies(
    payload: dict[str, object],
    *,
    platform: Platform,
    source_revision: str,
    record_created_at: datetime,
    payload_digests: tuple[str, ...],
    expected_arguments: tuple[tuple[str, str], ...],
) -> tuple[DependencyEvidence, ...]:
    raw_entries = payload.get("testImageDependencies")
    if not isinstance(raw_entries, list):
        raise InvalidInvocationError("Qualification test dependencies are malformed")
    values: list[DependencyEvidence] = []
    for raw_entry in raw_entries:
        entry = _narrow.object_value(raw_entry, "test dependency")
        image_id = _narrow.string_value(entry.get("imageId"), "test dependency image")
        subject = f"Test dependency {image_id}"
        if entry.get("platform") != str(platform):
            raise InvalidInvocationError(f"{subject} was built for another platform")
        if entry.get("sourceRevision") != source_revision:
            raise InvalidInvocationError(
                f"{subject} was built from another source revision"
            )
        if entry.get("testResultDigest") not in payload_digests:
            raise InvalidInvocationError(
                f"{subject} test result is not a bound payload"
            )
        containerfile_digest = _narrow.string_value(
            entry.get("containerfileDigest"), "test dependency Containerfile digest"
        )
        context_digest = _narrow.string_value(
            entry.get("contextDigest"), "test dependency context digest"
        )
        Digest(containerfile_digest)
        Digest(context_digest)
        entry_arguments = _read_build_arguments(
            entry, subject=subject, expected=expected_arguments
        )
        references, resolutions, limits = _read_pin_evidence(
            entry, record_created_at=record_created_at, subject=subject
        )
        values.append(
            DependencyEvidence(
                image_id=image_id,
                containerfile_digest=containerfile_digest,
                context_digest=context_digest,
                build_arguments=entry_arguments,
                pin_references=references,
                pin_resolutions=resolutions,
                effective_limits=limits,
            )
        )
    if len({item.image_id for item in values}) != len(values):
        raise InvalidInvocationError("Qualification repeats a test dependency")
    return tuple(values)


def _read_build_arguments(
    value: dict[str, object],
    *,
    subject: str,
    expected: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    """Require the recorded build arguments to equal the run's derived map exactly.

    Any missing, additional or differing key rejects the record: the map is
    derived from the coordinator's selected revision, observed commit time and
    release version, never from what a record claims about itself.
    """
    raw = _narrow.object_value(
        value.get("buildArguments"), f"{subject} build arguments"
    )
    arguments = {
        key: _narrow.string_value(item, f"{subject} build argument {key}")
        for key, item in raw.items()
    }
    expected_map = dict(expected)
    if arguments != expected_map:
        differing = sorted(
            key
            for key in {*arguments, *expected_map}
            if arguments.get(key) != expected_map.get(key)
        )
        raise InvalidInvocationError(
            f"{subject} build arguments differ from the selected commit: "
            + ", ".join(differing)
        )
    return tuple(sorted(arguments.items()))


def _read_pin_evidence(
    value: dict[str, object], *, record_created_at: datetime, subject: str
) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...], tuple[tuple[str, int], ...]]:
    """Validate the external images, limits and observations of one payload."""
    pin_references = tuple(
        sorted(
            _narrow.string_array_value(value.get("externalImages"), "external images")
        )
    )
    if len(pin_references) != len(set(pin_references)):
        raise InvalidInvocationError(f"{subject} repeats an external image")
    parsed_references = {
        OCIReference.parse(
            reference,
            require_tag=True,
            require_digest=True,
            allow_localhost=False,
        ): reference
        for reference in pin_references
    }
    limits_value = _narrow.object_value(
        value.get("effectiveLimits"), "effective limits"
    )
    effective_limits: list[tuple[str, int]] = []
    for name in ("pinFreshnessSeconds", "pinDivergenceSeconds"):
        item = limits_value.get(name)
        if not isinstance(item, int) or isinstance(item, bool):
            raise InvalidInvocationError(f"{subject} effective limits are malformed")
        effective_limits.append((name, item))
    limit_map = dict(effective_limits)
    raw_observations = value.get("pinObservations")
    if not isinstance(raw_observations, list):
        raise InvalidInvocationError(f"{subject} pin observations are malformed")
    observation_references: set[str] = set()
    pin_resolutions: list[tuple[str, str]] = []
    for raw_observation in raw_observations:
        observation = _narrow.object_value(raw_observation, "pin observation")
        reference_text = _narrow.string_value(
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
                f"{subject} observes an undeclared external image"
            )
        if observation.get("pinnedDigest") != str(reference.digest):
            raise InvalidInvocationError(
                f"{subject} pin observation has another pinned digest"
            )
        pinned_digest = reference.digest
        if pinned_digest is None:  # parser invariant
            raise OperationalError("Required pin digest is absent after validation")
        observed_digest = Digest(
            _narrow.string_value(
                observation.get("observedDigest"), "observed pin digest"
            )
        )
        pin_resolutions.append((reference_text, str(observed_digest)))
        checked_at = parse_timestamp(
            observation.get("checkedAt"),
            "pin observation time",
            error=InvalidInvocationError,
        )
        age = record_created_at - checked_at
        if age < timedelta(0) or age > timedelta(
            seconds=limit_map["pinFreshnessSeconds"]
        ):
            raise InvalidInvocationError(
                f"{subject} pin observation exceeds its freshness limit"
            )
        divergence_value = observation.get("divergenceSince")
        if observed_digest == pinned_digest:
            if divergence_value is not None:
                raise InvalidInvocationError(
                    "Matching pin observation has a divergence timestamp"
                )
        else:
            divergence_since = parse_timestamp(
                divergence_value, "pin divergence time", error=InvalidInvocationError
            )
            divergence_age = checked_at - divergence_since
            if divergence_age < timedelta(0) or divergence_age >= timedelta(
                seconds=limit_map["pinDivergenceSeconds"]
            ):
                raise InvalidInvocationError(
                    f"{subject} pin divergence exceeds its effective limit"
                )
        observation_findings = observation.get("findings")
        if not isinstance(observation_findings, list) or any(
            not isinstance(item, dict) for item in observation_findings
        ):
            raise InvalidInvocationError(f"{subject} pin findings are malformed")
        if any(item.get("severity") == "error" for item in observation_findings):
            raise InvalidInvocationError(
                "Accepted qualification contains a rejecting pin finding"
            )
        observation_references.add(reference_text)
    if observation_references != set(pin_references) or len(raw_observations) != len(
        observation_references
    ):
        raise InvalidInvocationError(
            f"{subject} pin observations do not exactly cover external images"
        )
    return (
        pin_references,
        tuple(sorted(pin_resolutions)),
        tuple(sorted(effective_limits)),
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
