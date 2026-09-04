"""Validated rehydration of release workflow artifacts from one workspace."""

from datetime import datetime
from pathlib import Path

from conclear.assembly import AssemblyObservation
from conclear.attestations import RELEASE_VERIFICATION_TYPE
from conclear.config import ImageConfig
from conclear.errors import InvalidInvocationError, RuleRejectionError
from conclear.jsonutil import load_json, sha256_file
from conclear.oci import validate_layout
from conclear.provenance import ProvenanceMaterial
from conclear.records import SourceIdentity, ToolIdentity, validate_record
from conclear.services.assembly import CandidateResult, QualificationTransport
from conclear.services.publication import (
    PublishedCandidate,
    ReleaseEvidence,
    VerificationResult,
    validate_release_provenance,
)
from conclear.values import Digest, OCIReference, Platform, candidate_tag
from conclear.workspace import ResourceKind, ResourceStatus, RunWorkspace


def load_candidate(workspace: RunWorkspace, image: ImageConfig) -> CandidateResult:
    """Load and cross-check one assembled candidate and its public record."""
    record_path = workspace.root / "records" / "release-candidate.json"
    value = load_json(record_path)
    validate_record(value)
    record = _object(value, "candidate record")
    _validate_workspace_record(record, workspace)
    if record.get("recordType") != "releaseCandidate":
        raise InvalidInvocationError("Workspace candidate record has the wrong type")
    if record.get("verdict") != "accepted":
        raise InvalidInvocationError("Workspace candidate was not accepted")
    if record.get("runId") != workspace.run_id:
        raise InvalidInvocationError("Workspace candidate belongs to another run")
    payload = _object(record.get("payload"), "candidate payload")
    if payload.get("imageId") != image.image_id:
        raise InvalidInvocationError("Workspace candidate belongs to another image")
    if payload.get("repository") != image.repository.repository_name:
        raise InvalidInvocationError(
            "Workspace candidate belongs to another repository"
        )
    expected_platforms = tuple(sorted(image.platforms))
    if _platforms(payload.get("requiredPlatforms"), "required platforms") != (
        expected_platforms
    ):
        raise RuleRejectionError(
            "Candidate required platform set changed", code="CC0304"
        )
    if _platforms(payload.get("acceptedPlatforms"), "accepted platforms") != (
        expected_platforms
    ):
        raise RuleRejectionError(
            "Candidate accepted platform set changed", code="CC0304"
        )
    candidate_tag_value = _string(payload.get("candidateTag"), "candidate tag")
    source_value = _object(record.get("source"), "candidate source")
    source_revision = _string(source_value.get("revision"), "source revision")
    naming = _object(payload.get("candidateNaming"), "candidate naming")
    version_value = naming.get("version")
    if version_value is not None and not isinstance(version_value, str):
        raise InvalidInvocationError("Candidate version is malformed")
    recorded_version = workspace.load().immutable_inputs.get("version") or None
    expected_tag = candidate_tag(
        version=recorded_version,
        run_id=workspace.run_id,
        source_revision=source_revision,
    )
    if (
        naming
        != {
            "version": recorded_version,
            "runId": workspace.run_id,
            "sourceRevision": source_revision,
            "tag": expected_tag,
        }
        or candidate_tag_value != expected_tag
    ):
        raise RuleRejectionError("Candidate naming inputs changed", code="CC0601")
    layout_path = workspace.root / "layouts" / image.image_id / "candidate"
    graph = validate_layout(layout_path, reference=candidate_tag_value)
    descriptor = _object(payload.get("subjectDescriptor"), "subject descriptor")
    if descriptor != graph.root.to_dict():
        raise RuleRejectionError(
            "Candidate record descriptor differs from layout", code="CC0602"
        )
    platform_manifests = _object(
        payload.get("platformManifests"), "platform manifest map"
    )
    observed = {
        str(item.platform): str(item.descriptor.digest) for item in graph.manifests
    }
    if platform_manifests != observed:
        raise RuleRejectionError(
            "Candidate record platform graph differs from layout", code="CC0602"
        )
    qualifications = payload.get("qualifications")
    if not isinstance(qualifications, list):
        raise InvalidInvocationError("Candidate qualifications are malformed")
    qualification_digests: list[str] = []
    payload_digests: set[str] = set()
    qualification_platforms: set[Platform] = set()
    for item in qualifications:
        qualification = _object(item, "candidate qualification")
        qualification_platform = Platform.parse(
            _string(qualification.get("platform"), "qualification platform")
        )
        if qualification_platform in qualification_platforms:
            raise InvalidInvocationError("Candidate repeats a qualification platform")
        qualification_platforms.add(qualification_platform)
        record_digest = _string(
            qualification.get("recordDigest"), "qualification record digest"
        )
        Digest(record_digest)
        qualification_digests.append(record_digest)
        values = qualification.get("payloadDigests")
        if not isinstance(values, list) or any(
            not isinstance(value, str) for value in values
        ):
            raise InvalidInvocationError("Candidate payload digests are malformed")
        if len(values) != len(set(values)):
            raise InvalidInvocationError("Candidate repeats a payload digest")
        for digest in values:
            Digest(digest)
            payload_digests.add(digest)
    if qualification_platforms != set(expected_platforms):
        raise RuleRejectionError(
            "Candidate qualification platform set changed", code="CC0304"
        )
    if len(qualification_digests) != len(set(qualification_digests)):
        raise InvalidInvocationError("Candidate repeats a qualification digest")
    return CandidateResult(
        record_path=record_path,
        record_digest=sha256_file(record_path),
        observation=AssemblyObservation(
            layout_path,
            candidate_tag_value,
            graph,
            tuple(
                sorted(
                    (item.platform, item.descriptor.digest) for item in graph.manifests
                )
            ),
        ),
        candidate_tag=candidate_tag_value,
        qualification_digests=tuple(qualification_digests),
        payload_digests=tuple(sorted(payload_digests)),
    )


def qualification_transports(
    workspace: RunWorkspace, image: ImageConfig
) -> tuple[QualificationTransport, ...]:
    """Load standard platform qualification transports from a workspace."""
    return tuple(
        qualification_transport(workspace, image, platform)
        for platform in image.platforms
    )


def qualification_transport(
    workspace: RunWorkspace, image: ImageConfig, platform: Platform
) -> QualificationTransport:
    """Load and validate one completed platform qualification transport."""
    record_path = (
        workspace.root / "records" / f"platform-qualification-{platform.key}.json"
    )
    record = _object(load_json(record_path), "qualification record")
    validate_record(record)
    _validate_workspace_record(record, workspace)
    if record.get("recordType") != "platformQualification":
        raise InvalidInvocationError(
            "Workspace qualification record has the wrong type"
        )
    if record.get("verdict") != "accepted":
        raise InvalidInvocationError("Workspace qualification was not accepted")
    payload = _object(record.get("payload"), "qualification payload")
    if payload.get("imageId") != image.image_id:
        raise InvalidInvocationError("Workspace qualification belongs to another image")
    recorded_platform = Platform.parse(
        _string(payload.get("platform"), "qualification platform")
    )
    if recorded_platform != platform:
        raise InvalidInvocationError("Workspace qualification has another platform")
    values = payload.get("payloadDigests")
    if not isinstance(values, list) or any(
        not isinstance(item, str) for item in values
    ):
        raise InvalidInvocationError("Qualification payload digests are malformed")
    for value in values:
        Digest(value)
    if len(values) != len(set(values)):
        raise InvalidInvocationError("Qualification repeats a payload digest")
    candidate_paths = _qualification_payload_paths(workspace, image, platform, payload)
    if {sha256_file(path) for path in candidate_paths} != set(values):
        raise RuleRejectionError(
            f"Qualification payload files are incomplete for {platform}",
            code="CC0703",
        )
    layout_path = workspace.root / "layouts" / image.image_id / platform.key
    graph = validate_layout(layout_path, reference="qualified")
    if len(graph.manifests) != 1 or not graph.manifests[
        0
    ].platform.semantically_matches(platform):
        raise RuleRejectionError(
            f"Qualification layout platform differs from {platform}", code="CC0303"
        )
    if payload.get("layoutDescriptor") != graph.root.to_dict():
        raise RuleRejectionError(
            f"Qualification layout descriptor changed for {platform}", code="CC0302"
        )
    if payload.get("manifestDigest") != str(graph.manifests[0].descriptor.digest):
        raise RuleRejectionError(
            f"Qualification manifest digest changed for {platform}", code="CC0302"
        )
    return QualificationTransport(
        record_path=record_path,
        layout_path=layout_path,
        layout_reference="qualified",
        payload_paths=candidate_paths,
    )


def load_release_evidence(
    workspace: RunWorkspace, image: ImageConfig
) -> ReleaseEvidence:
    """Load exact SBOM, scan, provenance and qualification evidence."""
    candidate = load_candidate(workspace, image)
    candidate_record = _object(load_json(candidate.record_path), "candidate record")
    source_value = _object(candidate_record.get("source"), "candidate source")
    configuration = _object(
        candidate_record.get("repositoryConfiguration"), "candidate configuration"
    )
    tools_value = candidate_record.get("tools")
    if not isinstance(tools_value, list):
        raise InvalidInvocationError("Candidate tool identities are malformed")
    tools = tuple(_tool_identity(item) for item in tools_value)
    sboms: list[tuple[Platform, Path, str]] = []
    scan_digests: list[str] = []
    for platform in image.platforms:
        record_path = (
            workspace.root / "records" / f"platform-qualification-{platform.key}.json"
        )
        record = _object(load_json(record_path), "qualification record")
        validate_record(record)
        _validate_workspace_record(record, workspace)
        if sha256_file(record_path) not in candidate.qualification_digests:
            raise RuleRejectionError(
                "Candidate does not bind a qualification record", code="CC0304"
            )
        payload = _object(record.get("payload"), "qualification payload")
        sbom_value = _object(payload.get("sbom"), "qualification SBOM")
        sbom_digest = _string(sbom_value.get("digest"), "SBOM digest")
        sbom_path = workspace.root / "exports" / "sbom" / f"{platform.key}.spdx.json"
        if sha256_file(sbom_path) != sbom_digest:
            raise RuleRejectionError(f"SBOM changed for {platform}", code="CC0504")
        sboms.append((platform, sbom_path, sbom_digest))
        scans = payload.get("scans")
        if not isinstance(scans, list):
            raise InvalidInvocationError("Qualification scans are malformed")
        for scan in scans:
            scan_value = _object(scan, "scan")
            scan_digest = _string(scan_value.get("digest"), "scan digest")
            Digest(scan_digest)
            scan_name = _string(scan_value.get("path"), "scan path")
            if Path(scan_name).name != scan_name:
                raise InvalidInvocationError("Qualification scan path is unsafe")
            scan_path = (
                workspace.root / "reports" / image.image_id / platform.key / scan_name
            )
            if sha256_file(scan_path) != scan_digest:
                raise RuleRejectionError(
                    f"Scan report changed for {platform}", code="CC0501"
                )
            scan_digests.append(scan_digest)
    provenance_path = workspace.root / "records" / "provenance.json"
    evidence = ReleaseEvidence(
        source=SourceIdentity(
            _string(source_value.get("repository"), "source repository"),
            _string(source_value.get("revision"), "source revision"),
        ),
        configuration_digest=_string(
            configuration.get("sha256"), "configuration digest"
        ),
        tools=tools,
        sboms=tuple(sboms),
        scan_digests=tuple(sorted(scan_digests)),
        provenance_path=provenance_path,
        provenance_digest=sha256_file(provenance_path),
        provenance_materials=load_provenance_materials(workspace, image),
        candidate_record_digest=candidate.record_digest,
        qualification_digests=candidate.qualification_digests,
    )
    provenance = _object(load_json(provenance_path), "provenance")
    validate_release_provenance(
        provenance,
        candidate.observation.graph,
        evidence=evidence,
        workspace=workspace,
        image=image,
    )
    return evidence


def load_provenance_materials(
    workspace: RunWorkspace, image: ImageConfig
) -> tuple[ProvenanceMaterial, ...]:
    """Load semantically named, digest-bound provenance dependencies."""
    candidate = load_candidate(workspace, image)
    materials: dict[str, Digest] = {}

    def add(uri: str, digest_value: object) -> None:
        digest = Digest(_string(digest_value, f"digest for {uri}"))
        previous = materials.get(uri)
        if previous is not None and previous != digest:
            raise RuleRejectionError(
                f"Provenance material changed: {uri}", code="CC0703"
            )
        materials[uri] = digest

    observed_payloads: set[str] = set()
    for platform in image.platforms:
        record_path = (
            workspace.root / "records" / f"platform-qualification-{platform.key}.json"
        )
        record_digest = sha256_file(record_path)
        if record_digest not in candidate.qualification_digests:
            raise RuleRejectionError(
                f"Candidate does not bind qualification for {platform}", code="CC0304"
            )
        record = _object(load_json(record_path), "qualification record")
        validate_record(record)
        payload = _object(record.get("payload"), "qualification payload")
        add(f"conclear:qualification/{platform}", record_digest)
        add(
            f"conclear:containerfile/{image.image_id}/{platform}",
            payload.get("containerfileDigest"),
        )
        add(
            f"conclear:context/{image.image_id}/{platform}",
            payload.get("contextDigest"),
        )
        add("conclear:trivy-database", payload.get("databaseDigest"))
        external_images = payload.get("externalImages")
        if not isinstance(external_images, list) or any(
            not isinstance(item, str) for item in external_images
        ):
            raise InvalidInvocationError("Qualification external images are malformed")
        for external_image in external_images:
            reference = OCIReference.parse(external_image, require_digest=True)
            if reference.digest is None:
                raise InvalidInvocationError("External image is not immutable")
            add(f"docker://{external_image}", str(reference.digest))
        for path in _qualification_payload_paths(workspace, image, platform, payload):
            digest = sha256_file(path)
            observed_payloads.add(digest)
            relative = path.relative_to(workspace.root).as_posix()
            add(f"conclear:workspace/{relative}", digest)
    if observed_payloads != set(candidate.payload_digests):
        raise RuleRejectionError(
            "Candidate provenance payload set changed", code="CC0703"
        )
    return tuple(
        ProvenanceMaterial(uri, digest) for uri, digest in sorted(materials.items())
    )


def load_published(
    workspace: RunWorkspace, candidate: CandidateResult, image: ImageConfig
) -> PublishedCandidate:
    """Load a conclusively published candidate from its ownership journal."""
    entries = [
        item
        for item in workspace.journal.entries()
        if item.kind is ResourceKind.CANDIDATE_REFERENCE
        and item.status is ResourceStatus.CREATED
    ]
    if len(entries) != 1:
        raise InvalidInvocationError("Workspace has no conclusive published candidate")
    entry = entries[0]
    reference = OCIReference.parse(entry.identifier, require_tag=True)
    if (
        reference.repository_name != image.repository.repository_name
        or reference.tag != candidate.candidate_tag
    ):
        raise RuleRejectionError(
            "Published candidate reference differs from the accepted candidate",
            code="CC0602",
        )
    digest = Digest(_string(entry.metadata.get("digest"), "published digest"))
    if digest != candidate.observation.graph.digest:
        raise RuleRejectionError(
            "Published digest differs from candidate", code="CC0602"
        )
    expiration = _datetime(entry.metadata.get("expiration"), "candidate expiration")
    immutable = entry.metadata.get("immutabilityEnabled")
    if not isinstance(immutable, bool):
        raise InvalidInvocationError("Candidate immutability observation is malformed")
    return PublishedCandidate(
        reference,
        image.repository.with_digest(digest),
        candidate.observation.graph,
        expiration,
        immutable,
    )


def load_verification(
    workspace: RunWorkspace, image: ImageConfig, subject: OCIReference
) -> VerificationResult:
    """Load a release-verification record and its exact in-toto statement."""
    if subject.digest is None:
        raise InvalidInvocationError("Release verification subject is not immutable")
    record_path = workspace.root / "records" / "release-verification.json"
    statement_path = workspace.root / "records" / "release-verification-statement.json"
    record = _object(load_json(record_path), "release verification record")
    validate_record(record)
    _validate_workspace_record(record, workspace)
    if record.get("recordType") != "releaseVerification":
        raise InvalidInvocationError("Release verification record has the wrong type")
    if record.get("verdict") != "accepted":
        raise InvalidInvocationError("Release verification record was not accepted")
    payload = _object(record.get("payload"), "release verification payload")
    if payload.get("subject") != {
        "repository": image.repository.repository_name,
        "digest": str(subject.digest),
    }:
        raise RuleRejectionError(
            "Release verification record subject differs", code="CC0703"
        )
    statement = _object(load_json(statement_path), "release verification statement")
    if statement.get("predicateType") != RELEASE_VERIFICATION_TYPE:
        raise InvalidInvocationError("Release verification predicate type is incorrect")
    if statement.get("predicate") != record:
        raise RuleRejectionError(
            "Release verification statement changed", code="CC0703"
        )
    statement_subjects = statement.get("subject")
    expected_subject = [
        {
            "name": image.repository.repository_name,
            "digest": {"sha256": subject.digest.encoded},
        }
    ]
    if statement_subjects != expected_subject:
        raise RuleRejectionError("Release verification subject differs", code="CC0703")
    record_digest = sha256_file(record_path)
    entries = [
        entry
        for entry in workspace.journal.entries()
        if entry.resource_id == "release-verification"
        and entry.kind is ResourceKind.ATTESTATION
        and entry.status is ResourceStatus.CREATED
        and entry.identifier == str(subject)
        and entry.metadata
        == {
            "predicateType": RELEASE_VERIFICATION_TYPE,
            "payloadDigest": record_digest,
        }
    ]
    if len(entries) != 1:
        raise InvalidInvocationError(
            "Release verification remote ownership is not established"
        )
    return VerificationResult(
        record_path,
        record_digest,
        statement_path,
        sha256_file(statement_path),
        subject,
        RELEASE_VERIFICATION_TYPE,
    )


def _qualification_payload_paths(
    workspace: RunWorkspace,
    image: ImageConfig,
    platform: Platform,
    payload: dict[str, object],
) -> tuple[Path, ...]:
    report_root = workspace.root / "reports" / image.image_id / platform.key
    paths = [
        report_root / "tests.json",
        workspace.root / "exports" / "sbom" / f"{platform.key}.spdx.json",
    ]
    scans = payload.get("scans")
    if not isinstance(scans, list):
        raise InvalidInvocationError("Qualification scans are malformed")
    for item in scans:
        scan = _object(item, "qualification scan")
        name = _string(scan.get("path"), "scan path")
        if Path(name).name != name:
            raise InvalidInvocationError("Qualification scan path is unsafe")
        paths.append(report_root / name)
    return tuple(paths)


def _tool_identity(value: object) -> ToolIdentity:
    item = _object(value, "tool identity")
    executable = item.get("executableDigest")
    image = item.get("imageDigest")
    return ToolIdentity(
        _string(item.get("name"), "tool name"),
        _string(item.get("version"), "tool version"),
        executable_digest=(
            _string(executable, "tool executable digest")
            if executable is not None
            else None
        ),
        image_digest=(
            _string(image, "tool image digest") if image is not None else None
        ),
    )


def _validate_workspace_record(
    record: dict[str, object], workspace: RunWorkspace
) -> None:
    snapshot = workspace.load()
    source = _object(record.get("source"), "record source")
    configuration = _object(
        record.get("repositoryConfiguration"), "record configuration"
    )
    if record.get("runId") != workspace.run_id:
        raise InvalidInvocationError("Record belongs to another run")
    if source.get("revision") != snapshot.immutable_inputs.get("sourceRevision"):
        raise InvalidInvocationError("Record source revision differs from the run")
    recorded_repository = snapshot.immutable_inputs.get("sourceRepository")
    if (
        recorded_repository is not None
        and source.get("repository") != recorded_repository
    ):
        raise InvalidInvocationError("Record source repository differs from the run")
    if configuration.get("path") != "conclear.toml" or configuration.get(
        "sha256"
    ) != snapshot.immutable_inputs.get("configurationDigest"):
        raise InvalidInvocationError(
            "Record repository configuration differs from the run"
        )


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise InvalidInvocationError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidInvocationError(f"{label} must be a non-empty string")
    return value


def _datetime(value: object, label: str) -> datetime:
    text = _string(value, label)
    try:
        result = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidInvocationError(f"{label} is malformed") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise InvalidInvocationError(f"{label} must be timezone-aware")
    return result


def _platforms(value: object, label: str) -> tuple[Platform, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise InvalidInvocationError(f"{label} must be a platform array")
    platforms = tuple(Platform.parse(item) for item in value)
    if len(platforms) != len(set(platforms)):
        raise InvalidInvocationError(f"{label} contains duplicates")
    return tuple(sorted(platforms))
