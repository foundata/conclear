"""Candidate publication, signing, verification and promotion services."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.cosign import (
    SignatureObservation,
    VerificationObservation,
)
from conclear.adapters.quay import QuayTagObservation
from conclear.adapters.skopeo import RegistryCopyObservation
from conclear.attestations import (
    RELEASE_VERIFICATION_TYPE,
    decode_dsse_statements,
    write_statement,
)
from conclear.config import ImageConfig, ReleaseProfile
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.jsonutil import load_json, sha256_file
from conclear.oci import OCIGraph, graph_fingerprint
from conclear.provenance import SLSA_PROVENANCE_TYPE
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
)
from conclear.schema import validate_external
from conclear.services.assembly import CandidateResult
from conclear.values import Digest, OCIReference, Platform
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
)


class Registry(Protocol):
    """Skopeo operations used by publication workflows."""

    def resolve_digest(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest:
        """Resolve one registry reference."""
        ...

    def resolve_optional(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest | None:
        """Resolve an unambiguously optional tag."""
        ...

    def copy_layout_to_registry(
        self,
        *,
        layout_path: Path,
        layout_reference: str,
        destination: OCIReference,
        auth_file: Path | None,
    ) -> None:
        """Copy one complete local graph."""
        ...

    def copy_registry_to_layout(
        self,
        *,
        source: OCIReference,
        layout_path: Path,
        layout_reference: str,
        auth_file: Path | None,
    ) -> RegistryCopyObservation:
        """Copy and validate one complete remote graph."""
        ...


class Quay(Protocol):
    """Quay tag controls used by publication workflows."""

    def get_tag(self, repository: OCIReference, tag: str) -> QuayTagObservation | None:
        """Read one exact tag."""
        ...

    def set_expiration(
        self, repository: OCIReference, tag: str, expiration: datetime
    ) -> QuayTagObservation:
        """Set and verify expiration."""
        ...

    def set_immutable(self, repository: OCIReference, tag: str) -> QuayTagObservation:
        """Enable and verify immutability."""
        ...

    def write_tag(
        self, repository: OCIReference, tag: str, digest: Digest
    ) -> QuayTagObservation:
        """Write and verify one tag."""
        ...

    def delete_tag(self, repository: OCIReference, tag: str) -> None:
        """Delete and verify one tag."""
        ...


class Signer(Protocol):
    """Cosign operations used by signing and verification workflows."""

    def sign(
        self, *, subject: OCIReference, private_key: str, passphrase: str | None
    ) -> SignatureObservation:
        """Sign one digest with public log inclusion."""
        ...

    def attest(
        self,
        *,
        subject: OCIReference,
        predicate: Path,
        predicate_type: str,
        private_key: str,
        passphrase: str | None,
    ) -> SignatureObservation:
        """Attach one predicate with public log inclusion."""
        ...

    def attest_statement(
        self,
        *,
        subject: OCIReference,
        statement: Path,
        private_key: str,
        passphrase: str | None,
    ) -> SignatureObservation:
        """Attach one complete statement with public log inclusion."""
        ...

    def attach_spdx(self, *, subject: OCIReference, sbom: Path) -> None:
        """Attach raw repository-scoped SPDX JSON."""
        ...

    def verify(
        self, *, subject: OCIReference, public_key: Path
    ) -> VerificationObservation:
        """Verify one signature and log inclusion."""
        ...

    def verify_attestation(
        self,
        *,
        subject: OCIReference,
        public_key: Path,
        predicate_type: str,
    ) -> VerificationObservation:
        """Verify matching attestations and log inclusion."""
        ...

    def download_attestations(
        self, *, subject: OCIReference, predicate_type: str
    ) -> tuple[object, ...]:
        """Download matching DSSE envelopes."""
        ...


@dataclass(frozen=True, slots=True)
class PublishedCandidate:
    """A candidate copied, graph-verified and expiration-controlled on Quay."""

    reference: OCIReference
    immutable_reference: OCIReference
    graph: OCIGraph
    expiration: datetime
    immutability_enabled: bool


@dataclass(frozen=True, slots=True)
class ReleaseEvidence:
    """Exact local evidence files and digests required for attestation."""

    source: SourceIdentity
    configuration_digest: str
    tools: tuple[ToolIdentity, ...]
    sboms: tuple[tuple[Platform, Path, str], ...]
    scan_digests: tuple[str, ...]
    provenance_path: Path
    provenance_digest: str
    candidate_record_digest: str
    qualification_digests: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Signed and retrieved release-verification result."""

    record_path: Path
    record_digest: str
    statement_path: Path
    statement_digest: str
    subject: OCIReference
    predicate_type: str


@dataclass(frozen=True, slots=True)
class PromotionResult:
    """Observed final tag mappings and candidate cleanup result."""

    tags: tuple[tuple[str, Digest], ...]
    candidate_deleted: bool


def publish_candidate(
    candidate: CandidateResult,
    *,
    image: ImageConfig,
    workspace: RunWorkspace,
    registry: Registry,
    quay: Quay,
    auth_file: Path | None,
    now: datetime,
) -> PublishedCandidate:
    """Publish one unused candidate, verify its graph and set bounded expiration."""
    if workspace.load().state is not RunState.ASSEMBLED:
        raise InvalidInvocationError("Candidate publication requires assembled state")
    tagged = image.repository.with_tag(candidate.candidate_tag)
    existing_entries = [
        item
        for item in workspace.journal.entries()
        if item.kind is ResourceKind.CANDIDATE_REFERENCE
        and item.identifier == str(tagged)
    ]
    if existing_entries:
        raise InvalidInvocationError("Candidate reference has already been attempted")
    if registry.resolve_optional(tagged, auth_file=auth_file) is not None:
        raise RuleRejectionError(
            f"Generated candidate tag is already in use: {tagged}", code="CC0601"
        )
    expiration = now.astimezone(UTC) + image.limits.candidate_lifetime
    workspace.journal.plan(
        resource_id="candidate",
        kind=ResourceKind.CANDIDATE_REFERENCE,
        identifier=str(tagged),
        ephemeral=True,
        metadata={"expiration": _timestamp(expiration)},
    )
    try:
        registry.copy_layout_to_registry(
            layout_path=candidate.observation.path,
            layout_reference=candidate.observation.reference,
            destination=tagged,
            auth_file=auth_file,
        )
        remote_digest = registry.resolve_digest(tagged, auth_file=auth_file)
        if remote_digest != candidate.observation.graph.digest:
            raise OperationalError(
                f"Published digest {remote_digest} differs from accepted {candidate.observation.graph.digest}"
            )
        immutable = image.repository.with_digest(remote_digest)
        remote = registry.copy_registry_to_layout(
            source=immutable,
            layout_path=workspace.root
            / "reports"
            / image.image_id
            / "remote-published",
            layout_reference="published",
            auth_file=auth_file,
        )
        _require_same_graph(candidate.observation.graph, remote.graph)
        expiration_observation = quay.set_expiration(
            image.repository, candidate.candidate_tag, expiration
        )
        if expiration_observation.digest != remote_digest:
            raise OperationalError("Quay expiration update observed another digest")
        immutable_enabled = False
        try:
            immutable_observation = quay.set_immutable(
                image.repository, candidate.candidate_tag
            )
            immutable_enabled = immutable_observation.immutable
        except OperationalError:
            immutable_enabled = False
    except Exception:
        _mark_failed(workspace, "candidate")
        raise
    workspace.journal.update(
        "candidate",
        ResourceStatus.CREATED,
        metadata={
            "digest": str(remote_digest),
            "expiration": _timestamp(expiration),
            "immutabilityEnabled": immutable_enabled,
        },
    )
    workspace.transition(RunState.PUBLISHED, now=now)
    return PublishedCandidate(
        tagged, immutable, remote.graph, expiration, immutable_enabled
    )


def attest_candidate(
    published: PublishedCandidate,
    evidence: ReleaseEvidence,
    *,
    workspace: RunWorkspace,
    signer: Signer,
    private_key: str,
    passphrase: str | None,
    registry: Registry,
    auth_file: Path | None,
    now: datetime,
) -> None:
    """Attach SPDX and provenance, then sign every unique image digest."""
    if workspace.load().state is not RunState.PUBLISHED:
        raise InvalidInvocationError("Attestation requires published state")
    _require_remote_unchanged(published, registry, auth_file)
    manifest_map = {
        item.platform: item.descriptor.digest for item in published.graph.manifests
    }
    sbom_map = {platform: (path, digest) for platform, path, digest in evidence.sboms}
    if set(sbom_map) != set(manifest_map):
        raise InvalidInvocationError(
            "SBOM platform coverage does not match published graph"
        )
    for platform, digest in sorted(manifest_map.items()):
        sbom_path, expected_digest = sbom_map[platform]
        if sha256_file(sbom_path) != expected_digest:
            raise InvalidInvocationError(f"SBOM digest changed for {platform}")
        sbom = _object(load_json(sbom_path), f"SBOM for {platform}")
        if sbom.get("spdxVersion") != "SPDX-2.3":
            raise InvalidInvocationError(
                f"SBOM for {platform} is not the required SPDX 2.3 document"
            )
        subject = published.reference.with_digest(digest)
        resource = f"sbom-{platform.key}"
        workspace.journal.plan(
            resource_id=resource,
            kind=ResourceKind.ATTESTATION,
            identifier=str(subject),
            ephemeral=False,
            metadata={"predicateType": "spdxjson", "payloadDigest": expected_digest},
        )
        try:
            signer.attach_spdx(subject=subject, sbom=sbom_path)
            signer.attest(
                subject=subject,
                predicate=sbom_path,
                predicate_type="spdxjson",
                private_key=private_key,
                passphrase=passphrase,
            )
        except Exception:
            _mark_failed(workspace, resource)
            raise
        workspace.journal.update(resource, ResourceStatus.CREATED)
    if sha256_file(evidence.provenance_path) != evidence.provenance_digest:
        raise InvalidInvocationError("Provenance digest changed before attestation")
    provenance = _object(load_json(evidence.provenance_path), "provenance")
    _validate_provenance(provenance, published)
    workspace.journal.plan(
        resource_id="provenance",
        kind=ResourceKind.ATTESTATION,
        identifier=str(published.immutable_reference),
        ephemeral=False,
        metadata={
            "predicateType": SLSA_PROVENANCE_TYPE,
            "payloadDigest": evidence.provenance_digest,
        },
    )
    try:
        signer.attest_statement(
            subject=published.immutable_reference,
            statement=evidence.provenance_path,
            private_key=private_key,
            passphrase=passphrase,
        )
        workspace.journal.update("provenance", ResourceStatus.CREATED)
    except Exception:
        _mark_failed(workspace, "provenance")
        raise
    subjects = {
        published.graph.digest,
        *(manifest.descriptor.digest for manifest in published.graph.manifests),
    }
    for index, digest in enumerate(sorted(subjects)):
        resource = f"signature-{index}"
        subject = published.reference.with_digest(digest)
        workspace.journal.plan(
            resource_id=resource,
            kind=ResourceKind.SIGNATURE,
            identifier=str(subject),
            ephemeral=False,
        )
        try:
            signer.sign(
                subject=subject,
                private_key=private_key,
                passphrase=passphrase,
            )
            workspace.journal.update(resource, ResourceStatus.CREATED)
        except Exception:
            _mark_failed(workspace, resource)
            raise
    workspace.transition(RunState.ATTESTED, now=now)


def verify_candidate(
    published: PublishedCandidate,
    candidate: CandidateResult,
    evidence: ReleaseEvidence,
    *,
    workspace: RunWorkspace,
    image: ImageConfig,
    profile: ReleaseProfile,
    signer: Signer,
    registry: Registry,
    auth_file: Path | None,
    private_key: str,
    passphrase: str | None,
    signer_mode: str,
    signer_key_id: str,
    host_architecture: str,
    ci_identity: dict[str, object] | None,
    now: datetime,
) -> VerificationResult:
    """Verify every subject and evidence payload, then sign the verification result."""
    if workspace.load().state is not RunState.ATTESTED:
        raise InvalidInvocationError("Verification requires attested state")
    if signer_mode not in {"managed-key", "kms", "hsm"}:
        raise InvalidInvocationError("Unsupported signer mode")
    if not signer_key_id:
        raise InvalidInvocationError("Signer identity must not be empty")
    if profile.mode.value == "local" and ci_identity is not None:
        raise InvalidInvocationError("Local releases cannot claim a CI identity")
    if profile.mode.value == "ci" and ci_identity is None:
        raise InvalidInvocationError("CI releases require an observed CI identity")
    Digest(evidence.configuration_digest)
    for evidence_digest in (
        *evidence.qualification_digests,
        *evidence.scan_digests,
        *(item[2] for item in evidence.sboms),
        evidence.provenance_digest,
        evidence.candidate_record_digest,
    ):
        Digest(evidence_digest)
    if (
        sha256_file(candidate.record_path) != candidate.record_digest
        or candidate.record_digest != evidence.candidate_record_digest
    ):
        raise InvalidInvocationError(
            "Release candidate record changed before verification"
        )
    _require_remote_unchanged(published, registry, auth_file)
    subjects = {
        published.graph.digest,
        *(manifest.descriptor.digest for manifest in published.graph.manifests),
    }
    for digest in sorted(subjects):
        signer.verify(
            subject=published.reference.with_digest(digest),
            public_key=profile.cosign_public_key,
        )
    manifest_map = {
        item.platform: item.descriptor.digest for item in published.graph.manifests
    }
    for platform, path, expected_digest in evidence.sboms:
        if manifest_map.get(platform) is None or sha256_file(path) != expected_digest:
            raise InvalidInvocationError(f"SBOM evidence changed for {platform}")
        subject = published.reference.with_digest(manifest_map[platform])
        signer.verify_attestation(
            subject=subject,
            public_key=profile.cosign_public_key,
            predicate_type="spdxjson",
        )
        _require_downloaded_predicate(
            signer,
            subject=subject,
            predicate_type="spdxjson",
            expected=load_json(path),
        )
    provenance = _object(load_json(evidence.provenance_path), "provenance")
    _validate_provenance(provenance, published)
    signer.verify_attestation(
        subject=published.immutable_reference,
        public_key=profile.cosign_public_key,
        predicate_type=SLSA_PROVENANCE_TYPE,
    )
    _require_downloaded_statement(
        signer,
        subject=published.immutable_reference,
        predicate_type=SLSA_PROVENANCE_TYPE,
        expected=provenance,
    )
    payload: dict[str, object] = {
        "subject": {
            "repository": image.repository.repository_name,
            "digest": str(published.graph.digest),
        },
        "platformDigests": {
            str(platform): str(digest) for platform, digest in manifest_map.items()
        },
        "releaseEnvironment": {
            "mode": profile.mode.value,
            "hostArchitecture": host_architecture,
            "runId": workspace.run_id,
            **({} if ci_identity is None else {"ciIdentity": ci_identity}),
        },
        "signer": {"mode": signer_mode, "keyId": signer_key_id},
        "evidence": {
            "platformQualifications": list(evidence.qualification_digests),
            "scanResults": list(evidence.scan_digests),
            "sboms": [digest for _platform, _path, digest in evidence.sboms],
            "provenance": evidence.provenance_digest,
            "candidateRecord": evidence.candidate_record_digest,
        },
    }
    record = RecordEnvelope(
        record_type="releaseVerification",
        created_at=now,
        run_id=workspace.run_id,
        source=evidence.source,
        configuration_digest=evidence.configuration_digest,
        tools=evidence.tools,
        verdict=Verdict.ACCEPTED,
        payload=payload,
    )
    record_path = workspace.root / "records" / "release-verification.json"
    record_digest = record.write(record_path)
    statement_path = workspace.root / "records" / "release-verification-statement.json"
    statement_digest = write_statement(
        subject_name=image.repository.repository_name,
        subject_digest=published.graph.digest,
        predicate_type=RELEASE_VERIFICATION_TYPE,
        predicate=record.to_dict(),
        path=statement_path,
    )
    workspace.journal.plan(
        resource_id="release-verification",
        kind=ResourceKind.ATTESTATION,
        identifier=str(published.immutable_reference),
        ephemeral=False,
        metadata={
            "predicateType": RELEASE_VERIFICATION_TYPE,
            "payloadDigest": record_digest,
        },
    )
    try:
        signer.attest_statement(
            subject=published.immutable_reference,
            statement=statement_path,
            private_key=private_key,
            passphrase=passphrase,
        )
        signer.verify_attestation(
            subject=published.immutable_reference,
            public_key=profile.cosign_public_key,
            predicate_type=RELEASE_VERIFICATION_TYPE,
        )
        _require_downloaded_statement(
            signer,
            subject=published.immutable_reference,
            predicate_type=RELEASE_VERIFICATION_TYPE,
            expected=_object(
                load_json(statement_path), "release verification statement"
            ),
        )
    except Exception:
        _mark_failed(workspace, "release-verification")
        raise
    workspace.journal.update("release-verification", ResourceStatus.CREATED)
    workspace.transition(RunState.VERIFIED, now=now)
    return VerificationResult(
        record_path,
        record_digest,
        statement_path,
        statement_digest,
        published.immutable_reference,
        RELEASE_VERIFICATION_TYPE,
    )


def promote_candidate(
    published: PublishedCandidate,
    verification: VerificationResult,
    *,
    image: ImageConfig,
    version: str | None,
    workspace: RunWorkspace,
    quay: Quay,
    registry: Registry,
    signer: Signer,
    public_key: Path,
    auth_file: Path | None,
    now: datetime,
) -> PromotionResult:
    """Repeat verification, apply exact digest tags and remove the candidate tag."""
    if workspace.load().state is not RunState.VERIFIED:
        raise InvalidInvocationError("Promotion requires verified state")
    tag_state = quay.get_tag(image.repository, published.reference.tag or "")
    if tag_state is None or tag_state.digest != published.graph.digest:
        raise OperationalError("Candidate tag changed before promotion")
    if tag_state.expiration is None or now.astimezone(UTC) >= tag_state.expiration:
        raise RuleRejectionError("Candidate expired before promotion", code="CC0603")
    signer.verify_attestation(
        subject=verification.subject,
        public_key=public_key,
        predicate_type=verification.predicate_type,
    )
    expected_statement = _object(
        load_json(verification.statement_path), "release verification statement"
    )
    _require_downloaded_statement(
        signer,
        subject=verification.subject,
        predicate_type=verification.predicate_type,
        expected=expected_statement,
    )
    immutable_tags = tuple(
        _render_tag(item, version) for item in image.release.immutable_tags
    )
    moving_tags = image.release.moving_tags
    if set(immutable_tags) & set(moving_tags):
        raise InvalidInvocationError(
            "Immutable and moving release tags must be disjoint"
        )
    observed: list[tuple[str, Digest]] = []
    for tag in immutable_tags:
        current = quay.get_tag(image.repository, tag)
        if current is not None and current.digest != published.graph.digest:
            raise RuleRejectionError(
                f"Immutable release tag already names another digest: {tag}",
                code="CC0604",
            )
        if current is not None:
            if not current.immutable:
                immutable_result = quay.set_immutable(image.repository, tag)
                if not immutable_result.immutable:
                    raise OperationalError(
                        f"Immutable release tag was not protected: {tag}"
                    )
            observed.append((tag, current.digest))
            continue
        _write_release_tag(
            tag,
            published.graph.digest,
            image,
            workspace,
            quay,
            registry,
            auth_file,
            immutable=True,
        )
        observed.append((tag, published.graph.digest))
    for tag in moving_tags:
        _write_release_tag(
            tag,
            published.graph.digest,
            image,
            workspace,
            quay,
            registry,
            auth_file,
            immutable=False,
        )
        observed.append((tag, published.graph.digest))
    workspace.transition(RunState.PROMOTED, now=now)
    try:
        quay.delete_tag(image.repository, published.reference.tag or "")
        workspace.journal.update("candidate", ResourceStatus.REMOVED)
    except Exception as exc:
        raise OperationalError(
            "Release was promoted, but candidate tag cleanup failed"
        ) from exc
    return PromotionResult(tuple(observed), True)


def _write_release_tag(
    tag: str,
    digest: Digest,
    image: ImageConfig,
    workspace: RunWorkspace,
    quay: Quay,
    registry: Registry,
    auth_file: Path | None,
    *,
    immutable: bool,
) -> None:
    resource_id = f"tag-{tag}"
    workspace.journal.plan(
        resource_id=resource_id,
        kind=ResourceKind.TAG_WRITE,
        identifier=str(image.repository.with_tag(tag)),
        ephemeral=False,
        metadata={"digest": str(digest), "immutable": immutable},
    )
    try:
        result = quay.write_tag(image.repository, tag, digest)
        resolved = registry.resolve_digest(
            image.repository.with_tag(tag), auth_file=auth_file
        )
        if result.digest != digest or resolved != digest:
            raise OperationalError(
                f"Release tag {tag} did not resolve to verified digest"
            )
        if immutable:
            immutable_result = quay.set_immutable(image.repository, tag)
            if not immutable_result.immutable:
                raise OperationalError(
                    f"Immutable release tag was not protected: {tag}"
                )
    except Exception:
        _mark_failed(workspace, resource_id)
        raise
    workspace.journal.update(resource_id, ResourceStatus.CREATED)


def _require_remote_unchanged(
    published: PublishedCandidate,
    registry: Registry,
    auth_file: Path | None,
) -> None:
    observed = registry.resolve_digest(published.reference, auth_file=auth_file)
    if observed != published.graph.digest:
        raise OperationalError("Candidate tag changed after publication")


def _require_same_graph(expected: OCIGraph, observed: OCIGraph) -> None:
    if (
        graph_fingerprint(expected) != graph_fingerprint(observed)
        or expected.platforms != observed.platforms
        or expected.digest != observed.digest
    ):
        raise OperationalError(
            "Remote OCI descriptor graph differs from accepted graph"
        )


def _require_downloaded_predicate(
    signer: Signer,
    *,
    subject: OCIReference,
    predicate_type: str,
    expected: object,
) -> None:
    statements = decode_dsse_statements(
        signer.download_attestations(
            subject=subject,
            predicate_type=predicate_type,
        )
    )
    if not any(
        statement.get("predicateType") == predicate_type
        and statement.get("predicate") == expected
        and _statement_has_digest(statement, subject.digest)
        for statement in statements
    ):
        raise OperationalError(
            f"Downloaded {predicate_type} predicate does not match evidence"
        )


def _require_downloaded_statement(
    signer: Signer,
    *,
    subject: OCIReference,
    predicate_type: str,
    expected: dict[str, object],
) -> None:
    statements = decode_dsse_statements(
        signer.download_attestations(subject=subject, predicate_type=predicate_type)
    )
    if expected not in statements:
        raise OperationalError(
            f"Downloaded {predicate_type} Statement does not match evidence"
        )


def _validate_provenance(
    provenance: dict[str, object], published: PublishedCandidate
) -> None:
    validate_external(provenance, "provenance.schema.json", label="provenance")
    expected = {
        published.graph.digest,
        *(item.descriptor.digest for item in published.graph.manifests),
    }
    subjects = provenance.get("subject")
    if not isinstance(subjects, list):
        raise InvalidInvocationError("Provenance subjects are malformed")
    observed: set[Digest] = set()
    for value in subjects:
        subject = _object(value, "provenance subject")
        digest = _object(subject.get("digest"), "provenance subject digest")
        encoded = digest.get("sha256")
        if not isinstance(encoded, str):
            raise InvalidInvocationError("Provenance subject digest is malformed")
        observed.add(Digest(f"sha256:{encoded}"))
    if observed != expected:
        raise InvalidInvocationError(
            "Provenance subject coverage does not match published graph"
        )


def _statement_has_digest(statement: dict[str, object], digest: Digest | None) -> bool:
    if digest is None:
        return False
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        return False
    expected = {"sha256": digest.encoded}
    return any(
        isinstance(subject, dict) and subject.get("digest") == expected
        for subject in subjects
    )


def _render_tag(template: str, version: str | None) -> str:
    if "{version}" in template:
        if version is None:
            raise InvalidInvocationError(
                "Version-dependent release tag requires --version"
            )
        rendered = template.replace("{version}", version)
    else:
        rendered = template
    OCIReference("registry.invalid", "validation").with_tag(rendered)
    return rendered


def _mark_failed(workspace: RunWorkspace, resource_id: str) -> None:
    try:
        workspace.journal.update(resource_id, ResourceStatus.FAILED)
    except Exception:
        return


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise OperationalError(f"{label} must be an object")
    return value


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Publication timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
