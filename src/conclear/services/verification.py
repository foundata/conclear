"""Independent verification of the attested candidate.

`verify_candidate` re-resolves the remote graph, verifies every image
signature, SBOM and provenance attestation against the local evidence and the
public log, then writes, signs and re-downloads the release-verification
statement that promotion later requires. A retry accepts only unchanged
evidence and reuses a verification statement the registry still serves.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from conclear.attestations import (
    RELEASE_VERIFICATION_TYPE,
    SPDX_DOCUMENT_TYPE,
    STATEMENT_TYPE,
    write_statement,
)
from conclear.config import ReleaseImageConfig
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.jsonutil import load_json, sha256_file
from conclear.parsing import object_value
from conclear.provenance import SLSA_PROVENANCE_TYPE
from conclear.records import RecordEnvelope, Verdict, validate_record
from conclear.release_profile import CIContextPolicy, ReleaseProfile
from conclear.services.assembly import CandidateResult
from conclear.services.attestation import (
    ReleaseEvidence,
    Signer,
    has_verified_statement,
    provenance_subjects,
    require_verified_predicate,
    require_verified_statement,
    validate_release_provenance,
    verify_image_signature,
)
from conclear.services.ci_context import PublicCIContext
from conclear.services.publication import (
    PublishedCandidate,
    Registry,
    require_remote_graph_unchanged,
    retry_entry,
)
from conclear.spdx import validate_spdx_document
from conclear.values import Digest, OCIReference
from conclear.workspace import ResourceKind, ResourceStatus, RunState, RunWorkspace


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Signed and retrieved release-verification result."""

    record_path: Path
    record_digest: str
    statement_path: Path
    statement_digest: str
    subject: OCIReference
    predicate_type: str


def verify_candidate(
    published: PublishedCandidate,
    candidate: CandidateResult,
    evidence: ReleaseEvidence,
    *,
    workspace: RunWorkspace,
    image: ReleaseImageConfig,
    profile: ReleaseProfile,
    signer: Signer,
    registry: Registry,
    auth_file: Path | None,
    private_key: str,
    passphrase: str | None,
    signer_mode: str,
    signer_key_id: str,
    host_architecture: str,
    ci_context: PublicCIContext | None,
    now: datetime,
    clock: Callable[[], datetime],
) -> VerificationResult:
    """Verify every subject and evidence payload, then sign the verification result."""
    snapshot = workspace.load()
    if snapshot.state is not RunState.ATTESTED:
        raise InvalidInvocationError("Verification requires attested state")
    candidate.qualification_window.require_current(now, phase="release verification")
    if signer_mode not in {"managed-key", "kms", "hsm"}:
        raise InvalidInvocationError("Unsupported signer mode")
    if not signer_key_id:
        raise InvalidInvocationError("Signer identity must not be empty")
    if profile.ci_context is CIContextPolicy.OMIT and ci_context is not None:
        raise InvalidInvocationError("CI context must be omitted by this profile")
    if profile.ci_context is CIContextPolicy.REQUIRE and ci_context is None:
        raise OperationalError("Required CI context is unavailable")
    if snapshot.immutable_inputs.get("builderId") != profile.builder.id:
        raise InvalidInvocationError("Release builder identity differs from the run")
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
        raise RuleRejectionError(
            "Release candidate record changed before verification", code="CC0602"
        )
    require_remote_graph_unchanged(
        published,
        registry,
        auth_file,
        workspace=workspace,
        image=image,
        phase="verification",
    )
    subjects = {
        published.graph.digest,
        *(manifest.descriptor.digest for manifest in published.graph.manifests),
    }
    for digest in sorted(subjects):
        verify_image_signature(
            signer,
            published.reference.with_digest(digest),
            profile.cosign_public_key,
        )
    manifest_map = {
        item.platform: item.descriptor.digest for item in published.graph.manifests
    }
    for platform, path, expected_digest in evidence.sboms:
        if manifest_map.get(platform) is None or sha256_file(path) != expected_digest:
            raise RuleRejectionError(
                f"SBOM evidence changed for {platform}", code="CC0703"
            )
        subject = published.reference.with_digest(manifest_map[platform])
        sbom = validate_spdx_document(load_json(path), label=f"SBOM for {platform}")
        require_verified_predicate(
            signer,
            public_key=profile.cosign_public_key,
            subject=subject,
            predicate_type=SPDX_DOCUMENT_TYPE,
            expected=sbom,
        )
    provenance = object_value(load_json(evidence.provenance_path), "provenance")
    validate_release_provenance(
        provenance,
        published.graph,
        evidence=evidence,
        workspace=workspace,
        image=image,
    )
    provenance_predicate = object_value(
        provenance.get("predicate"), "provenance predicate"
    )
    for _resource, provenance_subject in provenance_subjects(published):
        require_verified_predicate(
            signer,
            public_key=profile.cosign_public_key,
            subject=provenance_subject,
            predicate_type=SLSA_PROVENANCE_TYPE,
            expected=provenance_predicate,
        )
    payload: dict[str, object] = {
        "qualificationWindow": candidate.qualification_window.to_dict(),
        "subject": {
            "repository": image.repository.repository_name,
            "digest": str(published.graph.digest),
        },
        "platformDigests": {
            str(platform): str(digest) for platform, digest in manifest_map.items()
        },
        "releaseEnvironment": {
            "hostArchitecture": host_architecture,
            "runId": workspace.run_id,
            **(
                {} if ci_context is None else {"ciContext": ci_context.to_public_dict()}
            ),
        },
        "builder": {"id": profile.builder.id},
        "signer": {"mode": signer_mode, "keyId": signer_key_id},
        "evidence": {
            "platformQualifications": list(evidence.qualification_digests),
            "scanResults": list(evidence.scan_digests),
            "sboms": [digest for _platform, _path, digest in evidence.sboms],
            "provenance": evidence.provenance_digest,
            "candidateRecord": evidence.candidate_record_digest,
        },
    }
    verified_at = clock()
    candidate.qualification_window.require_current(
        verified_at, phase="release verification"
    )
    record = RecordEnvelope(
        record_type="releaseVerification",
        created_at=verified_at,
        run_id=workspace.run_id,
        source=evidence.source,
        configuration_digest=evidence.configuration_digest,
        tools=evidence.tools,
        verdict=Verdict.ACCEPTED,
        payload=payload,
    )
    record_path = workspace.root / "records" / "release-verification.json"
    statement_path = workspace.root / "records" / "release-verification-statement.json"
    current_record = record.to_dict()
    matches = [
        entry
        for entry in workspace.journal.entries()
        if entry.resource_id == "release-verification"
    ]
    if matches:
        stored_record = object_value(
            load_json(record_path), "release verification record"
        )
        validate_record(stored_record)
        if any(
            stored_record.get(key) != value
            for key, value in current_record.items()
            if key != "createdAt"
        ):
            raise RuleRejectionError(
                "Release verification retry inputs changed", code="CC0703"
            )
        record_digest = sha256_file(record_path)
        statement = object_value(
            load_json(statement_path), "release verification statement"
        )
        if (
            statement.get("_type") != STATEMENT_TYPE
            or statement.get("predicateType") != RELEASE_VERIFICATION_TYPE
            or statement.get("predicate") != stored_record
            or statement.get("subject")
            != [
                {
                    "name": image.repository.repository_name,
                    "digest": {"sha256": published.graph.digest.encoded},
                }
            ]
        ):
            raise RuleRejectionError(
                "Release verification statement changed", code="CC0703"
            )
        statement_digest = sha256_file(statement_path)
    else:
        record_digest = record.write(record_path)
        statement_digest = write_statement(
            subject_name=image.repository.repository_name,
            subject_digest=published.graph.digest,
            predicate_type=RELEASE_VERIFICATION_TYPE,
            predicate=current_record,
            path=statement_path,
        )
        statement = object_value(
            load_json(statement_path), "release verification statement"
        )
    verification_metadata: dict[str, object] = {
        "predicateType": RELEASE_VERIFICATION_TYPE,
        "payloadDigest": record_digest,
    }
    existing_verification = retry_entry(
        workspace,
        resource_id="release-verification",
        kind=ResourceKind.ATTESTATION,
        identifier=str(published.immutable_reference),
        metadata=verification_metadata,
    )
    if existing_verification is None:
        workspace.journal.plan(
            resource_id="release-verification",
            kind=ResourceKind.ATTESTATION,
            identifier=str(published.immutable_reference),
            ephemeral=False,
            metadata=verification_metadata,
        )
    elif has_verified_statement(
        signer,
        public_key=profile.cosign_public_key,
        subject=published.immutable_reference,
        predicate_type=RELEASE_VERIFICATION_TYPE,
        expected=statement,
    ):
        completed_at = clock()
        candidate.qualification_window.require_current(
            completed_at, phase="release verification resume"
        )
        workspace.journal.update("release-verification", ResourceStatus.CREATED)
        workspace.transition(RunState.VERIFIED, now=completed_at)
        return VerificationResult(
            record_path,
            record_digest,
            statement_path,
            statement_digest,
            published.immutable_reference,
            RELEASE_VERIFICATION_TYPE,
        )
    elif existing_verification.status is ResourceStatus.CREATED:
        raise OperationalError("Recorded release verification attestation is missing")
    try:
        candidate.qualification_window.require_current(
            clock(), phase="release verification signing"
        )
        signer.attest_statement(
            subject=published.immutable_reference,
            statement=statement_path,
            private_key=private_key,
            passphrase=passphrase,
            passphrase_path=profile.passphrase_file,
        )
        require_verified_statement(
            signer,
            public_key=profile.cosign_public_key,
            subject=published.immutable_reference,
            predicate_type=RELEASE_VERIFICATION_TYPE,
            expected=statement,
        )
        completed_at = clock()
        candidate.qualification_window.require_current(
            completed_at, phase="release verification completion"
        )
    except Exception:
        workspace.journal.mark_failed("release-verification")
        raise
    workspace.journal.update("release-verification", ResourceStatus.CREATED)
    workspace.transition(RunState.VERIFIED, now=completed_at)
    return VerificationResult(
        record_path,
        record_digest,
        statement_path,
        statement_digest,
        published.immutable_reference,
        RELEASE_VERIFICATION_TYPE,
    )
