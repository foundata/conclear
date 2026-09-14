"""Attestation of the published candidate.

`attest_candidate` attaches every platform SBOM and the SLSA provenance
statement, then signs the index and every platform manifest with mandatory
public log inclusion. The evidence matching it uses to recognise an already
attached attestation is shared with verification and promotion, which repeat
the verifier's authenticated payloads before they trust a remote statement.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.cosign import (
    SignatureObservation,
    VerificationObservation,
)
from conclear.attestations import (
    SPDX_DOCUMENT_TYPE,
    statement_matches,
)
from conclear.config import ReleaseImageConfig
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.identity import IDENTITY
from conclear.jsonutil import load_json, sha256_file
from conclear.oci import OCIGraph
from conclear.parsing import object_value
from conclear.provenance import SLSA_PROVENANCE_TYPE, ProvenanceMaterial
from conclear.records import SourceIdentity, ToolIdentity
from conclear.schema import validate_external
from conclear.services.attestation_reads import verified_statements
from conclear.services.publication import (
    PublishedCandidate,
    Registry,
    require_remote_graph_unchanged,
    retry_entry,
)
from conclear.spdx import validate_spdx_document
from conclear.values import Digest, OCIReference, Platform
from conclear.workspace import ResourceKind, ResourceStatus, RunState, RunWorkspace


class Signer(Protocol):
    """Cosign operations used by signing and verification workflows."""

    def sign(
        self,
        *,
        subject: OCIReference,
        private_key: str,
        passphrase: str | None,
        passphrase_path: Path | None = None,
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
        passphrase_path: Path | None = None,
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
        passphrase_path: Path | None = None,
    ) -> SignatureObservation:
        """Attach one complete statement with public log inclusion."""
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

    def download_signatures(self, *, subject: OCIReference) -> tuple[object, ...]:
        """Download signatures for conclusive retry recovery."""
        ...


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
    provenance_materials: tuple[ProvenanceMaterial, ...]
    candidate_record_digest: str
    qualification_digests: tuple[str, ...]


def match_sboms_to_platforms(
    platforms: tuple[Platform, ...],
    sboms: tuple[tuple[Platform, Path, str], ...],
) -> dict[Platform, tuple[Path, str]]:
    """Pair every published platform manifest with exactly one SBOM (CC0504).

    Buildah records the emulated arm64 manifest as `linux/arm64/v8` while the
    qualification names the declared `linux/arm64`; both spell the same
    target, so the pairing uses semantic platform matching. Every platform
    needs one SBOM and every SBOM must belong to one platform.
    """
    matched: dict[Platform, tuple[Path, str]] = {}
    used: set[int] = set()
    for platform in platforms:
        candidates = [
            index
            for index, (sbom_platform, _path, _digest) in enumerate(sboms)
            if sbom_platform.semantically_matches(platform)
        ]
        if len(candidates) != 1 or candidates[0] in used:
            raise RuleRejectionError(
                "SBOM platform coverage does not match published graph", code="CC0504"
            )
        used.add(candidates[0])
        _sbom_platform, path, digest = sboms[candidates[0]]
        matched[platform] = (path, digest)
    if len(used) != len(sboms):
        raise RuleRejectionError(
            "SBOM platform coverage does not match published graph", code="CC0504"
        )
    return matched


def attest_candidate(
    published: PublishedCandidate,
    evidence: ReleaseEvidence,
    *,
    image: ReleaseImageConfig,
    workspace: RunWorkspace,
    signer: Signer,
    private_key: str,
    public_key: Path,
    passphrase: str | None,
    passphrase_path: Path | None,
    registry: Registry,
    auth_file: Path | None,
    now: datetime,
) -> None:
    """Attach SPDX and provenance, then sign every unique image digest."""
    if workspace.load().state is not RunState.PUBLISHED:
        raise InvalidInvocationError("Attestation requires published state")
    published.require_current(now)
    require_remote_graph_unchanged(
        published,
        registry,
        auth_file,
        workspace=workspace,
        image=image,
        phase="before-attestation",
    )
    manifest_map = {
        item.platform: item.descriptor.digest for item in published.graph.manifests
    }
    sbom_map = match_sboms_to_platforms(tuple(manifest_map), evidence.sboms)
    for platform, digest in sorted(manifest_map.items()):
        sbom_path, expected_digest = sbom_map[platform]
        if sha256_file(sbom_path) != expected_digest:
            raise RuleRejectionError(
                f"SBOM digest changed for {platform}", code="CC0504"
            )
        sbom = validate_spdx_document(
            load_json(sbom_path), label=f"SBOM for {platform}"
        )
        subject = published.reference.with_digest(digest)
        resource = f"sbom-{platform.key}"
        metadata: dict[str, object] = {
            "predicateType": SPDX_DOCUMENT_TYPE,
            "payloadDigest": expected_digest,
        }
        existing = retry_entry(
            workspace,
            resource_id=resource,
            kind=ResourceKind.ATTESTATION,
            identifier=str(subject),
            metadata=metadata,
        )
        if existing is not None:
            if _has_verified_predicate(
                signer,
                public_key=public_key,
                subject=subject,
                predicate_type=SPDX_DOCUMENT_TYPE,
                expected=sbom,
            ):
                workspace.journal.update(resource, ResourceStatus.CREATED)
                continue
            if existing.status is ResourceStatus.CREATED:
                raise OperationalError(
                    f"Recorded SBOM attestation is missing: {platform}"
                )
        else:
            workspace.journal.plan(
                resource_id=resource,
                kind=ResourceKind.ATTESTATION,
                identifier=str(subject),
                ephemeral=False,
                metadata=metadata,
            )
        try:
            signer.attest(
                subject=subject,
                predicate=sbom_path,
                predicate_type="spdxjson",
                private_key=private_key,
                passphrase=passphrase,
                passphrase_path=passphrase_path,
            )
        except Exception:
            workspace.journal.mark_failed(resource)
            raise
        workspace.journal.update(resource, ResourceStatus.CREATED)
    if sha256_file(evidence.provenance_path) != evidence.provenance_digest:
        raise RuleRejectionError(
            "Provenance digest changed before attestation", code="CC0703"
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
    provenance_metadata: dict[str, object] = {
        "predicateType": SLSA_PROVENANCE_TYPE,
        "payloadDigest": evidence.provenance_digest,
    }
    for resource, subject in provenance_subjects(published):
        existing_provenance = retry_entry(
            workspace,
            resource_id=resource,
            kind=ResourceKind.ATTESTATION,
            identifier=str(subject),
            metadata=provenance_metadata,
        )
        if existing_provenance is not None:
            if _has_verified_predicate(
                signer,
                public_key=public_key,
                subject=subject,
                predicate_type=SLSA_PROVENANCE_TYPE,
                expected=provenance_predicate,
            ):
                workspace.journal.update(resource, ResourceStatus.CREATED)
                continue
            if existing_provenance.status is ResourceStatus.CREATED:
                raise OperationalError("Recorded provenance attestation is missing")
        else:
            workspace.journal.plan(
                resource_id=resource,
                kind=ResourceKind.ATTESTATION,
                identifier=str(subject),
                ephemeral=False,
                metadata=provenance_metadata,
            )
        try:
            signer.attest_statement(
                subject=subject,
                statement=evidence.provenance_path,
                private_key=private_key,
                passphrase=passphrase,
                passphrase_path=passphrase_path,
            )
            workspace.journal.update(resource, ResourceStatus.CREATED)
        except Exception:
            workspace.journal.mark_failed(resource)
            raise
    subjects = {
        published.graph.digest,
        *(manifest.descriptor.digest for manifest in published.graph.manifests),
    }
    for index, digest in enumerate(sorted(subjects)):
        resource = f"signature-{index}"
        subject = published.reference.with_digest(digest)
        existing_signature = retry_entry(
            workspace,
            resource_id=resource,
            kind=ResourceKind.SIGNATURE,
            identifier=str(subject),
            metadata={},
        )
        if existing_signature is not None:
            downloaded = signer.download_signatures(subject=subject)
            if downloaded:
                verify_image_signature(signer, subject, public_key)
                workspace.journal.update(resource, ResourceStatus.CREATED)
                continue
            if existing_signature.status is ResourceStatus.CREATED:
                raise OperationalError(
                    "Recorded image signature is missing", code="CC0702"
                )
        else:
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
                passphrase_path=passphrase_path,
            )
            workspace.journal.update(resource, ResourceStatus.CREATED)
        except Exception:
            workspace.journal.mark_failed(resource)
            raise
    workspace.transition(RunState.ATTESTED, now=now)


def _has_verified_predicate(
    signer: Signer,
    *,
    subject: OCIReference,
    public_key: Path,
    predicate_type: str,
    expected: object,
) -> bool:
    if not signer.download_attestations(subject=subject, predicate_type=predicate_type):
        return False
    statements = verified_statements(
        signer, subject=subject, public_key=public_key, predicate_type=predicate_type
    )
    return any(
        subject.digest is not None
        and statement_matches(
            statement,
            subject_name=subject.repository_name,
            subject_digest=subject.digest,
            predicate_type=predicate_type,
            predicate=expected,
        )
        for statement in statements
    )


def has_verified_statement(
    signer: Signer,
    *,
    subject: OCIReference,
    public_key: Path,
    predicate_type: str,
    expected: dict[str, object],
) -> bool:
    """Match the statement Cosign wrapped around `expected`'s predicate.

    Cosign owns the statement envelope, including its `_type` version and the
    single subject it signs, so the comparison covers the subject digest, the
    predicate type and the complete predicate rather than the whole document.
    """
    return _has_verified_predicate(
        signer,
        subject=subject,
        public_key=public_key,
        predicate_type=predicate_type,
        expected=expected.get("predicate"),
    )


def provenance_subjects(
    published: PublishedCandidate,
) -> tuple[tuple[str, OCIReference], ...]:
    """Name the index and every distinct platform manifest that carries provenance."""
    subjects: list[tuple[str, OCIReference]] = [
        ("provenance", published.immutable_reference)
    ]
    for manifest in published.graph.manifests:
        digest = manifest.descriptor.digest
        if digest == published.graph.digest:
            continue
        key = (
            manifest.platform.key
            if manifest.platform is not None
            else digest.encoded[:12]
        )
        subjects.append((f"provenance-{key}", published.reference.with_digest(digest)))
    return tuple(subjects)


def require_verified_predicate(
    signer: Signer,
    *,
    subject: OCIReference,
    public_key: Path,
    predicate_type: str,
    expected: object,
) -> None:
    """Fail unless a verified attestation carries the complete expected predicate."""
    if not any(
        subject.digest is not None
        and statement_matches(
            statement,
            subject_name=subject.repository_name,
            subject_digest=subject.digest,
            predicate_type=predicate_type,
            predicate=expected,
        )
        for statement in verified_statements(
            signer,
            subject=subject,
            public_key=public_key,
            predicate_type=predicate_type,
        )
    ):
        raise OperationalError(
            f"Verified {predicate_type} predicate does not match evidence"
        )


def require_verified_statement(
    signer: Signer,
    *,
    subject: OCIReference,
    public_key: Path,
    predicate_type: str,
    expected: dict[str, object],
) -> None:
    """Require the verified statement Cosign wrapped around `expected`."""
    require_verified_predicate(
        signer,
        subject=subject,
        public_key=public_key,
        predicate_type=predicate_type,
        expected=expected.get("predicate"),
    )


def validate_release_provenance(
    provenance: dict[str, object],
    graph: OCIGraph,
    *,
    evidence: ReleaseEvidence,
    workspace: RunWorkspace,
    image: ReleaseImageConfig,
) -> None:
    """Validate exact provenance subjects, inputs and builder identity."""
    validate_external(provenance, "provenance.schema.json", label="provenance")
    expected_subjects: list[dict[str, object]] = [
        {
            "name": image.repository.repository_name,
            "digest": {"sha256": graph.digest.encoded},
        }
    ]
    expected_subjects.extend(
        {
            "name": f"{image.repository.repository_name}#{manifest.platform}",
            "digest": {"sha256": manifest.descriptor.digest.encoded},
        }
        for manifest in sorted(graph.manifests, key=lambda value: value.platform)
    )
    if provenance.get("subject") != expected_subjects:
        raise RuleRejectionError(
            "Provenance subject coverage does not match published graph", code="CC0703"
        )
    predicate = object_value(provenance.get("predicate"), "provenance predicate")
    definition = object_value(
        predicate.get("buildDefinition"), "provenance build definition"
    )
    snapshot = workspace.load()
    expected_parameters = {
        "imageId": image.image_id,
        "version": snapshot.immutable_inputs.get("version") or None,
        "runId": workspace.run_id,
        "platforms": [
            str(manifest.platform)
            for manifest in sorted(graph.manifests, key=lambda value: value.platform)
        ],
    }
    if definition.get("externalParameters") != expected_parameters:
        raise RuleRejectionError("Provenance release parameters changed", code="CC0704")
    expected_dependencies: list[dict[str, object]] = [
        {
            "uri": evidence.source.repository,
            "digest": {"gitCommit": evidence.source.revision},
        },
        {
            "uri": "conclear.toml",
            "digest": {
                "sha256": Digest(evidence.configuration_digest).encoded,
            },
        },
    ]
    expected_dependencies.extend(
        {
            "uri": material.uri,
            "digest": {"sha256": material.digest.encoded},
        }
        for material in evidence.provenance_materials
    )
    if definition.get("resolvedDependencies") != expected_dependencies:
        raise RuleRejectionError(
            "Provenance resolved dependencies changed", code="CC0703"
        )
    details = object_value(predicate.get("runDetails"), "provenance run details")
    builder_id = snapshot.immutable_inputs.get("builderId")
    if builder_id is None:
        raise OperationalError("Release run has no trusted builder identity")
    if details.get("builder") != {
        "id": builder_id,
        "version": {
            "conclear": IDENTITY.version,
            "conclearSourceRevision": IDENTITY.source_revision,
        },
    }:
        raise RuleRejectionError("Provenance builder identity changed", code="CC0704")
    metadata = object_value(details.get("metadata"), "provenance run metadata")
    if metadata.get("invocationId") != workspace.run_id:
        raise RuleRejectionError(
            "Provenance invocation identity changed", code="CC0704"
        )


def verify_image_signature(
    signer: Signer, subject: OCIReference, public_key: Path
) -> None:
    """Verify one image signature, classifying a failure as `CC0702`."""
    try:
        signer.verify(subject=subject, public_key=public_key)
    except OperationalError as exc:
        raise OperationalError(
            f"Image signature coverage could not be verified for {subject}",
            code="CC0702",
        ) from exc
