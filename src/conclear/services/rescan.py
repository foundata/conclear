"""Digest-bound released-image rescan workflow."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.cosign import (
    SignatureObservation,
    VerificationObservation,
)
from conclear.adapters.skopeo import RegistryCopyObservation
from conclear.adapters.trivy import DatabaseObservation, ScanObservation
from conclear.attestations import (
    RELEASE_VERIFICATION_TYPE,
    RESCAN_TYPE,
    decode_dsse_statements,
    write_statement,
)
from conclear.config import VulnerabilityException
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import atomic_write_json, load_json
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
    validate_record,
)
from conclear.scan_policy import evaluate_trivy_report
from conclear.values import Digest, OCIReference
from conclear.workspace import ResourceKind, ResourceStatus, RunWorkspace


class Registry(Protocol):
    """Registry reads required by a rescan."""

    def copy_registry_to_layout(
        self,
        *,
        source: OCIReference,
        layout_path: Path,
        layout_reference: str,
        auth_file: Path | None,
    ) -> RegistryCopyObservation:
        """Retrieve and validate one immutable image graph."""
        ...


class Signer(Protocol):
    """Signature operations required by a rescan."""

    def verify_attestation(
        self,
        *,
        subject: OCIReference,
        public_key: Path,
        predicate_type: str,
    ) -> VerificationObservation:
        """Verify one predicate type and its public log inclusion."""
        ...

    def download_attestations(
        self, *, subject: OCIReference, predicate_type: str
    ) -> tuple[object, ...]:
        """Download DSSE envelopes for validated inspection."""
        ...

    def attest_statement(
        self,
        *,
        subject: OCIReference,
        statement: Path,
        private_key: str,
        passphrase: str | None,
    ) -> SignatureObservation:
        """Attach a signed complete statement using public logging."""
        ...


class Scanner(Protocol):
    """SBOM vulnerability matcher required by a rescan."""

    def scan_sbom(
        self,
        *,
        sbom_path: Path,
        report_path: Path,
        cache_root: Path,
    ) -> ScanObservation:
        """Match current vulnerability data against retained inventory."""
        ...

    def scan_layout(
        self,
        *,
        layout_path: Path,
        report_path: Path,
        cache_root: Path,
    ) -> ScanObservation:
        """Repeat vulnerability, secret and configuration scans on image content."""
        ...


@dataclass(frozen=True, slots=True)
class RescanSigning:
    """Optional authoritative signing authority for a rescan."""

    private_key: str
    public_key: Path
    passphrase: str | None


@dataclass(frozen=True, slots=True)
class RescanResult:
    """One immutable linked rescan observation."""

    record_path: Path
    record_digest: str
    statement_path: Path | None
    statement_digest: str | None
    authoritative: bool
    verdict: Verdict


def rescan_release(
    subject: OCIReference,
    *,
    workspace: RunWorkspace,
    registry: Registry,
    signer: Signer,
    scanner: Scanner,
    database: DatabaseObservation,
    public_key: Path,
    auth_file: Path | None,
    tools: tuple[ToolIdentity, ...],
    image_id: str,
    expected_configuration_digest: str,
    scope: str,
    exceptions: tuple[VulnerabilityException, ...],
    triage: tuple[dict[str, object], ...],
    previous_result_digest: str | None,
    signing: RescanSigning | None,
    now: datetime,
) -> RescanResult:
    """Verify retained evidence and evaluate all platform SBOMs with current data."""
    if subject.digest is None or subject.tag is not None:
        raise InvalidInvocationError("Rescan subject must be an immutable digest")
    if scope not in {"sbom-vulnerabilities", "full-image"}:
        raise InvalidInvocationError("Unsupported rescan scope")
    if previous_result_digest is not None:
        Digest(previous_result_digest)
    signer.verify_attestation(
        subject=subject,
        public_key=public_key,
        predicate_type=RELEASE_VERIFICATION_TYPE,
    )
    release_statement = _one_statement(
        signer.download_attestations(
            subject=subject, predicate_type=RELEASE_VERIFICATION_TYPE
        ),
        predicate_type=RELEASE_VERIFICATION_TYPE,
        subject_digest=subject.digest,
    )
    release_record = _object(release_statement.get("predicate"), "release record")
    validate_record(release_record)
    if release_record.get("recordType") != "releaseVerification":
        raise OperationalError("Verified release predicate has the wrong record type")
    payload = _object(release_record.get("payload"), "release payload")
    release_subject = _object(payload.get("subject"), "released subject")
    if release_subject.get("digest") != str(subject.digest):
        raise OperationalError("Release verification names another subject digest")
    repository_configuration = _object(
        release_record.get("repositoryConfiguration"), "repository configuration"
    )
    configuration_digest = _string(
        repository_configuration.get("sha256"), "repository configuration digest"
    )
    Digest(configuration_digest)
    if configuration_digest != expected_configuration_digest:
        raise InvalidInvocationError(
            "Rescan repository configuration differs from release verification"
        )
    source_value = _object(release_record.get("source"), "release source")
    source = SourceIdentity(
        _string(source_value.get("repository"), "source repository"),
        _string(source_value.get("revision"), "source revision"),
    )
    remote = registry.copy_registry_to_layout(
        source=subject,
        layout_path=workspace.root / "layouts" / image_id / "rescan",
        layout_reference="rescan",
        auth_file=auth_file,
    )
    if remote.graph.digest != subject.digest:
        raise OperationalError("Retrieved rescan graph differs from released subject")
    manifest_map = {
        item.platform: item.descriptor.digest for item in remote.graph.manifests
    }
    if None in manifest_map:
        raise OperationalError("Released graph has a manifest without a platform")
    recorded_platforms = _object(
        payload.get("platformDigests"), "release platform digests"
    )
    expected_platforms = {
        str(platform): str(digest) for platform, digest in manifest_map.items()
    }
    if recorded_platforms != expected_platforms:
        raise OperationalError(
            "Released platform graph differs from release verification"
        )
    report_root = workspace.root / "reports" / image_id / "rescan"
    report_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    findings: list[dict[str, object]] = []
    for platform, digest in sorted(manifest_map.items()):
        if platform is None:
            raise AssertionError("platform coverage checked above")
        manifest_subject = subject.with_digest(digest)
        signer.verify_attestation(
            subject=manifest_subject,
            public_key=public_key,
            predicate_type="spdxjson",
        )
        statement = _one_statement(
            signer.download_attestations(
                subject=manifest_subject, predicate_type="spdxjson"
            ),
            predicate_type="spdxjson",
            subject_digest=digest,
        )
        sbom = _object(statement.get("predicate"), f"SBOM for {platform}")
        if sbom.get("spdxVersion") != "SPDX-2.3":
            raise OperationalError(f"Unsupported retained SPDX version for {platform}")
        sbom_path = report_root / f"{platform.key}.spdx.json"
        atomic_write_json(sbom_path, sbom, mode=0o644)
        report_path = report_root / f"{platform.key}-scan.json"
        if scope == "full-image":
            platform_layout = workspace.root / "layouts" / image_id / platform.key
            platform_remote = registry.copy_registry_to_layout(
                source=manifest_subject,
                layout_path=platform_layout,
                layout_reference="rescan-platform",
                auth_file=auth_file,
            )
            if platform_remote.graph.digest != digest:
                raise OperationalError(
                    f"Retrieved rescan platform differs for {platform}"
                )
            scan = scanner.scan_layout(
                layout_path=platform_layout,
                report_path=report_path,
                cache_root=database.path,
            )
        else:
            scan = scanner.scan_sbom(
                sbom_path=sbom_path,
                report_path=report_path,
                cache_root=database.path,
            )
        evaluation = evaluate_trivy_report(
            scan.value,
            image_id=image_id,
            exceptions=exceptions,
            today=now.date(),
        )
        findings.extend(
            {
                "platform": str(platform),
                **finding.to_dict(),
            }
            for finding in evaluation.findings
        )
    verdict = (
        Verdict.REJECTED
        if any(item.get("severity") == "error" for item in findings)
        else Verdict.ACCEPTED
    )
    record = RecordEnvelope(
        record_type="rescanResult",
        created_at=now,
        run_id=workspace.run_id,
        source=source,
        configuration_digest=configuration_digest,
        tools=tools,
        verdict=verdict,
        payload={
            "subject": str(subject),
            "platformManifests": expected_platforms,
            "scanner": "trivy",
            "databaseDigest": database.digest,
            "scope": scope,
            "findings": findings,
            "triage": list(triage),
            "previousResultDigest": previous_result_digest,
            "authoritative": signing is not None,
        },
    )
    record_path = workspace.root / "records" / "rescan-result.json"
    record_digest = record.write(record_path)
    if signing is None:
        return RescanResult(record_path, record_digest, None, None, False, verdict)
    statement_path = workspace.root / "records" / "rescan-statement.json"
    statement_digest = write_statement(
        subject_name=subject.repository_name,
        subject_digest=subject.digest,
        predicate_type=RESCAN_TYPE,
        predicate=record.to_dict(),
        path=statement_path,
    )
    workspace.journal.plan(
        resource_id="rescan-result",
        kind=ResourceKind.ATTESTATION,
        identifier=str(subject),
        ephemeral=False,
        metadata={
            "predicateType": RESCAN_TYPE,
            "statementDigest": statement_digest,
        },
    )
    try:
        signer.attest_statement(
            subject=subject,
            statement=statement_path,
            private_key=signing.private_key,
            passphrase=signing.passphrase,
        )
    except Exception:
        workspace.journal.update("rescan-result", ResourceStatus.FAILED)
        raise
    workspace.journal.update("rescan-result", ResourceStatus.CREATED)
    signer.verify_attestation(
        subject=subject,
        public_key=signing.public_key,
        predicate_type=RESCAN_TYPE,
    )
    expected_statement = _object(load_json(statement_path), "rescan statement")
    _exact_statement(
        signer.download_attestations(subject=subject, predicate_type=RESCAN_TYPE),
        predicate_type=RESCAN_TYPE,
        subject_digest=subject.digest,
        expected=expected_statement,
    )
    return RescanResult(
        record_path,
        record_digest,
        statement_path,
        statement_digest,
        True,
        verdict,
    )


def _one_statement(
    envelopes: tuple[object, ...],
    *,
    predicate_type: str,
    subject_digest: Digest,
) -> dict[str, object]:
    matches = [
        statement
        for statement in decode_dsse_statements(envelopes)
        if statement.get("predicateType") == predicate_type
        and _has_subject(statement, subject_digest)
    ]
    if len(matches) != 1:
        raise OperationalError(
            f"Expected exactly one {predicate_type} attestation, found {len(matches)}"
        )
    return matches[0]


def _exact_statement(
    envelopes: tuple[object, ...],
    *,
    predicate_type: str,
    subject_digest: Digest,
    expected: dict[str, object],
) -> dict[str, object]:
    matches = [
        statement
        for statement in decode_dsse_statements(envelopes)
        if statement.get("predicateType") == predicate_type
        and _has_subject(statement, subject_digest)
        and statement == expected
    ]
    if len(matches) != 1:
        raise OperationalError(
            "Expected exactly one copy of the newly attached rescan result, "
            f"found {len(matches)}"
        )
    return matches[0]


def _has_subject(statement: dict[str, object], digest: Digest) -> bool:
    subjects = statement.get("subject")
    return isinstance(subjects, list) and any(
        isinstance(item, dict) and item.get("digest") == {"sha256": digest.encoded}
        for item in subjects
    )


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise OperationalError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise OperationalError(f"{label} must be a non-empty string")
    return value
