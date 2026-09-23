"""Digest-bound released-image rescan workflow."""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
    write_statement,
)
from conclear.config import (
    MAX_REMEDIATION,
    ConfigurationException,
    PackageAssessmentException,
    RuntimeConfig,
    VulnerabilityException,
)
from conclear.database import evaluate_java_database
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import atomic_write_json, sha256_file
from conclear.parsing import object_value, string_value
from conclear.presentation import Finding
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
    format_timestamp,
    parse_timestamp,
)
from conclear.rescan_history import (
    RemediationFindingKey,
    RescanHistoryEntry,
    history_from_records,
)
from conclear.scan_identity import ScanIdentity
from conclear.scan_policy import evaluate_trivy_report, java_artifacts
from conclear.services.attestation_reads import verified_statements
from conclear.services.rescan_evidence import (
    select_release_evidence,
    select_release_sbom,
    verified_predicates,
)
from conclear.spdx import SpdxFormat
from conclear.triage import TriageDecision
from conclear.values import Digest, OCIReference, Platform
from conclear.workspace import ResourceKind, ResourceStatus, RunState, RunWorkspace

LOGGER = logging.getLogger(__name__)


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


class SubjectResolver(Protocol):
    """Registry lookup that distinguishes an absent subject from other failures."""

    def resolve_optional(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest | None:
        """Return no digest only for an unambiguously absent registry reference."""


def require_present_subject(
    resolver: SubjectResolver, subject: OCIReference, *, auth_file: Path | None
) -> None:
    """Fail early when the released subject was retired from the registry.

    A retired subject has no retrievable attestations. Without this check the
    empty registry view would be compared with durable rescan history and be
    reported as a conflict, hiding the actual cause.
    """
    if resolver.resolve_optional(subject, auth_file=auth_file) is None:
        raise OperationalError(
            f"Released subject {subject} is no longer present in the registry; "
            "its release archive remains the retained evidence"
        )


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
        self,
        *,
        subject: OCIReference,
        predicate_type: str,
        allow_missing: bool = False,
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
        passphrase_path: Path | None = None,
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
        identity: ScanIdentity | None = None,
    ) -> ScanObservation:
        """Match current vulnerability data against retained inventory."""
        ...

    def scan_layout(
        self,
        *,
        layout_path: Path,
        report_path: Path,
        cache_root: Path,
        identity: ScanIdentity | None = None,
    ) -> ScanObservation:
        """Repeat vulnerability, secret and configuration scans on image content."""
        ...


@dataclass(frozen=True, slots=True)
class RescanSigning:
    """Optional authoritative signing authority for a rescan."""

    private_key: str
    public_key: Path
    passphrase: str | None
    passphrase_path: Path | None = None


@dataclass(frozen=True, slots=True)
class RescanResult:
    """One immutable linked rescan observation."""

    record_path: Path
    record_digest: str
    statement_path: Path | None
    statement_digest: str | None
    authoritative: bool
    verdict: Verdict
    verified_at: str | None
    active_findings: tuple[RemediationFindingKey, ...]
    release_record_digest: str
    findings: tuple[Finding, ...] = ()


def _public_findings(items: list[dict[str, object]]) -> tuple[Finding, ...]:
    """Lift the record's per-platform findings into the command result.

    The record keeps the platform as its own key; the result names it in the
    location so a rejected rescan says why on the command line, not only in
    the record.
    """
    findings: list[Finding] = []
    for item in items:
        platform = str(item.get("platform", ""))
        location = item.get("location")
        findings.append(
            Finding(
                str(item["checkId"]),
                str(item["severity"]),
                str(item["message"]),
                location=" ".join(
                    part for part in (platform, str(location or "")) if part
                ),
            )
        )
    return tuple(findings)


def verified_rescan_history(
    subject: OCIReference, *, signer: Signer, public_key: Path
) -> tuple[RescanHistoryEntry, ...]:
    """Reconstruct the authoritative chain from verified signed attestations."""
    envelopes = signer.download_attestations(
        subject=subject,
        predicate_type=RESCAN_TYPE,
        allow_missing=True,
    )
    if not envelopes:
        return ()
    statements = verified_statements(
        signer,
        subject=subject,
        public_key=public_key,
        predicate_type=RESCAN_TYPE,
    )
    predicates = verified_predicates(
        statements, predicate_type=RESCAN_TYPE, subject=subject
    )
    return history_from_records(tuple(predicates.values()), subject)


def resolve_triage_platforms(
    triage: tuple[TriageDecision, ...], platforms: tuple[Platform, ...]
) -> dict[Platform, Platform | None]:
    """Map each triage platform to the graph platform it selects, or None.

    Triage names the declared platform spelling; the graph may carry the
    variant Buildah wrote (`linux/arm64/v8`). Both spell the same target, so
    decisions are keyed by the graph's platform.
    """
    return {
        item.platform: next(
            (
                candidate
                for candidate in platforms
                if candidate.semantically_matches(item.platform)
            ),
            None,
        )
        for item in triage
    }


def _settle_rescan_run(workspace: RunWorkspace, verdict: Verdict) -> None:
    """Move a rescan run to its terminal state once its record exists.

    A rescan is not a release and has no intermediate states; leaving it in
    `created` would make a finished rescan indistinguishable from a run that
    stopped before doing anything.
    """
    workspace.transition(
        RunState.COMPLETED if verdict is Verdict.ACCEPTED else RunState.REJECTED
    )


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
    triage: tuple[TriageDecision, ...],
    previous_result_digest: str | None,
    remediation_limit: timedelta,
    remediation_history: tuple[RescanHistoryEntry, ...],
    signing: RescanSigning | None,
    now: datetime,
    record_clock: Callable[[], datetime],
    runtime_rules: RuntimeConfig | None = None,
    package_assessment_exception: PackageAssessmentException | None = None,
    configuration_exceptions: tuple[ConfigurationException, ...] = (),
    accept_stale_java_database: bool = False,
) -> RescanResult:
    """Verify retained evidence and evaluate all platform SBOMs with current data."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise OperationalError("Rescan time must be timezone-aware")
    if subject.digest is None or subject.tag is not None:
        raise InvalidInvocationError("Rescan subject must be an immutable digest")
    if scope not in {"sbom-vulnerabilities", "full-image"}:
        raise InvalidInvocationError("Unsupported rescan scope")
    if remediation_limit <= timedelta(0) or remediation_limit > MAX_REMEDIATION:
        raise InvalidInvocationError(
            "Rescan remediation limit must be positive and at most 30 days"
        )
    if previous_result_digest is not None:
        Digest(previous_result_digest)
    history_digest = (
        remediation_history[-1].record_digest if remediation_history else None
    )
    if history_digest != previous_result_digest:
        raise InvalidInvocationError(
            "Rescan remediation history does not match the previous result"
        )
    anchors = {item.release_record_digest for item in remediation_history}
    if len(anchors) > 1:
        raise OperationalError("Rescan history changes its release record anchor")
    LOGGER.info("Rescanning %s", subject)
    release = select_release_evidence(
        verified_statements(
            signer,
            subject=subject,
            public_key=public_key,
            predicate_type=RELEASE_VERIFICATION_TYPE,
        ),
        subject=subject,
        configuration_digest=expected_configuration_digest,
        anchored_digest=next(iter(anchors), None),
    )
    payload = release.payload
    source_value = object_value(release.record.get("source"), "release source")
    source = SourceIdentity(
        string_value(source_value.get("repository"), "source repository"),
        string_value(source_value.get("revision"), "source revision"),
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
        raise OperationalError(
            "Released graph has a manifest without a platform", code="CC0801"
        )
    recorded_platforms = object_value(
        payload.get("platformDigests"), "release platform digests"
    )
    expected_platforms = {
        str(platform): str(digest) for platform, digest in manifest_map.items()
    }
    graph_platform = resolve_triage_platforms(triage, tuple(manifest_map))
    unknown_triage_platforms = sorted(
        {
            str(platform)
            for platform, resolved in graph_platform.items()
            if resolved is None
        }
    )
    if unknown_triage_platforms:
        raise InvalidInvocationError(
            "Rescan triage names platforms outside the released subject: "
            + ", ".join(unknown_triage_platforms)
        )
    for decision in triage:
        decided_at = parse_timestamp(
            decision.decided_at, "triage decision time", error=InvalidInvocationError
        )
        if decided_at > now.astimezone(UTC):
            raise InvalidInvocationError(
                "Rescan triage decisions cannot be dated in the future"
            )
    triage_map = {
        (graph_platform[item.platform], item.component, item.advisory): item
        for item in triage
    }
    if recorded_platforms != expected_platforms:
        raise OperationalError(
            "Released platform graph differs from release verification", code="CC0801"
        )
    report_root = workspace.root / "reports" / image_id / "rescan"
    report_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    findings: list[dict[str, object]] = []
    applied_exceptions: list[dict[str, object]] = []
    applied_configuration_exceptions: list[dict[str, object]] = []
    applied_runtime_requirements: list[dict[str, object]] = []
    active_findings: set[RemediationFindingKey] = set()
    severities: dict[tuple[Platform, str, str], tuple[str, str | None]] = {}
    java_artifact_count = 0
    evidence = object_value(payload.get("evidence"), "release evidence")
    raw_sboms = evidence.get("sboms")
    if not isinstance(raw_sboms, list) or not all(
        isinstance(item, str) for item in raw_sboms
    ):
        raise OperationalError("Release SBOM references are malformed")
    sbom_digests = frozenset(string_value(item, "SBOM digest") for item in raw_sboms)
    sbom_format = SpdxFormat.from_record(payload.get("sbom"), label="release SBOM")
    consumed_sboms: set[str] = set()
    scan_results: list[dict[str, object]] = []
    for platform, digest in sorted(manifest_map.items()):
        if platform is None:
            raise OperationalError(
                "Rescan platform coverage invariant failed", code="CC0801"
            )
        manifest_subject = subject.with_digest(digest)
        sbom_digest, sbom = select_release_sbom(
            verified_statements(
                signer,
                subject=manifest_subject,
                public_key=public_key,
                predicate_type=sbom_format.predicate_type,
            ),
            subject=manifest_subject,
            evidence_digests=sbom_digests,
            sbom_format=sbom_format,
        )
        consumed_sboms.add(sbom_digest)
        sbom_path = report_root / f"{platform.key}.spdx.json"
        atomic_write_json(sbom_path, sbom, mode=0o644)
        platform_java = evaluate_java_database(
            database.metadata,
            at=now,
            artifacts=java_artifacts(sbom),
            accepted_stale=accept_stale_java_database,
        )
        java_artifact_count += platform_java.artifacts
        if platform_java.finding is not None:
            findings.append(
                {"platform": str(platform), **platform_java.finding.to_dict()}
            )
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
                identity=ScanIdentity(
                    workspace_root=workspace.root,
                    subject=str(manifest_subject),
                    artifact_path=platform_layout,
                ),
            )
        else:
            scan = scanner.scan_sbom(
                sbom_path=sbom_path,
                report_path=report_path,
                cache_root=database.path,
                identity=ScanIdentity(
                    workspace_root=workspace.root,
                    subject=str(manifest_subject),
                    artifact_path=sbom_path,
                ),
            )
        scan_results.append(
            {
                "platform": str(platform),
                "sbomDigest": sha256_file(sbom_path),
                "reportDigest": sha256_file(report_path),
                "javaArtifacts": platform_java.artifacts,
            }
        )
        evaluation = evaluate_trivy_report(
            scan.value,
            image_id=image_id,
            exceptions=exceptions,
            today=now.date(),
            runtime=runtime_rules,
            expect_packages=True,
            package_assessment_exception=package_assessment_exception,
            configuration_exceptions=configuration_exceptions,
        )
        applied_configuration_exceptions.extend(
            {"platform": str(platform), **item.to_dict()}
            for item in evaluation.applied_configuration_exceptions
        )
        scan_results[-1]["packageAssessment"] = (
            None
            if evaluation.package_assessment is None
            else evaluation.package_assessment.to_dict()
        )
        suppressed = set()
        for vulnerability in evaluation.fixable_vulnerabilities:
            severities[(platform, vulnerability.component, vulnerability.advisory)] = (
                vulnerability.severity,
                vulnerability.severity_source,
            )
            triage_decision = triage_map.get(
                (platform, vulnerability.component, vulnerability.advisory)
            )
            if (
                vulnerability.finding is not None
                and triage_decision is not None
                and triage_decision.decision == "not-applicable"
            ):
                suppressed.add(vulnerability.finding)
            elif vulnerability.finding is not None and not (
                triage_decision is not None and triage_decision.decision == "remediated"
            ):
                active_findings.add(
                    RemediationFindingKey(
                        platform=platform,
                        component=vulnerability.component,
                        advisory=vulnerability.advisory,
                    )
                )
        findings.extend(
            {
                "platform": str(platform),
                **finding.to_dict(),
            }
            for finding in evaluation.findings
            if finding not in suppressed
        )
        applied_exceptions.extend(
            {"platform": str(platform), **item.to_dict()}
            for item in evaluation.applied_exceptions
        )
        applied_runtime_requirements.extend(
            {"platform": str(platform), **item}
            for item in evaluation.applied_runtime_requirements
        )
    if consumed_sboms != sbom_digests:
        raise OperationalError("Release SBOM references do not match platform coverage")
    remediation_findings: list[dict[str, object]] = []
    for finding in sorted(active_findings):
        started_at = _remediation_start(finding, remediation_history)
        deadline = None if started_at is None else started_at + remediation_limit
        overdue = deadline is not None and now.astimezone(UTC) >= deadline
        severity, severity_source = severities.get(
            (finding.platform, finding.component, finding.advisory), (None, None)
        )
        remediation_findings.append(
            {
                **finding.to_dict(),
                "severity": severity,
                "severitySource": severity_source,
                "startedAt": (
                    None if started_at is None else format_timestamp(started_at)
                ),
                "deadline": None if deadline is None else format_timestamp(deadline),
                "overdue": overdue,
            }
        )
        if overdue:
            findings.append(
                {
                    "platform": str(finding.platform),
                    "checkId": "CC0802",
                    "severity": "error",
                    "message": (
                        "Fixable vulnerability exceeded the effective "
                        f"remediation deadline: {finding.advisory} in "
                        f"{finding.component}"
                    ),
                    "location": finding.component,
                }
            )
    verdict = (
        Verdict.REJECTED
        if any(item.get("severity") == "error" for item in findings)
        else Verdict.ACCEPTED
    )
    recorded_at = record_clock()
    if recorded_at.tzinfo is None or recorded_at.utcoffset() is None:
        raise OperationalError("Rescan record clock returned a naive timestamp")
    record = RecordEnvelope(
        record_type="rescanResult",
        created_at=recorded_at,
        run_id=workspace.run_id,
        source=source,
        configuration_digest=expected_configuration_digest,
        tools=tools,
        verdict=verdict,
        payload={
            "subject": str(subject),
            "releaseRecordDigest": release.digest,
            "platformManifests": expected_platforms,
            "scanner": _scanner_identity(tools),
            "databaseDigest": database.digest,
            "databaseMetadata": database.metadata,
            "javaDatabase": evaluate_java_database(
                database.metadata,
                at=now,
                artifacts=java_artifact_count,
                accepted_stale=accept_stale_java_database,
            ).to_dict(),
            "scanResults": scan_results,
            **{
                name: input_digest
                for name, input_digest in workspace.load().immutable_inputs.items()
                if name in {"sourceTreeDigest", "releaseArchiveDigest"}
            },
            "scope": scope,
            "findings": findings,
            "appliedExceptions": applied_exceptions,
            "appliedConfigurationExceptions": applied_configuration_exceptions,
            "appliedRuntimeRequirements": applied_runtime_requirements,
            "triage": [item.to_dict() for item in triage],
            "previousResultDigest": previous_result_digest,
            "authoritative": signing is not None,
            "remediation": {
                "limitSeconds": int(remediation_limit.total_seconds()),
                "findings": remediation_findings,
            },
        },
    )
    record_path = workspace.root / "records" / "rescan-result.json"
    record_digest = record.write(record_path)
    if signing is None:
        _settle_rescan_run(workspace, verdict)
        return RescanResult(
            record_path,
            record_digest,
            None,
            None,
            False,
            verdict,
            None,
            tuple(sorted(active_findings)),
            release.digest,
            findings=_public_findings(findings),
        )
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
            passphrase_path=signing.passphrase_path,
        )
        attested_history = verified_rescan_history(
            subject,
            signer=signer,
            public_key=signing.public_key,
        )
        expected_history = (
            *remediation_history,
            RescanHistoryEntry(
                record_digest=record_digest,
                release_record_digest=release.digest,
                verified_at=recorded_at,
                active_findings=tuple(sorted(active_findings)),
            ),
        )
        if attested_history != expected_history:
            raise OperationalError(
                "Post-attachment rescan history differs from the intended chain"
            )
    except Exception:
        workspace.journal.update("rescan-result", ResourceStatus.FAILED)
        raise
    verified_at = format_timestamp(recorded_at)
    workspace.journal.update(
        "rescan-result",
        ResourceStatus.CREATED,
        metadata={"verifiedAt": verified_at},
    )
    _settle_rescan_run(workspace, verdict)
    return RescanResult(
        record_path,
        record_digest,
        statement_path,
        statement_digest,
        True,
        verdict,
        verified_at,
        tuple(sorted(active_findings)),
        release.digest,
        findings=_public_findings(findings),
    )


def _remediation_start(
    finding: RemediationFindingKey,
    history: tuple[RescanHistoryEntry, ...],
) -> datetime | None:
    started_at: datetime | None = None
    for entry in reversed(history):
        if finding not in entry.active_findings:
            break
        started_at = entry.verified_at
    return started_at


def _scanner_identity(tools: tuple[ToolIdentity, ...]) -> str:
    matches = [tool for tool in tools if tool.name == "trivy"]
    if len(matches) != 1:
        raise OperationalError(
            "Rescan evidence requires exactly one Trivy tool identity"
        )
    return f"trivy {matches[0].version}"
