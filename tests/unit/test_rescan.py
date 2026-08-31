import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import conclear.records as records_module
from conclear.adapters.cosign import (
    SignatureObservation,
    VerificationObservation,
)
from conclear.adapters.skopeo import RegistryCopyObservation
from conclear.adapters.trivy import DatabaseObservation, ScanObservation
from conclear.attestations import (
    RELEASE_VERIFICATION_TYPE,
    RESCAN_TYPE,
    STATEMENT_TYPE,
)
from conclear.config import VulnerabilityException
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import atomic_write_json, canonical_json_bytes, load_json
from conclear.oci import (
    OCI_CONFIG,
    OCI_INDEX,
    OCI_MANIFEST,
    Descriptor,
    ManifestObservation,
    OCIGraph,
)
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
)
from conclear.rescan_history import (
    RemediationFindingKey,
    RescanHistoryEntry,
)
from conclear.services.rescan import RescanResult, RescanSigning, rescan_release
from conclear.triage import TriageDecision
from conclear.values import Digest, OCIReference, Platform
from conclear.workspace import ResourceStatus, RunWorkspace


class IdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


DATABASE_METADATA: dict[str, object] = {
    name: {
        "schemaVersion": version,
        "updatedAt": "2026-01-01T00:00:00Z",
        "nextUpdate": "2026-02-02T00:00:00Z",
        "downloadedAt": "2026-02-01T00:01:00Z",
    }
    for name, version in (("vulnerability", 2), ("java", 1))
}


class FakeRegistry:
    def __init__(self, graph: OCIGraph) -> None:
        self.graph = graph

    def copy_registry_to_layout(
        self,
        *,
        source: OCIReference,
        layout_path: Path,
        layout_reference: str,
        auth_file: Path | None,
    ) -> RegistryCopyObservation:
        del layout_reference, auth_file
        if source.digest != self.graph.root.digest:
            manifests = tuple(
                manifest
                for manifest in self.graph.manifests
                if manifest.descriptor.digest == source.digest
            )
            assert len(manifests) == 1
            manifest = manifests[0]
            graph = OCIGraph(
                root=manifest.descriptor,
                descriptors=(manifest.descriptor, manifest.config, *manifest.layers),
                manifests=(manifest,),
            )
            return RegistryCopyObservation(source, layout_path, graph)
        return RegistryCopyObservation(source, layout_path, self.graph)


class FakeSigner:
    def __init__(self) -> None:
        self.statements: dict[tuple[str, str], list[dict[str, object]]] = {}
        self.fail_rescan_verification = False

    def verify_attestation(
        self,
        *,
        subject: OCIReference,
        public_key: Path,
        predicate_type: str,
    ) -> VerificationObservation:
        assert public_key.is_file()
        assert (str(subject), predicate_type) in self.statements
        if self.fail_rescan_verification and predicate_type == RESCAN_TYPE:
            raise OperationalError("post-attachment verification failed")
        return VerificationObservation(subject, ({"verified": True},))

    def download_attestations(
        self, *, subject: OCIReference, predicate_type: str
    ) -> tuple[object, ...]:
        return tuple(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(canonical_json_bytes(statement)).decode(
                    "ascii"
                ),
            }
            for statement in self.statements[(str(subject), predicate_type)]
        )

    def attest_statement(
        self,
        *,
        subject: OCIReference,
        statement: Path,
        private_key: str,
        passphrase: str | None,
    ) -> SignatureObservation:
        del private_key, passphrase
        value = load_json(statement)
        assert isinstance(value, dict)
        predicate_type = value.get("predicateType")
        assert isinstance(predicate_type, str)
        self.statements.setdefault((str(subject), predicate_type), []).append(
            {str(key): item for key, item in value.items()}
        )
        return SignatureObservation(subject, "attested")

    def add(
        self,
        subject: OCIReference,
        predicate_type: str,
        predicate: dict[str, object],
    ) -> None:
        assert subject.digest is not None
        self.statements.setdefault((str(subject), predicate_type), []).append(
            {
                "_type": STATEMENT_TYPE,
                "subject": [
                    {
                        "name": subject.repository_name,
                        "digest": {"sha256": subject.digest.encoded},
                    }
                ],
                "predicateType": predicate_type,
                "predicate": predicate,
            }
        )


class FakeScanner:
    def __init__(self) -> None:
        self.sbom_scans = 0
        self.layout_scans = 0

    def scan_sbom(
        self,
        *,
        sbom_path: Path,
        report_path: Path,
        cache_root: Path,
    ) -> ScanObservation:
        self.sbom_scans += 1
        assert sbom_path.is_file()
        assert cache_root.is_dir()
        value = _scan_report()
        digest = atomic_write_json(report_path, value)
        return ScanObservation(report_path, digest, value)

    def scan_layout(
        self,
        *,
        layout_path: Path,
        report_path: Path,
        cache_root: Path,
    ) -> ScanObservation:
        assert layout_path
        assert cache_root.is_dir()
        self.layout_scans += 1
        value = _scan_report()
        digest = atomic_write_json(report_path, value)
        return ScanObservation(report_path, digest, value)


def _scan_report() -> dict[str, object]:
    return {
        "Results": [
            {
                "Target": "app",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "libssl",
                        "Severity": "CRITICAL",
                        "FixedVersion": "2.0",
                    }
                ],
            }
        ]
    }


def _exception() -> VulnerabilityException:
    return VulnerabilityException(
        image="app",
        component="libssl",
        advisory="CVE-2026-0001",
        rationale="Not reachable",
        reachability="No call path",
        exposure="Local only",
        compensating_controls="Seccomp",
        owner="security@example.com",
        expires="2026-12-31",
        review_trigger="Package update",
    )


@pytest.mark.parametrize(
    (
        "scope",
        "fail_post_verification",
        "triage_platform",
        "wrong_release_name",
        "use_exception",
        "triage_decision",
        "future_triage",
    ),
    [
        (
            "sbom-vulnerabilities",
            False,
            "linux/amd64",
            False,
            False,
            "not-applicable",
            False,
        ),
        ("sbom-vulnerabilities", False, "linux/amd64", False, False, "affected", False),
        ("full-image", False, "linux/amd64", False, True, "not-applicable", False),
        (
            "sbom-vulnerabilities",
            True,
            "linux/amd64",
            False,
            True,
            "not-applicable",
            False,
        ),
        (
            "sbom-vulnerabilities",
            False,
            "linux/arm64",
            False,
            True,
            "not-applicable",
            False,
        ),
        (
            "sbom-vulnerabilities",
            False,
            "linux/amd64",
            True,
            True,
            "not-applicable",
            False,
        ),
        (
            "sbom-vulnerabilities",
            False,
            "linux/amd64",
            False,
            True,
            "not-applicable",
            True,
        ),
    ],
)
def test_authoritative_rescan_verifies_complete_retained_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    fail_post_verification: bool,
    triage_platform: str,
    wrong_release_name: bool,
    use_exception: bool,
    triage_decision: str,
    future_triage: bool,
) -> None:
    monkeypatch.setattr(
        records_module,
        "IDENTITY",
        ApplicationIdentity(source_revision="c" * 40),
    )
    root_digest = Digest("sha256:" + "a" * 64)
    manifest_digest = Digest("sha256:" + "b" * 64)
    config_digest = Digest("sha256:" + "c" * 64)
    platform = Platform.parse("linux/amd64")
    root = Descriptor(OCI_INDEX, root_digest, 100)
    manifest_descriptor = Descriptor(
        OCI_MANIFEST, manifest_digest, 90, platform=platform
    )
    config = Descriptor(OCI_CONFIG, config_digest, 20)
    graph = OCIGraph(
        root=root,
        descriptors=(root, manifest_descriptor, config),
        manifests=(
            ManifestObservation(
                manifest_descriptor,
                platform,
                config,
                (),
                {"architecture": "amd64", "os": "linux"},
            ),
        ),
    )
    subject = OCIReference.parse(
        f"quay.io/example/app@{root_digest}", require_digest=True
    )
    manifest_subject = subject.with_digest(manifest_digest)
    run = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={"subject": str(subject)},
        id_factory=IdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    configuration_digest = "sha256:" + "d" * 64
    release_record = RecordEnvelope(
        record_type="releaseVerification",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        run_id=run.run_id,
        source=SourceIdentity("https://github.com/example/app", "e" * 40),
        configuration_digest=configuration_digest,
        tools=(),
        verdict=Verdict.ACCEPTED,
        payload={
            "subject": {
                "repository": subject.repository_name,
                "digest": str(root_digest),
            },
            "platformDigests": {str(platform): str(manifest_digest)},
            "releaseEnvironment": {
                "mode": "local",
                "hostArchitecture": "x86_64",
                "runId": run.run_id,
            },
            "signer": {"mode": "managed-key", "keyId": "test-key"},
            "evidence": {
                "platformQualifications": ["sha256:" + "1" * 64],
                "scanResults": ["sha256:" + "2" * 64],
                "sboms": ["sha256:" + "3" * 64],
                "provenance": "sha256:" + "4" * 64,
                "candidateRecord": "sha256:" + "5" * 64,
            },
        },
    ).to_dict()
    signer = FakeSigner()
    signer.add(subject, RELEASE_VERIFICATION_TYPE, release_record)
    if wrong_release_name:
        release_statement = signer.statements[
            (str(subject), RELEASE_VERIFICATION_TYPE)
        ][0]
        release_statement["subject"] = [
            {
                "name": "quay.io/example/other",
                "digest": {"sha256": root_digest.encoded},
            }
        ]
    signer.add(
        manifest_subject,
        "spdxjson",
        {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "app",
            "documentNamespace": "https://example.invalid/spdx/app",
            "creationInfo": {
                "creators": ["Tool: test"],
                "created": "2026-01-01T00:00:00Z",
            },
        },
    )
    signer.add(subject, RESCAN_TYPE, {"historical": True})
    signer.fail_rescan_verification = fail_post_verification
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("test", encoding="utf-8")
    cache = tmp_path / "trivy-cache"
    cache.mkdir()
    database = DatabaseObservation(cache, "sha256:" + "6" * 64, DATABASE_METADATA)

    scanner = FakeScanner()
    triage = (
        TriageDecision(
            subject=subject,
            platform=Platform.parse(triage_platform),
            component="libssl",
            advisory="CVE-2026-0001",
            decision=triage_decision,
            rationale="The vulnerable function is not reachable.",
            owner="security@example.com",
            decided_at=(
                "2026-02-02T00:00:00Z" if future_triage else "2026-02-01T00:00:00Z"
            ),
            remediating_digest=None,
        ),
    )
    previous_result_digest = (
        "sha256:" + "8" * 64
        if triage_decision == "affected" and not use_exception
        else None
    )
    remediation_history = (
        (
            RescanHistoryEntry(
                record_digest=previous_result_digest,
                verified_at=datetime(2026, 1, 1, tzinfo=UTC),
                active_findings=(
                    RemediationFindingKey(
                        platform=platform,
                        component="libssl",
                        advisory="CVE-2026-0001",
                    ),
                ),
            ),
        )
        if previous_result_digest is not None
        else ()
    )

    def run_rescan() -> RescanResult:
        return rescan_release(
            subject,
            workspace=run,
            registry=FakeRegistry(graph),
            signer=signer,
            scanner=scanner,
            database=database,
            public_key=public_key,
            auth_file=None,
            tools=(
                ToolIdentity("trivy", "0.69.3", executable_digest="sha256:" + "7" * 64),
            ),
            image_id="app",
            expected_configuration_digest=configuration_digest,
            scope=scope,
            exceptions=((_exception(),) if use_exception else ()),
            triage=triage,
            previous_result_digest=previous_result_digest,
            remediation_limit=timedelta(days=30),
            remediation_history=remediation_history,
            signing=RescanSigning("test.key", public_key, "secret"),
            now=datetime(2026, 2, 1, tzinfo=UTC),
            clock=lambda: datetime(2026, 2, 1, 0, 5, tzinfo=UTC),
        )

    if future_triage:
        with pytest.raises(InvalidInvocationError, match="dated in the future"):
            run_rescan()
        assert run.journal.entries() == ()
        return
    if wrong_release_name:
        with pytest.raises(OperationalError, match="exactly one"):
            run_rescan()
        assert run.journal.entries() == ()
        return
    if triage_platform == "linux/arm64":
        with pytest.raises(InvalidInvocationError, match="outside the released"):
            run_rescan()
        assert run.journal.entries() == ()
        return
    if fail_post_verification:
        with pytest.raises(OperationalError, match="post-attachment"):
            run_rescan()
        entry = run.journal.entries()[0]
        assert entry.status is ResourceStatus.FAILED
        assert "verifiedAt" not in entry.metadata
        return

    result = run_rescan()

    assert result.authoritative
    assert result.verdict is (
        Verdict.REJECTED if triage_decision == "affected" else Verdict.ACCEPTED
    )
    assert result.statement_path is not None
    record = load_json(result.record_path)
    assert record["payload"]["databaseDigest"] == database.digest
    assert record["payload"]["scanner"] == "trivy 0.69.3"
    expected_exceptions = (
        [
            {
                "platform": "linux/amd64",
                "image": "app",
                "component": "libssl",
                "advisory": "CVE-2026-0001",
                "expires": "2026-12-31",
            }
        ]
        if use_exception
        else []
    )
    assert record["payload"]["appliedExceptions"] == expected_exceptions
    expected_finding_count = (
        2 if triage_decision == "affected" and not use_exception else 0
    )
    assert len(record["payload"]["findings"]) == expected_finding_count
    expected_remediation = (
        [
            {
                "platform": "linux/amd64",
                "component": "libssl",
                "advisory": "CVE-2026-0001",
                "startedAt": "2026-01-01T00:00:00Z",
                "deadline": "2026-01-31T00:00:00Z",
                "overdue": True,
            }
        ]
        if triage_decision == "affected" and not use_exception
        else []
    )
    assert record["payload"]["remediation"] == {
        "limitSeconds": 2592000,
        "findings": expected_remediation,
    }
    assert record["payload"]["triage"] == [triage[0].to_dict()]
    assert scanner.sbom_scans == (1 if scope == "sbom-vulnerabilities" else 0)
    assert scanner.layout_scans == (1 if scope == "full-image" else 0)
    entry = run.journal.entries()[0]
    assert entry.resource_id == "rescan-result"
    assert entry.status is ResourceStatus.CREATED
    assert entry.metadata["verifiedAt"] == "2026-02-01T00:05:00Z"
    assert result.verified_at == "2026-02-01T00:05:00Z"
