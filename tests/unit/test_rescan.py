import base64
from datetime import UTC, datetime
from pathlib import Path

import pytest

import conclear.records as records_module
from conclear.adapters.cosign import (
    SignatureObservation,
    VerificationObservation,
)
from conclear.adapters.skopeo import RegistryCopyObservation
from conclear.adapters.trivy import DatabaseObservation, ScanObservation
from conclear.attestations import RELEASE_VERIFICATION_TYPE, STATEMENT_TYPE
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
from conclear.records import RecordEnvelope, SourceIdentity, Verdict
from conclear.services.rescan import RescanSigning, rescan_release
from conclear.values import Digest, OCIReference, Platform
from conclear.workspace import RunWorkspace


class IdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


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
        return RegistryCopyObservation(source, layout_path, self.graph)


class FakeSigner:
    def __init__(self) -> None:
        self.statements: dict[tuple[str, str], list[dict[str, object]]] = {}

    def verify_attestation(
        self,
        *,
        subject: OCIReference,
        public_key: Path,
        predicate_type: str,
    ) -> VerificationObservation:
        assert public_key.is_file()
        assert (str(subject), predicate_type) in self.statements
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
    def scan_sbom(
        self,
        *,
        sbom_path: Path,
        report_path: Path,
        cache_root: Path,
    ) -> ScanObservation:
        assert sbom_path.is_file()
        assert cache_root.is_dir()
        value: dict[str, object] = {"Results": []}
        digest = atomic_write_json(report_path, value)
        return ScanObservation(report_path, digest, value)


def test_authoritative_rescan_verifies_complete_retained_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
    signer.add(
        manifest_subject,
        "spdxjson",
        {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "app",
        },
    )
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("test", encoding="utf-8")
    cache = tmp_path / "trivy-cache"
    cache.mkdir()
    database = DatabaseObservation(cache, "sha256:" + "6" * 64, {})

    result = rescan_release(
        subject,
        workspace=run,
        registry=FakeRegistry(graph),
        signer=signer,
        scanner=FakeScanner(),
        database=database,
        public_key=public_key,
        auth_file=None,
        tools=(),
        image_id="app",
        exceptions=(),
        triage=(),
        previous_result_digest=None,
        signing=RescanSigning("test.key", public_key, "secret"),
        now=datetime(2026, 2, 1, tzinfo=UTC),
    )

    assert result.authoritative
    assert result.verdict is Verdict.ACCEPTED
    assert result.statement_path is not None
    assert load_json(result.record_path)["payload"]["databaseDigest"] == database.digest
