"""Retained release payloads and source remain useful after qualification expires."""

import shutil
import tarfile
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from conclear.adapters.trivy import DatabaseObservation
from conclear.config import load_repository_config
from conclear.errors import InvalidInvocationError
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import load_json, sha256_bytes, sha256_file
from conclear.records import Verdict
from conclear.services.rescan import RescanResult, rescan_release
from conclear.transport import TransportKind, export_transport
from conclear.values import OCIReference, Platform
from conclear.workspace import RunWorkspace
from tests.unit.test_release_workflow import NOW, FixedIdFactory, Harness
from tests.unit.test_rescan import DATABASE_METADATA, FakeScanner


def test_promoted_qualification_export_retains_payload_bytes_but_not_private_files(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    harness.complete()
    monkeypatch.setattr(
        "conclear.transport.IDENTITY", ApplicationIdentity(source_revision="c" * 40)
    )
    workspace = harness.workspace
    private = workspace.root / "reports/app/linux-amd64/test-inputs/outputs/private"
    private.mkdir(parents=True)
    (private / "secret").write_text("private-test-secret", encoding="utf-8")
    (workspace.root / "logs/command.log").write_text(
        "private-command-output", encoding="utf-8"
    )
    result = export_transport(
        workspace,
        harness.image,
        Platform.parse("linux/amd64"),
        destination=tmp_path / "platform-linux-amd64.tar",
        kind=TransportKind.ARCHIVE,
        now=NOW + timedelta(days=30),
    )
    contents: dict[str, bytes] = {}
    with tarfile.open(result.path) as archive:
        for entry in archive.getmembers():
            if entry.isfile():
                stream = archive.extractfile(entry)
                assert stream is not None
                contents[entry.name] = stream.read()
    for member in result.members:
        assert sha256_bytes(contents[member.path]) == member.digest
    assert set(result.payload_digests) <= {
        sha256_bytes(content) for content in contents.values()
    }
    for expected in (
        "records/platform-qualification-linux-amd64.json",
        "reports/linux-amd64/tests.json",
        "reports/linux-amd64/source-scan.json",
        "reports/linux-amd64/containerfile-scan.json",
        "reports/linux-amd64/image-scan.json",
        "exports/sbom/linux-amd64.spdx.json",
    ):
        assert expected in contents
    assert not any("logs/" in name or "test-inputs/" in name for name in contents)
    assert not any(b"private-test-secret" in value for value in contents.values())
    assert not any(b"private-command-output" in value for value in contents.values())
    verification = load_json(workspace.root / "records/release-verification.json")
    assert (
        result.record_digest
        in verification["payload"]["evidence"]["platformQualifications"]
    )
    assert (
        sha256_file(harness.source_root / "conclear.toml")
        == verification["repositoryConfiguration"]["sha256"]
    )


def test_restored_source_allows_rescan_when_current_configuration_has_changed(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    released = harness.complete()
    retained = shutil.copytree(harness.source_root, tmp_path / "retained-source")
    restored = load_repository_config(retained / "conclear.toml")
    current_path = harness.source_root / "conclear.toml"
    current_path.write_bytes(current_path.read_bytes() + b"\n# Later maintenance\n")
    current = load_repository_config(current_path)
    assert current.raw_bytes != restored.raw_bytes
    workspace = RunWorkspace.create(
        state_home=tmp_path / "rescan-state",
        immutable_inputs={"subject": released.subject},
        id_factory=FixedIdFactory(),
        now=NOW + timedelta(days=31),
    )
    scanner = FakeScanner()
    image = restored.release_image("app")

    def assess(configuration_digest: str) -> RescanResult:
        return rescan_release(
            OCIReference.parse(released.subject, require_digest=True),
            workspace=workspace,
            registry=harness.runtime.registry,
            signer=harness.runtime.signer,
            scanner=scanner,
            database=DatabaseObservation(
                tmp_path, "sha256:" + "f" * 64, DATABASE_METADATA
            ),
            public_key=harness.profile.cosign_public_key,
            auth_file=None,
            tools=harness.runtime.identities,
            image_id="app",
            expected_configuration_digest=configuration_digest,
            scope="sbom-vulnerabilities",
            exceptions=image.vulnerability_exceptions,
            triage=(),
            previous_result_digest=None,
            remediation_limit=image.release_limits.remediation,
            remediation_history=(),
            signing=None,
            now=NOW + timedelta(days=31),
            record_clock=lambda: NOW + timedelta(days=31, minutes=1),
            runtime_rules=image.runtime,
        )

    with pytest.raises(InvalidInvocationError, match="source checkout retained"):
        assess(sha256_bytes(current.raw_bytes))
    assert scanner.sbom_scans == 0
    result = assess(sha256_bytes(restored.raw_bytes))
    assert scanner.sbom_scans == 1
    assert result.verdict is Verdict.REJECTED
    assert not result.authoritative
    record = load_json(result.record_path)
    assert record["repositoryConfiguration"]["sha256"] == sha256_bytes(
        restored.raw_bytes
    )
    assert record["payload"]["databaseDigest"] == "sha256:" + "f" * 64
