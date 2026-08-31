from datetime import UTC, datetime
from pathlib import Path

import pytest

import conclear.records as records_module
from conclear.identity import ApplicationIdentity
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
    validate_record,
)


def _record() -> RecordEnvelope:
    digest = "sha256:" + "a" * 64
    return RecordEnvelope(
        record_type="rescanResult",
        created_at=datetime(2026, 8, 31, 10, 30, tzinfo=UTC),
        run_id="01k3z8h6v4n7c2m9p5q1r0s8tx",
        source=SourceIdentity(
            repository="https://github.com/example/app",
            revision="b" * 40,
        ),
        configuration_digest=digest,
        tools=(ToolIdentity("trivy", "0.69.3", executable_digest=digest),),
        verdict=Verdict.ACCEPTED,
        payload={
            "subject": f"quay.io/example/app@{digest}",
            "platformManifests": {"linux/amd64": digest},
            "scanner": "trivy 0.69.3",
            "databaseDigest": digest,
            "databaseMetadata": {
                name: {
                    "schemaVersion": version,
                    "updatedAt": "2026-08-31T09:00:00Z",
                    "nextUpdate": "2026-09-01T09:00:00Z",
                    "downloadedAt": "2026-08-31T09:01:00Z",
                }
                for name, version in (("vulnerability", 2), ("java", 1))
            },
            "scope": "sbom-vulnerabilities",
            "findings": [],
            "appliedExceptions": [],
            "triage": [],
            "previousResultDigest": None,
            "authoritative": False,
        },
    )


@pytest.fixture(autouse=True)
def embedded_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        records_module,
        "IDENTITY",
        ApplicationIdentity(source_revision="c" * 40),
    )


def test_record_serialization_is_deterministic_and_schema_valid() -> None:
    record = _record()
    assert record.content_bytes() == record.content_bytes()
    validate_record(record.to_dict())
    assert record.digest().startswith("sha256:")


def test_record_write_is_atomic_and_digest_bound(tmp_path: Path) -> None:
    record = _record()
    path = tmp_path / "record.json"
    digest = record.write(path)
    assert path.read_bytes() == record.content_bytes()
    assert digest == record.digest()
