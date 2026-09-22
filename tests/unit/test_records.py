from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

import conclear.records as records_module
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.identity import ApplicationIdentity
from conclear.records import (
    RECORD_SCHEMA_VERSIONS,
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
    format_timestamp,
    parse_timestamp,
    utc_now,
    validate_record,
)


def _record() -> RecordEnvelope:
    digest = "sha256:" + "a" * 64
    return RecordEnvelope(
        record_type="rescanResult",
        created_at=datetime(2026, 8, 31, 10, 30, tzinfo=UTC),
        run_id="01k3z8h6v4n7c2m9p5q1r0s8tx",
        source=SourceIdentity(
            repository="https://foundata.com/en/projects/example/#source",
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
            "releaseRecordDigest": "sha256:" + "9" * 64,
            "authoritative": False,
            "remediation": {"limitSeconds": 2592000, "findings": []},
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
    assert record.to_dict()["schemaVersion"] == 1
    validate_record(record.to_dict())
    assert record.digest().startswith("sha256:")


def test_image_backed_tool_identity_round_trips_and_validates() -> None:
    index_digest = "sha256:" + "1" * 64
    manifest_digest = "sha256:" + "2" * 64
    identity = ToolIdentity(
        "trivy",
        "0.74.0",
        image_digest=index_digest,
        image_manifest_digest=manifest_digest,
    )

    assert identity.to_dict() == {
        "name": "trivy",
        "version": "0.74.0",
        "imageDigest": index_digest,
        "imageManifestDigest": manifest_digest,
    }
    assert ToolIdentity.from_dict(identity.to_dict()) == identity
    record = _record()
    validate_record(
        {**record.to_dict(), "tools": [identity.to_dict()]},
    )
    host = ToolIdentity.from_dict({"name": "git", "version": "2.55.0"})
    assert (host.image_digest, host.image_manifest_digest) == (None, None)


def test_each_public_record_type_has_an_independent_initial_version() -> None:
    assert RECORD_SCHEMA_VERSIONS == {
        "platformQualification": 1,
        "releaseCandidate": 1,
        "releaseVerification": 1,
        "qualificationTransport": 1,
        "rescanResult": 1,
    }


def test_record_schema_rejects_a_version_from_another_generation() -> None:
    value = _record().to_dict()
    value["schemaVersion"] = 6
    with pytest.raises(InvalidInvocationError, match="1 was expected"):
        validate_record(value)


def test_record_schema_rejects_empty_tool_identity_set() -> None:
    value = _record().to_dict()
    value["tools"] = []

    with pytest.raises(InvalidInvocationError):
        validate_record(value)


def test_record_write_is_atomic_and_digest_bound(tmp_path: Path) -> None:
    record = _record()
    path = tmp_path / "record.json"
    digest = record.write(path)
    assert path.read_bytes() == record.content_bytes()
    assert digest == record.digest()


def test_utc_now_is_aware_and_whole_seconds() -> None:
    value = utc_now()
    assert value.tzinfo is UTC
    assert value.microsecond == 0


def test_format_timestamp_requires_aware_whole_second_values() -> None:
    assert format_timestamp(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)) == (
        "2026-01-02T03:04:05Z"
    )
    assert (
        format_timestamp(
            datetime(2026, 1, 2, 4, 4, 5, tzinfo=timezone(timedelta(hours=1)))
        )
        == "2026-01-02T03:04:05Z"
    )
    with pytest.raises(OperationalError, match="timezone-aware"):
        format_timestamp(datetime(2026, 1, 2, 3, 4, 5))  # noqa: DTZ001
    with pytest.raises(OperationalError, match="whole-second"):
        format_timestamp(datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=UTC))


def test_parse_timestamp_truncates_fractions_and_rejects_other_shapes() -> None:
    expected = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert parse_timestamp("2026-01-02T03:04:05Z", "created") == expected
    assert parse_timestamp("2026-01-02T03:04:05.987654Z", "created") == expected
    for value in (
        "",
        None,
        5,
        "not a time",
        "2026-01-02T03:04:05",
        "2026-01-02T04:04:05+01:00",
        "2026-01-02T03:04:05+00:00",
    ):
        with pytest.raises(OperationalError, match="created must be a UTC RFC 3339"):
            parse_timestamp(value, "created")
    with pytest.raises(InvalidInvocationError, match="UTC RFC 3339"):
        parse_timestamp("soon", "created", error=InvalidInvocationError)
