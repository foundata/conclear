import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import conclear.records as records_module
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import canonical_json_bytes, sha256_bytes
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
)
from conclear.rescan_history import (
    RemediationFindingKey,
    RescanHistoryEntry,
    RescanHistoryStore,
    history_from_records,
)
from conclear.values import OCIReference, Platform

SUBJECT = OCIReference.parse(
    "quay.io/example/app@sha256:" + "a" * 64,
    require_digest=True,
)
FINDING = RemediationFindingKey(
    Platform.parse("linux/amd64"),
    "libssl",
    "CVE-2026-0001",
)


def _entry(character: str, when: datetime) -> RescanHistoryEntry:
    return RescanHistoryEntry(
        record_digest="sha256:" + character * 64,
        release_record_digest="sha256:" + "9" * 64,
        verified_at=when,
        active_findings=(FINDING,),
    )


def _record(
    previous: str | None,
    when: datetime,
    *,
    finding: RemediationFindingKey | None = FINDING,
) -> dict[str, object]:
    remediation_findings = []
    if finding is not None:
        remediation_findings.append(
            {
                **finding.to_dict(),
                "startedAt": None,
                "deadline": None,
                "overdue": False,
            }
        )
    return RecordEnvelope(
        record_type="rescanResult",
        created_at=when,
        run_id="01arz3ndektsv4rrffq69g5fav",
        source=SourceIdentity(
            "https://foundata.com/en/projects/example/#source", "b" * 40
        ),
        configuration_digest="sha256:" + "c" * 64,
        tools=(
            ToolIdentity("trivy", "0.69.3", executable_digest="sha256:" + "f" * 64),
        ),
        verdict=Verdict.ACCEPTED,
        payload={
            "subject": str(SUBJECT),
            "releaseRecordDigest": "sha256:" + "9" * 64,
            "platformManifests": {"linux/amd64": "sha256:" + "d" * 64},
            "scanner": "trivy 0.69.3",
            "databaseDigest": "sha256:" + "e" * 64,
            "databaseMetadata": {
                name: {
                    "schemaVersion": version,
                    "updatedAt": "2026-01-01T00:00:00Z",
                    "nextUpdate": "2026-01-02T00:00:00Z",
                    "downloadedAt": "2026-01-01T00:01:00Z",
                }
                for name, version in (("vulnerability", 2), ("java", 1))
            },
            "scope": "sbom-vulnerabilities",
            "findings": [],
            "appliedExceptions": [],
            "triage": [],
            "previousResultDigest": previous,
            "authoritative": True,
            "remediation": {
                "limitSeconds": 604800,
                "findings": remediation_findings,
            },
        },
    ).to_dict()


def test_history_requires_exact_latest_result_link(tmp_path: Path) -> None:
    store = RescanHistoryStore(tmp_path)
    first = _entry("b", datetime(2026, 1, 1, tzinfo=UTC))

    assert store.linked_history(SUBJECT, None) == ()
    store.record(SUBJECT, first, expected_previous=None)

    with pytest.raises(InvalidInvocationError, match="required"):
        store.linked_history(SUBJECT, None)
    with pytest.raises(InvalidInvocationError, match="latest"):
        store.linked_history(SUBJECT, "sha256:" + "c" * 64)
    assert store.linked_history(SUBJECT, first.record_digest) == (first,)

    second = _entry("d", datetime(2026, 1, 2, tzinfo=UTC))
    store.record(SUBJECT, second, expected_previous=first.record_digest)
    assert store.linked_history(SUBJECT, second.record_digest) == (first, second)


def test_history_rejects_races_duplicate_and_backwards_time(tmp_path: Path) -> None:
    store = RescanHistoryStore(tmp_path)
    first = _entry("b", datetime(2026, 1, 2, tzinfo=UTC))
    store.record(SUBJECT, first, expected_previous=None)

    with pytest.raises(OperationalError, match="changed"):
        store.record(
            SUBJECT,
            _entry("c", datetime(2026, 1, 3, tzinfo=UTC)),
            expected_previous=None,
        )
    with pytest.raises(OperationalError, match="backwards"):
        store.record(
            SUBJECT,
            _entry("c", datetime(2026, 1, 1, tzinfo=UTC)),
            expected_previous=first.record_digest,
        )
    with pytest.raises(OperationalError, match="already recorded"):
        store.record(
            SUBJECT,
            _entry("b", datetime(2026, 1, 2, tzinfo=UTC) + timedelta(seconds=1)),
            expected_previous=first.record_digest,
        )


def test_history_rejects_symlink_and_oversized_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = RescanHistoryStore(tmp_path)
    root = tmp_path / "conclear" / "rescans"
    root.mkdir(parents=True)
    name = hashlib.sha256(str(SUBJECT).encode("utf-8")).hexdigest() + ".json"
    history_path = root / name
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    history_path.symlink_to(outside)

    with pytest.raises(OperationalError, match="regular file"):
        store.linked_history(SUBJECT, None)

    history_path.unlink()
    history_path.write_bytes(b"x" * 17)
    monkeypatch.setattr("conclear.rescan_history.MAX_RESCAN_HISTORY_BYTES", 16)
    with pytest.raises(OperationalError, match="size limit"):
        store.linked_history(SUBJECT, None)


def test_history_reconstructs_signed_chain_and_repairs_missing_or_behind_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        records_module,
        "IDENTITY",
        ApplicationIdentity(source_revision="f" * 40),
    )
    first_record = _record(None, datetime(2026, 1, 1, tzinfo=UTC))
    first_digest = sha256_bytes(canonical_json_bytes(first_record))
    second_record = _record(first_digest, datetime(2026, 1, 2, tzinfo=UTC))
    history = history_from_records((second_record, first_record), SUBJECT)
    second_digest = sha256_bytes(canonical_json_bytes(second_record))
    assert tuple(item.record_digest for item in history) == (
        first_digest,
        second_digest,
    )

    missing_store = RescanHistoryStore(tmp_path / "missing")
    assert missing_store.synchronize(SUBJECT, history, second_digest) == history
    assert missing_store.linked_history(SUBJECT, second_digest) == history

    behind_store = RescanHistoryStore(tmp_path / "behind")
    behind_store.synchronize(SUBJECT, history[:1], first_digest)
    assert behind_store.synchronize(SUBJECT, history, second_digest) == history
    assert behind_store.linked_history(SUBJECT, second_digest) == history


def test_history_rejects_cache_conflicts_and_signed_forks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        records_module,
        "IDENTITY",
        ApplicationIdentity(source_revision="f" * 40),
    )
    first_record = _record(None, datetime(2026, 1, 1, tzinfo=UTC))
    first_digest = sha256_bytes(canonical_json_bytes(first_record))
    signed_history = history_from_records((first_record,), SUBJECT)
    store = RescanHistoryStore(tmp_path)
    store.record(
        SUBJECT,
        RescanHistoryEntry(
            record_digest=first_digest,
            release_record_digest="sha256:" + "9" * 64,
            verified_at=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
            active_findings=(FINDING,),
        ),
        expected_previous=None,
    )
    with pytest.raises(OperationalError, match="conflicts with signed"):
        store.synchronize(SUBJECT, signed_history, first_digest)

    left = _record(first_digest, datetime(2026, 1, 2, tzinfo=UTC))
    right = _record(
        first_digest,
        datetime(2026, 1, 3, tzinfo=UTC),
        finding=None,
    )
    with pytest.raises(OperationalError, match="one complete chain"):
        history_from_records((first_record, left, right), SUBJECT)
