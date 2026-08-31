import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.rescan_history import (
    RemediationFindingKey,
    RescanHistoryEntry,
    RescanHistoryStore,
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
        verified_at=when,
        active_findings=(FINDING,),
    )


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
