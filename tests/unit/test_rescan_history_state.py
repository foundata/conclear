"""Durable rescan history refuses malformed state and inconsistent signed chains."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import conclear.records as records_module
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.identity import ApplicationIdentity
from conclear.rescan_history import RescanHistoryStore, history_from_records
from conclear.values import OCIReference
from tests.unit.test_rescan_history import SUBJECT, _entry, _record

START = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture(autouse=True)
def embedded_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        records_module, "IDENTITY", ApplicationIdentity(source_revision="c" * 40)
    )


def stored_path(tmp_path: Path) -> Path:
    store = RescanHistoryStore(tmp_path)
    store.record(SUBJECT, _entry("a", START), expected_previous=None)
    root = tmp_path / "conclear" / "rescans"
    (path,) = list(root.glob("*.json"))
    return path


def rewrite(path: Path, mutate: Any) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_durable_history_rejects_every_structural_corruption(tmp_path: Path) -> None:
    path = stored_path(tmp_path)
    store = RescanHistoryStore(tmp_path)
    original = path.read_bytes()

    def expect(mutate: Any, message: str) -> None:
        rewrite(path, mutate)
        with pytest.raises(OperationalError, match=message):
            store.synchronize(SUBJECT, (), None)
        path.write_bytes(original)

    expect(lambda value: value.update(schemaVersion=2), "malformed")
    expect(
        lambda value: value.update(subject="quay.io/example/other@sha256:" + "b" * 64),
        "another subject",
    )
    expect(lambda value: value.update(results={}), "results are malformed")
    expect(
        lambda value: value.update(results=value["results"] * 2),
        "duplicate results",
    )

    def unordered(value: dict[str, Any]) -> None:
        later = dict(value["results"][0])
        later["recordDigest"] = "sha256:" + "b" * 64
        later["verifiedAt"] = "2025-12-31T00:00:00Z"
        value["results"].append(later)

    expect(unordered, "unordered")

    path.unlink()
    os.mkfifo(path)
    with pytest.raises(OperationalError, match="not a regular file"):
        store.synchronize(SUBJECT, (), None)
    path.unlink()
    path.write_bytes(original)


def test_history_subjects_must_be_immutable_digest_references(tmp_path: Path) -> None:
    store = RescanHistoryStore(tmp_path)
    with pytest.raises(InvalidInvocationError, match="immutable digest subject"):
        store.synchronize(OCIReference.parse("quay.io/example/app:1"), (), None)
    with pytest.raises(InvalidInvocationError, match="immutable digest subject"):
        store.synchronize(
            OCIReference.parse("quay.io/example/app:1@sha256:" + "a" * 64), (), None
        )


def test_signed_chain_reconstruction_rejects_malformed_or_foreign_records() -> None:
    record = _record(None, START)

    def expect(mutate: Any, message: str) -> None:
        value = json.loads(json.dumps(record))
        mutate(value)
        with pytest.raises(OperationalError, match=message):
            history_from_records((value,), SUBJECT)

    expect(lambda value: value.update(recordType="releaseCandidate"), "malformed")
    expect(lambda value: value.pop("payload"), "malformed")
    expect(
        lambda value: value["payload"].update(
            subject="quay.io/example/other@sha256:" + "b" * 64
        ),
        "another subject",
    )
    expect(
        lambda value: value["payload"].update(authoritative=False),
        "diagnostic result",
    )
    expect(
        lambda value: value["payload"].update(previousResultDigest="sha256:short"),
        "malformed",
    )
    expect(
        lambda value: value["payload"]["remediation"].update(findings={}),
        "malformed",
    )
    assert history_from_records(
        (record, json.loads(json.dumps(record))), SUBJECT
    ) == history_from_records((record,), SUBJECT)

    chain = history_from_records((record,), SUBJECT)
    assert len(chain) == 1
    assert chain[0].verified_at == START

    second = _record(chain[0].record_digest, START + timedelta(days=1))
    assert len(history_from_records((second, record), SUBJECT)) == 2


def test_durable_history_lock_refuses_symbolic_links(tmp_path: Path) -> None:
    path = stored_path(tmp_path)
    store = RescanHistoryStore(tmp_path)
    original = path.read_bytes()
    outside = tmp_path / "outside.lock"
    outside.write_text("protected", encoding="utf-8")
    lock_path = path.with_suffix(".lock")
    lock_path.unlink()
    lock_path.symlink_to(outside)

    with pytest.raises(OperationalError, match="Unable to lock rescan history"):
        store.synchronize(SUBJECT, (), None)
    with pytest.raises(OperationalError, match="Unable to lock rescan history"):
        store.record(SUBJECT, _entry("b", START), expected_previous=None)

    assert outside.read_text(encoding="utf-8") == "protected"
    assert path.read_bytes() == original
