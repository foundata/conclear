import json
from pathlib import Path

import pytest

from conclear.errors import InvalidInvocationError
from conclear.triage import load_triage
from conclear.values import OCIReference

DIGEST = "sha256:" + "a" * 64
SUBJECT = OCIReference.parse(
    f"quay.io/example/app@{DIGEST}", require_digest=True, allow_localhost=False
)


def _triage() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "decisions": [
            {
                "subject": str(SUBJECT),
                "platform": "linux/amd64",
                "component": "openssl",
                "advisory": "CVE-2026-0001",
                "decision": "remediated",
                "rationale": "The fixed package is present in the named replacement.",
                "owner": "security@example.com",
                "decidedAt": "2026-08-31T12:34:56Z",
                "remediatingDigest": "sha256:" + "b" * 64,
            }
        ],
    }


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_load_triage_returns_exact_subject_bound_decisions(tmp_path: Path) -> None:
    path = tmp_path / "triage.json"
    _write(path, _triage())

    decisions = load_triage(path, subject=SUBJECT)

    assert len(decisions) == 1
    assert decisions[0].component == "openssl"
    assert decisions[0].remediating_digest is not None


def test_load_triage_rejects_another_subject(tmp_path: Path) -> None:
    value = _triage()
    decisions = value["decisions"]
    assert isinstance(decisions, list)
    decision = decisions[0]
    assert isinstance(decision, dict)
    decision["subject"] = f"quay.io/example/app@sha256:{'c' * 64}"
    path = tmp_path / "triage.json"
    _write(path, value)

    with pytest.raises(InvalidInvocationError, match="exact rescan subject"):
        load_triage(path, subject=SUBJECT)


def test_load_triage_rejects_duplicate_finding_identity(tmp_path: Path) -> None:
    value = _triage()
    decisions = value["decisions"]
    assert isinstance(decisions, list)
    decisions.append(dict(decisions[0]))
    path = tmp_path / "triage.json"
    _write(path, value)

    with pytest.raises(InvalidInvocationError, match="duplicate platform"):
        load_triage(path, subject=SUBJECT)


def test_load_triage_requires_digest_for_remediated_decision(tmp_path: Path) -> None:
    value = _triage()
    decisions = value["decisions"]
    assert isinstance(decisions, list)
    decision = decisions[0]
    assert isinstance(decision, dict)
    decision["remediatingDigest"] = None
    path = tmp_path / "triage.json"
    _write(path, value)

    with pytest.raises(InvalidInvocationError, match="remediatingDigest"):
        load_triage(path, subject=SUBJECT)


def test_load_triage_rejects_impossible_timestamp(tmp_path: Path) -> None:
    value = _triage()
    decisions = value["decisions"]
    assert isinstance(decisions, list)
    decision = decisions[0]
    assert isinstance(decision, dict)
    decision["decidedAt"] = "2026-02-31T12:34:56Z"
    path = tmp_path / "triage.json"
    _write(path, value)

    with pytest.raises(InvalidInvocationError, match="UTC RFC 3339"):
        load_triage(path, subject=SUBJECT)


def test_load_triage_rejects_oversized_input(tmp_path: Path) -> None:
    path = tmp_path / "triage.json"
    path.write_bytes(b" " * (1024 * 1024 + 1))

    with pytest.raises(InvalidInvocationError, match="Unable to read"):
        load_triage(path, subject=SUBJECT)
