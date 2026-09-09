from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import conclear.records as records_module
from conclear.attestations import (
    RELEASE_VERIFICATION_TYPE,
    SPDX_DOCUMENT_TYPE,
    STATEMENT_TYPE,
)
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import canonical_json_bytes, sha256_bytes
from conclear.parsing import object_value
from conclear.records import validate_record
from conclear.rescan_history import RescanHistoryStore, history_from_records
from conclear.services.rescan_evidence import (
    select_release_evidence,
    select_release_sbom,
    verified_predicates,
)
from tests.registry_policy_fixtures import STRICT_POLICY
from tests.unit.test_rescan_history import SUBJECT, _entry, _record

START = datetime(2026, 1, 1, tzinfo=UTC)
CONFIGURATION_DIGEST = "sha256:" + "c" * 64


@pytest.fixture
def release_record(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    monkeypatch.setattr(
        records_module, "IDENTITY", ApplicationIdentity(source_revision="c" * 40)
    )
    record = _record(None, START)
    record["recordType"] = "releaseVerification"
    record["payload"] = {
        "subject": {
            "repository": SUBJECT.repository_name,
            "digest": str(SUBJECT.digest),
        },
        "platformDigests": {"linux/amd64": "sha256:" + "d" * 64},
        "registryPolicy": STRICT_POLICY.to_dict(),
        "candidateAuthorization": {
            "reference": "quay.io/example/app:candidate-historical",
            "expiresAt": "2026-01-08T00:00:00Z",
        },
        "qualificationWindow": {
            "startedAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2026-01-02T00:00:00Z",
        },
        "releaseEnvironment": {
            "hostArchitecture": "x86_64",
            "runId": "01arz3ndektsv4rrffq69g5fav",
        },
        "builder": {"id": "https://example.invalid/builder"},
        "signer": {"mode": "managed-key", "keyId": "test-key"},
        "evidence": {
            "platformQualifications": ["sha256:" + "1" * 64],
            "scanResults": ["sha256:" + "2" * 64],
            "sboms": ["sha256:" + "3" * 64],
            "provenance": "sha256:" + "4" * 64,
            "candidateRecord": "sha256:" + "5" * 64,
        },
    }
    validate_record(record)
    return record


def statement(
    predicate: dict[str, object], predicate_type: str = RELEASE_VERIFICATION_TYPE
) -> dict[str, object]:
    assert SUBJECT.digest is not None
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": SUBJECT.repository_name,
                "digest": {"sha256": SUBJECT.digest.encoded},
            }
        ],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def test_repeat_release_selection_is_deterministic_and_history_stays_anchored(
    release_record: dict[str, object],
) -> None:
    later = {**release_record, "createdAt": "2026-01-03T00:00:00Z"}
    earlier = {**release_record, "createdAt": "2025-12-31T00:00:00Z"}
    digest = sha256_bytes(canonical_json_bytes(release_record))
    for records in ((later, release_record), (release_record, later, release_record)):
        selected = select_release_evidence(
            tuple(statement(record) for record in records),
            subject=SUBJECT,
            configuration_digest=CONFIGURATION_DIGEST,
            anchored_digest=None,
        )
        assert selected.digest == digest
    selected = select_release_evidence(
        tuple(statement(record) for record in (earlier, later, release_record)),
        subject=SUBJECT,
        configuration_digest=CONFIGURATION_DIGEST,
        anchored_digest=digest,
    )
    assert selected.digest == digest


def test_equal_timestamps_use_record_digest_and_other_configurations_do_not_match(
    release_record: dict[str, object],
) -> None:
    other = deepcopy(release_record)
    payload = object_value(other["payload"], "payload")
    payload["releaseEnvironment"] = {
        "hostArchitecture": "aarch64",
        "runId": "01arz3ndektsv4rrffq69g5fav",
    }
    foreign = {
        **release_record,
        "repositoryConfiguration": {
            "path": "conclear.toml",
            "sha256": "sha256:" + "f" * 64,
        },
    }
    for records in ((release_record, other, foreign), (foreign, other, release_record)):
        selected = select_release_evidence(
            tuple(statement(record) for record in records),
            subject=SUBJECT,
            configuration_digest=CONFIGURATION_DIGEST,
            anchored_digest=None,
        )
        assert selected.digest == min(
            sha256_bytes(canonical_json_bytes(record))
            for record in (release_record, other)
        )
    with pytest.raises(InvalidInvocationError, match=r"exact conclear\.toml"):
        select_release_evidence(
            (statement(foreign),),
            subject=SUBJECT,
            configuration_digest=CONFIGURATION_DIGEST,
            anchored_digest=None,
        )


@pytest.mark.parametrize("field", ["source", "platformDigests", "builder", "signer"])
def test_conflicting_release_identities_fail_closed(
    release_record: dict[str, object], field: str
) -> None:
    conflicting = deepcopy(release_record)
    payload = object_value(conflicting["payload"], "payload")
    if field == "source":
        object_value(conflicting["source"], "source")["revision"] = "a" * 40
    elif field == "platformDigests":
        payload[field] = {"linux/arm64": "sha256:" + "d" * 64}
    elif field == "builder":
        payload[field] = {"id": "https://example.invalid/other-builder"}
    else:
        payload[field] = {"mode": "managed-key", "keyId": "other-key"}
    with pytest.raises(OperationalError, match="conflicting identities"):
        select_release_evidence(
            (statement(release_record), statement(conflicting)),
            subject=SUBJECT,
            configuration_digest=CONFIGURATION_DIGEST,
            anchored_digest=None,
        )


def test_missing_anchor_is_not_replaced_by_a_repeat_release(
    release_record: dict[str, object],
) -> None:
    with pytest.raises(OperationalError, match=r"anchored.*missing"):
        select_release_evidence(
            (statement(release_record),),
            subject=SUBJECT,
            configuration_digest=CONFIGURATION_DIGEST,
            anchored_digest="sha256:" + "0" * 64,
        )


def test_sboms_are_bound_to_signed_subject_and_referenced_bytes() -> None:
    sbom: dict[str, object] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "app",
        "documentNamespace": "https://example.invalid/spdx/app",
        "creationInfo": {"creators": ["Tool: test"], "created": "2026-01-01T00:00:00Z"},
    }
    unrelated = {**sbom, "name": "different inventory"}
    digest = sha256_bytes(canonical_json_bytes(sbom))
    statements = tuple(
        statement(item, SPDX_DOCUMENT_TYPE) for item in (unrelated, sbom, sbom)
    )
    assert select_release_sbom(
        statements, subject=SUBJECT, evidence_digests=frozenset({digest})
    ) == (digest, sbom)
    for digests in (
        frozenset({"sha256:" + "0" * 64}),
        frozenset({digest, sha256_bytes(canonical_json_bytes(unrelated))}),
    ):
        with pytest.raises(OperationalError, match="exactly one release-bound SBOM"):
            select_release_sbom(statements, subject=SUBJECT, evidence_digests=digests)
    bad_subject = {**statements[1], "subject": []}
    with pytest.raises(OperationalError, match="unexpected subject"):
        select_release_sbom(
            (bad_subject,), subject=SUBJECT, evidence_digests=frozenset({digest})
        )
    with pytest.raises(OperationalError, match="predicate type"):
        verified_predicates(
            statements, subject=SUBJECT, predicate_type=RELEASE_VERIFICATION_TYPE
        )


def test_signed_and_durable_history_cannot_change_the_release_anchor(
    tmp_path: Path, release_record: dict[str, object]
) -> None:
    first = _record(None, START)
    second = _record(
        sha256_bytes(canonical_json_bytes(first)), START + timedelta(days=1)
    )
    object_value(second["payload"], "payload")["releaseRecordDigest"] = (
        "sha256:" + "0" * 64
    )
    with pytest.raises(OperationalError, match="changes its release record anchor"):
        history_from_records((first, second), SUBJECT)
    store = RescanHistoryStore(tmp_path)
    entry = _entry("a", START)
    store.record(SUBJECT, entry, expected_previous=None)
    with pytest.raises(OperationalError, match="changes its release record anchor"):
        store.record(
            SUBJECT,
            replace(_entry("b", START), release_record_digest="sha256:" + "0" * 64),
            expected_previous=entry.record_digest,
        )
