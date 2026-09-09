"""Every bundled schema accepts a representative fixture and rejects mutations."""

import json
import tomllib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import conclear.records as records_module
from conclear.artifacts import load_candidate
from conclear.config import load_repository_config
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import load_json
from conclear.presentation import CommandResult, Finding, ResultStatus
from conclear.records import validate_record
from conclear.schema import load_schema, validate_external
from tests.unit.test_release_workflow import Harness
from tests.unit.test_rescan_history import _record as rescan_record

SCHEMAS = (
    "config.schema.json",
    "profile.schema.json",
    "proposal.schema.json",
    "provenance.schema.json",
    "record.schema.json",
    "result.schema.json",
    "triage.schema.json",
)


@pytest.mark.parametrize("name", SCHEMAS)
def test_every_bundled_schema_meta_validates_against_its_dialect(name: str) -> None:
    schema = load_schema(name)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)
    assert schema.get("additionalProperties") is False
    assert schema["$id"].startswith("https://github.com/foundata/conclear/schemas/")


def _errors(name: str, value: object) -> list[str]:
    validator = Draft202012Validator(load_schema(name))
    return [error.message for error in validator.iter_errors(value)]


def test_release_records_validate_and_reject_security_significant_mutations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_factory: Callable[..., Path],
) -> None:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    harness.complete()
    records = harness.workspace.root / "records"
    fixtures = {
        "platformQualification": load_json(
            records / "platform-qualification-linux-amd64.json"
        ),
        "releaseCandidate": load_json(records / "release-candidate.json"),
        "releaseVerification": load_json(records / "release-verification.json"),
    }
    for record_type, value in fixtures.items():
        assert value["recordType"] == record_type
        validate_record(value)
        assert _errors("record.schema.json", value) == []
        assert _errors("record.schema.json", {**value, "unexpected": True})
        assert _errors(
            "record.schema.json",
            {**value, "ruleset": {**value["ruleset"], "guideRevision": "f" * 40}},
        )
        assert _errors("record.schema.json", {**value, "verdict": "approved"})
        assert _errors("record.schema.json", {**value, "runId": "RUN"})
        assert _errors(
            "record.schema.json",
            {**value, "source": {**value["source"], "revision": "abc"}},
        )
        assert _errors(
            "record.schema.json",
            {
                **value,
                "repositoryConfiguration": {
                    "path": "other.toml",
                    "sha256": value["repositoryConfiguration"]["sha256"],
                },
            },
        )
        assert _errors("record.schema.json", {**value, "tools": []})
        with pytest.raises(InvalidInvocationError):
            validate_record({**value, "payload": {**value["payload"], "extra": 1}})

    verification = fixtures["releaseVerification"]
    assert _errors(
        "record.schema.json",
        {
            **verification,
            "payload": {
                **verification["payload"],
                "signer": {"mode": "unsigned", "keyId": "x"},
            },
        },
    )
    assert _errors(
        "record.schema.json",
        {
            **verification,
            "payload": {
                **verification["payload"],
                "builder": {"id": "http://insecure.example/builder"},
            },
        },
    )

    provenance = load_json(records / "provenance.json")
    validate_external(provenance, "provenance.schema.json", label="provenance")
    assert _errors("provenance.schema.json", {**provenance, "extra": 1})
    tampered_provenance = json.loads(json.dumps(provenance))
    tampered_provenance["predicate"]["runDetails"]["builder"]["id"] = "not a uri"
    assert _errors("provenance.schema.json", tampered_provenance)

    rescan: dict[str, Any] = rescan_record(None, datetime(2026, 1, 1, tzinfo=UTC))
    validate_record(rescan)
    assert _errors(
        "record.schema.json",
        {**rescan, "payload": {**rescan["payload"], "authoritative": "yes"}},
    )
    assert _errors(
        "record.schema.json",
        {
            **rescan,
            "payload": {
                **rescan["payload"],
                "triage": [{"subject": "quay.io/example/app@sha256:" + "a" * 64}],
            },
        },
    )
    assert load_candidate(harness.workspace, harness.image).candidate_tag


def test_configuration_profile_result_and_triage_fixtures(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    configuration = tomllib.loads((root / "conclear.toml").read_text(encoding="utf-8"))
    assert _errors("config.schema.json", configuration) == []
    assert _errors("config.schema.json", {**configuration, "secrets": {}})
    image = dict(configuration["images"][0])
    image["runtime"] = {**image["runtime"], "capabilities": ["CAP_SYS_ADMIN", "cap_x"]}
    assert _errors("config.schema.json", {**configuration, "images": [image]})
    image = dict(configuration["images"][0])
    image["pins"] = [
        {"reference": "quay.io/example/base", "tag_intent": "immutable-version"}
    ]
    assert _errors("config.schema.json", {**configuration, "images": [image]})
    assert load_repository_config(root / "conclear.toml").images[0].image_id == "app"
    app = {**configuration["images"][0], "test": {"dependencies": ["helper"]}}
    helper = {"id": "helper", "platforms": ["linux/amd64"], "runtime": app["runtime"]}
    assert (
        _errors("config.schema.json", {**configuration, "images": [app, helper]}) == []
    )
    forbidden_cases: tuple[dict[str, object], ...] = (
        {"release": app["release"]},
        {"hooks": []},
        {"native_test_platforms": ["linux/amd64"]},
        {"test": {"launch": {"arguments": ["x"]}}},
        {"limits": {"remediation": "7d"}},
    )
    for forbidden in forbidden_cases:
        assert _errors(
            "config.schema.json",
            {**configuration, "images": [app, {**helper, **forbidden}]},
        ), forbidden
    unreleased = {key: value for key, value in app.items() if key != "release"}
    assert _errors("config.schema.json", {**configuration, "images": [unreleased]})

    profile = {
        "schema_version": 1,
        "ci_context": "observe",
        "builder": {
            "id": "https://foundata.com/en/projects/conclear/builder/simple-v1/"
        },
        "cosign_public_key": "/run/secrets/cosign.pub",
        "registry": {"provider": "quay", "host": "quay.io"},
    }
    assert _errors("profile.schema.json", profile) == []
    assert _errors("profile.schema.json", {**profile, "cosign_passphrase": "secret"})
    assert _errors(
        "profile.schema.json",
        {**profile, "registry": {"provider": "quay", "host": "quay.io", "token": "x"}},
    )
    assert _errors("profile.schema.json", {**profile, "ci_context": "trust"})
    assert _errors(
        "profile.schema.json",
        {k: v for k, v in profile.items() if k != "schema_version"},
    )
    assert _errors("profile.schema.json", {**profile, "schema_version": 2})

    result = CommandResult(
        "build",
        ResultStatus.RULE_REJECTION,
        "rejected",
        findings=(Finding("CC0107", "error", "remote ADD", "Containerfile:3"),),
        data={"runId": "01arz3ndektsv4rrffq69g5fav"},
    ).to_dict()
    assert _errors("result.schema.json", result) == []
    assert _errors("result.schema.json", {**result, "status": "success"})
    assert _errors(
        "result.schema.json",
        {
            **result,
            "data": {"runId": "01arz3ndektsv4rrffq69g5fav", "undocumented": True},
        },
    )
    assert _errors("result.schema.json", {**result, "data": {"runId": "not a ulid"}})
    assert _errors("result.schema.json", {**result, "status": "maybe"})
    assert _errors(
        "result.schema.json",
        {
            **result,
            "findings": [{"checkId": "X1", "severity": "error", "message": "m"}],
        },
    )
    assert _errors("result.schema.json", {**result, "schemaVersion": 2})

    triage: dict[str, Any] = {
        "schemaVersion": 1,
        "decisions": [
            {
                "subject": "quay.io/example/app@sha256:" + "a" * 64,
                "platform": "linux/amd64",
                "component": "openssl",
                "advisory": "CVE-2026-0001",
                "decision": "remediated",
                "rationale": "Rebuilt on the fixed base image.",
                "owner": "security@example.com",
                "decidedAt": "2026-08-31T12:34:56Z",
                "remediatingDigest": "sha256:" + "b" * 64,
            }
        ],
    }
    assert _errors("triage.schema.json", triage) == []
    decision = dict(triage["decisions"][0])
    decision["remediatingDigest"] = None
    assert _errors("triage.schema.json", {**triage, "decisions": [decision]})
    decision = dict(triage["decisions"][0])
    decision["decision"] = "ignore"
    assert _errors("triage.schema.json", {**triage, "decisions": [decision]})
    assert _errors("triage.schema.json", {**triage, "approvedBy": "bot"})


def test_unknown_record_types_are_never_serialized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        records_module, "IDENTITY", ApplicationIdentity(source_revision="c" * 40)
    )
    envelope = records_module.RecordEnvelope(
        record_type="auditLog",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        run_id="01arz3ndektsv4rrffq69g5fav",
        source=records_module.SourceIdentity(
            "https://github.com/example/app", "b" * 40
        ),
        configuration_digest="sha256:" + "a" * 64,
        tools=(),
        verdict=records_module.Verdict.ACCEPTED,
        payload={},
    )
    with pytest.raises(OperationalError, match="Unsupported public record type"):
        envelope.to_dict()
