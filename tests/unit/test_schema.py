import tomllib
from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator

from conclear.schema import load_schema, validate_schema
from tests.registry_policy_fixtures import REGISTRY_POLICY_TOML


@pytest.mark.parametrize(
    "name",
    [
        "config.schema.json",
        "profile.schema.json",
        "proposal.schema.json",
        "provenance.schema.json",
        "record.schema.json",
        "result.schema.json",
        "triage.schema.json",
    ],
)
def test_shipped_schema_is_valid_draft_2020_12(name: str) -> None:
    validate_schema(name)
    assert (
        load_schema(name)["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    )


def test_schema_files_are_packaged() -> None:
    schema_files = files("conclear.schemas")
    assert schema_files.joinpath("config.schema.json").is_file()
    assert schema_files.joinpath("proposal.schema.json").is_file()
    assert schema_files.joinpath("triage.schema.json").is_file()


def test_public_record_schema_has_a_stable_identifier() -> None:
    assert (
        load_schema("record.schema.json")["$id"]
        == "https://github.com/foundata/conclear/schemas/record.json"
    )


def test_readiness_result_schema_requires_complete_bounded_evidence() -> None:
    validator = Draft202012Validator(
        load_schema("record.schema.json")["$defs"]["testResult"]
    )
    result = {
        "name": "health",
        "status": "passed",
        "outcome": "ready",
        "attempts": 3,
        "elapsedSeconds": 0.5,
        "timeoutSeconds": 60,
        "containerStatus": "running",
        "containerExitStatus": None,
        "exitStatus": 0,
        "outputDigest": "sha256:" + "a" * 64,
    }

    validator.validate(result)
    assert list(validator.iter_errors({**result, "outcome": "unknown"}))
    assert list(validator.iter_errors({**result, "attempts": -1}))
    assert list(validator.iter_errors({**result, "timeoutSeconds": 0}))
    assert list(
        validator.iter_errors(
            {key: value for key, value in result.items() if key != "outputDigest"}
        )
    )


def test_public_ci_context_is_provider_neutral_and_omits_server_origins() -> None:
    ci_schema = load_schema("record.schema.json")["$defs"]["ciContext"]
    validator = Draft202012Validator(ci_schema)
    context = {
        "provider": "gitlab-ci",
        "source": "provider-environment",
        "repository": "foundata/conclear",
        "revision": "a" * 40,
        "runId": "123",
    }

    validator.validate(context)
    assert list(validator.iter_errors({**context, "server": "https://github.com"}))
    assert list(validator.iter_errors({**context, "repository": "example"}))
    assert list(validator.iter_errors({**context, "runId": "not valid"}))
    validator.validate({**context, "provider": "future-ci"})


def test_release_profile_schema_has_a_closed_registry_backend_matrix() -> None:
    validator = Draft202012Validator(load_schema("profile.schema.json"))
    profile = {
        "schema_version": 1,
        "ci_context": "omit",
        "allowed_source_origins": ["https://github.com/example/"],
        "builder": {
            "id": "https://foundata.com/en/projects/conclear/builder/simple-v1/"
        },
        "cosign_public_key": "/run/secrets/cosign.pub",
        "registry": {
            "provider": "quay",
            "host": "quay.io",
            **tomllib.loads(REGISTRY_POLICY_TOML),
        },
    }

    validator.validate(profile)
    assert list(
        validator.iter_errors(
            {**profile, "registry": {"provider": "docker", "host": "docker.io"}}
        )
    )
    assert list(
        validator.iter_errors(
            {**profile, "registry": {"provider": "quay", "host": "docker.io"}}
        )
    )
    assert list(
        validator.iter_errors(
            {key: value for key, value in profile.items() if key != "builder"}
        )
    )
    assert list(
        validator.iter_errors(
            {**profile, "builder": {"id": "https://foundata.com/builder/?id=v1"}}
        )
    )


def test_pin_update_proposal_schema_is_closed_and_bounded() -> None:
    validator = Draft202012Validator(load_schema("proposal.schema.json"))
    digest = "sha256:" + "a" * 64
    reference = "docker.io/library/debian:13-slim@" + digest
    ruleset: dict[str, object] = {
        "conclearVersion": "1.0.0",
        "conclearRevision": "b" * 40,
        "guideTitle": "OCI container image build and release guide",
        "guideRepository": "https://github.com/foundata/guidelines",
        "guidePath": "oci-container-image-guide.md",
        "guideRevision": "b179c89cd51f79cdb7f6d713a3e260b781b8b121",
    }
    lookup: dict[str, object] = {
        "imageIds": ["runtime"],
        "tagIntent": "moving-release-line",
        "originalReference": reference,
        "resolvedReference": reference.replace("a" * 64, "b" * 64),
        "oldDigest": digest,
        "newDigest": "sha256:" + "b" * 64,
        "resolvedAt": "2026-09-04T00:00:00Z",
        "reviewRequired": False,
    }
    file_entry: dict[str, object] = {
        "path": "Containerfile",
        "sha256": digest,
        "resultSha256": "sha256:" + "c" * 64,
        "edits": [
            {
                "start": 5,
                "end": 5 + len(reference),
                "oldBytes": reference,
                "newBytes": reference.replace("a" * 64, "b" * 64),
            }
        ],
    }
    proposal: dict[str, object] = {
        "schemaVersion": 1,
        "recordType": "pinUpdateProposal",
        "createdAt": "2026-09-04T00:00:00Z",
        "ruleset": ruleset,
        "source": {
            "repository": "https://foundata.com/en/projects/example/#source",
            "revision": "c" * 40,
        },
        "repositoryConfiguration": {"path": "conclear.toml", "sha256": digest},
        "tools": [{"name": "skopeo", "version": "1.22.2", "executableDigest": digest}],
        "imageIds": ["runtime"],
        "lookups": [lookup],
        "files": [file_entry],
        "reviewRequired": False,
    }

    validator.validate(proposal)
    assert list(validator.iter_errors({**proposal, "unknown": True}))
    assert list(validator.iter_errors({**proposal, "schemaVersion": 2}))
    assert list(validator.iter_errors({**proposal, "recordType": "releaseCandidate"}))
    assert list(validator.iter_errors({**proposal, "imageIds": []}))
    assert list(
        validator.iter_errors(
            {**proposal, "files": [{**file_entry, "path": "../Containerfile"}]}
        )
    )
    assert list(
        validator.iter_errors(
            {**proposal, "files": [{**file_entry, "path": "/Containerfile"}]}
        )
    )
    assert list(
        validator.iter_errors({**proposal, "lookups": [{**lookup, "authFile": "/x"}]})
    )
    assert list(
        validator.iter_errors(
            {**proposal, "ruleset": {**ruleset, "guideRevision": "c" * 40}}
        )
    )
