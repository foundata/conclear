from importlib.resources import files

import pytest
from jsonschema import Draft202012Validator

from conclear.schema import load_schema, validate_schema


@pytest.mark.parametrize(
    "name",
    [
        "config.schema.json",
        "profile.schema.json",
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
    assert schema_files.joinpath("triage.schema.json").is_file()


def test_public_record_schema_has_a_stable_identifier() -> None:
    assert (
        load_schema("record.schema.json")["$id"]
        == "https://github.com/foundata/conclear/schemas/record.json"
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
        "ci_context": "omit",
        "cosign_public_key": "/run/secrets/cosign.pub",
        "registry": {"provider": "quay", "host": "quay.io"},
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
