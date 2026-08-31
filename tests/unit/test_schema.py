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


def test_public_ci_identity_omits_non_public_server_origins() -> None:
    ci_schema = load_schema("record.schema.json")["$defs"]["ciIdentity"]
    validator = Draft202012Validator(ci_schema)
    identity = {
        "provider": "github-actions",
        "repository": "foundata/conclear",
        "workflow": "foundata/conclear/.github/workflows/check.yml@refs/heads/main",
        "runId": "123",
        "revision": "a" * 40,
    }

    validator.validate(identity)
    validator.validate({**identity, "server": "https://github.com"})
    assert list(
        validator.iter_errors({**identity, "server": "https://ci.internal.example"})
    )
