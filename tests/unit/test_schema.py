from importlib.resources import files

import pytest

from conclear.schema import load_schema, validate_schema


@pytest.mark.parametrize(
    "name",
    [
        "config.schema.json",
        "profile.schema.json",
        "provenance.schema.json",
        "record.schema.json",
        "result.schema.json",
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
