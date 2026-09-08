from collections.abc import Callable
from datetime import date

import pytest

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.parsing import string_value, toml_integer, toml_string, toml_table


def test_toml_table_preserves_values_without_field_policy() -> None:
    value = {"empty": "", "nested": {"enabled": True}, "date": date(2026, 9, 8)}

    assert toml_table(value) is value
    assert toml_table({}) == {}


@pytest.mark.parametrize("value", ["", " ", "literal", "\u00e4"])
def test_toml_string_does_not_strip_or_require_nonempty_content(value: str) -> None:
    assert toml_string(value) is value


@pytest.mark.parametrize("value", [-1, 0, 1, 2**63 - 1])
def test_toml_integer_preserves_integer_without_field_bounds(value: int) -> None:
    assert toml_integer(value) is value


@pytest.mark.parametrize(
    ("narrow", "value", "message"),
    [
        (toml_table, None, "Expected a table with string keys"),
        (toml_table, [], "Expected a table with string keys"),
        (toml_table, {1: "value"}, "Expected a table with string keys"),
        (toml_table, {"valid": 1, False: 2}, "Expected a table with string keys"),
        (toml_string, None, "Expected a string"),
        (toml_string, b"text", "Expected a string"),
        (toml_string, 1, "Expected a string"),
        (toml_string, False, "Expected a string"),
        (toml_integer, None, "Expected an integer"),
        (toml_integer, "1", "Expected an integer"),
        (toml_integer, 1.0, "Expected an integer"),
        (toml_integer, True, "Expected an integer"),
        (toml_integer, False, "Expected an integer"),
    ],
)
def test_toml_narrowing_preserves_error_type_code_and_message(
    narrow: Callable[[object], object], value: object, message: str
) -> None:
    with pytest.raises(InvalidInvocationError) as caught:
        narrow(value)

    assert str(caught.value) == message
    assert caught.value.code is None
    assert caught.value.exit_status == 64


def test_toml_and_tool_string_contracts_remain_distinct() -> None:
    assert toml_string("") == ""
    with pytest.raises(OperationalError, match="must be a non-empty string"):
        string_value("", "tool field")
