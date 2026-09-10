"""Typed narrowing of untrusted decoded JSON and TOML values."""

import json
from dataclasses import dataclass
from typing import Any

from conclear.errors import ConClearError, InvalidInvocationError, OperationalError
from conclear.jsonutil import structure_depth_is_bounded


@dataclass(frozen=True, slots=True)
class Narrower:
    """Narrow untrusted decoded values and raise one error class on failure.

    The error class states the trust boundary once per module: tool output and
    workspace state fail as `OperationalError`, while records, layouts and
    manifests a user supplies fail as `InvalidInvocationError`. Every method
    returns the value unchanged after proving its shape.
    """

    error: type[ConClearError]

    def object_value(self, value: object, label: str) -> dict[str, Any]:
        """Validate a string-keyed object."""
        if not isinstance(value, dict) or any(
            not isinstance(key, str) for key in value
        ):
            raise self.error(f"{label} must be a JSON object")
        return value

    def array_value(self, value: object, label: str) -> list[Any]:
        """Validate an array."""
        if not isinstance(value, list):
            raise self.error(f"{label} must be a JSON array")
        return value

    def string_value(self, value: object, label: str) -> str:
        """Validate a non-empty string field."""
        if not isinstance(value, str) or not value:
            raise self.error(f"{label} must be a non-empty string")
        return value

    def string_array_value(self, value: object, label: str) -> list[str]:
        """Validate an array whose items are all strings."""
        if not isinstance(value, list) or any(
            not isinstance(item, str) for item in value
        ):
            raise self.error(f"{label} must be an array of strings")
        return value

    def integer_value(self, value: object, label: str) -> int:
        """Validate an integer field, rejecting booleans."""
        if not isinstance(value, int) or isinstance(value, bool):
            raise self.error(f"{label} must be an integer")
        return value


TOOL_OUTPUT = Narrower(OperationalError)
"""Narrower for values that came from an external tool or run-owned state."""

object_value = TOOL_OUTPUT.object_value
array_value = TOOL_OUTPUT.array_value
string_value = TOOL_OUTPUT.string_value
string_array_value = TOOL_OUTPUT.string_array_value
integer_value = TOOL_OUTPUT.integer_value


def toml_table(value: object) -> dict[str, Any]:
    """Narrow one schema-validated TOML value to a string-keyed table."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise InvalidInvocationError("Expected a table with string keys")
    return value


def toml_string(value: object) -> str:
    """Narrow a TOML string without imposing field-specific content constraints."""
    if not isinstance(value, str):
        raise InvalidInvocationError("Expected a string")
    return value


def toml_integer(value: object) -> int:
    """Narrow one schema-validated TOML value to an integer, rejecting booleans."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidInvocationError("Expected an integer")
    return value


def json_value(text: str | bytes, *, label: str) -> object:
    """Decode tool JSON output without claiming a trusted type."""
    try:
        value: object = json.loads(text)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OperationalError(f"{label} did not return valid JSON") from exc
    if not structure_depth_is_bounded(value):
        raise OperationalError(f"{label} JSON exceeds the nesting limit")
    return value
