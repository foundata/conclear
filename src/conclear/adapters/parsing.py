"""Runtime validation helpers for untrusted adapter output."""

import json
from typing import Any

from conclear.errors import OperationalError
from conclear.jsonutil import structure_depth_is_bounded


def json_value(text: str, *, label: str) -> object:
    """Decode tool JSON output without claiming a trusted type."""
    try:
        value: object = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise OperationalError(f"{label} did not return valid JSON") from exc
    if not structure_depth_is_bounded(value):
        raise OperationalError(f"{label} JSON exceeds the nesting limit")
    return value


def object_value(value: object, *, label: str) -> dict[str, Any]:
    """Validate a string-keyed JSON object."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise OperationalError(f"{label} must be a JSON object")
    return value


def array_value(value: object, *, label: str) -> list[Any]:
    """Validate a JSON array."""
    if not isinstance(value, list):
        raise OperationalError(f"{label} must be a JSON array")
    return value


def string_value(value: object, *, label: str) -> str:
    """Validate a non-empty string field."""
    if not isinstance(value, str) or not value:
        raise OperationalError(f"{label} must be a non-empty string")
    return value


def integer_value(value: object, *, label: str) -> int:
    """Validate an integer field."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise OperationalError(f"{label} must be an integer")
    return value
