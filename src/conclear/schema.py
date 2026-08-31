"""Draft 2020-12 validation for external configuration and records."""

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import structure_depth_is_bounded


def load_schema(name: str) -> dict[str, Any]:
    """Load one shipped JSON Schema by filename."""
    resource = files("conclear.schemas").joinpath(name)
    try:
        value: Any = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OperationalError(f"Unable to load shipped schema {name}") from exc
    if not isinstance(value, dict) or not structure_depth_is_bounded(value):
        raise OperationalError(f"Shipped schema {name} is not a JSON object")
    return value


def validate_schema(name: str) -> None:
    """Check that a shipped schema is a valid Draft 2020-12 schema."""
    try:
        Draft202012Validator.check_schema(load_schema(name))
    except SchemaError as exc:
        raise OperationalError(
            f"Shipped schema {name} is invalid: {exc.message}"
        ) from exc


def validate_external(value: object, schema_name: str, *, label: str) -> None:
    """Validate untrusted data and report the first deterministic error."""
    if not structure_depth_is_bounded(value):
        raise InvalidInvocationError(f"Invalid {label}: nesting limit exceeded")
    validator = Draft202012Validator(load_schema(schema_name))
    try:
        errors = sorted(validator.iter_errors(value), key=_validation_error_key)
    except RecursionError as exc:
        raise InvalidInvocationError(
            f"Invalid {label}: nesting limit exceeded"
        ) from exc
    if not errors:
        return
    error = errors[0]
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    raise InvalidInvocationError(
        f"Invalid {label} at {location}: {error.message}",
    )


def _validation_error_key(error: ValidationError) -> tuple[str, str]:
    return ("/".join(str(part) for part in error.absolute_path), error.message)
