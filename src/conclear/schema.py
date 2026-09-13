"""Draft 2020-12 validation for external configuration and records."""

import json
from collections.abc import Mapping
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


def validate_external(
    value: object,
    schema_name: str,
    *,
    label: str,
    all_errors: bool = False,
    code: str | None = None,
) -> None:
    """Validate untrusted data, optionally collecting configuration diagnostics.

    `code` names the stable check a rejection belongs to, for inputs whose
    schema validation is itself a catalogued check.
    """
    if not structure_depth_is_bounded(value):
        raise InvalidInvocationError(
            f"Invalid {label}: nesting limit exceeded", code=code
        )
    validator = Draft202012Validator(load_schema(schema_name))
    try:
        errors = sorted(validator.iter_errors(value), key=_validation_error_key)
    except RecursionError as exc:
        raise InvalidInvocationError(
            f"Invalid {label}: nesting limit exceeded", code=code
        ) from exc
    if not errors:
        return
    if all_errors:
        messages = [
            f"  {'.'.join(str(part) for part in item.absolute_path) or '<root>'}: {item.message}"
            for item in errors
        ]
        raise InvalidInvocationError(
            f"Invalid {label}:\n" + "\n".join(messages), code=code
        )
    error = _most_specific(errors[0])
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    raise InvalidInvocationError(
        f"Invalid {label} at {location}: {_describe(error)}", code=code
    )


def _most_specific(error: ValidationError) -> ValidationError:
    """Descend through oneOf/anyOf alternatives to the error a reader can act on."""
    current = error
    while current.context:
        current = max(
            current.context,
            key=lambda item: (
                len(item.absolute_path),
                item.validator in _ACTIONABLE_VALIDATORS,
                -len(item.message),
            ),
        )
    return current


_ACTIONABLE_VALIDATORS = frozenset(
    {"additionalProperties", "required", "enum", "const", "type", "pattern"}
)


def _describe(error: ValidationError) -> str:
    """Return the error message without echoing the offending value."""
    if error.validator in {"oneOf", "anyOf"}:
        return "does not match any of the allowed forms"
    if error.validator == "additionalProperties":
        schema = error.schema if isinstance(error.schema, Mapping) else {}
        allowed = schema.get("properties") or {}
        unexpected = sorted(
            key
            for key in (error.instance if isinstance(error.instance, dict) else {})
            if key not in allowed
        )
        if unexpected:
            return "unexpected key(s): " + ", ".join(unexpected)
    if error.validator == "required":
        return str(error.message)
    message = str(error.message)
    # jsonschema phrases most messages as "<value repr> <verdict>"; keep the verdict.
    rendered = repr(error.instance)
    if message.startswith(rendered):
        message = message[len(rendered) :].strip()
    if not message:
        message = f"violates {error.validator}"
    return message if len(message) <= 200 else message[:197] + "..."


def _validation_error_key(error: ValidationError) -> tuple[str, str]:
    return ("/".join(str(part) for part in error.absolute_path), error.message)
