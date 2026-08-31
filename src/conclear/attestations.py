"""in-toto Statement creation and DSSE payload validation."""

import base64
import binascii
import json
from pathlib import Path

from conclear.errors import OperationalError
from conclear.jsonutil import atomic_write_json
from conclear.values import Digest

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
RELEASE_VERIFICATION_TYPE = (
    "https://github.com/foundata/conclear/predicates/release-verification/v1"
)
RESCAN_TYPE = "https://github.com/foundata/conclear/predicates/rescan/v1"
SPDX_DOCUMENT_TYPE = "https://spdx.dev/Document"


def write_statement(
    *,
    subject_name: str,
    subject_digest: Digest,
    predicate_type: str,
    predicate: dict[str, object],
    path: Path,
) -> str:
    """Write one deterministic in-toto Statement around a validated predicate."""
    if not predicate_type.startswith("https://"):
        raise ValueError("Predicate type must be an HTTPS URI")
    return atomic_write_json(
        path,
        {
            "_type": STATEMENT_TYPE,
            "subject": [
                {
                    "name": subject_name,
                    "digest": {"sha256": subject_digest.encoded},
                }
            ],
            "predicateType": predicate_type,
            "predicate": predicate,
        },
        mode=0o644,
    )


def decode_dsse_statements(
    envelopes: tuple[object, ...],
) -> tuple[dict[str, object], ...]:
    """Decode bounded Cosign DSSE envelopes into runtime-validated statements."""
    statements: list[dict[str, object]] = []
    for raw in envelopes:
        envelope = _object(raw, "DSSE envelope")
        payload_type = envelope.get("payloadType")
        if payload_type != "application/vnd.in-toto+json":
            raise OperationalError("Cosign returned an unexpected DSSE payload type")
        payload = envelope.get("payload")
        if not isinstance(payload, str) or len(payload) > 16 * 1024 * 1024:
            raise OperationalError("Cosign DSSE payload is missing or too large")
        try:
            decoded = base64.b64decode(payload, validate=True)
            value = json.loads(decoded.decode("utf-8"))
        except (binascii.Error, UnicodeError, json.JSONDecodeError) as exc:
            raise OperationalError("Cosign DSSE payload is malformed") from exc
        statement = _object(value, "in-toto Statement")
        if statement.get("_type") != STATEMENT_TYPE:
            raise OperationalError("Cosign payload is not an in-toto Statement v1")
        statements.append(statement)
    return tuple(statements)


def statement_matches(
    statement: dict[str, object],
    *,
    subject_name: str,
    subject_digest: Digest,
    predicate_type: str,
    predicate: object,
) -> bool:
    """Compare the complete signed subject and predicate without trusting shape."""
    subjects = statement.get("subject")
    expected_subject = [
        {"name": subject_name, "digest": {"sha256": subject_digest.encoded}}
    ]
    return (
        subjects == expected_subject
        and statement.get("predicateType") == predicate_type
        and statement.get("predicate") == predicate
    )


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise OperationalError(f"{label} must be an object")
    return value
