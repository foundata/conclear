import base64
import json

import pytest

from conclear.attestations import (
    LEGACY_STATEMENT_TYPE,
    STATEMENT_TYPE,
    decode_dsse_statements,
    statement_matches,
)
from conclear.errors import OperationalError
from conclear.values import Digest


def _envelope(statement: dict[str, object]) -> dict[str, object]:
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode("ascii"),
    }


def _statement(statement_type: str) -> dict[str, object]:
    return {
        "_type": statement_type,
        "subject": [{"name": "quay.io/example/app", "digest": {"sha256": "a" * 64}}],
        "predicateType": "https://example.invalid/predicates/custom/v1",
        "predicate": {"claim": True},
    }


def test_decoder_accepts_bare_envelopes_and_cosign_bundles_of_both_types() -> None:
    bare = _envelope(_statement(STATEMENT_TYPE))
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {},
        "dsseEnvelope": _envelope(_statement(LEGACY_STATEMENT_TYPE)),
    }

    statements = decode_dsse_statements((bare, bundle))

    assert [item["_type"] for item in statements] == [
        STATEMENT_TYPE,
        LEGACY_STATEMENT_TYPE,
    ]
    for statement in statements:
        assert statement_matches(
            statement,
            subject_name="quay.io/example/app",
            subject_digest=Digest("sha256:" + "a" * 64),
            predicate_type="https://example.invalid/predicates/custom/v1",
            predicate={"claim": True},
        )


@pytest.mark.parametrize(
    "envelope",
    [
        _envelope({"_type": "https://in-toto.io/Statement/v2", "subject": []}),
        {"dsseEnvelope": "not an object"},
        {"payloadType": "text/plain", "payload": "e30="},
    ],
    ids=["unknown-statement-type", "malformed-bundle", "wrong-payload-type"],
)
def test_decoder_rejects_unexpected_shapes(envelope: dict[str, object]) -> None:
    with pytest.raises(OperationalError):
        decode_dsse_statements((envelope,))
