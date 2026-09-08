"""Consume attestation payloads only from the signature verifier's result."""

from pathlib import Path
from typing import Protocol

from conclear.adapters.cosign import VerificationObservation
from conclear.attestations import SPDX_DOCUMENT_TYPE, decode_dsse_statements
from conclear.errors import OperationalError
from conclear.values import OCIReference


class AttestationVerifier(Protocol):
    """The authenticated read boundary shared by release and rescan workflows."""

    def verify_attestation(
        self, *, subject: OCIReference, public_key: Path, predicate_type: str
    ) -> VerificationObservation:
        """Return the envelopes actually verified with the approved key."""
        ...


def verified_statements(
    verifier: AttestationVerifier,
    *,
    subject: OCIReference,
    public_key: Path,
    predicate_type: str,
) -> tuple[dict[str, object], ...]:
    """Decode verified envelopes without a second, unauthenticated payload fetch."""
    observation = verifier.verify_attestation(
        subject=subject,
        public_key=public_key,
        predicate_type="spdxjson"
        if predicate_type == SPDX_DOCUMENT_TYPE
        else predicate_type,
    )
    if observation.subject != subject or not observation.entries:
        raise OperationalError(
            "Attestation verifier returned no entries for the requested subject",
            code="CC0701",
        )
    return decode_dsse_statements(observation.entries)
