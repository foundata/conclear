"""Select retained evidence without assuming one attestation per image digest."""

from dataclasses import dataclass

from conclear.attestations import RELEASE_VERIFICATION_TYPE, SPDX_DOCUMENT_TYPE
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import canonical_json_bytes, sha256_bytes
from conclear.parsing import object_value
from conclear.records import parse_timestamp, validate_record
from conclear.spdx import validate_spdx_document
from conclear.values import OCIReference


@dataclass(frozen=True, slots=True)
class ReleaseEvidence:
    """One validated release record and its stable content identity."""

    digest: str
    record: dict[str, object]
    payload: dict[str, object]


def verified_predicates(
    statements: tuple[dict[str, object], ...],
    *,
    predicate_type: str,
    subject: OCIReference,
) -> dict[str, dict[str, object]]:
    """Narrow verified statements and deduplicate identical predicate bytes."""
    if subject.digest is None or subject.tag is not None:
        raise OperationalError("Rescan statement subject is not immutable")
    expected_subject = [
        {
            "name": subject.repository_name,
            "digest": {"sha256": subject.digest.encoded},
        }
    ]
    predicates: dict[str, dict[str, object]] = {}
    for statement in statements:
        if (
            statement.get("predicateType") != predicate_type
            or statement.get("subject") != expected_subject
        ):
            raise OperationalError(
                "Verified attestation has an unexpected subject or predicate type"
            )
        predicate = object_value(statement.get("predicate"), "verified predicate")
        predicates[sha256_bytes(canonical_json_bytes(predicate))] = predicate
    return predicates


def select_release_evidence(
    statements: tuple[dict[str, object], ...],
    *,
    subject: OCIReference,
    configuration_digest: str,
    anchored_digest: str | None,
) -> ReleaseEvidence:
    """Select the earliest matching release, or retain an established rescan anchor."""
    predicates = verified_predicates(
        statements, predicate_type=RELEASE_VERIFICATION_TYPE, subject=subject
    )
    candidates: list[ReleaseEvidence] = []
    for digest, record in predicates.items():
        validate_record(record)
        if (
            record.get("recordType") != "releaseVerification"
            or record.get("verdict") != "accepted"
        ):
            raise OperationalError(
                "Verified release predicate is not an accepted release"
            )
        payload = object_value(record.get("payload"), "release payload")
        if payload.get("subject") != {
            "repository": subject.repository_name,
            "digest": str(subject.digest),
        }:
            raise OperationalError("Release verification names another subject")
        configuration = object_value(
            record.get("repositoryConfiguration"), "repository configuration"
        )
        if configuration.get("sha256") == configuration_digest:
            candidates.append(ReleaseEvidence(digest, record, payload))
    if not candidates:
        raise InvalidInvocationError(
            "Rescan repository configuration differs from release verification; "
            "use the exact conclear.toml and source checkout retained for this digest"
        )
    identities = {
        canonical_json_bytes(
            {
                "source": item.record.get("source"),
                "platforms": item.payload.get("platformDigests"),
                "builder": item.payload.get("builder"),
                "signer": item.payload.get("signer"),
            }
        )
        for item in candidates
    }
    if len(identities) != 1:
        raise OperationalError("Matching release records have conflicting identities")
    if anchored_digest is not None:
        for candidate in candidates:
            if candidate.digest == anchored_digest:
                return candidate
        raise OperationalError(
            "The release record anchored by rescan history is missing"
        )
    return min(
        candidates,
        key=lambda item: (
            parse_timestamp(item.record.get("createdAt"), "Release timestamp"),
            item.digest,
        ),
    )


def select_release_sbom(
    statements: tuple[dict[str, object], ...],
    *,
    subject: OCIReference,
    evidence_digests: frozenset[str],
) -> tuple[str, dict[str, object]]:
    """Select exactly one signed platform inventory referenced by the release."""
    predicates = verified_predicates(
        statements, predicate_type=SPDX_DOCUMENT_TYPE, subject=subject
    )
    matches = predicates.keys() & evidence_digests
    if len(matches) != 1:
        raise OperationalError(
            "Expected exactly one release-bound SBOM for "
            f"{subject}, found {len(matches)}"
        )
    digest = matches.pop()
    return digest, validate_spdx_document(
        predicates[digest], label=f"SBOM for {subject}"
    )
