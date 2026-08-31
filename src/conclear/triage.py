"""Validated external vulnerability-triage decisions for rescan evidence."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import load_json
from conclear.schema import validate_external
from conclear.values import Digest, OCIReference, Platform

MAX_TRIAGE_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class TriageDecision:
    """One externally owned decision bound to a released subject and finding."""

    subject: OCIReference
    platform: Platform
    component: str
    advisory: str
    decision: str
    rationale: str
    owner: str
    decided_at: str
    remediating_digest: Digest | None

    def to_dict(self) -> dict[str, object]:
        """Return the closed public evidence representation."""
        return {
            "subject": str(self.subject),
            "platform": str(self.platform),
            "component": self.component,
            "advisory": self.advisory,
            "decision": self.decision,
            "rationale": self.rationale,
            "owner": self.owner,
            "decidedAt": self.decided_at,
            "remediatingDigest": (
                None
                if self.remediating_digest is None
                else str(self.remediating_digest)
            ),
        }


def load_triage(path: Path, *, subject: OCIReference) -> tuple[TriageDecision, ...]:
    """Load schema-validated decisions and bind every entry to the CLI subject."""
    try:
        value = load_json(path, maximum_bytes=MAX_TRIAGE_BYTES)
    except OperationalError as exc:
        raise InvalidInvocationError("Unable to read rescan triage input") from exc
    validate_external(value, "triage.schema.json", label="rescan triage")
    if not isinstance(value, dict):  # schema-validated narrowing
        raise OperationalError("Triage schema accepted a non-object")
    raw_decisions = value.get("decisions")
    if not isinstance(raw_decisions, list):  # schema-validated narrowing
        raise OperationalError("Triage schema accepted a non-array")
    decisions = tuple(
        sorted(
            (_decision(item, subject=subject) for item in raw_decisions),
            key=lambda item: (item.platform, item.component, item.advisory),
        )
    )
    keys = [(item.platform, item.component, item.advisory) for item in decisions]
    if len(keys) != len(set(keys)):
        raise InvalidInvocationError(
            "Rescan triage contains duplicate platform, component and advisory entries"
        )
    return decisions


def _decision(value: object, *, subject: OCIReference) -> TriageDecision:
    if not isinstance(value, dict):  # schema-validated narrowing
        raise OperationalError("Triage schema accepted a non-object decision")
    decision_subject = OCIReference.parse(
        _string(value["subject"]), require_digest=True, allow_localhost=False
    )
    if decision_subject.tag is not None or decision_subject != subject:
        raise InvalidInvocationError(
            "Every rescan triage decision must name the exact rescan subject"
        )
    remediation_value = value["remediatingDigest"]
    remediation = (
        None if remediation_value is None else Digest(_string(remediation_value))
    )
    return TriageDecision(
        subject=decision_subject,
        platform=Platform.parse(_string(value["platform"])),
        component=_string(value["component"]),
        advisory=_string(value["advisory"]),
        decision=_string(value["decision"]),
        rationale=_string(value["rationale"]),
        owner=_string(value["owner"]),
        decided_at=_utc_timestamp(_string(value["decidedAt"])),
        remediating_digest=remediation,
    )


def _string(value: object) -> str:
    if not isinstance(value, str):  # schema-validated narrowing
        raise OperationalError("Triage schema accepted a non-string")
    return value


def _utc_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise InvalidInvocationError(
            f"Rescan triage timestamp is not valid: {value}"
        ) from exc
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise InvalidInvocationError("Rescan triage timestamps must use UTC")
    return value
