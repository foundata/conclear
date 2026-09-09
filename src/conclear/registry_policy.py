"""Reviewed registry protections and candidate-cleanup responsibilities."""

from dataclasses import dataclass
from enum import StrEnum

from conclear.errors import InvalidInvocationError
from conclear.parsing import Narrower
from conclear.presentation import Finding

_narrow = Narrower(InvalidInvocationError)


def policy_findings(policy: "RegistryPolicy") -> tuple[Finding, ...]:
    """Disclose reviewed operational fallbacks without weakening a required check."""
    findings: list[Finding] = []
    protection = policy.tag_protection
    if protection.mode is TagProtectionMode.NOT_ENFORCED:
        findings.append(
            Finding(
                "CC0604",
                "warning",
                f"Registry version-tag protection is not enforced; owner: {protection.owner}; rationale: {protection.rationale}",
            )
        )
    cleanup = policy.candidate_cleanup
    if cleanup.mode is CandidateCleanupMode.MANUAL:
        findings.append(
            Finding(
                "CC0603",
                "warning",
                f"Candidate cleanup is manual; owner: {cleanup.owner}; procedure: {cleanup.procedure}",
            )
        )
    return tuple(findings)


class TagProtectionMode(StrEnum):
    """Whether release authorization requires native version-tag protection."""

    REQUIRED = "required"
    NOT_ENFORCED = "not-enforced"


class CandidateCleanupMode(StrEnum):
    """Explicit cleanup mechanism, independent of candidate authorization."""

    MANUAL = "manual"
    TAG_EXPIRATION = "tag-expiration"
    AUTO_PRUNE = "auto-prune"


@dataclass(frozen=True, slots=True)
class TagProtectionPolicy:
    """Required protection or an owned, reviewed exception."""

    mode: TagProtectionMode
    rationale: str | None = None
    owner: str | None = None

    def __post_init__(self) -> None:
        """Require a real explanation only when enforcement is not required."""
        if self.mode is TagProtectionMode.NOT_ENFORCED:
            if (
                not self.rationale
                or not self.rationale.strip()
                or not self.owner
                or not self.owner.strip()
            ):
                raise InvalidInvocationError(
                    "Unenforced tag protection needs a rationale and owner"
                )
        elif self.rationale is not None or self.owner is not None:
            raise InvalidInvocationError(
                "Required tag protection cannot declare an exception"
            )

    def to_dict(self) -> dict[str, object]:
        """Return public policy evidence, without credential locations."""
        return {
            "mode": self.mode.value,
            "rationale": self.rationale,
            "owner": self.owner,
        }


@dataclass(frozen=True, slots=True)
class CandidateCleanupPolicy:
    """Owned cleanup procedure with an optional provider mechanism."""

    mode: CandidateCleanupMode
    owner: str
    procedure: str

    def __post_init__(self) -> None:
        """Reject empty ownership or procedures even in programmatic profiles."""
        if not self.owner.strip() or not self.procedure.strip():
            raise InvalidInvocationError(
                "Candidate cleanup needs an owner and procedure"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the public cleanup responsibility and selected mechanism."""
        return {
            "mode": self.mode.value,
            "owner": self.owner,
            "procedure": self.procedure,
        }


@dataclass(frozen=True, slots=True)
class RegistryPolicy:
    """Provider-independent release protections chosen by the maintainer."""

    tag_protection: TagProtectionPolicy
    candidate_cleanup: CandidateCleanupPolicy

    def to_dict(self) -> dict[str, object]:
        """Return the exact reviewed choices retained in signed evidence."""
        return {
            "tagProtection": self.tag_protection.to_dict(),
            "candidateCleanup": self.candidate_cleanup.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> "RegistryPolicy":
        """Read journaled policy, rejecting unknown or malformed fields."""
        policy = _narrow.object_value(value, "registry policy")
        protection = _narrow.object_value(policy.get("tagProtection"), "tag protection")
        cleanup = _narrow.object_value(
            policy.get("candidateCleanup"), "candidate cleanup"
        )
        try:
            result = cls(
                TagProtectionPolicy(
                    TagProtectionMode(
                        _narrow.string_value(
                            protection.get("mode"), "tag protection mode"
                        )
                    ),
                    None
                    if protection.get("rationale") is None
                    else _narrow.string_value(
                        protection["rationale"], "tag protection rationale"
                    ),
                    None
                    if protection.get("owner") is None
                    else _narrow.string_value(
                        protection["owner"], "tag protection owner"
                    ),
                ),
                CandidateCleanupPolicy(
                    CandidateCleanupMode(
                        _narrow.string_value(cleanup.get("mode"), "cleanup mode")
                    ),
                    _narrow.string_value(cleanup.get("owner"), "cleanup owner"),
                    _narrow.string_value(cleanup.get("procedure"), "cleanup procedure"),
                ),
            )
        except ValueError as exc:
            raise InvalidInvocationError("Unknown registry policy mode") from exc
        if result.to_dict() != policy:
            raise InvalidInvocationError(
                "Registry policy has unknown or missing fields"
            )
        return result
