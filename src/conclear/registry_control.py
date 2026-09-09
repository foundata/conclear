"""Provider-neutral release-registry control contract."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from conclear.values import Digest, OCIReference


@dataclass(frozen=True, slots=True)
class TagObservation:
    """Observed state for one exact registry tag."""

    name: str
    digest: Digest
    expiration: datetime | None
    immutable: bool


@dataclass(frozen=True, slots=True)
class CandidateRetentionObservation:
    """Provider retention already covering future generated candidate tags."""

    repository: OCIReference
    policy_id: str
    tag_pattern: str
    maximum_age: timedelta

    def to_dict(self) -> dict[str, object]:
        """Return non-secret evidence of the observed repository policy."""
        return {
            "repository": str(self.repository),
            "policyId": self.policy_id,
            "tagPattern": self.tag_pattern,
            "maximumAgeSeconds": int(self.maximum_age.total_seconds()),
        }


class RegistryControl(Protocol):
    """Control-plane operations required by release workflows."""

    @property
    def provider(self) -> str:
        """Return the normalized compiled backend identifier."""
        ...

    def observe_tag(self, repository: OCIReference, tag: str) -> TagObservation | None:
        """Observe one exact tag without accepting ambiguous list results."""
        ...

    def enforce_candidate_lifetime(
        self, repository: OCIReference, tag: str, expiration: datetime
    ) -> TagObservation:
        """Enforce and verify a candidate deadline independently of this process."""
        ...

    def ensure_candidate_retention(
        self, repository: OCIReference, maximum_age: timedelta
    ) -> CandidateRetentionObservation:
        """Establish independent retention for future candidates before any upload."""
        ...

    def ensure_tag_immutable(
        self, repository: OCIReference, tag: str
    ) -> TagObservation:
        """Ensure and verify that a tag cannot be repointed."""
        ...

    def verify_tag_policy(
        self,
        repository: OCIReference,
        *,
        version_tags: tuple[str, ...],
        mutable_tags: tuple[str, ...],
    ) -> None:
        """Require effective policies to protect final tags and exclude mutable tags."""
        ...

    def ensure_tag_mutable(self, repository: OCIReference, tag: str) -> TagObservation:
        """Ensure and verify that an owned candidate can be removed."""
        ...

    def assign_tag(
        self, repository: OCIReference, tag: str, digest: Digest
    ) -> TagObservation:
        """Assign and verify one tag against an exact digest."""
        ...

    def remove_tag(self, repository: OCIReference, tag: str) -> None:
        """Remove one owned tag and verify that it is absent."""
        ...

    def close(self) -> None:
        """Close backend-owned resources."""
        ...
