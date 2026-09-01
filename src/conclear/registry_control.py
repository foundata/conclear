"""Provider-neutral release-registry control contract."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from conclear.values import Digest, OCIReference


@dataclass(frozen=True, slots=True)
class TagObservation:
    """Observed state for one exact registry tag."""

    name: str
    digest: Digest
    expiration: datetime | None
    immutable: bool


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

    def ensure_tag_immutable(
        self, repository: OCIReference, tag: str
    ) -> TagObservation:
        """Ensure and verify that a tag cannot be repointed."""
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
