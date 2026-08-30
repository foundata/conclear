"""Versioned deterministic public release records."""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.identity import IDENTITY
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    sha256_bytes,
)
from conclear.schema import validate_external
from conclear.values import validate_run_id, validate_source_revision


class Verdict(StrEnum):
    """Stable record verdicts."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """Canonical observed source identity."""

    repository: str
    revision: str

    def __post_init__(self) -> None:
        """Validate the immutable source revision."""
        validate_source_revision(self.revision)


@dataclass(frozen=True, slots=True)
class ToolIdentity:
    """One resolved release tool identity."""

    name: str
    version: str
    executable_digest: str | None = None
    image_digest: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a public tool identity object."""
        value: dict[str, object] = {"name": self.name, "version": self.version}
        if self.executable_digest is not None:
            value["executableDigest"] = self.executable_digest
        if self.image_digest is not None:
            value["imageDigest"] = self.image_digest
        return value


@dataclass(frozen=True, slots=True)
class RecordEnvelope:
    """Shared identity and verdict fields for a public record."""

    record_type: str
    created_at: datetime
    run_id: str
    source: SourceIdentity
    configuration_digest: str
    tools: tuple[ToolIdentity, ...]
    verdict: Verdict
    payload: dict[str, object]

    def __post_init__(self) -> None:
        """Validate identity and timestamp invariants."""
        validate_run_id(self.run_id)
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("Record timestamps must be timezone-aware")

    def to_dict(self) -> dict[str, object]:
        """Return a schema-validated public record object."""
        try:
            validate_source_revision(IDENTITY.source_revision)
        except InvalidInvocationError as exc:
            raise OperationalError(
                "Public records require a staged build with embedded source identity"
            ) from exc
        created_at = self.created_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        value: dict[str, object] = {
            "schemaVersion": 1,
            "recordType": self.record_type,
            "createdAt": created_at,
            "runId": self.run_id,
            "ruleset": {
                "conclearVersion": IDENTITY.version,
                "conclearRevision": IDENTITY.source_revision,
                "guideTitle": IDENTITY.guide.title,
                "guideRepository": IDENTITY.guide.repository,
                "guidePath": IDENTITY.guide.path,
                "guideRevision": IDENTITY.guide.revision,
            },
            "source": {
                "repository": self.source.repository,
                "revision": self.source.revision,
            },
            "repositoryConfiguration": {
                "path": "conclear.toml",
                "sha256": self.configuration_digest,
            },
            "tools": [
                tool.to_dict()
                for tool in sorted(self.tools, key=lambda item: item.name)
            ],
            "verdict": self.verdict.value,
            "payload": self.payload,
        }
        validate_external(value, "record.schema.json", label=self.record_type)
        return value

    def content_bytes(self) -> bytes:
        """Return deterministic serialized bytes."""
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        """Return the digest of the exact serialized record bytes."""
        return sha256_bytes(self.content_bytes())

    def write(self, path: Path) -> str:
        """Atomically write the record and return its exact digest."""
        return atomic_write_json(path, self.to_dict())


def validate_record(value: object) -> None:
    """Validate an untrusted public record."""
    validate_external(value, "record.schema.json", label="public record")
