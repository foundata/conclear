"""Versioned deterministic public release records."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from conclear.errors import ConClearError, InvalidInvocationError, OperationalError
from conclear.identity import IDENTITY
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    sha256_bytes,
)
from conclear.parsing import Narrower
from conclear.schema import validate_external
from conclear.values import validate_run_id, validate_source_revision

_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)

RECORD_SCHEMA_VERSIONS: dict[str, int] = {
    "platformQualification": 1,
    "qualificationTransport": 1,
    "releaseCandidate": 1,
    "releaseVerification": 1,
    "rescanResult": 1,
}


def utc_now() -> datetime:
    """Read the clock as an aware UTC value at whole-second precision."""
    return datetime.now(UTC).replace(microsecond=0)


def format_timestamp(value: datetime) -> str:
    """Serialize one whole-second aware timestamp as UTC RFC 3339 with a `Z` suffix.

    Raises:
        OperationalError: If the value is naive or carries sub-second precision,
            which means it did not come from `utc_now` or `parse_timestamp`.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise OperationalError("Timestamps must be timezone-aware")
    if value.microsecond:
        raise OperationalError("Timestamps must have whole-second precision")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_timestamp(
    value: object, label: str, *, error: type[ConClearError] = OperationalError
) -> datetime:
    """Parse one RFC 3339 timestamp into aware UTC at whole-second precision.

    Only the canonical `Z`-suffixed form ConClear writes is accepted. A
    fractional second is truncated so values read back from older records
    compare equal to the whole-second values ConClear now writes.

    Raises:
        error: If the value is not a non-empty string, cannot be parsed or
            lacks a UTC offset.
    """
    if not isinstance(value, str) or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise error(f"{label} must be a UTC RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise error(f"{label} must be a UTC RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise error(f"{label} must be a UTC RFC 3339 timestamp")
    return parsed.astimezone(UTC).replace(microsecond=0)


class Verdict(StrEnum):
    """Stable record verdicts."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """The declared public source URL paired with the observed source revision.

    `repository` is `project.source` from the reviewed configuration, not the
    Git origin of the checkout; the origin never enters records.
    """

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
    # A tool run from an image records the pinned index digest and, beside it,
    # the platform manifest that actually ran, which differs per architecture.
    image_digest: str | None = None
    image_manifest_digest: str | None = None

    @classmethod
    def from_dict(
        cls, value: object, *, error: type[ConClearError] = OperationalError
    ) -> "ToolIdentity":
        """Rebuild one tool identity from its public record object."""
        narrow = Narrower(error)
        item = narrow.object_value(value, "tool identity")

        def optional(key: str, label: str) -> str | None:
            raw = item.get(key)
            return None if raw is None else narrow.string_value(raw, label)

        return cls(
            narrow.string_value(item.get("name"), "tool name"),
            narrow.string_value(item.get("version"), "tool version"),
            executable_digest=optional("executableDigest", "tool executable digest"),
            image_digest=optional("imageDigest", "tool image digest"),
            image_manifest_digest=optional(
                "imageManifestDigest", "tool image manifest digest"
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Return a public tool identity object."""
        value: dict[str, object] = {"name": self.name, "version": self.version}
        if self.executable_digest is not None:
            value["executableDigest"] = self.executable_digest
        if self.image_digest is not None:
            value["imageDigest"] = self.image_digest
        if self.image_manifest_digest is not None:
            value["imageManifestDigest"] = self.image_manifest_digest
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
            raise OperationalError("Record timestamps must be timezone-aware")

    def to_dict(self) -> dict[str, object]:
        """Return a schema-validated public record object."""
        try:
            validate_source_revision(IDENTITY.source_revision)
        except InvalidInvocationError as exc:
            raise OperationalError(
                "Public records require a staged build with embedded source identity"
            ) from exc
        created_at = format_timestamp(self.created_at)
        try:
            schema_version = RECORD_SCHEMA_VERSIONS[self.record_type]
        except KeyError as exc:
            raise OperationalError(
                f"Unsupported public record type: {self.record_type}"
            ) from exc
        value: dict[str, object] = {
            "schemaVersion": schema_version,
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
