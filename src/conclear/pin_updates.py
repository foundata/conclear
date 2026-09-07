"""Non-mutating pin-update proposals.

`propose_pin_updates` resolves each declared readable tag once and binds the
observed digest to every `[[images.pins]]` declaration and every Containerfile
image input that names the same tagged and digest-pinned reference. It returns
a schema-validated proposal and never edits a project file. The occurrences it
binds come from the read-only worktree view in `conclear.pin_occurrences`;
`conclear.pin_application` applies the proposal.
"""

import json
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from conclear.config import (
    PinIntent,
    RepositoryConfig,
)
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
)
from conclear.fileio import read_regular_file
from conclear.identity import IDENTITY
from conclear.jsonutil import (
    canonical_json_bytes,
    sha256_bytes,
    structure_depth_is_bounded,
)
from conclear.pin_occurrences import (
    CONFIGURATION_NAME,
    Occurrence,
    Snapshot,
    discover_occurrences,
)
from conclear.pins import PinResolver
from conclear.presentation import Finding
from conclear.records import (
    SourceIdentity,
    ToolIdentity,
    format_timestamp,
    parse_timestamp,
)
from conclear.schema import validate_external
from conclear.values import Digest, OCIReference, validate_source_revision

PROPOSAL_SCHEMA_VERSION = 1
PROPOSAL_RECORD_TYPE = "pinUpdateProposal"
MAX_PROPOSAL_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class PinLookup:
    """One original pinned reference and the single resolution bound to it."""

    image_ids: tuple[str, ...]
    tag_intent: PinIntent
    original_reference: OCIReference
    resolved_reference: OCIReference
    resolved_at: datetime

    def __post_init__(self) -> None:
        """Validate that only the digest differs between the references."""
        original = self.original_reference
        resolved = self.resolved_reference
        if original.tag is None or original.digest is None or resolved.digest is None:
            raise InvalidInvocationError("Pin lookups require tagged digest references")
        if (original.registry, original.repository, original.tag) != (
            resolved.registry,
            resolved.repository,
            resolved.tag,
        ):
            raise InvalidInvocationError(
                "Pin lookup changes the reference spelling instead of its digest"
            )
        if not self.image_ids or list(self.image_ids) != sorted(set(self.image_ids)):
            raise InvalidInvocationError(
                "Pin lookup image IDs must be sorted and unique"
            )
        require_aware(self.resolved_at, "resolution time")

    @property
    def old_digest(self) -> Digest:
        """Return the currently pinned digest."""
        if self.original_reference.digest is None:  # pragma: no cover - validated
            raise InvalidInvocationError("Original reference has no digest")
        return self.original_reference.digest

    @property
    def new_digest(self) -> Digest:
        """Return the observed digest."""
        if self.resolved_reference.digest is None:  # pragma: no cover - validated
            raise InvalidInvocationError("Resolved reference has no digest")
        return self.resolved_reference.digest

    @property
    def changed(self) -> bool:
        """Return whether the observed digest differs from the pinned digest."""
        return self.old_digest != self.new_digest

    @property
    def review_required(self) -> bool:
        """Return whether the change is an immutable-version supply-chain event."""
        return self.changed and self.tag_intent is PinIntent.IMMUTABLE_VERSION

    def to_dict(self) -> dict[str, object]:
        """Return the public lookup object."""
        return {
            "imageIds": list(self.image_ids),
            "tagIntent": self.tag_intent.value,
            "originalReference": str(self.original_reference),
            "resolvedReference": str(self.resolved_reference),
            "oldDigest": str(self.old_digest),
            "newDigest": str(self.new_digest),
            "resolvedAt": format_timestamp(self.resolved_at),
            "reviewRequired": self.review_required,
        }


@dataclass(frozen=True, slots=True)
class ProposedEdit:
    """One exact byte span replacement inside one file."""

    start: int
    end: int
    old_text: str
    new_text: str

    def __post_init__(self) -> None:
        """Validate span arithmetic and spelling preservation."""
        if self.start < 0 or self.end - self.start != len(self.old_text.encode()):
            raise InvalidInvocationError(
                "Proposed edit span does not match its old bytes"
            )
        if self.old_text.rsplit("@", 1)[0] != self.new_text.rsplit("@", 1)[0]:
            raise InvalidInvocationError(
                "Proposed edit changes the reference spelling instead of its digest"
            )
        if self.old_text == self.new_text:
            raise InvalidInvocationError("Proposed edit does not change its bytes")

    def to_dict(self) -> dict[str, object]:
        """Return the public edit object."""
        return {
            "start": self.start,
            "end": self.end,
            "oldBytes": self.old_text,
            "newBytes": self.new_text,
        }


@dataclass(frozen=True, slots=True)
class ProposedFile:
    """One repository file with its expected digests and ordered edits."""

    path: str
    sha256: str
    result_sha256: str
    edits: tuple[ProposedEdit, ...]

    def __post_init__(self) -> None:
        """Validate ordering and non-overlap of the edits."""
        if not self.edits:
            raise InvalidInvocationError(f"Proposed file has no edits: {self.path}")
        previous_end = -1
        for edit in self.edits:
            if edit.start < previous_end:
                raise InvalidInvocationError(
                    f"Proposed edits overlap or are unordered in {self.path}"
                )
            previous_end = edit.end

    def to_dict(self) -> dict[str, object]:
        """Return the public file object."""
        return {
            "path": self.path,
            "sha256": self.sha256,
            "resultSha256": self.result_sha256,
            "edits": [edit.to_dict() for edit in self.edits],
        }

    def apply_to(self, content: bytes) -> bytes:
        """Return the content with every edit applied after checking old bytes."""
        result = bytearray(content)
        for edit in reversed(self.edits):
            old = edit.old_text.encode("utf-8")
            if edit.end > len(content) or bytes(content[edit.start : edit.end]) != old:
                raise InvalidInvocationError(
                    f"Proposed old bytes do not match {self.path} at {edit.start}",
                    code="CC0207",
                )
            result[edit.start : edit.end] = edit.new_text.encode("utf-8")
        return bytes(result)


@dataclass(frozen=True, slots=True)
class PinUpdateProposal:
    """One complete, schema-validated version-1 pin update proposal."""

    created_at: datetime
    source: SourceIdentity
    configuration_digest: str
    tools: tuple[ToolIdentity, ...]
    image_ids: tuple[str, ...]
    lookups: tuple[PinLookup, ...]
    files: tuple[ProposedFile, ...]

    def __post_init__(self) -> None:
        """Validate cross-object invariants once at construction."""
        require_aware(self.created_at, "creation time")
        if list(self.image_ids) != sorted(set(self.image_ids)) or not self.image_ids:
            raise InvalidInvocationError("Proposal image IDs must be sorted and unique")
        originals = [str(item.original_reference) for item in self.lookups]
        if originals != sorted(set(originals)):
            raise InvalidInvocationError(
                "Proposal lookups must be unique and sorted by reference"
            )
        for lookup in self.lookups:
            if not set(lookup.image_ids) <= set(self.image_ids):
                raise InvalidInvocationError(
                    "Proposal lookup names an image outside the proposal"
                )
        paths = [item.path for item in self.files]
        if paths != sorted(set(paths)):
            raise InvalidInvocationError("Proposal files contain a duplicate path")
        replacements = {
            str(item.original_reference): str(item.resolved_reference)
            for item in self.lookups
            if item.changed
        }
        for item in self.files:
            for edit in item.edits:
                if replacements.get(edit.old_text) != edit.new_text:
                    raise InvalidInvocationError(
                        f"Proposed edit in {item.path} does not match a changed lookup"
                    )

    @property
    def changed(self) -> bool:
        """Return whether applying the proposal changes any file."""
        return bool(self.files)

    @property
    def review_required(self) -> bool:
        """Return whether any change needs immutable-version supply-chain review."""
        return any(item.review_required for item in self.lookups)

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Return the review findings that accompany the proposal."""
        return tuple(
            Finding(
                check_id="CC0205",
                severity="warning",
                message=(
                    f"Immutable-version tag changed from {item.old_digest} to "
                    f"{item.new_digest}; supply-chain review is required"
                ),
                location=str(item.original_reference),
            )
            for item in self.lookups
            if item.review_required
        )

    def to_dict(self) -> dict[str, object]:
        """Return the schema-validated public proposal object."""
        try:
            validate_source_revision(IDENTITY.source_revision)
        except InvalidInvocationError as exc:
            raise OperationalError(
                "Pin update proposals require a staged build with embedded source identity"
            ) from exc
        value: dict[str, object] = {
            "schemaVersion": PROPOSAL_SCHEMA_VERSION,
            "recordType": PROPOSAL_RECORD_TYPE,
            "createdAt": format_timestamp(self.created_at),
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
                "path": CONFIGURATION_NAME,
                "sha256": self.configuration_digest,
            },
            "tools": [
                tool.to_dict()
                for tool in sorted(self.tools, key=lambda item: item.name)
            ],
            "imageIds": list(self.image_ids),
            "lookups": [item.to_dict() for item in self.lookups],
            "files": [item.to_dict() for item in self.files],
            "reviewRequired": self.review_required,
        }
        validate_external(value, "proposal.schema.json", label="pin update proposal")
        return value

    def content_bytes(self) -> bytes:
        """Return the canonical serialized proposal bytes."""
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        """Return the proposal identity: the SHA-256 of its exact stored bytes."""
        return sha256_bytes(self.content_bytes())

    def write(self, path: Path) -> str:
        """Create the proposal file exclusively and return its digest."""
        content = self.content_bytes()
        try:
            descriptor = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
            )
        except FileExistsError as exc:
            raise InvalidInvocationError(
                f"Proposal output already exists: {path}"
            ) from exc
        except OSError as exc:
            raise OperationalError(f"Unable to create proposal output {path}") from exc
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            path.unlink(missing_ok=True)
            raise OperationalError(f"Unable to write proposal output {path}") from exc
        return sha256_bytes(content)


def propose_pin_updates(
    repository: RepositoryConfig,
    *,
    source: SourceIdentity,
    resolver: PinResolver,
    tools: tuple[ToolIdentity, ...],
    now: Callable[[], datetime],
    image_ids: tuple[str, ...] | None = None,
) -> PinUpdateProposal:
    """Resolve each readable tag once and bind it to every declared occurrence."""
    created_at = now()
    snapshot = discover_occurrences(repository, image_ids)
    resolutions: dict[str, tuple[Digest, datetime]] = {}
    lookups: list[PinLookup] = []
    grouped = _group_by_reference(snapshot.occurrences)
    for original_text in sorted(grouped):
        original = OCIReference.parse(
            original_text, require_tag=True, require_digest=True
        )
        readable = OCIReference(
            original.registry, original.repository, tag=original.tag
        )
        key = str(readable)
        if key not in resolutions:
            observed = resolver.resolve_digest(readable)
            resolutions[key] = (observed, now())
        observed_digest, resolved_at = resolutions[key]
        lookups.append(
            PinLookup(
                image_ids=tuple(
                    sorted({item.image_id for item in grouped[original_text]})
                ),
                tag_intent=snapshot.intents[original_text],
                original_reference=original,
                resolved_reference=OCIReference(
                    original.registry,
                    original.repository,
                    tag=original.tag,
                    digest=observed_digest,
                ),
                resolved_at=resolved_at,
            )
        )
    files = _proposed_files(snapshot, lookups)
    return PinUpdateProposal(
        created_at=created_at,
        source=source,
        configuration_digest=sha256_bytes(snapshot.contents[CONFIGURATION_NAME]),
        tools=tools,
        image_ids=snapshot.image_ids,
        lookups=tuple(lookups),
        files=files,
    )


def parse_proposal(value: object) -> PinUpdateProposal:
    """Validate an untrusted proposal object and build the typed proposal."""
    validate_external(value, "proposal.schema.json", label="pin update proposal")
    if not isinstance(value, dict):  # pragma: no cover - schema guarantees an object
        raise InvalidInvocationError("Invalid pin update proposal: not an object")
    try:
        source = SourceIdentity(
            repository=str(value["source"]["repository"]),
            revision=validate_source_revision(str(value["source"]["revision"])),
        )
        tools = tuple(
            ToolIdentity(
                name=str(tool["name"]),
                version=str(tool["version"]),
                executable_digest=_optional_string(tool.get("executableDigest")),
                image_digest=_optional_string(tool.get("imageDigest")),
            )
            for tool in value["tools"]
        )
        lookups = tuple(
            PinLookup(
                image_ids=tuple(str(item) for item in lookup["imageIds"]),
                tag_intent=PinIntent(str(lookup["tagIntent"])),
                original_reference=OCIReference.parse(
                    str(lookup["originalReference"]),
                    require_tag=True,
                    require_digest=True,
                ),
                resolved_reference=OCIReference.parse(
                    str(lookup["resolvedReference"]),
                    require_tag=True,
                    require_digest=True,
                ),
                resolved_at=parse_timestamp(
                    str(lookup["resolvedAt"]),
                    "Proposal timestamp",
                    error=InvalidInvocationError,
                ),
            )
            for lookup in value["lookups"]
        )
        for raw, lookup in zip(value["lookups"], lookups, strict=True):
            if str(lookup.old_digest) != raw["oldDigest"] or (
                str(lookup.new_digest) != raw["newDigest"]
            ):
                raise InvalidInvocationError(
                    "Proposal lookup digest fields do not match its references"
                )
            if lookup.review_required is not raw["reviewRequired"]:
                raise InvalidInvocationError(
                    "Proposal lookup review requirement does not match its intent"
                )
        files = tuple(
            ProposedFile(
                path=str(item["path"]),
                sha256=str(item["sha256"]),
                result_sha256=str(item["resultSha256"]),
                edits=tuple(
                    ProposedEdit(
                        start=int(edit["start"]),
                        end=int(edit["end"]),
                        old_text=str(edit["oldBytes"]),
                        new_text=str(edit["newBytes"]),
                    )
                    for edit in item["edits"]
                ),
            )
            for item in value["files"]
        )
        proposal = PinUpdateProposal(
            created_at=parse_timestamp(
                str(value["createdAt"]),
                "Proposal timestamp",
                error=InvalidInvocationError,
            ),
            source=source,
            configuration_digest=str(value["repositoryConfiguration"]["sha256"]),
            tools=tools,
            image_ids=tuple(str(item) for item in value["imageIds"]),
            lookups=lookups,
            files=files,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidInvocationError(
            "Invalid pin update proposal: malformed field"
        ) from exc
    if proposal.review_required is not value["reviewRequired"]:
        raise InvalidInvocationError(
            "Proposal review requirement does not match its lookups"
        )
    return proposal


def load_proposal(path: Path) -> PinUpdateProposal:
    """Load one bounded proposal file without following a symbolic link."""
    content = read_regular_file(
        path, maximum_bytes=MAX_PROPOSAL_BYTES, label="pin update proposal"
    )
    try:
        value: object = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InvalidInvocationError(
            f"Pin update proposal is not valid JSON: {path}"
        ) from exc
    if not structure_depth_is_bounded(value):
        raise InvalidInvocationError("Pin update proposal exceeds the nesting limit")
    return parse_proposal(value)


def _proposed_files(
    snapshot: Snapshot, lookups: list[PinLookup]
) -> tuple[ProposedFile, ...]:
    replacements = {
        str(item.original_reference): str(item.resolved_reference)
        for item in lookups
        if item.changed
    }
    files: list[ProposedFile] = []
    for path in sorted(snapshot.contents):
        seen: set[tuple[int, int]] = set()
        edits: list[ProposedEdit] = []
        for occurrence in snapshot.occurrences:
            if occurrence.path != path or (occurrence.start, occurrence.end) in seen:
                continue
            seen.add((occurrence.start, occurrence.end))
            new_text = replacements.get(str(occurrence.reference))
            if new_text is None:
                continue
            edits.append(
                ProposedEdit(
                    start=occurrence.start,
                    end=occurrence.end,
                    old_text=str(occurrence.reference),
                    new_text=new_text,
                )
            )
        if not edits:
            continue
        content = snapshot.contents[path]
        proposed = ProposedFile(
            path=path,
            sha256=sha256_bytes(content),
            result_sha256="sha256:" + "0" * 64,
            edits=tuple(sorted(edits, key=lambda item: item.start)),
        )
        files.append(
            ProposedFile(
                path=path,
                sha256=proposed.sha256,
                result_sha256=sha256_bytes(proposed.apply_to(content)),
                edits=proposed.edits,
            )
        )
    return tuple(files)


def _group_by_reference(
    occurrences: Iterable[Occurrence],
) -> dict[str, list[Occurrence]]:
    grouped: dict[str, list[Occurrence]] = {}
    for occurrence in occurrences:
        grouped.setdefault(str(occurrence.reference), []).append(occurrence)
    return grouped


def require_aware(value: datetime, label: str) -> None:
    """Reject a naive proposal timestamp."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise InvalidInvocationError(f"Proposal {label} must be timezone-aware")


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidInvocationError("Proposal tool digest must be a string")
    return value
