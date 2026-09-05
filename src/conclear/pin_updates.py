"""Non-mutating pin-update proposals and their occurrence discovery.

`propose_pin_updates` resolves each declared readable tag once and binds the
observed digest to every `[[images.pins]]` declaration and every Containerfile
image input that names the same tagged and digest-pinned reference. It returns
a schema-validated proposal and never edits a project file.

`discover_occurrences` is the shared read-only view of the worktree: it locates
every exact byte span that a proposal may replace. `conclear.pin_application`
reuses it to prove that the worktree still matches a proposal before and after
applying it.
"""

import json
import os
import re
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from conclear.checks import (
    MAX_CONTAINERFILE_BYTES,
    ReferenceOccurrence,
    analyze_containerfile,
    external_reference_occurrences,
)
from conclear.config import (
    MAX_CONFIG_BYTES,
    ImageConfig,
    PinIntent,
    RepositoryConfig,
)
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.fileio import read_regular_file
from conclear.identity import IDENTITY
from conclear.jsonutil import (
    canonical_json_bytes,
    sha256_bytes,
    structure_depth_is_bounded,
)
from conclear.path_safety import contained_path
from conclear.pins import PinResolver
from conclear.presentation import Finding
from conclear.records import SourceIdentity, ToolIdentity
from conclear.schema import validate_external
from conclear.toml_spans import locate_string_values
from conclear.values import Digest, OCIReference, validate_source_revision

PROPOSAL_SCHEMA_VERSION = 1
PROPOSAL_RECORD_TYPE = "pinUpdateProposal"
MAX_PROPOSAL_BYTES = 16 * 1024 * 1024
CONFIGURATION_NAME = "conclear.toml"
_REFERENCE_CHARACTERS = "A-Za-z0-9._:/@-"


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
            "resolvedAt": _timestamp(self.resolved_at),
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
            "createdAt": _timestamp(self.created_at),
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


@dataclass(frozen=True, slots=True)
class Occurrence:
    """One exact byte span naming a pinned reference in one repository file."""

    path: str
    start: int
    end: int
    reference: OCIReference
    image_id: str
    tag_intent: PinIntent | None


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Read-only view of every pin occurrence in the selected images.

    `contents` holds the exact bytes of each inspected repository-relative
    path, `intents` maps each original reference to its declared tag intent
    and `image_ids` is the sorted closed image selection.
    """

    root: Path
    contents: dict[str, bytes]
    occurrences: tuple[Occurrence, ...]
    intents: dict[str, PinIntent]
    image_ids: tuple[str, ...]


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
                resolved_at=_parse_timestamp(str(lookup["resolvedAt"])),
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
            created_at=_parse_timestamp(str(value["createdAt"])),
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


def discover_occurrences(
    repository: RepositoryConfig, image_ids: tuple[str, ...] | None
) -> Snapshot:
    """Locate every declared and Containerfile pin occurrence exactly once.

    Raises:
        InvalidInvocationError: If an occurrence is undeclared, ambiguous,
            duplicated or cannot be located exactly (`CC0206`).
        RuleRejectionError: If declared pins and Containerfile inputs differ
            (`CC0203`).
    """
    root = repository.path.parent
    selected = _select_images(repository, image_ids)
    contents: dict[str, bytes] = {}
    occurrences: list[Occurrence] = []
    for image in selected:
        occurrences.extend(_containerfile_occurrences(root, image, contents))
    occurrences.extend(_declaration_occurrences(repository, selected, contents))
    intents = _consistent_intents(occurrences)
    for occurrence in occurrences:
        if str(occurrence.reference) not in intents:
            raise InvalidInvocationError(
                f"Containerfile input has no declaration: {occurrence.reference}",
                code="CC0206",
            )
    _reject_ambiguous_spans(occurrences)
    _reject_extra_occurrences(contents, occurrences, intents)
    return Snapshot(
        root=root,
        contents=contents,
        occurrences=tuple(
            sorted(occurrences, key=lambda item: (item.path, item.start, item.image_id))
        ),
        intents=intents,
        image_ids=tuple(sorted(image.image_id for image in selected)),
    )


def _select_images(
    repository: RepositoryConfig, image_ids: tuple[str, ...] | None
) -> tuple[ImageConfig, ...]:
    if image_ids is None:
        return repository.images
    known = {image.image_id: image for image in repository.images}
    unknown = sorted(set(image_ids) - known.keys())
    if unknown:
        raise InvalidInvocationError(
            "Image selection names unknown images: " + ", ".join(unknown)
        )
    selected = {image_id: known[image_id] for image_id in image_ids}
    tags_by_image = {
        image.image_id: {_readable(pin.reference) for pin in image.pins}
        for image in repository.images
    }
    selected_tags = {tag for image_id in selected for tag in tags_by_image[image_id]}
    omitted = sorted(
        image_id
        for image_id, tags in tags_by_image.items()
        if image_id not in selected and tags & selected_tags
    )
    if omitted:
        raise InvalidInvocationError(
            "Image selection omits images bound to the same dependency: "
            + ", ".join(omitted)
        )
    return tuple(image for image in repository.images if image.image_id in selected)


def _containerfile_occurrences(
    root: Path,
    image: ImageConfig,
    contents: dict[str, bytes],
) -> list[Occurrence]:
    path = _relative(root, image.containerfile)
    content = _load_target(root, path, contents, MAX_CONTAINERFILE_BYTES)
    analysis = analyze_containerfile(image.containerfile)
    declared = {str(pin.reference) for pin in image.pins}
    observed = set(analysis.external_references)
    if declared != observed:
        missing = ", ".join(sorted(observed - declared)) or "none"
        orphaned = ", ".join(sorted(declared - observed)) or "none"
        raise RuleRejectionError(
            f"Declared pins and Containerfile inputs differ for {image.image_id}: "
            f"undeclared {missing}; unused {orphaned}",
            code="CC0203",
        )
    line_offsets = _line_offsets(content)
    grouped: dict[ReferenceOccurrence, int] = {}
    for occurrence in external_reference_occurrences(image.containerfile):
        grouped[occurrence] = grouped.get(occurrence, 0) + 1
    result: list[Occurrence] = []
    for occurrence, count in grouped.items():
        reference = OCIReference.parse(
            occurrence.reference, require_tag=True, require_digest=True
        )
        result.extend(
            Occurrence(
                path=path,
                start=start,
                end=start + len(occurrence.reference.encode("utf-8")),
                reference=reference,
                image_id=image.image_id,
                tag_intent=None,
            )
            for start in _instruction_spans(content, occurrence, count, line_offsets)
        )
    return result


def _instruction_spans(
    content: bytes,
    reference: ReferenceOccurrence,
    count: int,
    line_offsets: list[int],
) -> list[int]:
    start = line_offsets[reference.line_number - 1]
    end = (
        line_offsets[reference.end_line_number]
        if reference.end_line_number < len(line_offsets)
        else len(content)
    )
    matches = [
        match.start() + start
        for match in _token_pattern(reference.reference).finditer(content[start:end])
    ]
    if len(matches) != count:
        raise InvalidInvocationError(
            f"Containerfile input could not be located exactly: {reference.reference}",
            code="CC0206",
        )
    return matches


def _declaration_occurrences(
    repository: RepositoryConfig,
    selected: tuple[ImageConfig, ...],
    contents: dict[str, bytes],
) -> list[Occurrence]:
    root = repository.path.parent
    content = _load_target(root, CONFIGURATION_NAME, contents, MAX_CONFIG_BYTES)
    located = locate_string_values(content)
    selected_ids = {image.image_id for image in selected}
    by_image: dict[str, ImageConfig] = {}
    for image in repository.images:
        by_image[image.image_id] = image
    positions = list(repository.images)
    found: dict[tuple[int, int], tuple[int, int, str]] = {}
    for item in located:
        path = item.path
        if (
            len(path) == 5
            and path[0] == "images"
            and path[2] == "pins"
            and path[4] == "reference"
            and isinstance(path[1], int)
            and isinstance(path[3], int)
        ):
            found[(path[1], path[3])] = (item.start, item.end, item.value)
    result: list[Occurrence] = []
    for image_index, image in enumerate(positions):
        if image.image_id not in selected_ids:
            continue
        for pin_index, pin in enumerate(image.pins):
            declaration = found.get((image_index, pin_index))
            if declaration is None or declaration[2] != str(pin.reference):
                raise InvalidInvocationError(
                    f"Pin declaration could not be located exactly: {pin.reference}",
                    code="CC0206",
                )
            start, end, _ = declaration
            result.append(
                Occurrence(
                    path=CONFIGURATION_NAME,
                    start=start,
                    end=end,
                    reference=pin.reference,
                    image_id=image.image_id,
                    tag_intent=pin.tag_intent,
                )
            )
    return result


def _consistent_intents(occurrences: Iterable[Occurrence]) -> dict[str, PinIntent]:
    by_tag: dict[str, PinIntent] = {}
    intents: dict[str, PinIntent] = {}
    for occurrence in occurrences:
        if occurrence.tag_intent is None:
            continue
        tag = _readable(occurrence.reference)
        previous = by_tag.get(tag)
        if previous is not None and previous is not occurrence.tag_intent:
            raise InvalidInvocationError(
                f"Conflicting tag intent declarations for {tag}", code="CC0206"
            )
        by_tag[tag] = occurrence.tag_intent
        intents[str(occurrence.reference)] = occurrence.tag_intent
    return intents


def _reject_ambiguous_spans(occurrences: list[Occurrence]) -> None:
    by_path: dict[str, list[Occurrence]] = {}
    for occurrence in occurrences:
        by_path.setdefault(occurrence.path, []).append(occurrence)
    for path, items in by_path.items():
        ordered = sorted(items, key=lambda item: (item.start, item.end))
        previous_end = -1
        for item in ordered:
            if item.start < previous_end:
                raise InvalidInvocationError(
                    f"Overlapping or duplicate pin occurrences in {path}",
                    code="CC0206",
                )
            previous_end = item.end


def _reject_extra_occurrences(
    contents: dict[str, bytes],
    occurrences: list[Occurrence],
    intents: dict[str, PinIntent],
) -> None:
    structural: dict[tuple[str, str], int] = {}
    for occurrence in occurrences:
        key = (occurrence.path, str(occurrence.reference))
        structural[key] = structural.get(key, 0) + 1
    for path, content in contents.items():
        for reference in intents:
            textual = len(_token_pattern(reference).findall(content))
            if textual != structural.get((path, reference), 0):
                raise InvalidInvocationError(
                    f"Extra or unlocatable occurrence of {reference} in {path}",
                    code="CC0206",
                )


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


def confined_target(root: Path, relative: str) -> Path:
    """Resolve one repository-relative regular file without crossing a symlink."""
    resolved = contained_path(root, relative)
    current = root
    for part in Path(relative).parts:
        current = current / part
        try:
            if current.is_symlink():
                raise InvalidInvocationError(
                    f"Proposal target path contains a symbolic link: {relative}",
                    code="CC0002",
                )
        except OSError as exc:
            raise InvalidInvocationError(
                f"Unable to inspect proposal target path: {relative}", code="CC0002"
            ) from exc
    try:
        mode = os.lstat(resolved).st_mode
    except OSError as exc:
        raise InvalidInvocationError(
            f"Proposal target is unavailable: {relative}", code="CC0207"
        ) from exc
    if not stat.S_ISREG(mode):
        raise InvalidInvocationError(
            f"Proposal target is not a regular file: {relative}", code="CC0207"
        )
    return resolved


def _load_target(
    root: Path,
    relative: str,
    contents: dict[str, bytes],
    maximum_bytes: int,
) -> bytes:
    if relative in contents:
        return contents[relative]
    resolved = confined_target(root, relative)
    contents[relative] = read_regular_file(
        resolved, maximum_bytes=maximum_bytes, label=relative
    )
    return contents[relative]


def _relative(root: Path, path: Path) -> str:
    try:
        return (
            path.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()
        )
    except (OSError, ValueError) as exc:
        raise InvalidInvocationError(
            f"Containerfile escapes the repository root: {path}", code="CC0002"
        ) from exc


def _group_by_reference(
    occurrences: Iterable[Occurrence],
) -> dict[str, list[Occurrence]]:
    grouped: dict[str, list[Occurrence]] = {}
    for occurrence in occurrences:
        grouped.setdefault(str(occurrence.reference), []).append(occurrence)
    return grouped


def _readable(reference: OCIReference) -> str:
    return str(
        OCIReference(reference.registry, reference.repository, tag=reference.tag)
    )


def _line_offsets(content: bytes) -> list[int]:
    offsets = [0]
    for index, byte in enumerate(content):
        if byte == 0x0A:
            offsets.append(index + 1)
    return offsets


def _token_pattern(reference: str) -> re.Pattern[bytes]:
    escaped = re.escape(reference.encode("utf-8"))
    boundary = f"[{_REFERENCE_CHARACTERS}]".encode()
    return re.compile(
        rb"(?<!" + boundary + rb")" + escaped + rb"(?!" + boundary + rb")"
    )


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(text: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidInvocationError("Proposal timestamp is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InvalidInvocationError("Proposal timestamp is not timezone-aware")
    return parsed


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
