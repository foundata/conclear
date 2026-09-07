"""Read-only discovery of pin occurrences in one repository worktree.

`discover_occurrences` locates every exact byte span that names a declared
tagged and digest-pinned reference: each `[[images.pins]]` declaration in
`conclear.toml` and each Containerfile image input of the selected images. It
reads repository files without following symbolic links and never edits one.
`conclear.pin_updates` builds proposals from this view and
`conclear.pin_application` reuses it to prove that the worktree still matches a
proposal before and after applying it.
"""

import os
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass
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
from conclear.errors import InvalidInvocationError, RuleRejectionError
from conclear.fileio import read_regular_file
from conclear.path_safety import contained_path
from conclear.toml_spans import locate_string_values
from conclear.values import OCIReference

CONFIGURATION_NAME = "conclear.toml"
_REFERENCE_CHARACTERS = "A-Za-z0-9._:/@-"


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
