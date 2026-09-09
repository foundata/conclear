"""Read-only discovery of pin occurrences in one repository worktree.

`discover_occurrences` locates every exact byte span that names a declared
tagged and digest-pinned reference in the selected Containerfiles. The
`[[images.pins]]` declarations supply tag intent without repeating digests. It
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

from conclear.config import (
    MAX_CONFIG_BYTES,
    ImageConfig,
    PinIntent,
    RepositoryConfig,
)
from conclear.containerfile import MAX_CONTAINERFILE_BYTES, parse_containerfile
from conclear.errors import InvalidInvocationError, RuleRejectionError
from conclear.fileio import read_regular_file
from conclear.path_safety import contained_path
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
    tag_intent: PinIntent


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
    _load_target(root, CONFIGURATION_NAME, contents, MAX_CONFIG_BYTES)
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
    source = parse_containerfile(content, path=image.containerfile)
    declared = {str(pin.reference) for pin in image.pins}
    observed = {item.reference for item in source.external_inputs}
    if declared != observed:
        missing = ", ".join(sorted(observed - declared)) or "none"
        orphaned = ", ".join(sorted(declared - observed)) or "none"
        raise RuleRejectionError(
            f"Declared pins and Containerfile inputs differ for {image.image_id}: "
            f"undeclared {missing}; unused {orphaned}",
            code="CC0203",
        )
    result: list[Occurrence] = []
    for occurrence in source.external_inputs:
        reference = OCIReference.parse(
            occurrence.reference, require_tag=True, require_digest=True
        )
        start, end = occurrence.span.start, occurrence.span.end
        if content[start:end] != occurrence.reference.encode("utf-8"):
            raise InvalidInvocationError(
                "Pin updates require a contiguous literal image reference: "
                f"{occurrence.reference}",
                code="CC0206",
            )
        result.append(
            Occurrence(
                path=path,
                start=start,
                end=end,
                reference=reference,
                image_id=image.image_id,
                tag_intent=next(
                    pin.tag_intent for pin in image.pins if pin.reference == reference
                ),
            )
        )
    return result


def _consistent_intents(occurrences: Iterable[Occurrence]) -> dict[str, PinIntent]:
    by_tag: dict[str, PinIntent] = {}
    intents: dict[str, PinIntent] = {}
    for occurrence in occurrences:
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


def _token_pattern(reference: str) -> re.Pattern[bytes]:
    escaped = re.escape(reference.encode("utf-8"))
    boundary = f"[{_REFERENCE_CHARACTERS}]".encode()
    return re.compile(
        rb"(?<!" + boundary + rb")" + escaped + rb"(?!" + boundary + rb")"
    )
