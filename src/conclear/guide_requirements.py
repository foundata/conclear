"""Guide requirement inventory, coverage statuses and revision diffs.

The implemented guide assigns a stable identifier such as ``IG0042`` to every
normative statement. ConClear ships that inventory as package data, maps each
check to the identifiers it covers and classifies every remaining identifier in
a coverage file. Together they let the generated conformance document state,
for every requirement of the embedded guide revision, whether ConClear
automates it, leaves it to human review, leaves it to an external control or
does not support it.
"""

import argparse
import json
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from conclear.errors import ConClearError, OperationalError
from conclear.fileio import read_regular_file
from conclear.identity import GUIDE_REVISION
from conclear.jsonutil import atomic_write_bytes, structure_depth_is_bounded

INVENTORY_SCHEMA_VERSION = 1
COVERAGE_SCHEMA_VERSION = 1
INVENTORY_RESOURCE = "guide-requirements.json"
COVERAGE_RESOURCE = "requirement-coverage.json"
MAX_GUIDE_BYTES = 1024 * 1024
MAX_LISTING_BYTES = 4 * 1024 * 1024
MODALITIES = ("MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY")
COVERAGE_STATUSES = ("automated", "manual", "external", "unsupported")
_REQUIREMENT_ID = re.compile(r"IG[0-9]{4}")
_ANCHOR = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_EXPLICIT_ANCHOR = re.compile(r'<a id="([a-z0-9-]+)"></a>')


@dataclass(frozen=True, slots=True)
class Requirement:
    """One normative statement of the implemented guide."""

    requirement_id: str
    modality: str
    section: str
    anchor: str
    text: str


@dataclass(frozen=True, slots=True)
class RetiredRequirement:
    """One identifier the guide retired; it is never reused."""

    requirement_id: str
    note: str


@dataclass(frozen=True, slots=True)
class RequirementInventory:
    """Every requirement identifier of one guide revision."""

    guide_revision: str
    requirements: tuple[Requirement, ...]
    retired: tuple[RetiredRequirement, ...]

    def by_id(self) -> dict[str, Requirement]:
        """Return the active requirements keyed by identifier."""
        return {item.requirement_id: item for item in self.requirements}


@dataclass(frozen=True, slots=True)
class CoverageEntry:
    """The disposition of one requirement no check covers."""

    requirement_id: str
    status: str
    rationale: str


@dataclass(frozen=True, slots=True)
class RequirementCoverage:
    """Dispositions for every requirement outside the check catalog."""

    guide_revision: str
    entries: tuple[CoverageEntry, ...]


@dataclass(frozen=True, slots=True)
class RequirementStatus:
    """The effective status of one requirement and what establishes it."""

    requirement: Requirement
    status: str
    checks: tuple[str, ...]
    rationale: str


@dataclass(frozen=True, slots=True)
class InventoryDiff:
    """Requirements that differ between two inventories."""

    added: tuple[Requirement, ...]
    removed: tuple[Requirement, ...]
    reworded: tuple[tuple[Requirement, Requirement], ...]


class CoverageSource:
    """Read-only view of what references requirement identifiers."""

    def __init__(
        self,
        *,
        checks: Mapping[str, tuple[str, ...]],
        automated: frozenset[str],
    ) -> None:
        """Capture each check's requirements and which checks are automated."""
        self.checks = dict(checks)
        self.automated = automated

    def checks_for(self, requirement_id: str) -> tuple[str, ...]:
        """Return the checks that map to one requirement, in catalog order."""
        return tuple(
            check_id
            for check_id, requirements in self.checks.items()
            if requirement_id in requirements
        )


def load_requirements(*, enforce_revision: bool = True) -> RequirementInventory:
    """Load and validate the shipped requirement inventory."""
    untrusted = _load_resource(INVENTORY_RESOURCE, "requirement inventory")
    if set(untrusted) != {"schemaVersion", "guideRevision", "requirements", "retired"}:
        raise OperationalError("Requirement inventory fields are malformed")
    if untrusted.get("schemaVersion") != INVENTORY_SCHEMA_VERSION:
        raise OperationalError("Unsupported requirement inventory schema")
    revision = untrusted.get("guideRevision")
    if (
        not isinstance(revision, str)
        or re.fullmatch(r"[0-9a-f]{40,64}", revision) is None
    ):
        raise OperationalError("Requirement inventory guide revision is malformed")
    if enforce_revision and revision != GUIDE_REVISION:
        raise OperationalError(
            "Requirement inventory guide revision does not match the build"
        )
    return _inventory(revision, untrusted.get("requirements"), untrusted.get("retired"))


def load_coverage(*, enforce_revision: bool = True) -> RequirementCoverage:
    """Load and validate the shipped requirement coverage file."""
    untrusted = _load_resource(COVERAGE_RESOURCE, "requirement coverage")
    if set(untrusted) != {"schemaVersion", "guideRevision", "entries"}:
        raise OperationalError("Requirement coverage fields are malformed")
    if untrusted.get("schemaVersion") != COVERAGE_SCHEMA_VERSION:
        raise OperationalError("Unsupported requirement coverage schema")
    revision = untrusted.get("guideRevision")
    if not isinstance(revision, str):
        raise OperationalError("Requirement coverage guide revision is malformed")
    if enforce_revision and revision != GUIDE_REVISION:
        raise OperationalError(
            "Requirement coverage guide revision does not match the build"
        )
    raw_entries = untrusted.get("entries")
    if not isinstance(raw_entries, list):
        raise OperationalError("Requirement coverage entries are malformed")
    entries: list[CoverageEntry] = []
    for value in raw_entries:
        if not isinstance(value, dict) or set(value) != {"id", "status", "rationale"}:
            raise OperationalError("Requirement coverage contains a malformed entry")
        item = cast(dict[str, object], value)
        requirement_id = _identifier(item, "id", "Requirement coverage")
        status = _string(item, "status", "Requirement coverage")
        if status not in COVERAGE_STATUSES:
            raise OperationalError(
                f"Requirement coverage status is unsupported: {status}"
            )
        entries.append(
            CoverageEntry(
                requirement_id=requirement_id,
                status=status,
                rationale=_string(item, "rationale", "Requirement coverage"),
            )
        )
    _require_sorted_unique(
        tuple(entry.requirement_id for entry in entries), "Requirement coverage"
    )
    return RequirementCoverage(guide_revision=revision, entries=tuple(entries))


def effective_coverage(
    inventory: RequirementInventory,
    source: CoverageSource,
    coverage: RequirementCoverage,
) -> tuple[RequirementStatus, ...]:
    """Assign exactly one status to every active requirement or fail."""
    active = inventory.by_id()
    entries = {entry.requirement_id: entry for entry in coverage.entries}
    unknown = sorted(set(entries) - set(active))
    if unknown:
        raise OperationalError(
            "Requirement coverage references unknown requirements: "
            + ", ".join(unknown)
        )
    for check_id, requirements in source.checks.items():
        missing = sorted(set(requirements) - set(active))
        if missing:
            raise OperationalError(
                f"Check {check_id} references unknown requirements: "
                + ", ".join(missing)
            )
    statuses: list[RequirementStatus] = []
    uncovered: list[str] = []
    duplicated: list[str] = []
    for requirement in inventory.requirements:
        checks = source.checks_for(requirement.requirement_id)
        entry = entries.get(requirement.requirement_id)
        if checks and entry is not None:
            duplicated.append(requirement.requirement_id)
            continue
        if checks:
            manual = any(check_id not in source.automated for check_id in checks)
            statuses.append(
                RequirementStatus(
                    requirement=requirement,
                    status="manual" if manual else "automated",
                    checks=checks,
                    rationale="",
                )
            )
        elif entry is not None:
            statuses.append(
                RequirementStatus(
                    requirement=requirement,
                    status=entry.status,
                    checks=(),
                    rationale=entry.rationale,
                )
            )
        else:
            uncovered.append(requirement.requirement_id)
    if uncovered:
        raise OperationalError(
            "Requirements without a coverage status: " + ", ".join(uncovered)
        )
    if duplicated:
        raise OperationalError(
            "Requirements covered by both a check and a coverage entry: "
            + ", ".join(duplicated)
        )
    return tuple(statuses)


def validate_guide_anchors(
    path: Path, inventory: RequirementInventory | None = None
) -> None:
    """Require every requirement and section anchor in one guide file."""
    try:
        guide = read_regular_file(
            path, maximum_bytes=MAX_GUIDE_BYTES, label="OCI guide"
        ).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OperationalError("OCI guide is not UTF-8") from exc
    anchors = frozenset(_EXPLICIT_ANCHOR.findall(guide))
    selected = inventory or load_requirements()
    expected = {item.requirement_id.lower() for item in selected.requirements}
    expected.update(item.anchor for item in selected.requirements)
    missing = sorted(expected - anchors)
    if missing:
        raise OperationalError(
            "Requirement inventory references missing OCI guide anchors: "
            + ", ".join(missing)
        )


def read_listing(path: Path, *, guide_revision: str) -> RequirementInventory:
    """Read the guide's ``--list`` output as an inventory for one revision."""
    try:
        untrusted: Any = json.loads(
            read_regular_file(
                path, maximum_bytes=MAX_LISTING_BYTES, label="requirement listing"
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OperationalError("Requirement listing is not valid JSON") from exc
    if not isinstance(untrusted, dict) or not structure_depth_is_bounded(untrusted):
        raise OperationalError("Requirement listing must be a JSON object")
    raw_requirements = untrusted.get("requirements")
    if not isinstance(raw_requirements, list):
        raise OperationalError("Requirement listing requirements are malformed")
    stripped = [
        {key: value for key, value in item.items() if key != "line"}
        if isinstance(item, dict)
        else item
        for item in raw_requirements
    ]
    return _inventory(guide_revision, stripped, untrusted.get("retired"))


def render_inventory(inventory: RequirementInventory) -> bytes:
    """Serialize an inventory deterministically as package data."""
    value = {
        "schemaVersion": INVENTORY_SCHEMA_VERSION,
        "guideRevision": inventory.guide_revision,
        "requirements": [
            {
                "id": item.requirement_id,
                "modality": item.modality,
                "section": item.section,
                "anchor": item.anchor,
                "text": item.text,
            }
            for item in inventory.requirements
        ],
        "retired": [
            {"id": item.requirement_id, "note": item.note} for item in inventory.retired
        ],
    }
    return (json.dumps(value, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def diff_inventories(
    old: RequirementInventory, new: RequirementInventory
) -> InventoryDiff:
    """Return the requirements added, removed or reworded between revisions."""
    previous = old.by_id()
    current = new.by_id()
    added = tuple(current[key] for key in sorted(set(current) - set(previous)))
    removed = tuple(previous[key] for key in sorted(set(previous) - set(current)))
    reworded = tuple(
        (previous[key], current[key])
        for key in sorted(set(previous) & set(current))
        if previous[key].text != current[key].text
        or previous[key].modality != current[key].modality
    )
    return InventoryDiff(added=added, removed=removed, reworded=reworded)


def render_diff(
    diff: InventoryDiff,
    references: Mapping[str, Iterable[str]],
) -> str:
    """Render a revision diff with the artifacts that reference each change."""
    lines: list[str] = []

    def referenced_by(requirement_id: str) -> str:
        names = sorted(references.get(requirement_id, ()))
        return "referenced by " + ", ".join(names) if names else "not referenced"

    lines.append(f"Added: {len(diff.added)}")
    for item in diff.added:
        lines.append(f"  + {item.requirement_id} [{item.modality}] {item.text}")
    lines.append(f"Removed: {len(diff.removed)}")
    for item in diff.removed:
        lines.append(
            f"  - {item.requirement_id} [{item.modality}] {item.text}"
            f" ({referenced_by(item.requirement_id)})"
        )
    lines.append(f"Reworded: {len(diff.reworded)}")
    for before, after in diff.reworded:
        lines.append(
            f"  ~ {after.requirement_id} [{before.modality} -> {after.modality}]"
            f" ({referenced_by(after.requirement_id)})"
        )
        lines.append(f"      was: {before.text}")
        lines.append(f"      now: {after.text}")
    return "\n".join(lines) + "\n"


def shipped_references() -> dict[str, set[str]]:
    """Return every shipped artifact that references each requirement.

    A guide revision update edits the shipped data in steps, so a source that
    is unavailable or stale is reported and skipped rather than fatal.
    """
    from conclear.catalog import load_catalog
    from conclear.guide_options import load_guide_options

    references: dict[str, set[str]] = {}
    try:
        for check in load_catalog(enforce_revision=False).checks:
            for requirement_id in check.requirements:
                references.setdefault(requirement_id, set()).add(check.check_id)
    except OperationalError as exc:
        print(f"Skipping check catalog references: {exc}", file=sys.stderr)
    try:
        for option in load_guide_options(enforce_revision=False).options:
            for requirement_id in option.requirements:
                references.setdefault(requirement_id, set()).add(option.option_id)
    except OperationalError as exc:
        print(f"Skipping guide-option references: {exc}", file=sys.stderr)
    try:
        for entry in load_coverage(enforce_revision=False).entries:
            references.setdefault(entry.requirement_id, set()).add("coverage")
    except OperationalError as exc:
        print(f"Skipping coverage references: {exc}", file=sys.stderr)
    return references


def inventory_path() -> Path:
    """Return the writable location of the shipped inventory."""
    return Path(str(files("conclear.data").joinpath(INVENTORY_RESOURCE)))


def _previous_inventory() -> RequirementInventory:
    try:
        return load_requirements(enforce_revision=False)
    except OperationalError as exc:
        print(f"No usable shipped inventory: {exc}", file=sys.stderr)
        return RequirementInventory(guide_revision="", requirements=(), retired=())


def main() -> int:
    """Verify, diff or import the guide requirement inventory."""
    parser = argparse.ArgumentParser(
        prog="python -m conclear.guide_requirements",
        description="Verify, diff or import the guide requirement inventory.",
    )
    parser.add_argument("--check", action="store_true", help="verify shipped data")
    parser.add_argument("--guide", type=Path, help="guide file to validate anchors in")
    parser.add_argument("--diff", type=Path, help="requirement listing to compare")
    parser.add_argument(
        "--import",
        dest="import_path",
        type=Path,
        help="requirement listing to import for the embedded guide revision",
    )
    arguments = parser.parse_args()
    try:
        if arguments.diff is not None or arguments.import_path is not None:
            listing = arguments.diff or arguments.import_path
            new = read_listing(listing, guide_revision=GUIDE_REVISION)
            sys.stdout.write(
                render_diff(
                    diff_inventories(_previous_inventory(), new), shipped_references()
                )
            )
            if arguments.import_path is not None:
                target = inventory_path()
                atomic_write_bytes(target, render_inventory(new), mode=0o644)
                print(f"Imported {len(new.requirements)} requirements into {target}")
            return 0
        inventory = load_requirements()
        if arguments.guide is not None:
            validate_guide_anchors(arguments.guide, inventory)
        from conclear.catalog import coverage_source, load_catalog

        statuses = effective_coverage(
            inventory, coverage_source(load_catalog()), load_coverage()
        )
    except ConClearError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    counts = dict.fromkeys(COVERAGE_STATUSES, 0)
    for item in statuses:
        counts[item.status] += 1
    print(
        f"{len(statuses)} requirements at guide revision {GUIDE_REVISION}: "
        + ", ".join(f"{count} {status}" for status, count in counts.items())
    )
    return 0


def _load_resource(name: str, label: str) -> dict[str, Any]:
    resource = files("conclear.data").joinpath(name)
    try:
        untrusted: Any = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OperationalError(f"Unable to load the shipped {label}") from exc
    if not isinstance(untrusted, dict) or not structure_depth_is_bounded(untrusted):
        raise OperationalError(f"{label.capitalize()} must be a JSON object")
    return cast(dict[str, Any], untrusted)


def _inventory(
    revision: str, raw_requirements: object, raw_retired: object
) -> RequirementInventory:
    if not isinstance(raw_requirements, list) or not raw_requirements:
        raise OperationalError("Requirement inventory requirements are malformed")
    if not isinstance(raw_retired, list):
        raise OperationalError("Requirement inventory retired list is malformed")
    requirements: list[Requirement] = []
    for value in raw_requirements:
        if not isinstance(value, dict) or set(value) != {
            "id",
            "modality",
            "section",
            "anchor",
            "text",
        }:
            raise OperationalError("Requirement inventory contains a malformed entry")
        item = cast(dict[str, object], value)
        modality = _string(item, "modality", "Requirement inventory")
        if modality not in MODALITIES:
            raise OperationalError(f"Requirement modality is unsupported: {modality}")
        anchor = _string(item, "anchor", "Requirement inventory")
        if _ANCHOR.fullmatch(anchor) is None:
            raise OperationalError("Requirement anchor is malformed")
        requirements.append(
            Requirement(
                requirement_id=_identifier(item, "id", "Requirement inventory"),
                modality=modality,
                section=_string(item, "section", "Requirement inventory"),
                anchor=anchor,
                text=_string(item, "text", "Requirement inventory"),
            )
        )
    retired: list[RetiredRequirement] = []
    for value in raw_retired:
        if not isinstance(value, dict) or set(value) != {"id", "note"}:
            raise OperationalError(
                "Requirement inventory contains a malformed retired entry"
            )
        item = cast(dict[str, object], value)
        retired.append(
            RetiredRequirement(
                requirement_id=_identifier(item, "id", "Requirement inventory"),
                note=_string(item, "note", "Requirement inventory"),
            )
        )
    _require_sorted_unique(
        tuple(item.requirement_id for item in requirements), "Requirement inventory"
    )
    identifiers = [
        *(item.requirement_id for item in requirements),
        *(item.requirement_id for item in retired),
    ]
    if len(identifiers) != len(set(identifiers)):
        raise OperationalError("Retired requirement identifiers must not be active")
    return RequirementInventory(
        guide_revision=revision,
        requirements=tuple(requirements),
        retired=tuple(retired),
    )


def _require_sorted_unique(identifiers: tuple[str, ...], label: str) -> None:
    if len(identifiers) != len(set(identifiers)):
        raise OperationalError(f"{label} identifiers must be unique")
    if list(identifiers) != sorted(identifiers):
        raise OperationalError(f"{label} must be ordered by identifier")


def _identifier(value: dict[str, object], key: str, label: str) -> str:
    item = _string(value, key, label)
    if _REQUIREMENT_ID.fullmatch(item) is None:
        raise OperationalError(f"{label} identifiers must match IGnnnn")
    return item


def _string(value: dict[str, object], key: str, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item or "\n" in item:
        raise OperationalError(f"{label} field {key} is malformed")
    return item


if __name__ == "__main__":
    raise SystemExit(main())
