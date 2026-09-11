"""Stable check catalog loading and conformance generation."""

import json
import re
import textwrap
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

from conclear.errors import OperationalError
from conclear.guide_requirements import (
    COVERAGE_STATUSES,
    CoverageSource,
    RequirementCoverage,
    RequirementInventory,
    RequirementStatus,
    effective_coverage,
    load_coverage,
    load_requirements,
)
from conclear.identity import GUIDE_REVISION, GUIDE_TITLE
from conclear.jsonutil import atomic_write_bytes, structure_depth_is_bounded

if TYPE_CHECKING:
    from conclear.guide_options import GuideOptionInventory

GUIDE_URL = (
    "https://github.com/foundata/guidelines/blob/"
    f"{GUIDE_REVISION}/oci-container-image-guide.md"
)
_REQUIREMENT_ID = re.compile(r"IG[0-9]{4}")


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    """One stable conformance check definition."""

    check_id: str
    summary: str
    severity: str
    behavior: str
    requirements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LimitDefinition:
    """One built-in non-disableable maximum."""

    name: str
    value: str


@dataclass(frozen=True, slots=True)
class RetiredCheckDefinition:
    """One historical identifier that must never be reused."""

    check_id: str
    summary: str


@dataclass(frozen=True, slots=True)
class CheckCatalog:
    """The complete machine-readable check catalog."""

    checks: tuple[CheckDefinition, ...]
    limits: tuple[LimitDefinition, ...]
    retired: tuple[RetiredCheckDefinition, ...]


def load_catalog(*, enforce_revision: bool = True) -> CheckCatalog:
    """Load and validate the shipped stable check catalog."""
    resource = files("conclear.data").joinpath("checks.json")
    try:
        untrusted: Any = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OperationalError("Unable to load the shipped check catalog") from exc
    if not isinstance(untrusted, dict) or not structure_depth_is_bounded(untrusted):
        raise OperationalError("Check catalog must be a JSON object")
    if untrusted.get("schemaVersion") != 1:
        raise OperationalError("Unsupported check catalog schema")
    if enforce_revision and untrusted.get("guideRevision") != GUIDE_REVISION:
        raise OperationalError("Check catalog guide revision does not match the build")
    checks_value = untrusted.get("checks")
    limits_value = untrusted.get("limits")
    retired_value = untrusted.get("retired")
    if (
        not isinstance(checks_value, list)
        or not isinstance(limits_value, list)
        or not isinstance(retired_value, list)
    ):
        raise OperationalError("Check catalog arrays are malformed")
    checks: list[CheckDefinition] = []
    for item in checks_value:
        if not isinstance(item, dict) or any(not isinstance(key, str) for key in item):
            raise OperationalError("Check catalog contains a malformed check")
        try:
            check = CheckDefinition(
                check_id=_required_string(item, "id"),
                summary=_required_string(item, "summary"),
                severity=_required_string(item, "severity"),
                behavior=_required_string(item, "behavior"),
                requirements=_requirement_ids(item),
            )
        except KeyError as exc:
            raise OperationalError(
                "Check catalog contains an incomplete check"
            ) from exc
        checks.append(check)
    retired: list[RetiredCheckDefinition] = []
    for item in retired_value:
        if not isinstance(item, dict) or any(not isinstance(key, str) for key in item):
            raise OperationalError("Check catalog contains a malformed retired check")
        retired.append(
            RetiredCheckDefinition(
                check_id=_required_string(item, "id"),
                summary=_required_string(item, "summary"),
            )
        )
    identifiers = [
        *(check.check_id for check in checks),
        *(check.check_id for check in retired),
    ]
    if any(
        re.fullmatch(r"CC[0-9]{4}", identifier) is None for identifier in identifiers
    ):
        raise OperationalError("Check catalog identifiers must match CCnnnn")
    if len(identifiers) != len(set(identifiers)):
        raise OperationalError("Check catalog identifiers must be unique")
    limits: list[LimitDefinition] = []
    for item in limits_value:
        if not isinstance(item, dict):
            raise OperationalError("Check catalog contains a malformed limit")
        limits.append(
            LimitDefinition(
                name=_required_string(item, "name"),
                value=_required_string(item, "value"),
            )
        )
    if enforce_revision:
        known = set(load_requirements().by_id())
        unknown = sorted(
            {
                requirement_id
                for check in checks
                for requirement_id in check.requirements
                if requirement_id not in known
            }
        )
        if unknown:
            raise OperationalError(
                "Check catalog references unknown requirements: " + ", ".join(unknown)
            )
    return CheckCatalog(
        checks=tuple(checks),
        limits=tuple(limits),
        retired=tuple(retired),
    )


def coverage_source(catalog: CheckCatalog) -> CoverageSource:
    """Expose the catalog's requirement mapping to the coverage calculation."""
    return CoverageSource(
        checks={check.check_id: check.requirements for check in catalog.checks},
        automated=frozenset(
            check.check_id for check in catalog.checks if check.behavior == "automated"
        ),
    )


def requirement_statuses(
    catalog: CheckCatalog | None = None,
    inventory: RequirementInventory | None = None,
    coverage: RequirementCoverage | None = None,
) -> tuple[RequirementStatus, ...]:
    """Return the effective status of every requirement or fail closed."""
    return effective_coverage(
        inventory or load_requirements(),
        coverage_source(catalog or load_catalog()),
        coverage or load_coverage(),
    )


def render_conformance(
    catalog: CheckCatalog | None = None,
    *,
    statuses: tuple[RequirementStatus, ...] | None = None,
    options: "GuideOptionInventory | None" = None,
) -> str:
    """Render deterministic generated conformance documentation."""
    from conclear.guide_options import render_guide_options

    selected = catalog or load_catalog()
    selected_statuses = requirement_statuses(selected) if statuses is None else statuses
    introduction = (
        "ConClear implements the automatable rules of the foundata "
        f"[{GUIDE_TITLE}]({GUIDE_URL}) at revision `{GUIDE_REVISION}`. Every "
        "check names the guide requirements it covers, the guide-option section "
        "states a disposition for choices the catalog does not show, and the "
        "requirement coverage section states a status for every requirement of "
        "that revision."
    )
    lines = [
        "# ConClear conformance",
        "",
        "<!-- Generated by python -m conclear.conformance. Do not edit by hand. -->",
        "",
        *_wrap_markdown(introduction),
        "",
        "## Built-in limits",
        "",
        *_wrap_markdown(
            "Repository configuration may shorten these limits but cannot extend "
            "or disable them."
        ),
        "",
        *_markdown_table(
            ("Limit", "Maximum"),
            tuple((limit.name, limit.value) for limit in selected.limits),
            alignments=("left", "right"),
        ),
    ]
    lines.extend(
        [
            "",
            "## Retired identifiers",
            "",
        ]
    )
    if selected.retired:
        lines.extend(
            _markdown_table(
                ("Check", "Historical summary"),
                tuple(
                    (f"`{check.check_id}`", check.summary) for check in selected.retired
                ),
            )
        )
    else:
        lines.append("No identifiers are retired.")
    lines.extend(
        [
            "",
            "## Check catalog",
            "",
            *_wrap_markdown(
                "Manual entries identify requirements that still need human "
                "judgment. The last column lists the guide requirements each check "
                "covers; the coverage section below links every identifier to the "
                "guide."
            ),
            "",
        ]
    )
    check_rows: list[tuple[str, ...]] = []
    for check in selected.checks:
        check_rows.append(
            (
                f"`{check.check_id}`",
                check.behavior,
                check.severity,
                check.summary,
                ", ".join(f"`{item}`" for item in check.requirements),
            )
        )
    lines.extend(
        _markdown_table(
            ("Check", "Behavior", "Severity", "Summary", "Guide requirements"),
            tuple(check_rows),
        )
    )
    lines.append("")
    lines.extend(render_guide_options(options))
    lines.extend(
        [
            "",
            "## Requirement coverage",
            "",
            *_wrap_markdown(
                "Every requirement of the implemented guide revision has exactly "
                "one status. `automated` means a mechanical check or workflow step "
                "enforces it; `manual` means it needs human judgment, either "
                "through a manual check or as described in the basis; `external` "
                "means a control outside ConClear's scope owns it; `unsupported` "
                "means the guide permits a choice this release does not implement. "
                "A requirement that a manual check covers is manual even when "
                "automated checks support it. The basis names the checks that cover "
                "a requirement or explains its status."
            ),
            "",
        ]
    )
    counts = dict.fromkeys(COVERAGE_STATUSES, 0)
    for item in selected_statuses:
        counts[item.status] += 1
    lines.extend(
        _markdown_table(
            ("Status", "Requirements"),
            tuple((status, str(count)) for status, count in counts.items()),
            alignments=("left", "right"),
        )
    )
    lines.append("")
    coverage_rows: list[tuple[str, ...]] = []
    for item in selected_statuses:
        requirement = item.requirement
        identifier = requirement.requirement_id
        basis = (
            ", ".join(f"`{check_id}`" for check_id in item.checks)
            if item.checks
            else item.rationale
        )
        coverage_rows.append(
            (
                f"[`{identifier}`]({GUIDE_URL}#{identifier.lower()})",
                requirement.modality,
                f"[{requirement.anchor}]({GUIDE_URL}#{requirement.anchor})",
                item.status,
                basis,
            )
        )
    lines.extend(
        _markdown_table(
            ("Requirement", "Modality", "Section", "Status", "Basis"),
            tuple(coverage_rows),
        )
    )
    return "\n".join(lines) + "\n"


def write_conformance(path: Path) -> None:
    """Write generated conformance documentation atomically."""
    atomic_write_bytes(path, render_conformance().encode("utf-8"), mode=0o644)


def _wrap_markdown(value: str) -> list[str]:
    protected = re.sub(
        r"\[[^]]+\]\([^)]+\)",
        lambda match: match.group(0).replace(" ", "\0"),
        value,
    )
    return [
        line.replace("\0", " ")
        for line in textwrap.wrap(
            protected,
            width=80,
            break_long_words=False,
            break_on_hyphens=False,
        )
    ]


def _markdown_table(
    headers: tuple[str, ...],
    rows: tuple[tuple[str, ...], ...],
    *,
    alignments: tuple[str, ...] | None = None,
) -> list[str]:
    selected_alignments = alignments or tuple("left" for _ in headers)
    last_column = len(headers) - 1
    widths = tuple(
        max(3, len(header))
        if index == last_column
        else max(3, len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    )

    def row(values: tuple[str, ...], *, header: bool = False) -> str:
        cells = []
        for index, value in enumerate(values):
            if header:
                padding = widths[index] - len(value)
                cells.append(
                    " " * (padding // 2) + value + " " * (padding - padding // 2)
                )
            elif selected_alignments[index] == "right":
                cells.append(value.rjust(widths[index]))
            else:
                cells.append(value.ljust(widths[index]))
        return "| " + " | ".join(cells) + " |"

    separators = tuple(
        "-" * (width - 1) + ":" if alignment == "right" else "-" * width
        for width, alignment in zip(widths, selected_alignments, strict=True)
    )
    return [
        row(headers, header=True),
        row(separators),
        *(row(values) for values in rows),
    ]


def _required_string(item: dict[str, object], key: str) -> str:
    value = item[key]
    if not isinstance(value, str) or not value:
        raise OperationalError(f"Catalog field {key} must be a non-empty string")
    return value


def _requirement_ids(item: dict[str, object]) -> tuple[str, ...]:
    value = item["requirements"]
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(entry, str) for entry in value)
    ):
        raise OperationalError("Catalog field requirements must be a non-empty list")
    identifiers = tuple(str(entry) for entry in value)
    if any(_REQUIREMENT_ID.fullmatch(entry) is None for entry in identifiers):
        raise OperationalError("Catalog requirement identifiers must match IGnnnn")
    if list(identifiers) != sorted(set(identifiers)):
        raise OperationalError(
            "Catalog requirement identifiers must be unique and sorted"
        )
    return identifiers
