"""Stable check catalog loading and conformance generation."""

import json
import re
import textwrap
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from conclear.errors import OperationalError
from conclear.identity import GUIDE_REVISION, GUIDE_TITLE
from conclear.jsonutil import atomic_write_bytes, structure_depth_is_bounded


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    """One stable conformance check definition."""

    check_id: str
    summary: str
    severity: str
    behavior: str
    anchor: str


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


def load_catalog() -> CheckCatalog:
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
    if untrusted.get("guideRevision") != GUIDE_REVISION:
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
                anchor=_required_string(item, "anchor"),
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
    return CheckCatalog(
        checks=tuple(checks),
        limits=tuple(limits),
        retired=tuple(retired),
    )


def render_conformance(catalog: CheckCatalog | None = None) -> str:
    """Render deterministic generated conformance documentation."""
    selected = catalog or load_catalog()
    introduction = (
        "ConClear implements the automatable rules of the foundata "
        f"[{GUIDE_TITLE}](https://github.com/foundata/guidelines/blob/"
        f"{GUIDE_REVISION}/oci-container-image-guide.md) at revision "
        f"`{GUIDE_REVISION}`. Manual entries identify requirements that still "
        "need human judgment."
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
        ]
    )
    check_rows: list[tuple[str, ...]] = []
    for check in selected.checks:
        guide_link = (
            "https://github.com/foundata/guidelines/blob/"
            f"{GUIDE_REVISION}/oci-container-image-guide.md#{check.anchor}"
        )
        check_rows.append(
            (
                f"`{check.check_id}`",
                check.behavior,
                check.severity,
                f"[{check.anchor}]({guide_link})",
                check.summary,
            )
        )
    lines.extend(
        _markdown_table(
            ("Check", "Behavior", "Severity", "Guide section", "Summary"),
            tuple(check_rows),
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
