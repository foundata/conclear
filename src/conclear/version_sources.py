"""Compare a release version with the places where the project states it."""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from conclear.config import VersionSourceConfig
from conclear.errors import OperationalError
from conclear.presentation import Finding

CHECK_ID = "CC0005"
MAX_SOURCE_BYTES = 1024 * 1024
UNRELEASED = "unreleased"
_CHANGELOG_HEADING = re.compile(r"^## \[([^\]]+)\]")
_PLACEHOLDER = "{version}"


@dataclass(frozen=True, slots=True)
class VersionSourceObservation:
    """What one declared version source states, and whether it agrees."""

    kind: str
    path: str | None
    pattern: str | None
    observed: tuple[str, ...]
    matched: bool

    def to_dict(self) -> dict[str, object]:
        """Return the record representation."""
        return {
            "kind": self.kind,
            "path": self.path,
            "pattern": self.pattern,
            "observed": list(self.observed),
            "matched": self.matched,
        }

    @property
    def label(self) -> str:
        """Name the source for a human."""
        target = self.path if self.path is not None else self.pattern
        return f"{self.kind} source {target}"


def observe_version_sources(
    sources: Iterable[VersionSourceConfig],
    *,
    source_root: Path,
    version: str,
    revision_tags: Sequence[str],
) -> tuple[VersionSourceObservation, ...]:
    """Read every declared source and compare it with the release version."""
    return tuple(
        _observe(source, source_root=source_root, version=version, tags=revision_tags)
        for source in sources
    )


def version_source_findings(
    observations: Iterable[VersionSourceObservation], version: str
) -> tuple[Finding, ...]:
    """Reject every declared source that does not state the release version."""
    findings: list[Finding] = []
    for item in observations:
        if item.matched:
            continue
        if item.kind == "git-tag":
            tags = (
                f"; versions stated by tags at the revision: {', '.join(item.observed)}"
                if item.observed
                else ""
            )
            message = (
                f"No tag matching {item.pattern} names version {version} at the "
                f"released revision{tags}"
            )
        elif item.observed:
            message = (
                f"{item.label} states version {', '.join(item.observed)} rather than "
                f"{version}"
            )
        else:
            message = f"{item.label} states no version"
        findings.append(Finding(CHECK_ID, "error", message, location=item.path))
    return tuple(findings)


def _observe(
    source: VersionSourceConfig, *, source_root: Path, version: str, tags: Sequence[str]
) -> VersionSourceObservation:
    relative = None if source.path is None else _relative(source.path, source_root)
    if source.kind == "git-tag":
        assert source.pattern is not None
        expected = source.pattern.replace(_PLACEHOLDER, version)
        wildcard = _wildcard(source.pattern)
        observed = tuple(
            match.group(1) for tag in tags if (match := wildcard.fullmatch(tag))
        )
        return VersionSourceObservation(
            source.kind, None, source.pattern, observed, expected in tags
        )
    assert source.path is not None
    text = _read(source.path)
    if source.kind == "changelog":
        headings = [
            match.group(1)
            for line in text.splitlines()
            if (match := _CHANGELOG_HEADING.match(line))
        ]
        versions = [item for item in headings if item.lower() != UNRELEASED]
        return VersionSourceObservation(
            source.kind,
            relative,
            None,
            tuple(versions[:1]),
            bool(versions) and versions[0] == version,
        )
    assert source.pattern is not None
    exact = re.compile(
        source.pattern.replace(_PLACEHOLDER, re.escape(version)), re.MULTILINE
    )
    wildcard = re.compile(source.pattern.replace(_PLACEHOLDER, "(.+?)"), re.MULTILINE)
    observed = tuple(dict.fromkeys(match.group(1) for match in wildcard.finditer(text)))
    return VersionSourceObservation(
        source.kind, relative, source.pattern, observed, exact.search(text) is not None
    )


def _wildcard(pattern: str) -> re.Pattern[str]:
    head, _, tail = pattern.partition(_PLACEHOLDER)
    return re.compile(re.escape(head) + "(.+)" + re.escape(tail))


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            raise OperationalError(f"Version source {path} exceeds the size limit")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise OperationalError(f"Unable to read version source {path}") from exc


def _relative(path: Path, source_root: Path) -> str:
    try:
        return path.resolve().relative_to(source_root.resolve()).as_posix()
    except ValueError:
        return str(path)
