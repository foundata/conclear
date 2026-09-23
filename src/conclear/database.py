"""Freshness policy for immutable Trivy database snapshots."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.trivy import DatabaseObservation
from conclear.errors import OperationalError, RuleRejectionError
from conclear.freshness import QualificationWindow
from conclear.presentation import Finding
from conclear.records import format_timestamp, parse_timestamp
from conclear.values import Digest


class DatabaseAdapter(Protocol):
    """Trivy database operations used by release startup."""

    def select_database(self, cache_root: Path) -> DatabaseObservation:
        """Select and validate an installed snapshot."""
        ...

    def refresh_database(self, cache_root: Path) -> DatabaseObservation:
        """Refresh and atomically install one snapshot."""
        ...

    def select_database_by_digest(
        self, cache_root: Path, expected_digest: Digest
    ) -> DatabaseObservation:
        """Select and validate one immutable snapshot by content digest."""
        ...


@dataclass(frozen=True, slots=True)
class DatabaseFreshness:
    """Freshness of each Trivy database component at one instant.

    The two components are judged separately because they carry different
    weight: the vulnerability database is what every assessment reads, while
    the Java database only identifies jar artifacts by content hash and so
    matters only to an image that contains them.
    """

    vulnerability: bool
    java: bool
    java_next_update: datetime


@dataclass(frozen=True, slots=True)
class JavaDatabaseEvidence:
    """Recorded verdict on the Java database for one scanned subject."""

    fresh: bool
    required: bool
    accepted_stale: bool
    artifacts: int
    finding: Finding | None

    def to_dict(self) -> dict[str, object]:
        """Return the public Java database object."""
        return {
            "fresh": self.fresh,
            "required": self.required,
            "acceptedStale": self.accepted_stale,
            "artifacts": self.artifacts,
        }


def trivy_cache_root(cache_home: Path) -> Path:
    """Return the ConClear-owned Trivy database cache below one cache home."""
    return cache_home / "conclear" / "trivy"


def select_fresh_database(
    adapter: DatabaseAdapter, cache_root: Path, *, now: datetime
) -> DatabaseObservation:
    """Select a fresh snapshot or perform one bounded refresh.

    A stale Java database still triggers the refresh, because a refresh is the
    only way to obtain a newer one, but only the vulnerability database has to
    be fresh afterward. Java freshness is judged per subject once a scan has
    shown whether the image contains Java artifacts.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise OperationalError("Database selection time must be timezone-aware")
    try:
        selected = adapter.select_database(cache_root)
        freshness = database_freshness(selected.metadata, now)
        if not freshness.vulnerability or not freshness.java:
            raise OperationalError("Installed Trivy database is stale")
    except OperationalError:
        selected = adapter.refresh_database(cache_root)
        if not database_freshness(selected.metadata, now).vulnerability:
            raise OperationalError(
                "Refreshed Trivy vulnerability database is already stale"
            ) from None
    return selected


def select_database_by_digest(
    adapter: DatabaseAdapter,
    cache_root: Path,
    *,
    expected_digest: Digest,
    now: datetime,
    qualification_started_at: datetime | None = None,
) -> DatabaseObservation:
    """Select an exact distributed snapshot without consulting a mutable pointer."""
    selected = adapter.select_database_by_digest(cache_root, expected_digest)
    if selected.digest != str(expected_digest):
        raise OperationalError(
            "Selected Trivy database does not match the expected digest", code="CC0505"
        )
    qualification_database_window(
        selected, started_at=qualification_started_at or now, now=now
    )
    return selected


def qualification_database_window(
    database: DatabaseObservation, *, started_at: datetime, now: datetime
) -> QualificationWindow:
    """Require a database fresh at the original start and a still-valid window."""
    window = QualificationWindow.start(started_at)
    window.require_current(now, phase="qualification")
    require_database_fresh_at(database.metadata, started_at, java_required=False)
    return window


def require_database_fresh_at(
    metadata: dict[str, object], now: datetime, *, java_required: bool = False
) -> DatabaseFreshness:
    """Validate historical database freshness without applying today's clock."""
    freshness = database_freshness(metadata, now)
    if not freshness.vulnerability:
        raise RuleRejectionError(
            "Trivy vulnerability database was not fresh at the qualification start; "
            "select a fresh common snapshot or supply its original qualification start",
            code="CC0505",
        )
    if java_required and not freshness.java:
        raise RuleRejectionError(
            "Java artifacts were assessed against a Java database whose next update "
            f"was due {format_timestamp(freshness.java_next_update)}; refresh it or "
            "accept the risk with --accept-stale-java-database",
            code="CC0507",
        )
    return freshness


def evaluate_java_database(
    metadata: dict[str, object],
    *,
    at: datetime,
    artifacts: int,
    accepted_stale: bool,
) -> JavaDatabaseEvidence:
    """Judge the Java database against the Java artifacts one subject contains."""
    if artifacts < 0:
        raise OperationalError("Java artifact count cannot be negative")
    freshness = database_freshness(metadata, at)
    required = artifacts > 0
    finding: Finding | None = None
    if required and not freshness.java:
        due = format_timestamp(freshness.java_next_update)
        finding = (
            Finding(
                "CC0507",
                "warning",
                f"Maintainer accepted a Java database whose next update was due {due} "
                f"for {artifacts} Java artifacts",
            )
            if accepted_stale
            else Finding(
                "CC0507",
                "error",
                f"{artifacts} Java artifacts assessed against a Java database whose "
                f"next update was due {due}; refresh it or accept the risk with "
                "--accept-stale-java-database",
            )
        )
    return JavaDatabaseEvidence(
        fresh=freshness.java,
        required=required,
        accepted_stale=accepted_stale,
        artifacts=artifacts,
        finding=finding,
    )


def database_freshness(metadata: dict[str, object], now: datetime) -> DatabaseFreshness:
    """Judge each Trivy database component separately at one instant."""
    vulnerability, _ = _component_freshness(metadata, "vulnerability", now)
    java, java_next_update = _component_freshness(metadata, "java", now)
    return DatabaseFreshness(
        vulnerability=vulnerability, java=java, java_next_update=java_next_update
    )


def _component_freshness(
    metadata: dict[str, object], name: str, now: datetime
) -> tuple[bool, datetime]:
    component = metadata.get(name)
    if not isinstance(component, dict):
        raise OperationalError(f"Trivy {name} database metadata is malformed")
    value = component.get("nextUpdate")
    if not isinstance(value, str):
        raise OperationalError(
            f"Trivy {name} database metadata has no next-update time"
        )
    try:
        next_update = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperationalError(
            f"Trivy {name} database next-update time is malformed"
        ) from exc
    if next_update.tzinfo is None or next_update.utcoffset() is None:
        raise OperationalError(
            f"Trivy {name} database next-update time lacks a timezone"
        )
    updated_at = parse_timestamp(
        component.get("updatedAt"),
        f"Trivy {name} database update time",
        error=OperationalError,
    )
    if updated_at > now or updated_at >= next_update:
        return False, next_update
    return now.astimezone(UTC) < next_update.astimezone(UTC), next_update
