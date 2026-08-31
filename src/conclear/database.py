"""Freshness policy for immutable Trivy database snapshots."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.trivy import DatabaseObservation
from conclear.errors import OperationalError


class DatabaseAdapter(Protocol):
    """Trivy database operations used by release startup."""

    def select_database(self, cache_root: Path) -> DatabaseObservation:
        """Select and validate an installed snapshot."""
        ...

    def refresh_database(self, cache_root: Path) -> DatabaseObservation:
        """Refresh and atomically install one snapshot."""
        ...


def select_fresh_database(
    adapter: DatabaseAdapter, cache_root: Path, *, now: datetime
) -> DatabaseObservation:
    """Select a fresh snapshot or perform one bounded refresh."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Database selection time must be timezone-aware")
    try:
        selected = adapter.select_database(cache_root)
        if not _fresh(selected, now):
            raise OperationalError("Installed Trivy database is stale")
    except OperationalError:
        selected = adapter.refresh_database(cache_root)
        if not _fresh(selected, now):
            raise OperationalError(
                "Refreshed Trivy database is already stale"
            ) from None
    return selected


def _fresh(database: DatabaseObservation, now: datetime) -> bool:
    value = database.metadata.get("NextUpdate")
    if not isinstance(value, str):
        value = database.metadata.get("nextUpdate")
    if not isinstance(value, str):
        raise OperationalError("Trivy database metadata has no next-update time")
    try:
        next_update = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperationalError("Trivy database next-update time is malformed") from exc
    if next_update.tzinfo is None or next_update.utcoffset() is None:
        raise OperationalError("Trivy database next-update time lacks a timezone")
    return now.astimezone(UTC) < next_update.astimezone(UTC)
