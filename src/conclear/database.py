"""Freshness policy for immutable Trivy database snapshots."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.trivy import DatabaseObservation
from conclear.errors import OperationalError
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


def trivy_cache_root(cache_home: Path) -> Path:
    """Return the ConClear-owned Trivy database cache below one cache home."""
    return cache_home / "conclear" / "trivy"


def select_fresh_database(
    adapter: DatabaseAdapter, cache_root: Path, *, now: datetime
) -> DatabaseObservation:
    """Select a fresh snapshot or perform one bounded refresh."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise OperationalError("Database selection time must be timezone-aware")
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


def select_database_by_digest(
    adapter: DatabaseAdapter,
    cache_root: Path,
    *,
    expected_digest: Digest,
) -> DatabaseObservation:
    """Select an exact distributed snapshot without consulting a mutable pointer."""
    selected = adapter.select_database_by_digest(cache_root, expected_digest)
    if selected.digest != str(expected_digest):
        raise OperationalError(
            "Selected Trivy database does not match the expected digest", code="CC0505"
        )
    return selected


def _fresh(database: DatabaseObservation, now: datetime) -> bool:
    next_updates: list[datetime] = []
    for name in ("vulnerability", "java"):
        component = database.metadata.get(name)
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
        next_updates.append(next_update)
    return all(now.astimezone(UTC) < item.astimezone(UTC) for item in next_updates)
