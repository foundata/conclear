"""Session-scoped provisioning shared by the local integration tier.

The Trivy database snapshot is selected or downloaded once per session, so every
case that depends on it sees the same populated manifest-owned cache no matter
in which order pytest collects the modules.
"""

import os
from pathlib import Path

import pytest

from conclear.database import require_database_fresh_at, select_fresh_database
from conclear.errors import OperationalError, RuleRejectionError
from conclear.records import utc_now
from conclear.runtime import ApplicationRuntime
from conclear.tools import ToolName
from tests.local_integration.fixtures import tool_resolver


@pytest.fixture(scope="session")
def trivy_cache(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Return a manifest-owned cache fresh enough to start real qualification."""
    value = os.environ.get("CONCLEAR_TEST_TRIVY_CACHE")
    if value is None:
        pytest.skip(
            "Trivy database cases require a manifest-owned CONCLEAR_TEST_TRIVY_CACHE"
        )
    cache_root = Path(value)
    if not cache_root.is_absolute():
        pytest.skip("CONCLEAR_TEST_TRIVY_CACHE must be an absolute path")
    runtime = ApplicationRuntime.create(
        tmp_path_factory.mktemp("trivy-provision") / "environment",
        names=(ToolName.TRIVY,),
        resolver=tool_resolver(),
    )
    if os.environ.get("CONCLEAR_TEST_TRIVY_DOWNLOAD") == "1":
        selected = select_fresh_database(runtime.trivy(), cache_root, now=utc_now())
    else:
        try:
            selected = runtime.trivy().select_database(cache_root)
            require_database_fresh_at(selected.metadata, utc_now())
        except (OperationalError, RuleRejectionError) as exc:
            pytest.skip(
                "Trivy cache is unavailable or stale; set CONCLEAR_TEST_TRIVY_DOWNLOAD=1 "
                f"to permit refresh: {exc}"
            )
    assert selected.path.parent == cache_root / "snapshots"
    assert selected.digest.startswith("sha256:")
    return cache_root
