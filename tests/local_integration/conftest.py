"""Session-scoped provisioning shared by the local integration tier.

The Trivy database snapshot is selected or downloaded once per session, so every
case that depends on it sees the same populated manifest-owned cache no matter
in which order pytest collects the modules.
"""

import os
from pathlib import Path

import pytest

from conclear.runtime import ApplicationRuntime
from conclear.tools import ToolName
from tests.local_integration.fixtures import tool_resolver


@pytest.fixture(scope="session")
def trivy_cache(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Return the manifest-owned Trivy cache with a validated snapshot installed."""
    value = os.environ.get("CONCLEAR_TEST_TRIVY_CACHE")
    if value is None:
        pytest.skip(
            "Trivy database cases require a manifest-owned CONCLEAR_TEST_TRIVY_CACHE"
        )
    cache_root = Path(value)
    if not cache_root.is_absolute():
        pytest.skip("CONCLEAR_TEST_TRIVY_CACHE must be an absolute path")
    if not (cache_root / "current.json").is_file():
        if os.environ.get("CONCLEAR_TEST_TRIVY_DOWNLOAD") != "1":
            pytest.skip(
                "no Trivy database snapshot in CONCLEAR_TEST_TRIVY_CACHE and "
                "CONCLEAR_TEST_TRIVY_DOWNLOAD is not set"
            )
        runtime = ApplicationRuntime.create(
            tmp_path_factory.mktemp("trivy-provision") / "environment",
            names=(ToolName.TRIVY,),
            resolver=tool_resolver(),
        )
        refreshed = runtime.trivy().refresh_database(cache_root)
        assert refreshed.path.parent == cache_root / "snapshots"
        assert refreshed.digest.startswith("sha256:")
    return cache_root
