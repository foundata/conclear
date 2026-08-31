import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conclear.adapters.trivy import DatabaseObservation
from conclear.ci import observe_ci_identity
from conclear.database import select_fresh_database
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.fileio import read_regular_file
from conclear.jsonutil import load_json, sha256_file
from conclear.secrets import MAX_SECRET_BYTES, read_secret_fd, read_secret_file
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
    RunWorkspace,
)


class IdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def database_metadata(next_update: str) -> dict[str, object]:
    return {
        name: {
            "schemaVersion": version,
            "updatedAt": "2026-01-01T00:00:00Z",
            "nextUpdate": next_update,
            "downloadedAt": "2026-01-01T00:01:00Z",
        }
        for name, version in (("vulnerability", 2), ("java", 1))
    }


class FakeDatabase:
    def __init__(
        self, selected: DatabaseObservation | Exception, refreshed: DatabaseObservation
    ) -> None:
        self.selected = selected
        self.refreshed = refreshed
        self.refreshes = 0

    def select_database(self, cache_root: Path) -> DatabaseObservation:
        del cache_root
        if isinstance(self.selected, Exception):
            raise self.selected
        return self.selected

    def refresh_database(self, cache_root: Path) -> DatabaseObservation:
        del cache_root
        self.refreshes += 1
        return self.refreshed


def test_database_refreshes_stale_snapshot_once(tmp_path: Path) -> None:
    stale = DatabaseObservation(
        tmp_path,
        "sha256:" + "a" * 64,
        database_metadata("2025-12-31T00:00:00Z"),
    )
    fresh = DatabaseObservation(
        tmp_path,
        "sha256:" + "b" * 64,
        database_metadata("2026-01-02T00:00:00Z"),
    )
    adapter = FakeDatabase(stale, fresh)

    selected = select_fresh_database(
        adapter, tmp_path, now=datetime(2026, 1, 1, tzinfo=UTC)
    )

    assert selected is fresh
    assert adapter.refreshes == 1


def test_database_rejects_stale_refresh(tmp_path: Path) -> None:
    stale = DatabaseObservation(
        tmp_path,
        "sha256:" + "a" * 64,
        database_metadata("2025-12-31T00:00:00Z"),
    )
    adapter = FakeDatabase(OperationalError("missing"), stale)

    with pytest.raises(OperationalError, match="already stale"):
        select_fresh_database(adapter, tmp_path, now=datetime(2026, 1, 1, tzinfo=UTC))


def test_secret_descriptor_is_read_once_and_closed() -> None:
    readable, writable = os.pipe()
    os.write(writable, b"protected\n")
    os.close(writable)

    assert read_secret_fd(readable) == "protected"
    with pytest.raises(OSError):
        os.read(readable, 1)


def test_secret_file_rejects_symbolic_link(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("protected\n", encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(InvalidInvocationError, match="unavailable"):
        read_secret_file(link)


def test_secret_file_read_is_bounded(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(b"x" * (MAX_SECRET_BYTES + 1))
    secret.chmod(0o600)

    with pytest.raises(InvalidInvocationError, match="size limit"):
        read_secret_file(secret)


def test_file_hash_rejects_symbolic_link(tmp_path: Path) -> None:
    target = tmp_path / "payload"
    target.write_bytes(b"payload")
    link = tmp_path / "payload-link"
    link.symlink_to(target)

    with pytest.raises(OperationalError, match="Unable to hash"):
        sha256_file(link)


def test_json_reader_rejects_symlinks_and_oversized_files(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"ok":true}', encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)

    with pytest.raises(OperationalError, match="Unable to decode JSON file"):
        load_json(link)
    with pytest.raises(OperationalError, match="exceeds the size limit"):
        load_json(target, maximum_bytes=4)


def test_regular_file_reader_rejects_symlink_and_oversized_file(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"payload")
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(OperationalError, match="Unable to read test input"):
        read_regular_file(link, maximum_bytes=32, label="test input")
    with pytest.raises(InvalidInvocationError, match="size limit"):
        read_regular_file(target, maximum_bytes=4, label="test input")


def test_ci_identity_requires_complete_validated_provider_values() -> None:
    identity = observe_ci_identity(
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "foundata/example",
            "GITHUB_WORKFLOW_REF": "foundata/example/.github/workflows/release.yml@refs/heads/main",
            "GITHUB_RUN_ID": "1234",
            "GITHUB_SHA": "a" * 40,
        }
    )

    assert identity["provider"] == "github-actions"
    with pytest.raises(InvalidInvocationError, match="run id"):
        observe_ci_identity(
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_SERVER_URL": "https://github.com",
                "GITHUB_REPOSITORY": "foundata/example",
                "GITHUB_WORKFLOW_REF": "workflow",
                "GITHUB_RUN_ID": "not-a-number",
                "GITHUB_SHA": "a" * 40,
            }
        )


def test_removed_resource_identifier_can_be_planned_for_bounded_retry(
    tmp_path: Path,
) -> None:
    workspace = RunWorkspace.create(
        state_home=tmp_path,
        immutable_inputs={"source": "a" * 40},
        id_factory=IdFactory(),
    )
    path = workspace.root / "layouts" / "retry"
    workspace.journal.plan(
        resource_id="layout",
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(path),
        ephemeral=True,
    )
    workspace.journal.update("layout", ResourceStatus.FAILED)
    workspace.journal.update("layout", ResourceStatus.REMOVED)

    retried = workspace.journal.plan(
        resource_id="layout",
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(path),
        ephemeral=True,
    )

    assert retried.status is ResourceStatus.PLANNED
