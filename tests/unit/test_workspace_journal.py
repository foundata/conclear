"""Workspace state and ownership-journal failure paths."""

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.workspace import (
    ResourceJournal,
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
)

OTHER_RUN = "01arz3ndektsv4rrffq69g5faw"


class FixedIdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def create(tmp_path: Path) -> RunWorkspace:
    return RunWorkspace.create(
        state_home=tmp_path,
        immutable_inputs={"sourceRevision": "a" * 40, "image": "app"},
        id_factory=FixedIdFactory(),
        now=datetime(2026, 1, 2, tzinfo=UTC),
    )


def rewrite_state(workspace: RunWorkspace, **changes: object) -> None:
    path = workspace.root / "run.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    for key, item in changes.items():
        if item is None:
            value.pop(key, None)
        else:
            value[key] = item
    path.write_text(json.dumps(value), encoding="utf-8")


def test_immutable_inputs_bind_only_while_created_and_never_conflict(
    tmp_path: Path,
) -> None:
    workspace = create(tmp_path)

    with pytest.raises(InvalidInvocationError, match="cannot be empty"):
        workspace.bind_immutable_inputs({})
    with pytest.raises(InvalidInvocationError, match="cannot be empty"):
        workspace.bind_immutable_inputs({"tool.git": ""})
    with pytest.raises(InvalidInvocationError, match="conflict"):
        workspace.bind_immutable_inputs({"image": "other"})

    bound = workspace.bind_immutable_inputs(
        {"image": "app", "tool.git": "2.55.0@sha256:" + "1" * 64},
        now=datetime(2026, 1, 3, tzinfo=UTC),
    )
    assert bound.immutable_inputs["tool.git"].startswith("2.55.0@")
    assert bound.updated_at == "2026-01-03T00:00:00Z"

    workspace.transition(RunState.QUALIFIED)
    with pytest.raises(InvalidInvocationError, match="only be bound while"):
        workspace.bind_immutable_inputs({"tool.podman": "5.8.4@sha256:" + "2" * 64})


def test_opening_requires_matching_run_identity_and_valid_persisted_state(
    tmp_path: Path,
) -> None:
    workspace = create(tmp_path)

    rewrite_state(workspace, runId=OTHER_RUN)
    with pytest.raises(InvalidInvocationError, match="identity does not match"):
        RunWorkspace.open(state_home=tmp_path, run_id=workspace.run_id)

    rewrite_state(workspace, runId=workspace.run_id, state="unknown")
    with pytest.raises(OperationalError, match="unknown state"):
        workspace.load()

    rewrite_state(workspace, state="incomplete", resumeState=None)
    with pytest.raises(OperationalError, match="invalid resume metadata"):
        workspace.load()

    rewrite_state(workspace, state="incomplete", resumeState="promoted")
    with pytest.raises(OperationalError, match="invalid resume state"):
        workspace.load()

    rewrite_state(
        workspace, state="created", resumeState=None, immutableInputs={"x": 1}
    )
    with pytest.raises(OperationalError, match="immutable inputs are malformed"):
        workspace.load()

    rewrite_state(workspace, immutableInputs={"x": "y"}, schemaVersion=2)
    with pytest.raises(OperationalError, match="Run state is malformed"):
        workspace.load()

    rewrite_state(workspace, schemaVersion=1, createdAt="yesterday")
    with pytest.raises(OperationalError, match="UTC RFC 3339"):
        workspace.load()

    with pytest.raises(InvalidInvocationError, match="Unknown or unsafe run"):
        RunWorkspace.open(state_home=tmp_path, run_id=OTHER_RUN)
    with pytest.raises(InvalidInvocationError, match="lowercase ULID"):
        RunWorkspace.open(state_home=tmp_path, run_id="../escape")


def test_resume_restores_the_recorded_stable_state_only_once_interrupted(
    tmp_path: Path,
) -> None:
    workspace = create(tmp_path)
    expected = {"sourceRevision": "a" * 40, "image": "app"}

    assert workspace.resume(expected).state is RunState.CREATED

    workspace.transition(RunState.QUALIFIED)
    workspace.transition(RunState.INCOMPLETE)
    snapshot = workspace.resume(expected, now=datetime(2026, 1, 4, tzinfo=UTC))
    assert snapshot.state is RunState.QUALIFIED
    assert snapshot.resume_state is None
    assert snapshot.updated_at == "2026-01-04T00:00:00Z"

    assert workspace.transition(RunState.QUALIFIED).state is RunState.QUALIFIED
    workspace.transition(RunState.REJECTED)
    with pytest.raises(InvalidInvocationError, match="terminal state"):
        workspace.resume(expected)
    with pytest.raises(InvalidInvocationError, match="already in terminal state"):
        workspace.transition(RunState.REJECTED)


def test_journal_rejects_conflicting_plans_and_invalid_transitions(
    tmp_path: Path,
) -> None:
    journal = create(tmp_path).journal

    with pytest.raises(InvalidInvocationError, match="cannot be empty"):
        journal.plan(
            resource_id="", kind=ResourceKind.LOCAL_PATH, identifier="x", ephemeral=True
        )
    with pytest.raises(InvalidInvocationError, match="valid JSON"):
        journal.plan(
            resource_id="blob",
            kind=ResourceKind.LOCAL_PATH,
            identifier="x",
            ephemeral=True,
            metadata={"raw": b"bytes"},
        )

    journal.plan(
        resource_id="layout",
        kind=ResourceKind.LOCAL_PATH,
        identifier="/workspace/layout",
        ephemeral=True,
    )
    with pytest.raises(InvalidInvocationError, match="already recorded"):
        journal.plan(
            resource_id="layout",
            kind=ResourceKind.LOCAL_PATH,
            identifier="/workspace/layout",
            ephemeral=True,
        )
    with pytest.raises(InvalidInvocationError, match="Unknown resource id"):
        journal.update("missing", ResourceStatus.CREATED)

    journal.update("layout", ResourceStatus.CREATED, metadata={"digest": "a"})
    journal.update("layout", ResourceStatus.REMOVED)
    with pytest.raises(InvalidInvocationError, match="Invalid resource transition"):
        journal.update("layout", ResourceStatus.CREATED)
    with pytest.raises(InvalidInvocationError, match="valid JSON"):
        journal.update("layout", ResourceStatus.REMOVED, metadata={"raw": b"bytes"})
    with pytest.raises(InvalidInvocationError, match="already recorded"):
        journal.plan(
            resource_id="layout",
            kind=ResourceKind.BUILDAH_STORAGE,
            identifier="/workspace/layout",
            ephemeral=True,
        )

    replanned = journal.plan(
        resource_id="layout",
        kind=ResourceKind.LOCAL_PATH,
        identifier="/workspace/layout",
        ephemeral=True,
        metadata={"attempt": 2},
    )
    assert replanned.status is ResourceStatus.PLANNED
    assert replanned.metadata == {"attempt": 2}
    assert [entry.resource_id for entry in journal.cleanup_candidates()] == ["layout"]


def test_journal_rejects_persisted_corruption(tmp_path: Path) -> None:
    workspace = create(tmp_path)
    path = workspace.root / "resources.json"
    original = path.read_bytes()

    def expect(value: object, message: str) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(OperationalError, match=message):
            workspace.journal.entries()

    expect({"schemaVersion": 2}, "journal is malformed")
    expect(
        {"schemaVersion": 1, "runId": OTHER_RUN, "resources": []},
        "belongs to another run",
    )
    expect(
        {"schemaVersion": 1, "runId": workspace.run_id, "resources": {}},
        "entries are malformed",
    )
    expect(
        {"schemaVersion": 1, "runId": workspace.run_id, "resources": [1]},
        "entry is malformed",
    )
    entry = {
        "resourceId": "x",
        "kind": "localPath",
        "identifier": "/x",
        "ephemeral": True,
        "status": "created",
        "metadata": [],
    }
    expect(
        {"schemaVersion": 1, "runId": workspace.run_id, "resources": [entry]},
        "metadata is malformed",
    )
    expect(
        {
            "schemaVersion": 1,
            "runId": workspace.run_id,
            "resources": [{**entry, "metadata": {}, "kind": "teleport"}],
        },
        "unknown enum value",
    )
    expect(
        {
            "schemaVersion": 1,
            "runId": workspace.run_id,
            "resources": [{**entry, "metadata": {}, "ephemeral": "yes"}],
        },
        "must be a boolean",
    )
    path.write_bytes(original)
    assert workspace.journal.entries() == ()


def test_state_lock_failure_is_an_operational_failure(tmp_path: Path) -> None:
    workspace = create(tmp_path)
    if os.geteuid() == 0:
        pytest.skip("root can always create lock files")
    workspace.root.chmod(0o500)
    try:
        with pytest.raises(OperationalError, match="Unable to lock run state"):
            workspace.transition(RunState.QUALIFIED)
    finally:
        workspace.root.chmod(0o700)
    assert workspace.load().state is RunState.CREATED


def test_journal_mark_failed_only_logs_a_failed_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    workspace = create(tmp_path)
    workspace.journal.plan(
        resource_id="layout",
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(tmp_path / "layout"),
        ephemeral=True,
    )

    workspace.journal.mark_failed("layout")
    (entry,) = workspace.journal.entries()
    assert entry.status is ResourceStatus.FAILED

    def fail_update(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("injected journal failure")

    monkeypatch.setattr(ResourceJournal, "update", fail_update)
    caplog.set_level(logging.DEBUG, logger="conclear.workspace")

    workspace.journal.mark_failed("layout", "missing")

    assert "Failed to record resource failure for layout" in caplog.text
    assert "Failed to record resource failure for missing" in caplog.text
    assert "injected journal failure" in caplog.text
