import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import atomic_write_bytes, atomic_write_json, load_json
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
)


class FixedIdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def create_workspace(tmp_path: Path) -> RunWorkspace:
    return RunWorkspace.create(
        state_home=tmp_path,
        immutable_inputs={"sourceRevision": "a" * 40, "image": "example"},
        id_factory=FixedIdFactory(),
        now=datetime(2026, 1, 2, tzinfo=UTC),
    )


def test_workspace_transitions_and_resumes_interrupted_state(tmp_path: Path) -> None:
    workspace = create_workspace(tmp_path)
    assert workspace.load().state is RunState.CREATED
    workspace.transition(RunState.QUALIFIED)
    interrupted = workspace.transition(RunState.INCOMPLETE)
    assert interrupted.resume_state is RunState.QUALIFIED

    resumed = workspace.resume({"sourceRevision": "a" * 40, "image": "example"})

    assert resumed.state is RunState.QUALIFIED
    assert resumed.resume_state is None


def test_workspace_refuses_changed_inputs_and_invalid_transition(
    tmp_path: Path,
) -> None:
    workspace = create_workspace(tmp_path)
    with pytest.raises(InvalidInvocationError, match="immutable inputs changed"):
        workspace.validate_resume({"sourceRevision": "b" * 40, "image": "example"})
    with pytest.raises(InvalidInvocationError, match="Invalid run transition"):
        workspace.transition(RunState.PUBLISHED)


def test_completed_is_terminal_and_reachable_only_from_created(tmp_path: Path) -> None:
    # A rescan run has no intermediate states: created -> completed. A release
    # that has started qualifying can never be marked completed instead of
    # promoted, and a completed run is neither resumable nor re-enterable.
    started = create_workspace(tmp_path / "started")
    started.transition(RunState.QUALIFIED)
    with pytest.raises(InvalidInvocationError, match="Invalid run transition"):
        started.transition(RunState.COMPLETED)

    rescan = create_workspace(tmp_path / "rescan")
    assert rescan.transition(RunState.COMPLETED).state is RunState.COMPLETED
    with pytest.raises(InvalidInvocationError, match="terminal state completed"):
        rescan.validate_resume({"sourceRevision": "a" * 40, "image": "example"})
    with pytest.raises(InvalidInvocationError, match="Invalid run transition"):
        rescan.transition(RunState.QUALIFIED)
    with pytest.raises(InvalidInvocationError, match="finished run"):
        rescan.bind_tool_identities({"tool.trivy": "1.0.0@sha256:" + "1" * 64})


@pytest.mark.parametrize(
    "terminal_state", (RunState.REJECTED, RunState.PROMOTED, RunState.COMPLETED)
)
def test_workspace_rejects_repeated_terminal_transition(
    tmp_path: Path, terminal_state: RunState
) -> None:
    workspace = create_workspace(tmp_path)
    if terminal_state in {RunState.REJECTED, RunState.COMPLETED}:
        workspace.transition(terminal_state)
    else:
        for state in (
            RunState.QUALIFIED,
            RunState.ASSEMBLED,
            RunState.PUBLISHED,
            RunState.ATTESTED,
            RunState.VERIFIED,
            RunState.PROMOTED,
        ):
            workspace.transition(state)

    with pytest.raises(InvalidInvocationError, match="already in terminal state"):
        workspace.transition(terminal_state)


@pytest.mark.parametrize(
    "timestamp",
    (
        "not-a-timestamp",
        "2026-13-01T00:00:00Z",
        "2026-01-01T00:00:00+00:00",
    ),
)
def test_workspace_rejects_malformed_persisted_timestamp(
    tmp_path: Path, timestamp: str
) -> None:
    workspace = create_workspace(tmp_path)
    state = load_json(workspace.root / "run.json")
    assert isinstance(state, dict)
    state["updatedAt"] = timestamp
    atomic_write_json(workspace.root / "run.json", state)

    with pytest.raises(OperationalError, match="timestamp"):
        workspace.load()


def test_workspace_open_rejects_symlinked_run(tmp_path: Path) -> None:
    state_home = tmp_path / "state"
    runs = state_home / "conclear" / "runs"
    runs.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    run_id = "01arz3ndektsv4rrffq69g5fav"
    (runs / run_id).symlink_to(outside, target_is_directory=True)

    with pytest.raises(InvalidInvocationError, match="unsafe run workspace"):
        RunWorkspace.open(state_home=state_home, run_id=run_id)


def test_resource_journal_limits_cleanup_to_owned_ephemeral_entries(
    tmp_path: Path,
) -> None:
    workspace = create_workspace(tmp_path)
    journal = workspace.journal
    journal.plan(
        resource_id="layout",
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(workspace.root / "layouts/example/linux-amd64"),
        ephemeral=True,
    )
    journal.update("layout", ResourceStatus.CREATED)
    journal.plan(
        resource_id="signature",
        kind=ResourceKind.SIGNATURE,
        identifier="quay.io/foundata/example@sha256:" + "1" * 64,
        ephemeral=False,
    )
    journal.update("signature", ResourceStatus.CREATED)

    assert [entry.resource_id for entry in journal.cleanup_candidates()] == ["layout"]
    journal.update("layout", ResourceStatus.REMOVED)
    assert journal.cleanup_candidates() == ()


def test_resource_journal_records_intent_before_mutation(tmp_path: Path) -> None:
    workspace = create_workspace(tmp_path)
    entry = workspace.journal.plan(
        resource_id="candidate",
        kind=ResourceKind.CANDIDATE_REFERENCE,
        identifier="quay.io/foundata/example:candidate",
        ephemeral=True,
        metadata={"expiration": "2026-01-03T00:00:00Z"},
    )
    assert entry.status is ResourceStatus.PLANNED
    assert workspace.journal.entries() == (entry,)
    assert workspace.journal.cleanup_candidates() == (entry,)

    with pytest.raises(InvalidInvocationError, match="valid JSON"):
        workspace.journal.update(
            "candidate", ResourceStatus.CREATED, metadata={"x": {1}}
        )


def test_resource_journal_can_record_planned_resource_as_absent(tmp_path: Path) -> None:
    workspace = create_workspace(tmp_path)
    workspace.journal.plan(
        resource_id="test-inputs",
        kind=ResourceKind.TEST_INPUTS,
        identifier=str(workspace.root / "reports" / "test-inputs"),
        ephemeral=True,
    )

    entry = workspace.journal.update("test-inputs", ResourceStatus.REMOVED)

    assert entry.status is ResourceStatus.REMOVED
    assert workspace.journal.cleanup_candidates() == ()


def test_atomic_write_failure_preserves_previous_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "state.json"
    target.write_bytes(b"old\n")
    original_replace = Path.replace

    def fail_replace(path: Path, destination: Path) -> Path:
        if destination == target:
            raise OSError("interrupted")
        return original_replace(path, destination)

    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OperationalError, match="atomically write"):
        atomic_write_bytes(target, b"new\n")

    assert target.read_bytes() == b"old\n"
    assert list(tmp_path.glob(".state.json.*.tmp")) == []


def test_atomic_write_closes_descriptor_when_fchmod_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptors: list[int] = []
    original_mkstemp = tempfile.mkstemp

    def record_mkstemp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        descriptor, name = original_mkstemp(*args, **kwargs)
        assert isinstance(name, str)
        descriptors.append(descriptor)
        return descriptor, name

    def fail_fchmod(descriptor: int, mode: int) -> None:
        del descriptor, mode
        raise OSError("injected fchmod failure")

    monkeypatch.setattr(tempfile, "mkstemp", record_mkstemp)
    monkeypatch.setattr(os, "fchmod", fail_fchmod)

    with pytest.raises(OperationalError, match="atomically write"):
        atomic_write_bytes(tmp_path / "state.json", b"new\n")

    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert list(tmp_path.glob(".state.json.*.tmp")) == []


def test_workspace_locks_refuse_symbolic_links(tmp_path: Path) -> None:
    workspace = create_workspace(tmp_path)
    outside = tmp_path / "outside.lock"
    outside.write_text("protected", encoding="utf-8")
    for lock_path, label, operation in (
        (
            workspace.root / ".run.lock",
            "run state",
            lambda: workspace.transition(RunState.QUALIFIED),
        ),
        (
            workspace.root / "resources.lock",
            "resource journal",
            lambda: workspace.journal.plan(
                resource_id="layout",
                kind=ResourceKind.LOCAL_PATH,
                identifier=str(tmp_path / "layout"),
                ephemeral=True,
            ),
        ),
    ):
        lock_path.unlink(missing_ok=True)
        lock_path.symlink_to(outside)
        with pytest.raises(OperationalError, match=f"Unable to lock {label}"):
            operation()
        assert outside.read_text(encoding="utf-8") == "protected"
        lock_path.unlink()
    assert workspace.load().state is RunState.CREATED
    assert workspace.journal.entries() == ()


def test_tool_identities_bind_at_first_use_and_never_change(tmp_path: Path) -> None:
    workspace = create_workspace(tmp_path)
    first = {"tool.git": "2.55.0@sha256:" + "1" * 64}
    workspace.bind_tool_identities(first)
    workspace.transition(RunState.QUALIFIED)
    workspace.transition(RunState.ASSEMBLED)

    later = workspace.bind_tool_identities(
        {**first, "tool.skopeo": "1.22.2@sha256:" + "2" * 64}
    )
    assert later.state is RunState.ASSEMBLED
    assert later.immutable_inputs["tool.skopeo"].startswith("1.22.2@")

    unchanged = workspace.bind_tool_identities(first)
    assert unchanged.updated_at == later.updated_at

    with pytest.raises(InvalidInvocationError, match=r"conflict: tool\.git"):
        workspace.bind_tool_identities({"tool.git": "2.55.0@sha256:" + "3" * 64})
    with pytest.raises(InvalidInvocationError, match="must name tools"):
        workspace.bind_tool_identities({"image": "other"})
    with pytest.raises(InvalidInvocationError, match="must name tools"):
        workspace.bind_tool_identities({})

    workspace.transition(RunState.REJECTED)
    assert workspace.bind_tool_identities(first).state is RunState.REJECTED
    with pytest.raises(InvalidInvocationError, match="finished run"):
        workspace.bind_tool_identities({"tool.cosign": "3.1.3@sha256:" + "4" * 64})
    assert "tool.cosign" not in workspace.load().immutable_inputs
