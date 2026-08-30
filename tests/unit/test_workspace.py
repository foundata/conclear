from datetime import UTC, datetime
from pathlib import Path

import pytest

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import atomic_write_bytes
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

    with pytest.raises(InvalidInvocationError, match="valid JSON"):
        workspace.journal.update(
            "candidate", ResourceStatus.CREATED, metadata={"x": {1}}
        )


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
