"""Real Git checkout mutations must not survive source-run reopening."""

from collections.abc import Callable
from pathlib import Path

import pytest

from conclear.errors import InvalidInvocationError
from conclear.jsonutil import atomic_write_json, load_json
from conclear.runtime import ApplicationRuntime
from conclear.services.run_context import create_source_run, open_source_run
from conclear.tools import ToolName
from tests.local_integration.fixtures import manifest_run_id
from tests.local_integration.test_adapter_failures import _git

pytestmark = pytest.mark.local_integration


@pytest.mark.parametrize(
    "mutation",
    [
        "tracked",
        "untracked",
        "ignored",
        "hook",
        "mode",
        "missing-binding",
    ],
)
def test_real_git_resume_rejects_changed_source_bytes(
    tmp_path: Path, repository_factory: Callable[..., Path], mutation: str
) -> None:
    """The export that builds read has no Git and tolerates no change at all."""
    manifest_run_id()
    root = repository_factory()
    (root / ".gitignore").write_text("ignored.txt\n")
    (root / "hook.sh").write_text("#!/bin/sh\nexit 0\n")
    runtime = ApplicationRuntime.create(tmp_path / "environment", names=(ToolName.GIT,))
    _git(runtime, "init", "--quiet", "--initial-branch=main", str(root))
    _git(
        runtime,
        "-C",
        str(root),
        "remote",
        "add",
        "origin",
        "https://github.com/example/app.git",
    )
    _git(runtime, "-C", str(root), "add", "--all")
    _git(runtime, "-C", str(root), "commit", "--quiet", "-m", "fixture")
    created = create_source_run(
        source_root=root,
        selector="HEAD",
        image_id="app",
        version="1.2.3",
        state_home=tmp_path / "state",
        names=(),
    )
    export = created.repository.path.parent
    open_source_run(
        state_home=tmp_path / "state", run_id=created.workspace.run_id, names=()
    )
    target = export / "Containerfile"
    if mutation == "tracked":
        target.write_text(target.read_text() + "\nRUN echo changed\n")
    elif mutation in {"untracked", "ignored"}:
        target = export / f"{mutation}.txt"
        target.write_text("uncommitted build input\n")
    elif mutation == "hook":
        target = export / "hook.sh"
        target.write_text("#!/bin/sh\nexit 1\n")
    elif mutation == "mode":
        target.chmod(0o755)
    else:
        state = load_json(created.workspace.root / "run.json")
        assert isinstance(state, dict)
        state["immutableInputs"].pop("sourceTreeDigest")
        atomic_write_json(created.workspace.root / "run.json", state)
    before = target.read_bytes()
    with pytest.raises(InvalidInvocationError, match="source content"):
        open_source_run(
            state_home=tmp_path / "state", run_id=created.workspace.run_id, names=()
        )
    assert target.read_bytes() == before


@pytest.mark.parametrize(
    ("mutation", "accepted"),
    [
        ("tracked", False),
        ("staged", False),
        ("assume-unchanged", False),
        ("mode", False),
        ("hook", False),
        ("deleted", False),
        ("untracked", True),
        ("ignored", True),
        ("venv", True),
    ],
)
def test_real_git_checkout_tolerates_untracked_files_but_binds_tracked_content(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    mutation: str,
    accepted: bool,
) -> None:
    """Hooks run in the checkout; only the tracked tree there is bound."""
    manifest_run_id()
    root = repository_factory()
    (root / ".gitignore").write_text("ignored.txt\n.venv/\n")
    (root / "hook.sh").write_text("#!/bin/sh\nexit 0\n")
    # An ignored file in the ordinary checkout must never reach the export.
    (root / "ignored.txt").write_text("developer scratch\n")
    runtime = ApplicationRuntime.create(tmp_path / "environment", names=(ToolName.GIT,))
    _git(runtime, "init", "--quiet", "--initial-branch=main", str(root))
    _git(
        runtime,
        "-C",
        str(root),
        "remote",
        "add",
        "origin",
        "https://github.com/example/app.git",
    )
    _git(runtime, "-C", str(root), "add", "--all")
    _git(runtime, "-C", str(root), "commit", "--quiet", "-m", "fixture")
    created = create_source_run(
        source_root=root,
        selector="HEAD",
        image_id="app",
        version="1.2.3",
        state_home=tmp_path / "state",
        names=(),
    )
    export = created.repository.path.parent
    checkout = created.workspace.root / "checkout"
    assert export == created.workspace.root / "source"
    assert not (export / "ignored.txt").exists()
    assert not (export / ".git").exists()
    assert (checkout / ".git").exists()
    assert (export / "Containerfile").read_bytes() == (
        checkout / "Containerfile"
    ).read_bytes()

    target = checkout / "Containerfile"
    if mutation in {"tracked", "staged", "assume-unchanged"}:
        if mutation == "assume-unchanged":
            _git(
                runtime,
                "-C",
                str(checkout),
                "update-index",
                "--assume-unchanged",
                "Containerfile",
            )
        target.write_text(target.read_text() + "\nRUN echo changed\n")
        if mutation == "staged":
            _git(runtime, "-C", str(checkout), "add", "Containerfile")
    elif mutation == "mode":
        target.chmod(0o755)
    elif mutation == "hook":
        (checkout / "hook.sh").write_text("#!/bin/sh\nexit 1\n")
    elif mutation == "deleted":
        target.unlink()
    elif mutation == "untracked":
        (checkout / "notes.txt").write_text("not committed\n")
    elif mutation == "ignored":
        (checkout / "ignored.txt").write_text("hook scratch\n")
    else:
        (checkout / ".venv" / "lib").mkdir(parents=True)
        (checkout / ".venv" / "lib" / "site.py").write_text("venv\n")
        (checkout / "__pycache__").mkdir()
        (checkout / "__pycache__" / "x.pyc").write_bytes(b"\x00")

    if accepted:
        reopened = open_source_run(
            state_home=tmp_path / "state", run_id=created.workspace.run_id, names=()
        )
        assert reopened.repository.path.parent == export
    else:
        with pytest.raises(InvalidInvocationError, match="checkout content changed"):
            open_source_run(
                state_home=tmp_path / "state",
                run_id=created.workspace.run_id,
                names=(),
            )
    # The export is untouched either way.
    assert not (export / "notes.txt").exists()
    assert not (export / ".venv").exists()
