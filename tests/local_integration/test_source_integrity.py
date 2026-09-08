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
        "staged",
        "untracked",
        "ignored",
        "hook",
        "mode",
        "assume-unchanged",
        "missing-binding",
    ],
)
def test_real_git_resume_rejects_changed_source_bytes(
    tmp_path: Path, repository_factory: Callable[..., Path], mutation: str
) -> None:
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
    checkout = created.repository.path.parent
    open_source_run(
        state_home=tmp_path / "state", run_id=created.workspace.run_id, names=()
    )
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
    elif mutation in {"untracked", "ignored"}:
        target = checkout / f"{mutation}.txt"
        target.write_text("uncommitted build input\n")
    elif mutation == "hook":
        target = checkout / "hook.sh"
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
