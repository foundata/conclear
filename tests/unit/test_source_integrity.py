import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conclear.errors import InvalidInvocationError
from conclear.services.qualification import build_platform
from conclear.services.runtime_tests import test_platform as run_platform_tests
from conclear.source_integrity import (
    CHECKOUT_RESOURCE,
    require_source_integrity,
    source_tree_digest,
)
from conclear.workspace import ResourceKind, ResourceStatus, RunWorkspace
from tests.unit.test_qualification import Builder, Runtime, hook_runner, inputs


class FixedIdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def test_source_digest_covers_bytes_modes_and_symlink_targets_but_not_directories(
    tmp_path: Path,
) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "index").write_text("index cache")
    source = tmp_path / "input.txt"
    source.write_text("original")
    (tmp_path / "link").symlink_to("input.txt")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "file").write_text("nested")
    baseline = source_tree_digest(tmp_path)
    (tmp_path / ".git" / "index").write_text("new index cache")
    assert source_tree_digest(tmp_path) == baseline
    # Git tracks file modes but not directory modes; an empty directory is not
    # part of any tracked tree either.
    (tmp_path / "nested").chmod(0o700)
    (tmp_path / "empty").mkdir()
    assert source_tree_digest(tmp_path) == baseline
    source.write_text("changed")
    assert source_tree_digest(tmp_path) != baseline
    source.write_text("original")
    assert source_tree_digest(tmp_path) == baseline
    source.chmod(0o755)
    assert source_tree_digest(tmp_path) != baseline
    source.chmod(0o644)
    (tmp_path / "link").unlink()
    (tmp_path / "link").symlink_to("nested/file")
    assert source_tree_digest(tmp_path) != baseline


def _run_with_export_and_checkout(
    tmp_path: Path, repository_factory: Callable[..., Path]
) -> tuple[RunWorkspace, Path, Path]:
    fixture = repository_factory()
    workspace = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={"sourceRevision": "a" * 40, "image": "app"},
        id_factory=FixedIdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    export = workspace.root / "source"
    checkout = workspace.root / "checkout"
    shutil.copytree(fixture, export)
    shutil.copytree(fixture, checkout)
    workspace.journal.plan(
        resource_id=CHECKOUT_RESOURCE,
        kind=ResourceKind.GIT_WORKTREE,
        identifier=str(checkout),
        ephemeral=True,
        metadata={"repository": str(fixture)},
    )
    workspace.journal.update(CHECKOUT_RESOURCE, ResourceStatus.CREATED)
    workspace.bind_immutable_inputs({"sourceTreeDigest": source_tree_digest(export)})
    return workspace, export, checkout


def test_checkout_may_gain_untracked_files_but_not_change_tracked_content(
    tmp_path: Path, repository_factory: Callable[..., Path]
) -> None:
    workspace, export, checkout = _run_with_export_and_checkout(
        tmp_path, repository_factory
    )
    require_source_integrity(workspace, export)

    # What hook tooling leaves behind: a virtual environment, bytecode, a test
    # cache. None of it is read later, so none of it fails the run.
    (checkout / ".venv" / "lib").mkdir(parents=True)
    (checkout / ".venv" / "lib" / "site.py").write_text("venv")
    (checkout / "__pycache__").mkdir()
    (checkout / "__pycache__" / "x.pyc").write_bytes(b"\x00")
    (checkout / ".pytest_cache").mkdir()
    (checkout / "notes.txt").write_text("not even ignored")
    require_source_integrity(workspace, export)

    containerfile = checkout / "Containerfile"
    original = containerfile.read_text()
    containerfile.write_text(original + "\nRUN echo changed\n")
    with pytest.raises(InvalidInvocationError, match="checkout content changed"):
        require_source_integrity(workspace, export)
    containerfile.write_text(original)
    require_source_integrity(workspace, export)

    containerfile.chmod(0o755)
    with pytest.raises(InvalidInvocationError, match="checkout content changed"):
        require_source_integrity(workspace, export)
    containerfile.chmod(0o644)

    containerfile.unlink()
    with pytest.raises(InvalidInvocationError, match="checkout content changed"):
        require_source_integrity(workspace, export)


def test_export_must_stay_byte_identical(
    tmp_path: Path, repository_factory: Callable[..., Path]
) -> None:
    workspace, export, _checkout = _run_with_export_and_checkout(
        tmp_path, repository_factory
    )
    (export / "extra").write_text("anything written into the export")
    with pytest.raises(InvalidInvocationError, match="source content changed"):
        require_source_integrity(workspace, export)


def test_missing_binding_is_rejected(
    tmp_path: Path, repository_factory: Callable[..., Path]
) -> None:
    fixture = repository_factory()
    workspace = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={"sourceRevision": "a" * 40, "image": "app"},
        id_factory=FixedIdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    export = workspace.root / "source"
    shutil.copytree(fixture, export)
    with pytest.raises(InvalidInvocationError, match="lacks source content binding"):
        require_source_integrity(workspace, export)


def test_build_rejects_source_changes_during_execution(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = repository_factory()
    value = inputs(root, tmp_path)
    builder = Builder()
    original = builder.build

    def mutate(**arguments: Any) -> Any:
        result = original(**arguments)
        (root / "Containerfile").write_text("changed during build")
        return result

    monkeypatch.setattr(builder, "build", mutate)
    with pytest.raises(InvalidInvocationError, match="source content changed"):
        build_platform(value, builder)
    assert (root / "Containerfile").read_text() == "changed during build"


def test_runtime_phase_rejects_source_changes_before_container_operations(
    tmp_path: Path, repository_factory: Callable[..., Path]
) -> None:
    root = repository_factory()
    value = inputs(root, tmp_path)
    build = build_platform(value, Builder())
    (root / "new-input").write_text("not in the selected source")
    runtime = Runtime()
    with pytest.raises(InvalidInvocationError, match="source content changed"):
        run_platform_tests(value, build, runtime, hook_runner(value))
