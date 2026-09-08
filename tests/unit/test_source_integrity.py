from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conclear.errors import InvalidInvocationError
from conclear.services.qualification import build_platform
from conclear.services.runtime_tests import test_platform as run_platform_tests
from conclear.source_integrity import source_tree_digest
from tests.unit.test_qualification import Builder, Runtime, hook_runner, inputs


def test_source_digest_covers_ignored_files_modes_and_symlink_targets(
    tmp_path: Path,
) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "index").write_text("index cache")
    (tmp_path / ".gitignore").write_text("*.txt\n")
    source = tmp_path / "input.txt"
    source.write_text("original")
    (tmp_path / "link").symlink_to("input.txt")
    baseline = source_tree_digest(tmp_path)
    (tmp_path / ".git" / "index").write_text("new index cache")
    assert source_tree_digest(tmp_path) == baseline
    source.write_text("changed")
    assert source_tree_digest(tmp_path) != baseline
    source.write_text("original")
    assert source_tree_digest(tmp_path) == baseline
    source.chmod(0o755)
    assert source_tree_digest(tmp_path) != baseline


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
