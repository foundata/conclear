import os
import shutil
from pathlib import Path

import pytest

from conclear.config import (
    TestConfig as RuntimeTestConfig,
)
from conclear.config import (
    TestLaunchConfig as RuntimeTestLaunchConfig,
)
from conclear.config import (
    TestOutputConfig as RuntimeTestOutputConfig,
)
from conclear.errors import OperationalError
from conclear.test_inputs import (
    destroy_secret_test_outputs,
    materialize_test_inputs,
    observe_test_tree,
    remove_materialized_test_inputs,
)


def test_tree_observation_rejects_nested_symbolic_link(tmp_path: Path) -> None:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("private", encoding="utf-8")
    (fixture / "link").symlink_to(outside)

    with pytest.raises(OperationalError, match="symbolic link"):
        observe_test_tree(fixture, secret=False)


def test_tree_observation_rejects_group_writable_and_special_files(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    writable = fixture / "writable"
    writable.write_text("content", encoding="utf-8")
    writable.chmod(0o620)

    with pytest.raises(OperationalError, match="unsafe permissions"):
        observe_test_tree(fixture, secret=False)

    writable.unlink()
    fifo = fixture / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(OperationalError, match="not a regular file"):
        observe_test_tree(fixture, secret=False)


def test_secret_tree_observation_omits_content_digest(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.mkdir(mode=0o700)
    payload = secret / "payload"
    payload.write_text("private-value", encoding="utf-8")
    payload.chmod(0o600)

    observation = observe_test_tree(secret, secret=True)

    assert observation.digest is None
    assert "digest" not in observation.to_dict(name="secret", secret=True)


def test_marker_cleanup_refuses_preexisting_caller_path(tmp_path: Path) -> None:
    path = tmp_path / "test-inputs"
    path.mkdir()
    caller_file = path / "caller-owned"
    caller_file.write_text("keep", encoding="utf-8")

    with pytest.raises(OperationalError, match="ownership marker"):
        remove_materialized_test_inputs(path, run_id="01arz3ndektsv4rrffq69g5fav")

    assert caller_file.read_text(encoding="utf-8") == "keep"


def test_materialized_secret_outputs_are_removed_before_whole_tree(
    tmp_path: Path,
) -> None:
    test = RuntimeTestConfig(
        fixtures=(),
        outputs=(RuntimeTestOutputConfig("secret", True),),
        preparations=(),
        launch=RuntimeTestLaunchConfig((), (), (), 0),
    )
    root = tmp_path / "test-inputs"
    value = materialize_test_inputs(
        root, run_id="01arz3ndektsv4rrffq69g5fav", test=test
    )
    payload = value.outputs["secret"] / "payload"
    payload.write_text("private", encoding="utf-8")
    payload.chmod(0o600)

    destroy_secret_test_outputs(value)

    assert not value.outputs["secret"].exists()
    remove_materialized_test_inputs(root, run_id="01arz3ndektsv4rrffq69g5fav")
    assert not root.exists()


def test_partial_materialization_removes_the_new_run_owned_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    test = RuntimeTestConfig(
        fixtures=(),
        outputs=(RuntimeTestOutputConfig("result", False),),
        preparations=(),
        launch=RuntimeTestLaunchConfig((), (), (), 0),
    )
    root = tmp_path / "test-inputs"
    original_mkdir = Path.mkdir

    def fail_output_root(
        path: Path,
        mode: int = 0o777,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        if path == root / "outputs":
            raise OSError("injected output-root failure")
        original_mkdir(path, mode, parents, exist_ok)

    monkeypatch.setattr(Path, "mkdir", fail_output_root)

    with pytest.raises(OperationalError, match="Unable to create run-owned"):
        materialize_test_inputs(root, run_id="01arz3ndektsv4rrffq69g5fav", test=test)

    assert not root.exists()


def test_removal_keeps_the_marker_until_the_tree_is_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hook may leave content this user cannot unlink; retries must still work."""
    test = RuntimeTestConfig(
        fixtures=(),
        outputs=(RuntimeTestOutputConfig("result", False),),
        preparations=(),
        launch=RuntimeTestLaunchConfig((), (), (), 0),
    )
    run_id = "01arz3ndektsv4rrffq69g5fav"
    root = tmp_path / "test-inputs"
    value = materialize_test_inputs(root, run_id=run_id, test=test)
    # Sorted last, so the entries before it are already gone when it refuses.
    hook_store = root / "zz-hook-podman-root"
    hook_store.mkdir()
    (hook_store / "layer").write_text("root-mapped", encoding="utf-8")
    (value.outputs["result"] / "report.txt").write_text("kept", encoding="utf-8")

    real_rmtree = shutil.rmtree

    def refuse_hook_store(path: Path) -> None:
        if path == hook_store:
            raise PermissionError(13, "Permission denied", str(path))
        real_rmtree(path)

    monkeypatch.setattr(shutil, "rmtree", refuse_hook_store)
    with pytest.raises(OperationalError, match="podman unshare rm -rf") as caught:
        remove_materialized_test_inputs(root, run_id=run_id)

    assert str(hook_store) in str(caught.value)
    assert (root / ".conclear-owner").is_file()
    assert not value.outputs["result"].exists()

    monkeypatch.setattr(shutil, "rmtree", real_rmtree)
    remove_materialized_test_inputs(root, run_id=run_id)

    assert not root.exists()


def test_removal_of_an_absent_tree_is_silent_and_a_stripped_tree_is_named(
    tmp_path: Path,
) -> None:
    run_id = "01arz3ndektsv4rrffq69g5fav"
    remove_materialized_test_inputs(tmp_path / "absent", run_id=run_id)

    stripped = tmp_path / "stripped"
    stripped.mkdir(mode=0o700)
    with pytest.raises(OperationalError, match="ownership marker is missing below"):
        remove_materialized_test_inputs(stripped, run_id=run_id)
    assert stripped.is_dir()
