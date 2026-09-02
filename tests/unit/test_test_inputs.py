import os
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
        dependencies=(),
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
        dependencies=(),
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
