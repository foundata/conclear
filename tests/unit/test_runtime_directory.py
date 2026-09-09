import shutil
from pathlib import Path
from typing import override

import pytest

from conclear.errors import OperationalError
from conclear.jsonutil import atomic_write_json, load_json
from conclear.runtime_directory import (
    OWNER_MARKER,
    OWNERSHIP_FILE,
    prepare_runtime_directory,
    remove_runtime_directory,
)
from conclear.services.cleanup import cleanup_run
from conclear.workspace import ResourceKind, ResourceStatus
from tests.unit.test_cleanup import FakeBuildah, FakePodman, workspace


@pytest.fixture
def runtime_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "login-runtime"
    path.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(path))
    return path


def test_runtime_directories_are_private_isolated_and_journaled_before_use(
    tmp_path: Path, runtime_home: Path
) -> None:
    run = workspace(tmp_path)
    owner = run.root / "environment"
    owner.mkdir(mode=0o700)
    path = prepare_runtime_directory(owner, required=True, journal=run.journal)
    assert path.parent == runtime_home
    assert path.stat().st_mode & 0o777 == 0o700
    assert load_json(path / OWNER_MARKER) == load_json(owner / OWNERSHIP_FILE)
    assert prepare_runtime_directory(owner, required=True, journal=run.journal) == path
    assert prepare_runtime_directory(owner, required=False, journal=run.journal) == path
    (entry,) = run.journal.entries()
    assert entry.kind is ResourceKind.RUNTIME_DIRECTORY
    assert entry.status is ResourceStatus.CREATED
    assert entry.identifier == str(owner)
    second = tmp_path / "other-command"
    second.mkdir(mode=0o700)
    other_path = prepare_runtime_directory(second, required=True)
    assert other_path != path
    assert remove_runtime_directory(owner)
    assert not path.exists()
    assert other_path.is_dir()
    assert remove_runtime_directory(second)


def test_reboot_recreates_transient_files_without_changing_persistent_state(
    tmp_path: Path, runtime_home: Path
) -> None:
    run = workspace(tmp_path)
    owner = run.root / "environment"
    owner.mkdir(mode=0o700)
    path = prepare_runtime_directory(owner, required=True, journal=run.journal)
    snapshot = (run.root / "run.json").read_bytes()
    journal = (run.root / "resources.json").read_bytes()
    ownership = (owner / OWNERSHIP_FILE).read_bytes()
    shutil.rmtree(runtime_home)
    assert remove_runtime_directory(owner)
    runtime_home.mkdir(mode=0o700)
    assert prepare_runtime_directory(owner, required=True, journal=run.journal) == path
    assert path.is_dir()
    assert (owner / OWNERSHIP_FILE).read_bytes() == ownership
    assert (run.root / "run.json").read_bytes() == snapshot
    assert (run.root / "resources.json").read_bytes() == journal


@pytest.mark.parametrize(
    "unsafe", ["missing", "mode", "symlink", "parent", "relative", "owner"]
)
def test_container_runtime_refuses_unsafe_login_directories(
    tmp_path: Path, runtime_home: Path, monkeypatch: pytest.MonkeyPatch, unsafe: str
) -> None:
    owner = tmp_path / "environment"
    owner.mkdir(mode=0o700)
    if unsafe == "missing":
        runtime_home.rmdir()
    elif unsafe == "mode":
        runtime_home.chmod(0o755)
    elif unsafe == "symlink":
        alias = tmp_path / "runtime-alias"
        alias.symlink_to(runtime_home)
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(alias))
    elif unsafe == "parent":
        tmp_path.chmod(0o777)
    elif unsafe == "relative":
        monkeypatch.setenv("XDG_RUNTIME_DIR", "relative-runtime")
    else:
        monkeypatch.setattr("conclear.runtime_directory.os.getuid", lambda: 999999)
    with pytest.raises(OperationalError, match=r"[Rr]untime directory"):
        prepare_runtime_directory(owner, required=True)
    assert not (owner / OWNERSHIP_FILE).exists()


def test_static_tools_do_not_require_a_login_runtime_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "missing"))
    path = prepare_runtime_directory(tmp_path, required=False)
    assert path == tmp_path / "runtime"
    assert not remove_runtime_directory(tmp_path)


@pytest.mark.parametrize("tampering", ["symlink", "marker", "owner", "directory"])
def test_runtime_cleanup_refuses_unowned_paths(
    tmp_path: Path, runtime_home: Path, tampering: str
) -> None:
    owner = tmp_path / "environment"
    owner.mkdir(mode=0o700)
    path = prepare_runtime_directory(owner, required=True)
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    retained = protected / "keep.txt"
    retained.write_text("keep", encoding="utf-8")
    if tampering == "symlink":
        shutil.rmtree(path)
        path.symlink_to(protected)
    elif tampering == "marker":
        atomic_write_json(path / OWNER_MARKER, {"owner": "another run"})
    else:
        record = load_json(owner / OWNERSHIP_FILE)
        record[tampering] = str(protected)
        atomic_write_json(owner / OWNERSHIP_FILE, record)
    with pytest.raises(OperationalError):
        remove_runtime_directory(owner)
    assert retained.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize("failed", [False, True])
def test_cleanup_keeps_runtime_until_container_cleanup_finishes(
    tmp_path: Path, runtime_home: Path, failed: bool
) -> None:
    run = workspace(tmp_path)
    owner = run.root / "environment"
    owner.mkdir(mode=0o700)
    path = prepare_runtime_directory(owner, required=True, journal=run.journal)
    run.journal.plan(
        resource_id="container",
        kind=ResourceKind.PODMAN_IMPORT,
        identifier="test-container",
        ephemeral=True,
        metadata={"storageRoot": str(run.root / "podman" / "root")},
    )

    class Podman(FakePodman):
        @override
        def remove_storage(self, *, root: Path, runroot: Path) -> None:
            assert path.is_dir()
            if failed:
                raise OperationalError("storage is busy")
            super().remove_storage(root=root, runroot=runroot)

    def cleanup() -> None:
        result = cleanup_run(
            run, buildah=FakeBuildah(), podman=Podman(), registry_control=None
        )
        assert result.removed == ("container", "runtime-directory")

    if failed:
        with pytest.raises(OperationalError, match="storage is busy"):
            cleanup()
        assert path.is_dir()
    else:
        cleanup()
        assert not path.exists()
        assert (run.root / "run.json").is_file()
        assert (
            prepare_runtime_directory(owner, required=True, journal=run.journal) == path
        )
