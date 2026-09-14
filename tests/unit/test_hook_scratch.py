import shutil
from pathlib import Path
from typing import Any

import pytest

from conclear.errors import OperationalError
from conclear.hook_scratch import (
    active_mounts_below,
    create_hook_scratch,
    hook_scratch_root,
    remove_hook_scratch,
)


class FakeRuntime:
    def __init__(self, *, leave_behind: bool = False) -> None:
        self.calls: list[tuple[Path, Path]] = []
        self.leave_behind = leave_behind

    def remove_mapped_tree(self, path: Path, *, storage: Path) -> None:
        self.calls.append((path, storage))
        # Podman initializes a storage location even for `unshare`.
        (storage / "root").mkdir(parents=True)
        (storage / "root" / "db.sql").write_bytes(b"")
        if not self.leave_behind:
            shutil.rmtree(path)


def test_scratch_is_created_private_and_empty_below_the_run(tmp_path: Path) -> None:
    path = hook_scratch_root(tmp_path, "app", "linux-amd64")

    create_hook_scratch(path)

    assert path == tmp_path / "hook-scratch" / "app" / "linux-amd64"
    assert path.is_dir() and not any(path.iterdir())
    for current in (path, path.parent, path.parent.parent):
        assert current.stat().st_mode & 0o777 == 0o700
    with pytest.raises(OperationalError, match="Unable to create hook scratch"):
        create_hook_scratch(path)


def test_plain_removal_never_enters_the_namespace(tmp_path: Path) -> None:
    path = hook_scratch_root(tmp_path, "app", "linux-amd64")
    create_hook_scratch(path)
    (path / "store").mkdir()
    (path / "store" / "layer").write_text("user-owned", encoding="utf-8")
    runtime = FakeRuntime()

    remove_hook_scratch(path, runtime=runtime, storage=tmp_path / ".unshare")
    remove_hook_scratch(path, runtime=runtime, storage=tmp_path / ".unshare")

    assert not path.exists()
    assert runtime.calls == []


def test_blocked_removal_falls_back_to_the_namespace_and_drops_its_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = hook_scratch_root(tmp_path, "app", "linux-amd64")
    create_hook_scratch(path)
    (path / "store").mkdir()
    real_rmtree = shutil.rmtree
    blocked = {"active": True}

    def refuse_once(target: Path, *args: Any, **kwargs: Any) -> None:
        if blocked["active"] and target == path:
            blocked["active"] = False
            raise PermissionError(13, "Permission denied", str(path / "store"))
        real_rmtree(target, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", refuse_once)
    monkeypatch.setattr(
        "conclear.hook_scratch.active_mounts_below", lambda *_a, **_k: ()
    )
    runtime = FakeRuntime()
    storage = tmp_path / "hook-scratch" / ".unshare"

    remove_hook_scratch(path, runtime=runtime, storage=storage)

    assert runtime.calls == [(path, storage)]
    assert not path.exists()
    assert not storage.exists()


def test_active_mounts_below_the_scratch_refuse_the_namespace_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = hook_scratch_root(tmp_path, "app", "linux-amd64")
    create_hook_scratch(path)
    (path / "store").mkdir()
    monkeypatch.setattr(
        shutil,
        "rmtree",
        lambda *_a, **_k: (_ for _ in ()).throw(PermissionError(13, "denied")),
    )
    monkeypatch.setattr(
        "conclear.hook_scratch.active_mounts_below",
        lambda *_a, **_k: (str(path / "store" / "overlay"),),
    )
    runtime = FakeRuntime()

    with pytest.raises(OperationalError, match="active mounts below it"):
        remove_hook_scratch(path, runtime=runtime, storage=tmp_path / ".unshare")

    assert runtime.calls == []
    assert path.is_dir()


def test_content_surviving_the_namespace_step_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = hook_scratch_root(tmp_path, "app", "linux-amd64")
    create_hook_scratch(path)
    (path / "store").mkdir()
    real_rmtree = shutil.rmtree

    def refuse_scratch(target: Path, *args: Any, **kwargs: Any) -> None:
        if target == path:
            raise PermissionError(13, "denied")
        real_rmtree(target, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", refuse_scratch)
    monkeypatch.setattr(
        "conclear.hook_scratch.active_mounts_below", lambda *_a, **_k: ()
    )
    storage = tmp_path / ".unshare"

    with pytest.raises(OperationalError, match="still present"):
        remove_hook_scratch(
            path, runtime=FakeRuntime(leave_behind=True), storage=storage
        )
    assert not storage.exists()


def test_symbolic_link_in_place_of_the_scratch_is_refused(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    path = tmp_path / "scratch"
    path.symlink_to(elsewhere)

    with pytest.raises(OperationalError, match="not a directory"):
        remove_hook_scratch(path, runtime=FakeRuntime(), storage=tmp_path / ".u")
    assert elsewhere.is_dir()


def test_mountinfo_matching_is_exact_and_decodes_escapes(tmp_path: Path) -> None:
    mountinfo = tmp_path / "mountinfo"
    scratch = "/state/runs/01/hook-scratch/app/linux-amd64"
    mountinfo.write_text(
        "\n".join(
            (
                "45 1 0:36 /root / rw,relatime shared:1 - btrfs /dev/x rw",
                f"90 45 0:50 / {scratch}/store/overlay rw - overlay overlay rw",
                f"91 45 0:51 / {scratch}-other/mnt rw - tmpfs tmpfs rw",
                f"92 45 0:52 / {scratch}/with\\040space rw - tmpfs tmpfs rw",
                "93 45 0:53 / /state/runs/01/hook-scratch rw - tmpfs tmpfs rw",
                "malformed line",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    found = active_mounts_below(Path(scratch), mountinfo=mountinfo)

    assert found == (f"{scratch}/store/overlay", f"{scratch}/with space")
    assert active_mounts_below(Path(scratch) / "store" / "overlay", mountinfo=mountinfo)
    assert active_mounts_below(Path(scratch) / "absent", mountinfo=mountinfo) == ()
    with pytest.raises(OperationalError, match="Unable to read"):
        active_mounts_below(Path(scratch), mountinfo=tmp_path / "missing")
