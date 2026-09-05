import os
import stat
from pathlib import Path

import pytest

from conclear.errors import OperationalError
from conclear.fileio import locked_file


def test_locked_file_creates_a_private_lock_and_holds_it(tmp_path: Path) -> None:
    lock_path = tmp_path / "state.lock"

    with locked_file(lock_path, label="example state") as stream:
        assert stream.readable() and stream.writable()
        mode = stat.S_IMODE(lock_path.stat().st_mode)

    assert mode == 0o600
    assert lock_path.is_file()


def test_locked_file_refuses_a_symbolic_link_without_touching_its_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "outside"
    target.write_text("protected", encoding="utf-8")
    lock_path = tmp_path / "state.lock"
    lock_path.symlink_to(target)

    with pytest.raises(OperationalError, match="Unable to lock example state"):
        with locked_file(lock_path, label="example state"):
            pytest.fail("the block must not run")

    assert target.read_text(encoding="utf-8") == "protected"
    assert lock_path.is_symlink()


def test_locked_file_refuses_a_non_regular_file(tmp_path: Path) -> None:
    lock_path = tmp_path / "state.lock"
    os.mkfifo(lock_path)

    with pytest.raises(OperationalError, match="Example state lock is not a regular"):
        with locked_file(lock_path, label="example state"):
            pytest.fail("the block must not run")


def test_locked_file_wraps_os_errors_raised_inside_the_block(tmp_path: Path) -> None:
    with pytest.raises(OperationalError, match="Unable to lock example state") as info:
        with locked_file(tmp_path / "state.lock", label="example state"):
            raise OSError("disk unavailable")

    assert isinstance(info.value.__cause__, OSError)


def test_locked_file_reports_an_unwritable_parent(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can always create lock files")
    parent = tmp_path / "locked"
    parent.mkdir(mode=0o500)
    try:
        with pytest.raises(OperationalError, match="Unable to lock example state"):
            with locked_file(parent / "state.lock", label="example state"):
                pytest.fail("the block must not run")
    finally:
        parent.chmod(0o700)
