"""Path confinement and archive extraction refuse every escape or special member."""

import io
import tarfile
import warnings
import zipfile
from pathlib import Path

import pytest

import conclear.path_safety as path_safety_module
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.path_safety import (
    contained_path,
    extract_tar_safely,
    extract_zip_safely,
)


@pytest.mark.parametrize(
    "candidate",
    ["/etc/passwd", "nul\x00byte", "nested/../sibling", "./relative", "a/./b"],
)
def test_contained_path_rejects_absolute_empty_and_dotted_components(
    tmp_path: Path, candidate: str
) -> None:
    with pytest.raises(InvalidInvocationError) as caught:
        contained_path(tmp_path, candidate)
    assert caught.value.code == "CC0002"


def test_contained_path_resolves_below_the_root_and_can_target_new_paths(
    tmp_path: Path,
) -> None:
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "file").write_text("x", encoding="utf-8")

    assert contained_path(tmp_path, "dir/file") == (tmp_path / "dir" / "file").resolve()
    assert (
        contained_path(tmp_path, "dir/new", must_exist=False)
        == (tmp_path / "dir" / "new").resolve()
    )
    with pytest.raises(InvalidInvocationError, match="cannot be resolved"):
        contained_path(tmp_path, "dir/missing")
    with pytest.raises(InvalidInvocationError, match="cannot be resolved"):
        contained_path(tmp_path / "absent-root", "file")


def _tar(path: Path, *members: tuple[str, bytes | None, bytes]) -> Path:
    with tarfile.open(path, mode="w") as archive:
        for name, content, kind in members:
            info = tarfile.TarInfo(name)
            if kind == tarfile.DIRTYPE:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif content is None:
                info.type = kind
                archive.addfile(info)
            else:
                info.size = len(content)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(content))
    return path


def test_tar_extraction_preserves_files_and_rejects_duplicates_and_special_members(
    tmp_path: Path,
) -> None:
    archive = _tar(
        tmp_path / "ok.tar",
        ("dir", None, tarfile.DIRTYPE),
        ("dir/file", b"content", tarfile.REGTYPE),
    )
    destination = tmp_path / "ok"
    extract_tar_safely(archive, destination)
    assert (destination / "dir" / "file").read_bytes() == b"content"
    assert (destination / "dir" / "file").stat().st_mode & 0o777 == 0o755

    duplicate = _tar(
        tmp_path / "duplicate.tar",
        ("file", b"a", tarfile.REGTYPE),
        ("file", b"b", tarfile.REGTYPE),
    )
    with pytest.raises(InvalidInvocationError, match="duplicate member"):
        extract_tar_safely(duplicate, tmp_path / "duplicate")

    fifo = _tar(tmp_path / "fifo.tar", ("pipe", None, tarfile.FIFOTYPE))
    with pytest.raises(InvalidInvocationError, match="not a regular file"):
        extract_tar_safely(fifo, tmp_path / "fifo")

    with pytest.raises(OperationalError, match="Unable to extract"):
        extract_tar_safely(tmp_path / "missing.tar", tmp_path / "missing")


def test_tar_extraction_bounds_the_member_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(path_safety_module, "MAX_ARCHIVE_MEMBERS", 1)
    archive = _tar(
        tmp_path / "many.tar",
        ("one", b"1", tarfile.REGTYPE),
        ("two", b"2", tarfile.REGTYPE),
    )

    with pytest.raises(InvalidInvocationError, match="member limit"):
        extract_tar_safely(archive, tmp_path / "many")


def test_zip_extraction_rejects_symlinks_duplicates_and_bounded_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "link.zip"
    with zipfile.ZipFile(archive, mode="w") as zipped:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        zipped.writestr(info, "target")
    with pytest.raises(InvalidInvocationError, match="symbolic link"):
        extract_zip_safely(archive, tmp_path / "link")

    duplicate = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(duplicate, mode="w") as zipped:
        zipped.writestr("file", "a")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            zipped.writestr("file", "b")
    with pytest.raises(InvalidInvocationError, match="duplicate member"):
        extract_zip_safely(duplicate, tmp_path / "duplicate")

    ok = tmp_path / "ok.zip"
    with zipfile.ZipFile(ok, mode="w") as zipped:
        zipped.writestr("dir/", "")
        info = zipfile.ZipInfo("dir/file")
        info.external_attr = 0o100640 << 16
        zipped.writestr(info, "content")
    destination = tmp_path / "ok"
    extract_zip_safely(ok, destination)
    assert (destination / "dir" / "file").read_text(encoding="utf-8") == "content"
    assert (destination / "dir" / "file").stat().st_mode & 0o777 == 0o640

    monkeypatch.setattr(path_safety_module, "MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(InvalidInvocationError, match="member limit"):
        extract_zip_safely(ok, tmp_path / "bounded")

    with pytest.raises(OperationalError, match="Unable to extract"):
        extract_zip_safely(tmp_path / "missing.zip", tmp_path / "missing")


def test_archive_member_paths_reject_backslashes_and_traversal(tmp_path: Path) -> None:
    for index, name in enumerate(("dir\\file", "../escape", "/absolute")):
        archive = tmp_path / "bad.zip"
        with zipfile.ZipFile(archive, mode="w") as zipped:
            zipped.writestr(name, "x")
        with pytest.raises(InvalidInvocationError, match="Unsafe archive member"):
            extract_zip_safely(archive, tmp_path / f"bad-{index}")
        archive.unlink()
