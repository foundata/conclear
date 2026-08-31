import io
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import conclear.path_safety as path_safety_module
from conclear.errors import InvalidInvocationError
from conclear.path_safety import (
    contained_path,
    extract_tar_safely,
    extract_zip_safely,
)


@given(depth=st.integers(min_value=1, max_value=20))
def test_contained_path_rejects_parent_traversal(depth: int) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory) / "root"
        root.mkdir()
        with pytest.raises(InvalidInvocationError) as caught:
            contained_path(root, "/".join([".."] * depth), must_exist=False)
        assert caught.value.code == "CC0002"


def test_contained_path_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(InvalidInvocationError, match="escapes"):
        contained_path(root, "escape/value", must_exist=False)


@pytest.mark.parametrize("member_name", ["../escape", "/absolute", "a/../../escape"])
def test_tar_extraction_rejects_traversal(member_name: str, tmp_path: Path) -> None:
    archive_path = tmp_path / "input.tar"
    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo(member_name)
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(InvalidInvocationError, match="Unsafe archive member"):
        extract_tar_safely(archive_path, tmp_path / "output")
    assert not (tmp_path / "escape").exists()


def test_tar_extraction_rejects_symbolic_links(tmp_path: Path) -> None:
    archive_path = tmp_path / "input.tar"
    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "../escape"
        archive.addfile(member)
    with pytest.raises(InvalidInvocationError, match="not a regular file"):
        extract_tar_safely(archive_path, tmp_path / "output")


def test_zip_extraction_rejects_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "input.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape", "x")
    with pytest.raises(InvalidInvocationError, match="Unsafe archive member"):
        extract_zip_safely(archive_path, tmp_path / "output")


@pytest.mark.parametrize("kind", ["tar", "zip"])
def test_archive_extraction_bounds_total_content(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(path_safety_module, "MAX_ARCHIVE_CONTENT_BYTES", 1)
    archive_path = tmp_path / f"input.{kind}"
    if kind == "tar":
        with tarfile.open(archive_path, "w") as archive:
            member = tarfile.TarInfo("value")
            member.size = 2
            archive.addfile(member, io.BytesIO(b"xx"))
        expected = "Tar archive exceeds"
        extractor = extract_tar_safely
    else:
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("value", "xx")
        expected = "ZIP archive exceeds"
        extractor = extract_zip_safely

    with pytest.raises(InvalidInvocationError, match=expected):
        extractor(archive_path, tmp_path / "output")


@given(depth=st.integers(min_value=1, max_value=20))
def test_archive_extractors_reject_generated_parent_traversal(depth: int) -> None:
    member_name = "/".join([".."] * depth + ["escape"])
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        tar_path = root / "input.tar"
        with tarfile.open(tar_path, "w") as archive:
            member = tarfile.TarInfo(member_name)
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with pytest.raises(InvalidInvocationError, match="Unsafe archive member"):
            extract_tar_safely(tar_path, root / "tar-output")

        zip_path = root / "input.zip"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr(member_name, "x")
        with pytest.raises(InvalidInvocationError, match="Unsafe archive member"):
            extract_zip_safely(zip_path, root / "zip-output")
