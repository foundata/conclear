import os
import tempfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from conclear.context import hash_build_context
from conclear.errors import InvalidInvocationError, OperationalError


def test_context_hash_is_deterministic_and_excludes_ignored_content(
    tmp_path: Path,
) -> None:
    (tmp_path / ".containerignore").write_text(".git/\n*.key\n", encoding="utf-8")
    (tmp_path / "Containerfile").write_text("FROM scratch\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("secret", encoding="utf-8")
    (tmp_path / "private.key").write_text("secret", encoding="utf-8")

    first = hash_build_context(tmp_path)
    (tmp_path / ".git" / "config").write_text("changed", encoding="utf-8")
    second = hash_build_context(tmp_path)

    assert first.digest == second.digest
    assert [entry.path for entry in first.entries] == [
        ".containerignore",
        "Containerfile",
    ]


def test_context_hash_rejects_nonignored_symlink(tmp_path: Path) -> None:
    (tmp_path / ".containerignore").write_text(".git/\n", encoding="utf-8")
    outside = tmp_path.parent / "outside-secret"
    outside.write_text("secret", encoding="utf-8")
    (tmp_path / "link").symlink_to(outside)

    with pytest.raises(InvalidInvocationError, match="symbolic link"):
        hash_build_context(tmp_path)


def test_context_hash_rejects_oversized_ignore_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".containerignore").write_bytes(b"x" * 17)
    monkeypatch.setattr("conclear.context.MAX_CONTAINERIGNORE_BYTES", 16)

    with pytest.raises(InvalidInvocationError, match="size limit"):
        hash_build_context(tmp_path)


def test_context_hash_rejects_excessive_path_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".containerignore").write_text(".git/\n", encoding="utf-8")
    (tmp_path / "content").write_text("content", encoding="utf-8")
    monkeypatch.setattr("conclear.context.MAX_CONTEXT_PATHS", 1)

    with pytest.raises(InvalidInvocationError, match="path-count limit"):
        hash_build_context(tmp_path)


def test_context_hash_detects_file_replacement_during_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".containerignore").write_text(".git/\n", encoding="utf-8")
    target = tmp_path / "content"
    target.write_text("before", encoding="utf-8")
    real_open = os.open

    def replacing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == "content" and dir_fd is not None:
            replacement = tmp_path / "replacement"
            replacement.write_text("after", encoding="utf-8")
            replacement.replace(target)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("conclear.context.os.open", replacing_open)
    with pytest.raises(OperationalError, match="changed while hashing"):
        hash_build_context(tmp_path)


@given(content=st.binary(max_size=1024))
def test_context_digest_changes_with_included_bytes(content: bytes) -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / ".containerignore").write_text(".git/\n", encoding="utf-8")
        target = root / "content"
        target.write_bytes(content)
        before = hash_build_context(root).digest
        target.write_bytes(content + b"x")
        assert hash_build_context(root).digest != before
