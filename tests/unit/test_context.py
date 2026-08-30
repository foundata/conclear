import tempfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from conclear.context import hash_build_context
from conclear.errors import InvalidInvocationError


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
