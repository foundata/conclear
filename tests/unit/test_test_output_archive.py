"""Persist only declared non-secret generated test outputs."""

import io
import tarfile
from pathlib import Path

import pytest

from conclear.errors import InvalidInvocationError
from conclear.test_inputs import observe_test_tree
from conclear.test_output_archive import retain_test_outputs


def test_public_outputs_keep_content_and_executable_modes(tmp_path: Path) -> None:
    public = tmp_path / "test-inputs/outputs/public"
    public.mkdir(mode=0o700, parents=True)
    nested = public / "nested"
    nested.mkdir(mode=0o700)
    (nested / "result").write_bytes(b"observed result")
    (nested / "result").chmod(0o700)
    secret = public.parent / "private"
    secret.mkdir(mode=0o700)
    (secret / "key").write_bytes(b"private key material")
    observation: dict[str, object] = {
        "outputs": [
            {
                "name": "public",
                "secret": False,
                "digest": observe_test_tree(public, secret=False).digest,
            },
            {"name": "private", "secret": True},
        ]
    }
    result = retain_test_outputs(tmp_path, observation)
    assert result is not None
    with tarfile.open(fileobj=io.BytesIO(result.read_bytes())) as archive:
        assert not any(name.startswith("private") for name in archive.getnames())
        entry = archive.getmember("public/nested/result")
        assert entry.mode == 0o700
        content = archive.extractfile(entry)
        assert content is not None and content.read() == b"observed result"
    (nested / "result").write_bytes(b"changed result")
    with pytest.raises(InvalidInvocationError, match="changed after"):
        retain_test_outputs(tmp_path, observation)


@pytest.mark.parametrize("name", ["../outside", "nested/output", "."])
def test_output_names_are_single_safe_components(tmp_path: Path, name: str) -> None:
    with pytest.raises(InvalidInvocationError):
        retain_test_outputs(tmp_path, {"outputs": [{"name": name, "secret": False}]})


def test_no_public_outputs_need_no_archive(tmp_path: Path) -> None:
    assert (
        retain_test_outputs(
            tmp_path, {"outputs": [{"name": "private", "secret": True}]}
        )
        is None
    )
