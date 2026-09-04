import getpass
import os
from pathlib import Path

import pytest

import conclear.secrets as secrets_module
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.secrets import (
    MAX_SECRET_BYTES,
    read_passphrase,
    read_protected_file,
    read_secret_fd,
    read_secret_file,
    token_provider,
)


def private_file(tmp_path: Path, content: bytes, *, mode: int = 0o600) -> Path:
    path = tmp_path / "secret"
    path.write_bytes(content)
    path.chmod(mode)
    return path


def test_protected_file_requires_a_private_regular_file(tmp_path: Path) -> None:
    path = private_file(tmp_path, b"value\n", mode=0o640)
    with pytest.raises(
        InvalidInvocationError, match="permissions are unsafe"
    ) as caught:
        read_protected_file(path, maximum_bytes=64)
    assert caught.value.code == "CC0003"
    assert read_protected_file(path, maximum_bytes=64, allow_group_read=True) == (
        b"value\n"
    )

    with pytest.raises(InvalidInvocationError, match="not a regular file") as caught:
        read_protected_file(tmp_path, maximum_bytes=64)
    assert caught.value.code == "CC0003"

    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(InvalidInvocationError, match="unavailable"):
        read_protected_file(link, maximum_bytes=64)
    with pytest.raises(InvalidInvocationError, match="unavailable"):
        read_protected_file(tmp_path / "missing", maximum_bytes=64)

    with pytest.raises(InvalidInvocationError, match="size limit"):
        read_protected_file(private_file(tmp_path, b"x" * 65), maximum_bytes=64)


def test_secret_file_values_are_trimmed_and_validated(tmp_path: Path) -> None:
    assert read_secret_file(private_file(tmp_path, b"passphrase\r\n")) == "passphrase"
    assert token_provider(private_file(tmp_path, b"token\n")) == "token"

    with pytest.raises(InvalidInvocationError, match="invalid value"):
        read_secret_file(private_file(tmp_path, b"\n"))
    with pytest.raises(InvalidInvocationError, match="invalid value"):
        read_secret_file(private_file(tmp_path, b"line one\nline two\n"))
    with pytest.raises(InvalidInvocationError, match="invalid value"):
        read_secret_file(private_file(tmp_path, b"nul\x00byte\n"))
    with pytest.raises(InvalidInvocationError, match="not UTF-8"):
        read_secret_file(private_file(tmp_path, b"\xff\xfe\n"))
    with pytest.raises(InvalidInvocationError, match="size limit"):
        read_secret_file(private_file(tmp_path, b"x" * (MAX_SECRET_BYTES + 1)))


def test_secret_descriptor_is_read_once_bounded_and_closed() -> None:
    reader, writer = os.pipe()
    os.write(writer, b"from-descriptor\n")
    os.close(writer)

    assert read_secret_fd(reader) == "from-descriptor"
    with pytest.raises(OSError):
        os.fstat(reader)

    with pytest.raises(InvalidInvocationError, match="3 or greater"):
        read_secret_fd(2)

    reader, writer = os.pipe()
    os.close(writer)
    with pytest.raises(InvalidInvocationError, match="invalid value"):
        read_secret_fd(reader)

    reader, writer = os.pipe()
    os.close(reader)
    with pytest.raises(OperationalError, match="Unable to read signing passphrase"):
        read_secret_fd(writer)


def test_oversized_descriptor_secret_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(secrets_module, "MAX_SECRET_BYTES", 8)
    reader, writer = os.pipe()
    os.write(writer, b"x" * 9)
    os.close(writer)

    with pytest.raises(InvalidInvocationError, match="size limit"):
        read_secret_fd(reader)


def test_passphrase_sources_are_exclusive_and_terminal_input_is_validated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = private_file(tmp_path, b"file-passphrase\n")
    reader, writer = os.pipe()
    os.write(writer, b"descriptor-passphrase\n")
    os.close(writer)

    with pytest.raises(InvalidInvocationError, match="not both"):
        read_passphrase(file=path, descriptor=reader)
    assert read_passphrase(file=None, descriptor=reader) == "descriptor-passphrase"
    assert read_passphrase(file=path, descriptor=None) == "file-passphrase"

    prompts: list[str] = []

    def prompt(message: str) -> str:
        prompts.append(message)
        return "typed"

    monkeypatch.setattr(getpass, "getpass", prompt)
    assert read_passphrase(file=None, descriptor=None) == "typed"
    assert prompts == ["Cosign key passphrase: "]

    monkeypatch.setattr(getpass, "getpass", lambda message: "")
    with pytest.raises(InvalidInvocationError, match="cannot be empty"):
        read_passphrase(file=None, descriptor=None)

    def unavailable(message: str) -> str:
        raise EOFError

    monkeypatch.setattr(getpass, "getpass", unavailable)
    with pytest.raises(OperationalError, match="terminal"):
        read_passphrase(file=None, descriptor=None)
