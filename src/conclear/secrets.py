"""Protected file-descriptor, file and terminal secret providers."""

import getpass
import os
import stat
from pathlib import Path

from conclear.errors import InvalidInvocationError, OperationalError

MAX_SECRET_BYTES = 64 * 1024
MAX_PROFILE_BYTES = 1024 * 1024


def read_protected_file(
    path: Path,
    *,
    maximum_bytes: int,
    allow_group_read: bool = False,
) -> bytes:
    """Read a bounded user-owned regular file without following its final link."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InvalidInvocationError(
            f"Credential or profile file is unavailable: {path}"
        ) from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise InvalidInvocationError(
                f"Credential or profile path is not a regular file: {path}"
            )
        if file_stat.st_uid != os.getuid():
            raise InvalidInvocationError(
                f"Credential or profile file is not owned by this user: {path}"
            )
        allowed = 0o640 if allow_group_read else 0o600
        if stat.S_IMODE(file_stat.st_mode) & ~allowed:
            raise InvalidInvocationError(
                f"Credential or profile file permissions are unsafe: {path}"
            )
        content = bytearray()
        while len(content) <= maximum_bytes:
            chunk = os.read(
                descriptor, min(64 * 1024, maximum_bytes + 1 - len(content))
            )
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > maximum_bytes:
            raise InvalidInvocationError(
                f"Credential or profile file exceeds the size limit: {path}"
            )
        return bytes(content)
    except OSError as exc:
        raise OperationalError(f"Unable to read protected file {path}") from exc
    finally:
        os.close(descriptor)


def read_secret_file(path: Path) -> str:
    """Read one bounded secret from a profile-validated private file."""
    content = read_protected_file(path, maximum_bytes=MAX_SECRET_BYTES)
    return _decode_secret(content)


def read_secret_fd(descriptor: int) -> str:
    """Read a secret exactly once from an explicitly supplied descriptor."""
    if descriptor < 3:
        raise InvalidInvocationError("Secret descriptor must be 3 or greater")
    chunks = bytearray()
    try:
        while len(chunks) <= MAX_SECRET_BYTES:
            chunk = os.read(descriptor, min(4096, MAX_SECRET_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
    except OSError as exc:
        raise OperationalError("Unable to read signing passphrase descriptor") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return _decode_secret(bytes(chunks))


def read_passphrase(*, file: Path | None, descriptor: int | None) -> str:
    """Read a passphrase from one protected non-environment source."""
    if file is not None and descriptor is not None:
        raise InvalidInvocationError(
            "Choose either a passphrase file or descriptor, not both"
        )
    if descriptor is not None:
        return read_secret_fd(descriptor)
    if file is not None:
        return read_secret_file(file)
    try:
        value = getpass.getpass("Cosign key passphrase: ")
    except (EOFError, OSError) as exc:
        raise OperationalError("Unable to read passphrase from the terminal") from exc
    if not value:
        raise InvalidInvocationError("Signing passphrase cannot be empty")
    return value


def token_provider(path: Path) -> str:
    """Read one Quay bearer token on demand from its protected file."""
    return read_secret_file(path)


def _decode_secret(content: bytes) -> str:
    if len(content) > MAX_SECRET_BYTES:
        raise InvalidInvocationError("Protected secret exceeds the size limit")
    try:
        value = content.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise InvalidInvocationError("Protected secret is not UTF-8") from exc
    if not value or any(character in value for character in ("\x00", "\r", "\n")):
        raise InvalidInvocationError("Protected secret has an invalid value")
    return value
