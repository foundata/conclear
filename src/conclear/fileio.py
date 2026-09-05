"""Bounded no-follow reads and exclusive locks on untrusted regular files."""

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO

from conclear.errors import InvalidInvocationError, OperationalError


def read_regular_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    """Read one bounded regular file without following its final symlink."""
    if maximum_bytes < 1:
        raise OperationalError("Regular-file size limit must be positive")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise InvalidInvocationError(f"{label} is not a regular file: {path}")
        content = bytearray()
        while len(content) <= maximum_bytes:
            chunk = os.read(
                descriptor, min(64 * 1024, maximum_bytes + 1 - len(content))
            )
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > maximum_bytes:
            raise InvalidInvocationError(f"{label} exceeds the size limit: {path}")
        return bytes(content)
    except OSError as exc:
        raise OperationalError(f"Unable to read {label}: {path}") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


@contextmanager
def locked_file(path: Path, *, label: str) -> Iterator[IO[bytes]]:
    """Hold an exclusive advisory lock on one regular file for the block.

    The lock file is created with mode `0o600` when absent. A symbolic link or
    any other non-regular file at `path` is rejected instead of followed.

    Raises:
        OperationalError: If the lock file cannot be opened, is not a regular
            file, cannot be locked or the block raises `OSError`.
    """
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OperationalError(
                f"{label[:1].upper()}{label[1:]} lock is not a regular file"
            )
        stream = os.fdopen(descriptor, "r+b")
        descriptor = None
        with stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            yield stream
    except OSError as exc:
        raise OperationalError(f"Unable to lock {label} {path}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
