"""Bounded no-follow reads for untrusted regular files."""

import os
import stat
from pathlib import Path

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
