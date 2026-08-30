"""Deterministic JSON and hashing helpers."""

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from conclear.errors import OperationalError


def canonical_json_bytes(value: object) -> bytes:
    """Serialize a JSON-compatible value deterministically."""
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def sha256_bytes(content: bytes) -> str:
    """Return an OCI-style SHA-256 digest for bytes."""
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def sha256_file(path: Path) -> str:
    """Return an OCI-style SHA-256 digest for a regular file."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise OperationalError(f"Unable to hash {path}") from exc
    return f"sha256:{digest.hexdigest()}"


def atomic_write_bytes(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    """Atomically replace a file with flushed content on the same filesystem."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.replace(path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise OperationalError(f"Unable to atomically write {path}") from exc


def atomic_write_json(path: Path, value: object, *, mode: int = 0o600) -> str:
    """Write deterministic JSON atomically and return its content digest."""
    content = canonical_json_bytes(value)
    atomic_write_bytes(path, content, mode=mode)
    return sha256_bytes(content)


def load_json(path: Path) -> Any:
    """Decode a UTF-8 JSON file without claiming a validated type."""
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OperationalError(f"Unable to decode JSON file {path}") from exc
