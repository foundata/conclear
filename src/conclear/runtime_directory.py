"""Private transient directories with durable ownership for interrupted runs."""

import os
import shutil
import stat
from pathlib import Path
from uuid import uuid4

from conclear.errors import OperationalError
from conclear.fileio import locked_file
from conclear.jsonutil import atomic_write_json, load_json
from conclear.parsing import object_value, string_value
from conclear.workspace import ResourceJournal, ResourceKind, ResourceStatus

OWNERSHIP_FILE = "runtime-directory.json"
OWNER_MARKER = ".conclear-owner.json"
RESOURCE_ID = "runtime-directory"


def prepare_runtime_directory(
    owner: Path, *, required: bool, journal: ResourceJournal | None = None
) -> Path:
    """Use the login runtime area for container tools and retain its ownership.

    Other tools can use a local private directory without a login session. Once
    container tools have established a runtime directory, later phases reuse it.
    """
    owner = owner.resolve(strict=True)
    record_path = owner / OWNERSHIP_FILE
    if not required and not record_path.exists() and not record_path.is_symlink():
        path = owner / "runtime"
        path.mkdir(mode=0o700, exist_ok=True)
        _private_directory(path)
        return path
    with locked_file(owner / ".runtime-directory.lock", label="runtime directory"):
        if record_path.exists() or record_path.is_symlink():
            record, path = _ownership(owner)
        else:
            base = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
            _private_directory(base)
            token = uuid4().hex
            path = base / f"conclear-{token[:16]}"
            record = {
                "schemaVersion": 1,
                "owner": str(owner),
                "directory": str(path),
                "token": token,
            }
            atomic_write_json(record_path, record)
        _private_directory(path.parent)
        _plan(journal, owner, path)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            _require_owner(path, record)
        else:
            try:
                atomic_write_json(path / OWNER_MARKER, record)
            except BaseException:
                # We just created this directory; remove it only if still empty.
                if not any(path.iterdir()):
                    path.rmdir()
                raise
        if journal is not None:
            journal.update(RESOURCE_ID, ResourceStatus.CREATED)
        return path


def remove_runtime_directory(
    owner: Path, *, expected_directory: str | None = None
) -> bool:
    """Remove only the exact recorded directory after checking its ownership marker."""
    if not owner.exists():
        return False
    owner = owner.resolve(strict=True)
    record_path = owner / OWNERSHIP_FILE
    if not record_path.exists() and not record_path.is_symlink():
        return False
    with locked_file(owner / ".runtime-directory.lock", label="runtime directory"):
        record, path = _ownership(owner)
        if expected_directory is not None and str(path) != expected_directory:
            raise OperationalError(
                "Journaled runtime directory differs from ownership record"
            )
        try:
            _private_directory(path.parent)
        except OperationalError:
            # A logout or reboot may remove the entire login runtime directory.
            if not path.parent.exists() and not path.parent.is_symlink():
                return True
            raise
        try:
            path.lstat()
        except FileNotFoundError:
            return True
        _require_owner(path, record)
        try:
            shutil.rmtree(path)
        except OSError as exc:
            raise OperationalError(
                f"Unable to remove owned runtime directory {path}"
            ) from exc
    return True


def _ownership(owner: Path) -> tuple[dict[str, object], Path]:
    record = object_value(
        load_json(owner / OWNERSHIP_FILE, maximum_bytes=4096), "runtime ownership"
    )
    if record.get("schemaVersion") != 1 or record.get("owner") != str(owner):
        raise OperationalError("Runtime ownership identifies another environment")
    token = string_value(record.get("token"), "runtime ownership token")
    if len(token) != 32 or any(
        character not in "0123456789abcdef" for character in token
    ):
        raise OperationalError("Runtime ownership token is malformed")
    path = Path(string_value(record.get("directory"), "runtime directory"))
    if not path.is_absolute() or path.name != f"conclear-{token[:16]}":
        raise OperationalError("Runtime ownership directory is malformed")
    return record, path


def _plan(journal: ResourceJournal | None, owner: Path, path: Path) -> None:
    if journal is None:
        return
    metadata: dict[str, object] = {"runtimeDirectory": str(path)}
    entries = [entry for entry in journal.entries() if entry.resource_id == RESOURCE_ID]
    if entries:
        entry = entries[0]
        if (
            entry.kind is not ResourceKind.RUNTIME_DIRECTORY
            or entry.identifier != str(owner)
            or entry.metadata != metadata
            or not entry.ephemeral
        ):
            raise OperationalError("Journaled runtime directory ownership changed")
        if entry.status is not ResourceStatus.REMOVED:
            return
    journal.plan(
        resource_id=RESOURCE_ID,
        kind=ResourceKind.RUNTIME_DIRECTORY,
        identifier=str(owner),
        ephemeral=True,
        metadata=metadata,
    )


def _require_owner(path: Path, record: dict[str, object]) -> None:
    _private_directory(path)
    if load_json(path / OWNER_MARKER, maximum_bytes=4096) != record:
        raise OperationalError("Runtime directory ownership marker does not match")


def _private_directory(path: Path) -> None:
    try:
        observed = path.lstat()
        if (
            not path.is_absolute()
            or path.resolve(strict=True) != path
            or not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o700
        ):
            raise OperationalError(f"Unsafe runtime directory: {path}")
        for parent in path.parents:
            parent_stat = parent.stat()
            writable = parent_stat.st_mode & 0o022
            protected_sticky = (
                parent_stat.st_uid == 0 and parent_stat.st_mode & stat.S_ISVTX
            )
            if parent_stat.st_uid not in {0, os.getuid()} or (
                writable and not protected_sticky
            ):
                raise OperationalError(f"Unsafe runtime directory parent: {parent}")
    except OSError as exc:
        raise OperationalError(
            f"Runtime directory unavailable: {path}; container commands need a local "
            "user-owned mode-0700 XDG_RUNTIME_DIR, normally /run/user/<uid>. "
            "Use a login session or provision its lifecycle on the managed host."
        ) from exc
