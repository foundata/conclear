"""Inject externally observed identity into a staged clean build tree."""

from pathlib import Path

from conclear.jsonutil import atomic_write_bytes
from conclear.values import validate_source_revision


def write_embedded_identity(package_directory: Path, source_revision: str) -> Path:
    """Write the generated identity module used by a staged distribution build."""
    validate_source_revision(source_revision)
    target = package_directory / "_embedded_identity.py"
    content = (
        '"""Generated source identity for this distribution build."""\n\n'
        f'SOURCE_REVISION = "{source_revision}"\n'
    ).encode("ascii")
    atomic_write_bytes(target, content, mode=0o644)
    return target
