import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from conclear.errors import OperationalError
from conclear.release_check import validate_distribution_artifact


def test_wheel_hygiene_requires_embedded_identity(tmp_path: Path) -> None:
    wheel = tmp_path / "conclear.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        for name in (
            "conclear/_embedded_identity.py",
            "conclear/data/checks.json",
            "conclear/schemas/config.schema.json",
            "conclear/schemas/profile.schema.json",
            "conclear/schemas/provenance.schema.json",
            "conclear/schemas/record.schema.json",
            "conclear/schemas/result.schema.json",
        ):
            archive.writestr(name, b"test")

    validate_distribution_artifact(wheel, kind="wheel")


def test_wheel_hygiene_rejects_development_identity(tmp_path: Path) -> None:
    wheel = tmp_path / "conclear.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("conclear/_development_identity.py", b"test")

    with pytest.raises(OperationalError, match="development-only"):
        validate_distribution_artifact(wheel, kind="wheel")


def test_source_distribution_hygiene_rejects_traversal(tmp_path: Path) -> None:
    sdist = tmp_path / "conclear.tar.gz"
    with tarfile.open(sdist, mode="w:gz") as archive:
        member = tarfile.TarInfo("../outside")
        member.size = 4
        archive.addfile(member, io.BytesIO(b"test"))

    with pytest.raises(OperationalError, match="unsafe path"):
        validate_distribution_artifact(sdist, kind="sdist")
