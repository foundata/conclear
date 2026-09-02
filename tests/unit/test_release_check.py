import io
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

from conclear.errors import OperationalError
from conclear.release_check import validate_distribution_artifact


def test_pytest_configuration_enables_pytest_nine_strict_mode() -> None:
    project = tomllib.loads(
        (Path(__file__).parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    )
    options = project["tool"]["pytest"]["ini_options"]
    assert options["strict"] is True
    assert "--strict-config" not in options["addopts"]
    assert "--strict-markers" not in options["addopts"]


def test_pytest_configuration_rejects_unknown_marker(tmp_path: Path) -> None:
    project_root = Path(__file__).parents[2]
    test_file = tmp_path / "test_unknown_marker.py"
    test_file.write_text(
        "import pytest\n\n"
        "@pytest.mark.unit\n"
        "@pytest.mark.marker_typo\n"
        "def test_marker_typo():\n"
        "    pass\n",
        encoding="utf-8",
    )

    observed = subprocess.run(
        (
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(project_root / "pyproject.toml"),
            "--collect-only",
            str(test_file),
        ),
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert observed.returncode != 0
    assert "marker_typo" in observed.stdout + observed.stderr
    assert "not found in `markers`" in observed.stdout + observed.stderr


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
