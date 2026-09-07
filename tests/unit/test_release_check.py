import io
import json
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

from conclear.errors import OperationalError
from conclear.process import ProcessResult
from conclear.release_check import (
    GateRuntime,
    retain_distribution_artifacts,
    run_release_check,
    validate_distribution_artifact,
)


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
            "conclear/data/guide-options.json",
            "conclear/data/guide-requirements.json",
            "conclear/data/implementation.json",
            "conclear/data/requirement-coverage.json",
            "conclear/schemas/config.schema.json",
            "conclear/schemas/profile.schema.json",
            "conclear/schemas/proposal.schema.json",
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


def test_validated_distribution_artifacts_are_retained_atomically(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "gate-artifacts"
    artifacts.mkdir()
    sdist = artifacts / "conclear-1.0.0.tar.gz"
    wheel = artifacts / "conclear-1.0.0-py3-none-any.whl"
    sdist.write_bytes(b"validated source distribution")
    wheel.write_bytes(b"validated wheel")
    destination = tmp_path / "retained"

    retained = retain_distribution_artifacts(
        sdist=sdist,
        wheel=wheel,
        destination=destination,
        source_revision="a" * 40,
    )

    assert retained.directory == destination
    assert (destination / sdist.name).read_bytes() == sdist.read_bytes()
    assert (destination / wheel.name).read_bytes() == wheel.read_bytes()
    manifest = json.loads((destination / "artifacts.json").read_text(encoding="utf-8"))
    assert manifest["conclearRevision"] == "a" * 40
    assert manifest["artifacts"] == [
        {"filename": sdist.name, "sha256": retained.sdist_digest},
        {"filename": wheel.name, "sha256": retained.wheel_digest},
    ]


def test_retained_distribution_rejects_preexisting_and_symlink_destinations(
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "conclear.tar.gz"
    wheel = tmp_path / "conclear.whl"
    sdist.write_bytes(b"sdist")
    wheel.write_bytes(b"wheel")
    existing = tmp_path / "existing"
    existing.mkdir()

    with pytest.raises(OperationalError, match="must not already exist"):
        retain_distribution_artifacts(
            sdist=sdist,
            wheel=wheel,
            destination=existing,
            source_revision="a" * 40,
        )

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(OperationalError, match="symbolic link"):
        retain_distribution_artifacts(
            sdist=sdist,
            wheel=wheel,
            destination=link / "retained",
            source_revision="a" * 40,
        )


def test_retained_distribution_cleans_only_its_partial_staging_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdist = tmp_path / "conclear.tar.gz"
    wheel = tmp_path / "conclear.whl"
    sdist.write_bytes(b"sdist")
    wheel.write_bytes(b"wheel")
    caller_owned = tmp_path / "caller-owned"
    caller_owned.write_text("preserve", encoding="utf-8")
    destination = tmp_path / "retained"
    real_copyfile = shutil.copyfile
    copies = 0

    def fail_second_copy(source: Path, target: Path) -> None:
        nonlocal copies
        copies += 1
        if copies == 2:
            raise OSError("injected copy failure")
        real_copyfile(source, target)

    monkeypatch.setattr("conclear.release_check.shutil.copyfile", fail_second_copy)

    with pytest.raises(OperationalError, match="Unable to stage"):
        retain_distribution_artifacts(
            sdist=sdist,
            wheel=wheel,
            destination=destination,
            source_revision="a" * 40,
        )

    assert not destination.exists()
    assert caller_owned.read_text(encoding="utf-8") == "preserve"
    assert tuple(tmp_path.glob(".retained.conclear-*")) == ()


def test_dirty_source_rejects_retention_without_creating_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (repository / "uv.lock").write_text("version = 1\n", encoding="utf-8")

    class DirtyRuntime:
        git = Path("/usr/bin/git")

        def run(
            self,
            label: str,
            argv: tuple[str, ...],
            **values: object,
        ) -> ProcessResult:
            del argv, values
            output = (
                str(repository) + "\n"
                if label == "locate repository"
                else " M README.md\n"
            )
            return ProcessResult((), 0, output, "", 0.0, 1, False, False)

    monkeypatch.setattr(
        GateRuntime,
        "create",
        classmethod(lambda cls, temporary_root: DirtyRuntime()),
    )
    destination = tmp_path / "retained"

    with pytest.raises(OperationalError, match="clean checkout"):
        run_release_check(repository, output_directory=destination)

    assert not destination.exists()
