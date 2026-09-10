"""Exercise the documented local backup recipe on disposable files."""

import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.local_integration


@pytest.fixture
def backup_script() -> str:
    for tool in (
        "bash",
        "tar",
        "gzip",
        "realpath",
        "mktemp",
        "date",
        "sha256sum",
        "mv",
        "rm",
    ):
        if shutil.which(tool) is None:
            pytest.skip(f"backup recipe requires {tool}")
    document = Path(__file__).resolve().parents[2] / "docs" / "backup.md"
    blocks: list[str] = re.findall(
        r"^```bash\n(.*?)^```$", document.read_text(encoding="utf-8"), re.M | re.S
    )
    assert len(blocks) == 1
    return blocks[0]


def _environment(root: Path, *, xdg: bool = False) -> dict[str, str]:
    home = root / "home with spaces"
    config = home / ("custom-config" if xdg else ".config")
    state = home / ("custom-state" if xdg else ".local/state")
    environment = {
        **os.environ,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(config) if xdg else "",
        "XDG_STATE_HOME": str(state) if xdg else "",
        "secure_storage": str(root / "secure storage"),
        "evidence_dir": str(root / "evidence"),
        "operations_dir": str(root / "operations"),
        "TAR_OPTIONS": "--exclude=*",
    }
    for directory in (
        config / "conclear",
        state / "conclear" / "pins",
        Path(environment["evidence_dir"]),
        Path(environment["operations_dir"]),
    ):
        directory.mkdir(parents=True)
        (directory / "record").write_text("preserved\n", encoding="utf-8")
    Path(environment["secure_storage"]).mkdir()
    key = config / "conclear" / "cosign.key"
    key.write_text("test signing key\n", encoding="utf-8")
    key.chmod(0o600)
    (config / "conclear" / "key-link").symlink_to("cosign.key")
    return environment


def _run(script: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", script],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize("xdg", [False, True])
def test_backup_restores_files_modes_and_links_without_overwriting_previous_archives(
    tmp_path: Path, backup_script: str, xdg: bool
) -> None:
    environment = _environment(tmp_path, xdg=xdg)
    storage = Path(environment["secure_storage"])

    for _ in range(2):
        result = _run(backup_script, environment)
        assert result.returncode == 0, result.stderr
    backups = list(storage.iterdir())
    assert len(backups) == 2
    for backup in backups:
        assert backup.name.startswith("conclear-")
        assert backup.stat().st_mode & 0o777 == 0o700
        archive = backup / "local.tar.gz"
        assert archive.stat().st_mode & 0o777 == 0o600
        verification = subprocess.run(
            ["sha256sum", "--check", "SHA256SUMS"],
            cwd=backup,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert verification.returncode == 0, verification.stderr
        restored = tmp_path / f"restored-{backup.name}"
        with tarfile.open(archive) as content:
            assert all(not member.name.startswith("/") for member in content)
            content.extractall(restored, filter="data")
        assert len(list(restored.rglob("record"))) == 4
        key = next(restored.rglob("cosign.key"))
        assert key.read_text(encoding="utf-8") == "test signing key\n"
        assert key.stat().st_mode & 0o777 == 0o600
        assert key.with_name("key-link").is_symlink()
        assert key.with_name("key-link").readlink() == Path("cosign.key")


@pytest.mark.parametrize("missing", ["evidence_dir", "secure_storage"])
def test_backup_rejects_missing_sources_or_storage(
    tmp_path: Path, backup_script: str, missing: str
) -> None:
    environment = _environment(tmp_path)
    storage = Path(environment["secure_storage"])
    environment[missing] = str(tmp_path / "missing")

    result = _run(backup_script, environment)

    assert result.returncode != 0
    assert not list(storage.iterdir())


@pytest.mark.parametrize("nested", [False, True])
def test_backup_rejects_destination_inside_a_source(
    tmp_path: Path, backup_script: str, nested: bool
) -> None:
    environment = _environment(tmp_path)
    destination = Path(environment["evidence_dir"])
    if nested:
        destination /= "backups"
        destination.mkdir()
    environment["secure_storage"] = str(destination)

    result = _run(backup_script, environment)

    assert result.returncode != 0
    assert "outside every source" in result.stderr
    assert not list(destination.glob("*conclear-*"))


def test_backup_removes_partial_output_after_archive_failure(
    tmp_path: Path, backup_script: str
) -> None:
    environment = _environment(tmp_path)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    failing_tar = binaries / "tar"
    failing_tar.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
    failing_tar.chmod(0o700)
    environment["PATH"] = f"{binaries}:{os.environ['PATH']}"

    result = _run(backup_script, environment)

    assert result.returncode == 2
    assert not list(Path(environment["secure_storage"]).iterdir())
    assert "Backup:" not in result.stdout
