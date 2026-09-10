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
def backup_scripts() -> list[str]:
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
        "find",
        "sort",
    ):
        if shutil.which(tool) is None:
            pytest.skip(f"backup recipe requires {tool}")
    document = Path(__file__).resolve().parents[2] / "docs" / "backup.md"
    blocks: list[str] = re.findall(
        r"^```bash\n(.*?)^```$", document.read_text(encoding="utf-8"), re.M | re.S
    )
    assert len(blocks) == 2
    return blocks


@pytest.fixture
def backup_script(backup_scripts: list[str]) -> str:
    return backup_scripts[0]


@pytest.fixture
def cleanup_script(backup_scripts: list[str]) -> str:
    return backup_scripts[1]


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
        "TAR_OPTIONS": "--exclude=*",
    }
    environment.pop("keep", None)
    for directory in (
        config / "conclear",
        state / "conclear" / "pins",
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
        assert len(list(restored.rglob("record"))) == 2
        key = next(restored.rglob("cosign.key"))
        assert key.read_text(encoding="utf-8") == "test signing key\n"
        assert key.stat().st_mode & 0o777 == 0o600
        assert key.with_name("key-link").is_symlink()
        assert key.with_name("key-link").readlink() == Path("cosign.key")


@pytest.mark.parametrize("missing", ["XDG_CONFIG_HOME", "secure_storage"])
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
    destination = Path(environment["HOME"]) / ".config/conclear"
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


def _backups(root: Path, count: int = 4) -> tuple[dict[str, str], list[Path]]:
    environment = _environment(root)
    storage = Path(environment["secure_storage"])
    result: list[Path] = []
    for index in range(count):
        directory = storage / f"conclear-20260910T120000Z-{index:06d}"
        directory.mkdir()
        archive = directory / "local.tar.gz"
        archive.write_bytes(b"retained archive")
        checksum = subprocess.run(
            ["sha256sum", "local.tar.gz"],
            cwd=directory,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        (directory / "SHA256SUMS").write_text(checksum.stdout, encoding="utf-8")
        # Reverse filename order to test timestamp ordering without sleeps.
        timestamp = 1_700_000_000 - index
        os.utime(directory, (timestamp, timestamp))
        result.append(directory)
    return environment, result


@pytest.mark.parametrize("keep", ["1", "2", "7"])
def test_cleanup_keeps_newest_archives_and_ignores_other_directories(
    tmp_path: Path, cleanup_script: str, keep: str
) -> None:
    environment, backups = _backups(tmp_path)
    environment["keep"] = keep
    storage = Path(environment["secure_storage"])
    unrelated = storage / "other-backup"
    unrelated.mkdir()
    partial = storage / ".conclear-20260910T120000Z-PART01"
    partial.mkdir()
    incomplete = storage / "conclear-20260910T120000Z-INCOMP"
    incomplete.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = storage / "conclear-20260910T120000Z-SYMLNK"
    link.symlink_to(outside, target_is_directory=True)

    result = _run(cleanup_script, environment)

    assert result.returncode == 0, result.stderr
    assert [path for path in backups if path.exists()] == backups[: int(keep)]
    assert all(path.is_dir() for path in (unrelated, partial, incomplete, outside))
    assert link.is_symlink()


@pytest.mark.parametrize("keep", ["0", "-1", "1.5", "all", "999999999999999999999"])
def test_cleanup_rejects_invalid_retention_without_deleting_archives(
    tmp_path: Path, cleanup_script: str, keep: str
) -> None:
    environment, backups = _backups(tmp_path)
    environment["keep"] = keep

    result = _run(cleanup_script, environment)

    assert result.returncode != 0
    assert all(path.is_dir() for path in backups)


def test_cleanup_aborts_before_deletion_if_a_retained_archive_is_corrupt(
    tmp_path: Path, cleanup_script: str
) -> None:
    environment, backups = _backups(tmp_path)
    environment["keep"] = "2"
    (backups[1] / "local.tar.gz").write_bytes(b"corrupted")

    result = _run(cleanup_script, environment)

    assert result.returncode != 0
    assert all(path.is_dir() for path in backups)


@pytest.mark.parametrize("linked", ["local.tar.gz", "SHA256SUMS"])
def test_cleanup_does_not_count_or_delete_backups_with_linked_members(
    tmp_path: Path, cleanup_script: str, linked: str
) -> None:
    environment, backups = _backups(tmp_path)
    environment["keep"] = "2"
    directory = Path(environment["secure_storage"]) / "conclear-20260910T120000Z-LINKED"
    directory.mkdir()
    for name in ("local.tar.gz", "SHA256SUMS"):
        if name == linked:
            (directory / name).symlink_to(backups[0] / name)
        else:
            shutil.copyfile(backups[0] / name, directory / name)

    result = _run(cleanup_script, environment)

    assert result.returncode == 0, result.stderr
    assert [path for path in backups if path.exists()] == backups[:2]
    assert directory.is_dir()
    assert (directory / linked).is_symlink()


def test_cleanup_leaves_empty_storage_unchanged(
    tmp_path: Path, cleanup_script: str
) -> None:
    environment = _environment(tmp_path)

    result = _run(cleanup_script, environment)

    assert result.returncode == 0, result.stderr
    assert not list(Path(environment["secure_storage"]).iterdir())
