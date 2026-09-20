"""Run the documented manifest verification on retained, disposable bytes."""

import subprocess
import sys
from pathlib import Path

import pytest

from conclear.release_check import retain_distribution_artifacts

pytestmark = pytest.mark.local_integration

DOCUMENTED_COMMAND = 'uv run release artifacts verify "${artifact_dir}/artifacts.json"'


def test_documented_manifest_verification_accepts_bytes_and_rejects_changes(
    tmp_path: Path,
) -> None:
    documentation = (Path(__file__).resolve().parents[2] / "DEVELOPMENT.md").read_text(
        encoding="utf-8"
    )
    assert DOCUMENTED_COMMAND in documentation, (
        "release procedure names another command"
    )

    wheel = tmp_path / "conclear-1.0.0-py3-none-any.whl"
    sdist = tmp_path / "conclear-1.0.0.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    retained = retain_distribution_artifacts(
        wheel=wheel,
        sdist=sdist,
        destination=tmp_path / "retained",
        source_revision="a" * 40,
        repository="foundata/conclear",
    )

    def verify() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "releasing",
                "artifacts",
                "verify",
                str(retained.directory / "artifacts.json"),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    accepted = verify()
    assert accepted.returncode == 0, accepted.stderr
    retained.wheel.write_bytes(b"modified")
    assert verify().returncode != 0
