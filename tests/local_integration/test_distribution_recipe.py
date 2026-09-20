"""Run the documented checksum recipe on retained, disposable artifact bytes."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from conclear.release_check import retain_distribution_artifacts

pytestmark = pytest.mark.local_integration


def test_documented_artifact_checksums_accept_exact_bytes_and_reject_changes(
    tmp_path: Path,
) -> None:
    for tool in ("sh", "jq", "sha256sum"):
        if shutil.which(tool) is None:
            pytest.skip(f"checksum recipe requires {tool}")
    documentation = (Path(__file__).resolve().parents[2] / "DEVELOPMENT.md").read_text(
        encoding="utf-8"
    )
    match = re.search(
        r'```sh\n\s*(\(\n\s*cd "\$\{artifact_dir\}"\n.*?\n\s*\))\n\s*```',
        documentation,
        re.DOTALL,
    )
    assert match is not None, "documented artifact verification snippet is missing"
    wheel = tmp_path / "conclear-1.0.0-py3-none-any.whl"
    sdist = tmp_path / "conclear-1.0.0.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    destination = tmp_path / "retained"
    retained = retain_distribution_artifacts(
        wheel=wheel,
        sdist=sdist,
        destination=destination,
        source_revision="a" * 40,
        repository="foundata/conclear",
    )

    def verify() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", "-eu", "-c", match[1]],
            env={**os.environ, "artifact_dir": str(destination)},
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    result = verify()
    assert result.returncode == 0, result.stderr
    assert result.stdout.count(": OK") == 2
    retained.wheel.write_bytes(b"modified")
    assert verify().returncode != 0
