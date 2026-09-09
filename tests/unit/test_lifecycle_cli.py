"""The live CLI wrapper preserves failed run ownership and protected diagnostics."""

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from conclear.jsonutil import atomic_write_json, canonical_json_bytes, load_json
from tests.network.test_release_lifecycle import RetainedCli


@pytest.mark.parametrize("status", [0, 1])
def test_retained_cli_tracks_runs_even_when_command_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    manifest = tmp_path / "resources.json"
    atomic_write_json(manifest, {"created": {}})
    command_result = {"data": {"runId": "owned-run"}}

    def run(arguments: list[str], **kwargs: Any) -> SimpleNamespace:
        assert arguments == ["/test/conclear", "release", "--format", "json"]
        assert kwargs["cwd"] == tmp_path
        assert kwargs["env"] == {"XDG_STATE_HOME": "/test/state"}
        assert kwargs["timeout"] == 3600
        kwargs["stdout"].write(canonical_json_bytes(command_result))
        kwargs["stderr"].write(b"protected diagnostic")
        return SimpleNamespace(returncode=status)

    monkeypatch.setattr(subprocess, "run", run)
    cli = RetainedCli(
        Path("/test/conclear"), tmp_path, manifest, {"XDG_STATE_HOME": "/test/state"}
    )
    if status:
        with pytest.raises(AssertionError, match="inspect"):
            cli.run("release")
    else:
        assert cli.run("release") == command_result
    assert load_json(manifest)["created"]["conclear_runs"] == ["owned-run"]
    for extension in ("stdout", "stderr"):
        assert (tmp_path / f"001-release.{extension}").stat().st_mode & 0o777 == 0o600


def test_retained_cli_accepts_the_unwrapped_version_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def run(_arguments: list[str], **kwargs: Any) -> SimpleNamespace:
        kwargs["stdout"].write(canonical_json_bytes({"sourceRevision": "a" * 40}))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    cli = RetainedCli(Path("/test/conclear"), tmp_path, tmp_path / "unused", {})
    assert cli.run("version")["sourceRevision"] == "a" * 40
