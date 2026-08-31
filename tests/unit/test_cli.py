import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

import conclear.commands.local as local_commands
from conclear.cli import main, root
from conclear.errors import OperationalError, RuleRejectionError

DOCUMENTED_COMMANDS = {
    "assemble",
    "attest",
    "build",
    "check",
    "cleanup",
    "doctor",
    "evidence",
    "pins",
    "promote",
    "provenance",
    "publish",
    "qualify",
    "release",
    "rescan",
    "test",
    "verify",
    "version",
}


class FakeHadolint:
    def check(self, path: Path) -> tuple[object, ...]:
        del path
        return ()


class FakeRuntime:
    def hadolint(self) -> FakeHadolint:
        return FakeHadolint()


@contextmanager
def fake_runtime(names: object) -> Iterator[FakeRuntime]:
    del names
    yield FakeRuntime()


def test_root_help_succeeds() -> None:
    result = CliRunner().invoke(root, ["--help"])
    assert result.exit_code == 0
    assert "version" in result.stdout
    assert result.stderr == ""
    assert DOCUMENTED_COMMANDS <= set(root.commands)


@pytest.mark.parametrize("command", sorted(DOCUMENTED_COMMANDS))
def test_every_documented_command_has_help(command: str) -> None:
    result = CliRunner().invoke(root, [command, "--help"])
    assert result.exit_code == 0
    assert result.stderr == ""


def test_root_version_reports_full_identity() -> None:
    result = CliRunner().invoke(root, ["--version"])
    assert result.exit_code == 0
    assert "ConClear 0.1.0" in result.stdout
    assert "909794089dbabbf6c8d8e50fcf47bb2b6fd315b9" in result.stdout
    assert result.stderr == ""


def test_version_json_is_exactly_one_document() -> None:
    result = CliRunner().invoke(root, ["version", "--format", "json"])
    assert result.exit_code == 0
    value = json.loads(result.stdout)
    assert value["name"] == "conclear"
    assert value["guide"]["revision"] == "909794089dbabbf6c8d8e50fcf47bb2b6fd315b9"
    assert result.stdout.count("\n") == 1
    assert result.stderr == ""


def test_main_maps_malformed_option_to_usage_status(
    capsys: pytest.CaptureFixture[str],
) -> None:
    del capsys
    assert main(["version", "--bad-option"]) == 64


def test_main_keeps_json_usage_result_on_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["version", "--format", "json", "--bad-option"]) == 64
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "invalidInvocation"
    assert "Error" in captured.err


def test_check_json_rule_rejection_uses_exit_two(
    repository_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_path = repository_factory(containerfile="from scratch\nUSER 0\n")
    monkeypatch.setattr(local_commands, "command_runtime", fake_runtime)
    result = CliRunner().invoke(
        root,
        [
            "check",
            "--config",
            str(root_path / "conclear.toml"),
            "--image",
            "app",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout)["status"] == "ruleRejection"
    assert result.stdout.count("\n") == 1
    assert result.stderr == ""


def test_main_maps_operational_failure_to_one(
    repository_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root_path = repository_factory()
    monkeypatch.setattr(local_commands, "command_runtime", fake_runtime)
    monkeypatch.setattr(
        local_commands,
        "check_image",
        lambda image, hadolint: (_ for _ in ()).throw(OperationalError("failed")),
    )

    assert (
        main(
            [
                "check",
                "--config",
                str(root_path / "conclear.toml"),
                "--image",
                "app",
                "--format",
                "json",
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "operationalFailure"
    assert "failed" in captured.err


def test_main_preserves_rule_identifier_in_human_and_json_output(
    repository_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root_path = repository_factory()
    monkeypatch.setattr(local_commands, "command_runtime", fake_runtime)
    monkeypatch.setattr(
        local_commands,
        "check_image",
        lambda image, hadolint: (_ for _ in ()).throw(
            RuleRejectionError("rejected", code="CC0107")
        ),
    )

    assert (
        main(
            [
                "check",
                "--config",
                str(root_path / "conclear.toml"),
                "--image",
                "app",
                "--format",
                "json",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    value = json.loads(captured.out)
    assert value["status"] == "ruleRejection"
    assert value["findings"] == [
        {"checkId": "CC0107", "severity": "error", "message": "rejected"}
    ]
    assert "CC0107 error: rejected" in captured.err
