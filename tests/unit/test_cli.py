import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import click
import pytest
from click.testing import CliRunner

import conclear.commands.local as local_commands
from conclear.cli import main, root
from conclear.errors import (
    ConClearError,
    OperationalError,
    RuleRejectionError,
    bind_failed_run,
    failed_run_id,
)
from conclear.presentation import CommandResult, Finding, ResultStatus

DOCUMENTED_COMMANDS = {
    "adopt",
    "assemble",
    "attest",
    "build",
    "check",
    "cleanup",
    "doctor",
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
    def check(self, path: Path, *, config_directory: Path) -> tuple[object, ...]:
        del path, config_directory
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


def test_rescan_help_exposes_external_triage_input() -> None:
    result = CliRunner().invoke(root, ["rescan", "--help"])
    assert result.exit_code == 0
    assert "--triage-file" in result.stdout


def test_qualify_help_exposes_distributed_database_digest() -> None:
    result = CliRunner().invoke(root, ["qualify", "--help"])
    assert result.exit_code == 0
    assert "--database-digest" in result.stdout


def test_root_version_reports_full_identity() -> None:
    result = CliRunner().invoke(root, ["--version"])
    assert result.exit_code == 0
    assert "ConClear 1.0.0" in result.stdout
    assert "cd95e231b73e023d91b47c91c58fc6acadf56f61" in result.stdout
    assert result.stderr == ""


def test_version_json_is_exactly_one_document() -> None:
    result = CliRunner().invoke(root, ["version", "--format", "json"])
    assert result.exit_code == 0
    value = json.loads(result.stdout)
    assert value["name"] == "conclear"
    assert value["guide"]["revision"] == "cd95e231b73e023d91b47c91c58fc6acadf56f61"
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
    path = root_path / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").split("[[images.pins]]")[0], encoding="utf-8"
    )
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


def test_main_preserves_operational_identifier_without_changing_exit_status(
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
            OperationalError("could not verify", code="CC0305")
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
        == 1
    )
    captured = capsys.readouterr()
    value = json.loads(captured.out)
    assert value["status"] == "operationalFailure"
    assert value["findings"] == [
        {"checkId": "CC0305", "severity": "error", "message": "could not verify"}
    ]
    assert "CC0305 error: could not verify" in captured.err


def test_main_redacts_unhandled_exception_and_writes_one_json_result(
    repository_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    root_path = repository_factory()
    monkeypatch.setattr(local_commands, "command_runtime", fake_runtime)
    monkeypatch.setattr(
        local_commands,
        "check_image",
        lambda image, hadolint: (_ for _ in ()).throw(
            ValueError("private path: /run/secrets/release-key")
        ),
    )

    caplog.set_level(logging.DEBUG, logger="conclear.cli")
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
    result = json.loads(captured.out)
    assert result["status"] == "operationalFailure"
    assert result["message"] == "ConClear encountered an internal error"
    assert captured.out.count("\n") == 1
    assert "ValueError" in captured.err
    assert "traceback:" in caplog.text
    assert "tests/unit/test_cli.py" in caplog.text
    assert "in <lambda>" in caplog.text
    assert "/run/secrets" not in captured.out + captured.err + caplog.text


def test_main_allows_unhandled_exception_to_retain_human_traceback(
    repository_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_path = repository_factory()
    monkeypatch.setattr(local_commands, "command_runtime", fake_runtime)
    monkeypatch.setattr(
        local_commands,
        "check_image",
        lambda image, hadolint: (_ for _ in ()).throw(ValueError("unexpected")),
    )

    with pytest.raises(ValueError, match="unexpected"):
        main(
            [
                "check",
                "--config",
                str(root_path / "conclear.toml"),
                "--image",
                "app",
            ]
        )


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


RUN_ID = "01m1t72srrb9dfv2rk96396tvs"


def test_bound_run_identity_is_read_from_the_failure_or_its_cause() -> None:
    error = OperationalError("failed")
    assert failed_run_id(error) is None
    bind_failed_run(error, RUN_ID)
    assert error.run_id == RUN_ID
    assert failed_run_id(error) == RUN_ID

    interrupt = KeyboardInterrupt()
    bind_failed_run(interrupt, RUN_ID)
    try:
        raise click.Abort() from interrupt
    except click.Abort as abort:
        assert failed_run_id(abort) == RUN_ID
    assert failed_run_id(ValueError("plain")) is None


def test_failure_results_carry_only_the_run_identity() -> None:
    CommandResult(
        "check", ResultStatus.OPERATIONAL_FAILURE, "failed", data={"runId": RUN_ID}
    ).to_dict()
    with pytest.raises(ConClearError):
        CommandResult(
            "check",
            ResultStatus.OPERATIONAL_FAILURE,
            "failed",
            data={"runId": RUN_ID, "layout": "/layout"},
        ).to_dict()


@pytest.mark.parametrize(
    ("failure", "exit_code", "status"),
    [
        (OperationalError("failed"), 1, "operationalFailure"),
        (RuleRejectionError("rejected", code="CC0306"), 2, "ruleRejection"),
        (click.UsageError("undeclared platform"), 64, "invalidInvocation"),
        (ValueError("internal"), 1, "operationalFailure"),
        (KeyboardInterrupt(), 1, "operationalFailure"),
    ],
)
def test_main_names_the_bound_run_in_every_failure_output(
    repository_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: BaseException,
    exit_code: int,
    status: str,
) -> None:
    root_path = repository_factory()
    monkeypatch.setattr(local_commands, "command_runtime", fake_runtime)

    def fail(image: Any, hadolint: Any) -> None:
        bind_failed_run(failure, RUN_ID)
        raise failure

    monkeypatch.setattr(local_commands, "check_image", fail)

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
        == exit_code
    )
    captured = capsys.readouterr()
    value = json.loads(captured.out)
    assert (value["status"], value["data"]) == (status, {"runId": RUN_ID})
    assert f"conclear cleanup {RUN_ID}" in captured.err


def test_main_renders_the_findings_behind_an_aggregate_rejection(
    repository_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root_path = repository_factory()
    monkeypatch.setattr(local_commands, "command_runtime", fake_runtime)
    nested = Finding("CC0403", "error", "Repository hook failed: smoke", "linux/arm64")
    monkeypatch.setattr(
        local_commands,
        "check_image",
        lambda image, hadolint: (_ for _ in ()).throw(
            RuleRejectionError(
                "Platform qualification rejected linux/arm64",
                code="CC0403",
                findings=(nested,),
            )
        ),
    )

    exit_status = main(
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

    assert exit_status == 2
    captured = capsys.readouterr()
    value = json.loads(captured.out)
    assert value["message"] == "Platform qualification rejected linux/arm64"
    assert value["findings"] == [nested.to_dict()]
    assert "Repository hook failed: smoke (linux/arm64)" in captured.err
