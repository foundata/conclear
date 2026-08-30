import json

import pytest
from click.testing import CliRunner

from conclear.cli import main, root


def test_root_help_succeeds() -> None:
    result = CliRunner().invoke(root, ["--help"])
    assert result.exit_code == 0
    assert "version" in result.stdout
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
