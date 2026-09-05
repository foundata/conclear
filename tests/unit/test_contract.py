"""The committed prospective-v1 contract inventory must match the implementation."""

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from conclear.catalog import load_catalog
from conclear.cli import root
from conclear.contract import (
    CONTRACT_PATH,
    SCHEMA_NAMES,
    main,
    render_contract,
    render_contract_text,
    write_contract,
)
from conclear.errors import ExitStatus
from conclear.presentation import ResultStatus

REPOSITORY = Path(__file__).parents[2]


def committed() -> dict[str, Any]:
    text = (REPOSITORY / CONTRACT_PATH).read_text(encoding="utf-8")
    value: dict[str, Any] = json.loads(text)
    return value


def test_committed_contract_inventory_matches_the_implementation() -> None:
    assert (REPOSITORY / CONTRACT_PATH).read_text(encoding="utf-8") == (
        render_contract_text()
    ), (
        "public contract changed; review the diff and regenerate docs/contract-v1.json "
        "with `uv run python -m conclear.contract`"
    )


def test_contract_covers_every_command_option_and_argument() -> None:
    inventory = {entry["name"]: entry for entry in committed()["commands"]}
    runner = CliRunner()

    def walk(command: Any, path: tuple[str, ...]) -> None:
        if path:
            name = " ".join(path)
            assert name in inventory, name
            entry = inventory[name]
            declared = {
                (item["name"], tuple(item["declarations"]), item["required"])
                for item in entry["parameters"]
            }
            actual = {
                (parameter.name, tuple(parameter.opts), bool(parameter.required))
                for parameter in command.params
            }
            assert declared == actual, name
            help_result = runner.invoke(root, [*path, "--help"])
            assert help_result.exit_code == 0, name
            assert help_result.stderr == ""
        if hasattr(command, "commands"):
            for child_name, child in command.commands.items():
                walk(child, (*path, child_name))

    walk(root, ())
    assert {entry["name"] for entry in committed()["commands"]} == set(inventory)
    assert {"release", "pins check", "pins propose", "pins apply", "rescan"} <= set(
        inventory
    )


def test_contract_records_exit_statuses_schemas_and_identifiers() -> None:
    value = committed()

    assert {item["value"] for item in value["exitStatuses"]} == {
        int(status) for status in ExitStatus
    }
    assert value["resultStatuses"] == {
        ResultStatus.SUCCESS.value: 0,
        ResultStatus.OPERATIONAL_FAILURE.value: 1,
        ResultStatus.RULE_REJECTION.value: 2,
        ResultStatus.INVALID_INVOCATION.value: 64,
    }
    schemas = {item["file"]: item for item in value["schemas"]}
    assert set(schemas) == {f"{name}.schema.json" for name in SCHEMA_NAMES}
    identifiers = [item["id"] for item in value["schemas"]]
    assert len(identifiers) == len(set(identifiers))
    assert all(
        item["dialect"] == "https://json-schema.org/draft/2020-12/schema"
        for item in value["schemas"]
    )
    assert value["recordTypes"] == {
        "platformQualification": 1,
        "qualificationTransport": 1,
        "releaseCandidate": 1,
        "releaseVerification": 1,
        "rescanResult": 1,
        "pinUpdateProposal": 1,
    }
    assert value["commandResultSchemaVersion"] == 1

    catalog = load_catalog()
    active = {item["id"] for item in value["checks"]["active"]}
    retired = set(value["checks"]["retired"])
    assert active == {check.check_id for check in catalog.checks}
    assert retired == {check.check_id for check in catalog.retired}
    assert not active & retired


def test_contract_detects_removed_or_renamed_surfaces() -> None:
    current = render_contract()
    mutated = json.loads(json.dumps(current))
    mutated["commands"] = [
        entry for entry in mutated["commands"] if entry["name"] != "pins apply"
    ]
    assert mutated != current

    renamed = json.loads(json.dumps(current))
    renamed["commands"][0]["parameters"][0]["declarations"] = ["--renamed"]
    assert renamed != current

    reused = json.loads(json.dumps(current))
    reused["checks"]["retired"].append(reused["checks"]["active"][0]["id"])
    assert reused != current


def test_contract_entry_point_verifies_and_regenerates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "contract.json"
    monkeypatch.setattr(sys, "argv", ["contract", "--check", "--output", str(output)])
    assert main() == 1
    assert "missing" in capsys.readouterr().err

    monkeypatch.setattr(sys, "argv", ["contract", "--output", str(output)])
    assert main() == 0
    assert output.read_text(encoding="utf-8") == render_contract_text()

    monkeypatch.setattr(sys, "argv", ["contract", "--check", "--output", str(output)])
    assert main() == 0

    output.write_text("{}\n", encoding="utf-8")
    assert main() == 1
    assert "stale" in capsys.readouterr().err

    write_contract(output)
    assert main() == 0
