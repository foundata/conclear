"""Prospective version-1 public contract inventory and verification.

The inventory enumerates every compatibility surface that `DEVELOPMENT.md`
promises to change only deliberately: the Click command hierarchy with its
options and arguments, the bundled JSON Schemas, public record types and
their schema versions, exit statuses and the stable check identifiers. It is
rendered deterministically and committed as `docs/contract-v1.json`; the unit
suite fails when the implementation drifts from that committed file, so a
contract change is always an explicit, reviewable regeneration.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import click

from conclear.catalog import load_catalog
from conclear.cli import root
from conclear.errors import ExitStatus
from conclear.jsonutil import atomic_write_bytes
from conclear.pin_updates import PROPOSAL_RECORD_TYPE, PROPOSAL_SCHEMA_VERSION
from conclear.presentation import CommandResult, ResultStatus
from conclear.records import RECORD_SCHEMA_VERSIONS
from conclear.schema import load_schema

CONTRACT_VERSION = 1
CONTRACT_PATH = Path("docs/contract-v1.json")
SCHEMA_NAMES = (
    "config",
    "profile",
    "proposal",
    "provenance",
    "record",
    "result",
    "triage",
)
EXIT_STATUS_MEANINGS = {
    ExitStatus.SUCCESS: "Success.",
    ExitStatus.OPERATIONAL_FAILURE: (
        "Operational failure: a required fact could not be established."
    ),
    ExitStatus.RULE_REJECTION: (
        "Rule rejection: observed content violates the guide or the effective "
        "configuration."
    ),
    ExitStatus.INVALID_INVOCATION: "Invalid invocation or configuration.",
}


def render_contract() -> dict[str, object]:
    """Return the deterministic public contract inventory."""
    catalog = load_catalog()
    return {
        "contractVersion": CONTRACT_VERSION,
        "commands": _commands(root, ()),
        "schemas": [_schema(name) for name in SCHEMA_NAMES],
        "recordTypes": {
            **dict(sorted(RECORD_SCHEMA_VERSIONS.items())),
            PROPOSAL_RECORD_TYPE: PROPOSAL_SCHEMA_VERSION,
        },
        "commandResultSchemaVersion": CommandResult(
            "version", ResultStatus.SUCCESS, "contract"
        ).to_dict()["schemaVersion"],
        "exitStatuses": [
            {
                "name": status.name.lower().replace("_", "-"),
                "value": int(status),
                "meaning": EXIT_STATUS_MEANINGS[status],
            }
            for status in ExitStatus
        ],
        "resultStatuses": {
            status.value: int(CommandResult("version", status, "contract").exit_status)
            for status in ResultStatus
        },
        "checks": {
            "active": [
                {
                    "id": check.check_id,
                    "behavior": check.behavior,
                    "severity": check.severity,
                    "anchor": check.anchor,
                }
                for check in catalog.checks
            ],
            "retired": [check.check_id for check in catalog.retired],
        },
    }


def render_contract_text() -> str:
    """Return the reviewable JSON form committed to the repository."""
    return json.dumps(render_contract(), indent=2, sort_keys=True) + "\n"


def write_contract(path: Path) -> None:
    """Write the contract inventory atomically."""
    atomic_write_bytes(path, render_contract_text().encode("utf-8"), mode=0o644)


def _commands(command: click.Command, path: tuple[str, ...]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    if path:
        entries.append(
            {
                "name": " ".join(path),
                "group": isinstance(command, click.Group),
                "help": (command.help or "").strip().splitlines()[0]
                if command.help
                else "",
                "parameters": [_parameter(item) for item in command.params],
            }
        )
    if isinstance(command, click.Group):
        for name in sorted(command.commands):
            entries.extend(_commands(command.commands[name], (*path, name)))
    return entries


def _parameter(parameter: click.Parameter) -> dict[str, object]:
    value: dict[str, object] = {
        "name": parameter.name,
        "kind": "option" if isinstance(parameter, click.Option) else "argument",
        "declarations": list(parameter.opts),
        "required": bool(parameter.required),
        "multiple": bool(parameter.multiple),
        "type": parameter.type.name,
    }
    if isinstance(parameter.type, click.Choice):
        value["choices"] = list(parameter.type.choices)
    if isinstance(parameter, click.Option) and parameter.is_flag:
        value["flag"] = True
    default = parameter.default
    if isinstance(default, _PUBLIC_DEFAULT_TYPES):
        value["default"] = _jsonable(default)
    return value


_PUBLIC_DEFAULT_TYPES = (str, int, float, bool, Path, list, tuple)


def _jsonable(value: object) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [
            _jsonable(item) for item in value if isinstance(item, _PUBLIC_DEFAULT_TYPES)
        ]
    return value


def _schema(name: str) -> dict[str, object]:
    schema = load_schema(f"{name}.schema.json")
    properties = schema.get("properties")
    version: object = None
    if isinstance(properties, dict):
        declared = properties.get("schemaVersion")
        if isinstance(declared, dict):
            version = declared.get("const", declared.get("minimum"))
    return {
        "file": f"{name}.schema.json",
        "id": schema.get("$id"),
        "dialect": schema.get("$schema"),
        "title": schema.get("title"),
        "schemaVersion": version,
    }


def main() -> int:
    """Generate docs/contract-v1.json or verify that it is current."""
    parser = argparse.ArgumentParser(
        prog="python -m conclear.contract",
        description="Render or verify the prospective v1 public contract inventory.",
    )
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=CONTRACT_PATH)
    arguments = parser.parse_args()
    expected = render_contract_text()
    if arguments.check:
        try:
            observed = arguments.output.read_text(encoding="utf-8")
        except OSError:
            print(f"Contract inventory is missing: {arguments.output}", file=sys.stderr)
            return 1
        if observed != expected:
            print(
                "Contract inventory is stale; review the change and regenerate it "
                "with `uv run python -m conclear.contract`",
                file=sys.stderr,
            )
            return 1
        return 0
    write_contract(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
