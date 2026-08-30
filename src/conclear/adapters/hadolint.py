"""Hadolint diagnostic adapter."""

from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.adapters.parsing import (
    array_value,
    integer_value,
    json_value,
    object_value,
    string_value,
)
from conclear.errors import CommandExecutionError


@dataclass(frozen=True, slots=True)
class HadolintFinding:
    """One normalized Hadolint observation."""

    code: str
    level: str
    message: str
    line: int
    column: int


class HadolintAdapter(ToolAdapter):
    """Run Hadolint and normalize its JSON diagnostics."""

    def check(self, containerfile: Path) -> tuple[HadolintFinding, ...]:
        """Return findings while preserving malformed output as an operation failure."""
        try:
            result = self._run(
                ("--format", "json", str(containerfile)), timeout_seconds=120
            )
            output = result.stdout
        except CommandExecutionError as exc:
            if not exc.stdout:
                raise
            output = exc.stdout
        values = array_value(json_value(output, label="Hadolint"), label="Hadolint")
        findings: list[HadolintFinding] = []
        for raw in values:
            item = object_value(raw, label="Hadolint finding")
            findings.append(
                HadolintFinding(
                    code=string_value(item.get("code"), label="Hadolint code"),
                    level=string_value(item.get("level"), label="Hadolint level"),
                    message=string_value(item.get("message"), label="Hadolint message"),
                    line=integer_value(item.get("line"), label="Hadolint line"),
                    column=integer_value(item.get("column"), label="Hadolint column"),
                )
            )
        return tuple(findings)
