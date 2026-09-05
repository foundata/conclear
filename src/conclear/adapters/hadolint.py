"""Hadolint diagnostic adapter."""

import stat
from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.errors import CommandExecutionError, InvalidInvocationError
from conclear.parsing import (
    array_value,
    integer_value,
    json_value,
    object_value,
    string_value,
)

_CONFIG_NAMES = (".hadolint.yaml", ".hadolint.yml")


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

    def check(
        self, containerfile: Path, *, config_directory: Path
    ) -> tuple[HadolintFinding, ...]:
        """Return findings while preserving malformed output as an operation failure."""
        config = _committed_config(config_directory)
        arguments = () if config is None else ("--config", str(config))
        try:
            result = self._run(
                (*arguments, "--format", "json", str(containerfile)),
                timeout_seconds=120,
                cwd=config_directory,
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


def _committed_config(directory: Path) -> Path | None:
    """Return the reviewed Hadolint configuration in the image context, if any."""
    for name in _CONFIG_NAMES:
        candidate = directory / name
        try:
            file_stat = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise InvalidInvocationError(
                f"Unable to inspect Hadolint configuration: {candidate}"
            ) from exc
        if not stat.S_ISREG(file_stat.st_mode):
            raise InvalidInvocationError(
                f"Hadolint configuration must be a regular file: {candidate}"
            )
        return candidate
    return None
