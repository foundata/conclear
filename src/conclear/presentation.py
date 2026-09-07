"""Human and JSON rendering for shared command results."""

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TextIO

from conclear.errors import ExitStatus
from conclear.schema import validate_external


class ResultStatus(StrEnum):
    """Stable JSON status names."""

    SUCCESS = "success"
    RULE_REJECTION = "ruleRejection"
    OPERATIONAL_FAILURE = "operationalFailure"
    INVALID_INVOCATION = "invalidInvocation"


@dataclass(frozen=True, slots=True)
class Finding:
    """One stable policy or diagnostic finding."""

    check_id: str
    severity: str
    message: str
    location: str | None = None
    image: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the public finding object."""
        value: dict[str, object] = {
            "checkId": self.check_id,
            "severity": self.severity,
            "message": self.message,
        }
        if self.location is not None:
            value["location"] = self.location
        if self.image is not None:
            value["image"] = self.image
        return value


@dataclass(frozen=True, slots=True)
class CommandResult:
    """One command result used by both presenters."""

    command: str
    status: ResultStatus
    message: str
    findings: tuple[Finding, ...] = ()
    data: dict[str, object] = field(default_factory=dict)
    details: tuple[str, ...] = ()

    @property
    def exit_status(self) -> ExitStatus:
        """Map the stable result status to its public exit status."""
        return {
            ResultStatus.SUCCESS: ExitStatus.SUCCESS,
            ResultStatus.RULE_REJECTION: ExitStatus.RULE_REJECTION,
            ResultStatus.OPERATIONAL_FAILURE: ExitStatus.OPERATIONAL_FAILURE,
            ResultStatus.INVALID_INVOCATION: ExitStatus.INVALID_INVOCATION,
        }[self.status]

    def to_dict(self) -> dict[str, object]:
        """Return and validate the public result object."""
        value: dict[str, object] = {
            "schemaVersion": 1,
            "command": self.command,
            "status": self.status.value,
            "message": self.message,
            "findings": [finding.to_dict() for finding in self.findings],
            "data": self.data,
        }
        validate_external(value, "result.schema.json", label="command result")
        return value


def present_json(result: CommandResult, stream: TextIO) -> None:
    """Write exactly one unstyled JSON object."""
    json.dump(result.to_dict(), stream, ensure_ascii=True, sort_keys=True)
    stream.write("\n")


def present_human(result: CommandResult, stream: TextIO) -> None:
    """Write concise human-readable output.

    Detail lines carry human context whose structured form already lives in
    `data`; they never appear in JSON mode.
    """
    stream.write(f"{result.message}\n")
    for detail in result.details:
        stream.write(f"  {detail}\n")
    for finding in result.findings:
        location = f" ({finding.location})" if finding.location else ""
        image = f" [{finding.image}]" if finding.image else ""
        stream.write(
            f"{finding.check_id} {finding.severity}: "
            f"{finding.message}{location}{image}\n"
        )
