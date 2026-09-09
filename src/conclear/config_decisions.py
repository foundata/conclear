"""Explicit owner decisions shared by adoption and configuration diagnostics."""

from dataclasses import dataclass

from conclear.errors import InvalidInvocationError
from conclear.jsonutil import structure_depth_is_bounded

DECIDE = "DECIDE"
RESOURCE_DECISIONS = {
    "memory": "Measure peak memory under representative load and allow a justified margin.",
    "cpus": "Measure CPU demand and choose the CPU quota the application needs.",
    "pids": "Measure process and thread demand, including startup and shutdown.",
    "nofile": "Measure open-file demand under representative load.",
}


@dataclass(frozen=True, slots=True)
class ConfigurationDecision:
    """One unresolved input, including its exact location and owner-facing reason."""

    field: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        """Return a non-secret diagnostic value."""
        return {"field": self.field, "reason": self.reason}


def unresolved_decisions(value: object) -> tuple[ConfigurationDecision, ...]:
    """Find every reserved DECIDE placeholder without treating it as a value."""
    if not structure_depth_is_bounded(value):
        raise InvalidInvocationError("Invalid conclear.toml: nesting limit exceeded")
    decisions: list[ConfigurationDecision] = []

    def visit(item: object, path: tuple[str, ...]) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                visit(child, (*path, str(key)))
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, (*path, str(index)))
        elif isinstance(item, str) and (
            item.strip() == DECIDE or item.strip().startswith(DECIDE + ":")
        ):
            reason = item.strip().removeprefix(DECIDE).removeprefix(":").strip()
            decisions.append(
                ConfigurationDecision(
                    ".".join(path), reason or "Owner decision required."
                )
            )

    visit(value, ())
    return tuple(decisions)
