"""Static repository check service."""

from dataclasses import dataclass

from conclear.adapters.hadolint import HadolintAdapter
from conclear.checks import check_image_static
from conclear.config import ImageConfig
from conclear.presentation import Finding


@dataclass(frozen=True, slots=True)
class CheckOutcome:
    """Combined internal and Hadolint policy findings."""

    findings: tuple[Finding, ...]

    @property
    def accepted(self) -> bool:
        """Return whether no error finding was observed."""
        return not any(finding.severity == "error" for finding in self.findings)


def check_image(image: ImageConfig, hadolint: HadolintAdapter) -> CheckOutcome:
    """Run deterministic source checks and the supported Hadolint adapter."""
    findings = list(check_image_static(image))
    for item in hadolint.check(image.containerfile):
        severity = "warning" if item.level in {"warning", "info", "style"} else "error"
        findings.append(
            Finding(
                check_id="CC0114",
                severity=severity,
                message=f"Hadolint {item.code}: {item.message}",
                location=f"{image.containerfile}:{item.line}:{item.column}",
            )
        )
    return CheckOutcome(
        tuple(
            sorted(
                findings,
                key=lambda finding: (
                    finding.check_id,
                    finding.location or "",
                    finding.message,
                ),
            )
        )
    )
