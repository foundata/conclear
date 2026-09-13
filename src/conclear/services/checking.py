"""Static repository check service."""

from dataclasses import dataclass, replace
from pathlib import Path

from conclear.adapters.hadolint import HadolintAdapter
from conclear.checks import check_image_static
from conclear.config import ImageConfig
from conclear.presentation import Finding
from conclear.scan_identity import evidence_path

# The guide forbids requiring exact distribution package versions by default
# (IG0181) and leaves a justified constraint to review (IG0175), so Hadolint's
# distribution package pinning rules cannot apply. Language package managers
# (pip, npm, gem) are application dependencies and stay reported.
_DISTRIBUTION_PINNING_RULES = frozenset(
    {"DL3008", "DL3018", "DL3033", "DL3037", "DL3041"}
)


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
    for item in hadolint.check(image.containerfile, config_directory=image.context):
        if item.code in _DISTRIBUTION_PINNING_RULES:
            continue
        if (
            item.code == "DL3002"
            and image.runtime.user == 0
            and image.runtime.root_requirement is not None
        ):
            continue
        severity = "warning" if item.level in {"warning", "info", "style"} else "error"
        findings.append(
            Finding(
                check_id="CC0114",
                severity=severity,
                message=f"Hadolint {item.code}: {item.message}",
                location=f"{evidence_path(image.containerfile, image.context)}:{item.line}:{item.column}",
            )
        )
    findings = [_relative_location(finding, image.context) for finding in findings]
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


def _relative_location(finding: Finding, root: Path) -> Finding:
    """Report file locations relative to the build context, never as host paths."""
    if finding.location is None:
        return finding
    path, separator, suffix = finding.location.partition(":")
    if not path.startswith("/"):
        return finding
    return replace(
        finding, location=evidence_path(Path(path), root) + separator + suffix
    )
