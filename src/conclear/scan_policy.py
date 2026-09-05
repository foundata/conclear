"""Workflow-level evaluation of untrusted scanner observations."""

from dataclasses import dataclass
from datetime import date

from conclear.config import VulnerabilityException
from conclear.errors import OperationalError
from conclear.parsing import array_value, object_value, string_value
from conclear.presentation import Finding


@dataclass(frozen=True, slots=True)
class AppliedException:
    """One exact unexpired exception matched to a scanner finding."""

    image: str
    component: str
    advisory: str
    expires: str

    def to_dict(self) -> dict[str, object]:
        """Return the evidence representation."""
        return {
            "image": self.image,
            "component": self.component,
            "advisory": self.advisory,
            "expires": self.expires,
        }


@dataclass(frozen=True, slots=True)
class FixableVulnerability:
    """One structured fixable HIGH or CRITICAL scanner observation."""

    component: str
    advisory: str
    severity: str
    fixed_version: str
    finding: Finding | None


@dataclass(frozen=True, slots=True)
class ScanEvaluation:
    """Policy findings and exact exceptions applied to one Trivy report."""

    findings: tuple[Finding, ...]
    applied_exceptions: tuple[AppliedException, ...]
    fixable_vulnerabilities: tuple[FixableVulnerability, ...]

    @property
    def accepted(self) -> bool:
        """Return whether no scanner policy finding rejects the image."""
        return not any(finding.severity == "error" for finding in self.findings)


# The guide forbids HEALTHCHECK in OCI-format images and CC0112 rejects it, so
# Trivy's "No HEALTHCHECK defined" Dockerfile check can never be satisfied.
_INAPPLICABLE_MISCONFIGURATIONS = frozenset({"DS-0026", "DS026", "AVD-DS-0026"})


def evaluate_trivy_report(
    value: object,
    *,
    image_id: str,
    exceptions: tuple[VulnerabilityException, ...],
    today: date,
) -> ScanEvaluation:
    """Reject secrets, failed misconfigurations and unexcepted fixable vulnerabilities."""
    report = object_value(value, label="Trivy report")
    results_value = report.get("Results", [])
    results = array_value(results_value, label="Trivy results")
    findings: list[Finding] = []
    applied: list[AppliedException] = []
    vulnerabilities: list[FixableVulnerability] = []
    for raw_result in results:
        result = object_value(raw_result, label="Trivy result")
        target = result.get("Target")
        location = target if isinstance(target, str) else None
        for raw_secret in _array_or_empty(result.get("Secrets"), label="Trivy secrets"):
            secret = object_value(raw_secret, label="Trivy secret")
            rule = string_value(secret.get("RuleID"), label="Trivy secret rule")
            findings.append(
                Finding("CC0501", "error", f"Secret finding {rule}", location)
            )
        for raw_misconfiguration in _array_or_empty(
            result.get("Misconfigurations"), label="Trivy misconfigurations"
        ):
            misconfiguration = object_value(
                raw_misconfiguration, label="Trivy misconfiguration"
            )
            status = string_value(
                misconfiguration.get("Status"), label="Trivy misconfiguration status"
            )
            if status.upper() != "FAIL":
                continue
            identifier = string_value(
                misconfiguration.get("ID"), label="Trivy misconfiguration ID"
            )
            if identifier in _INAPPLICABLE_MISCONFIGURATIONS:
                continue
            findings.append(
                Finding(
                    "CC0501",
                    "error",
                    f"Configuration finding {identifier}",
                    location,
                )
            )
        for raw_vulnerability in _array_or_empty(
            result.get("Vulnerabilities"), label="Trivy vulnerabilities"
        ):
            vulnerability = object_value(raw_vulnerability, label="Trivy vulnerability")
            severity = string_value(
                vulnerability.get("Severity"), label="Trivy vulnerability severity"
            ).upper()
            fixed = vulnerability.get("FixedVersion")
            if (
                severity not in {"HIGH", "CRITICAL"}
                or not isinstance(fixed, str)
                or not fixed
            ):
                continue
            advisory = string_value(
                vulnerability.get("VulnerabilityID"), label="Trivy advisory"
            )
            component = string_value(
                vulnerability.get("PkgName"), label="Trivy component"
            )
            matched, expired = _match_exception(
                image_id=image_id,
                component=component,
                advisory=advisory,
                exceptions=exceptions,
                today=today,
            )
            finding: Finding | None = None
            if matched is not None:
                applied.append(matched)
            elif expired:
                finding = Finding(
                    "CC0503",
                    "error",
                    f"Vulnerability exception expired for {advisory} in {component}",
                    location,
                )
                findings.append(finding)
            else:
                finding = Finding(
                    "CC0502",
                    "error",
                    f"Fixable {severity} vulnerability {advisory} in {component}",
                    location,
                )
                findings.append(finding)
            vulnerabilities.append(
                FixableVulnerability(
                    component=component,
                    advisory=advisory,
                    severity=severity,
                    fixed_version=fixed,
                    finding=finding,
                )
            )
    return ScanEvaluation(
        findings=tuple(
            sorted(
                findings,
                key=lambda item: (item.check_id, item.location or "", item.message),
            )
        ),
        applied_exceptions=tuple(
            sorted(applied, key=lambda item: (item.component, item.advisory))
        ),
        fixable_vulnerabilities=tuple(
            sorted(
                vulnerabilities,
                key=lambda item: (item.component, item.advisory, item.severity),
            )
        ),
    )


def _match_exception(
    *,
    image_id: str,
    component: str,
    advisory: str,
    exceptions: tuple[VulnerabilityException, ...],
    today: date,
) -> tuple[AppliedException | None, bool]:
    candidates = [
        item
        for item in exceptions
        if item.image == image_id
        and item.component == component
        and item.advisory == advisory
    ]
    if len(candidates) > 1:
        raise OperationalError(
            f"Multiple vulnerability exceptions match {component} {advisory}"
        )
    if not candidates:
        return None, False
    item = candidates[0]
    try:
        expiry = date.fromisoformat(item.expires)
    except ValueError as exc:
        raise OperationalError(
            f"Vulnerability exception has invalid expiry: {item.expires}"
        ) from exc
    if expiry < today:
        return None, True
    return (
        AppliedException(item.image, item.component, item.advisory, item.expires),
        False,
    )


def _array_or_empty(value: object, *, label: str) -> list[object]:
    if value is None:
        return []
    return array_value(value, label=label)
