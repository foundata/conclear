"""Workflow-level evaluation of untrusted scanner observations."""

import re
from dataclasses import dataclass
from datetime import date

from conclear.config import (
    ConfigurationException,
    PackageAssessmentException,
    RuntimeConfig,
    VulnerabilityException,
)
from conclear.errors import OperationalError
from conclear.parsing import array_value, object_value, string_value
from conclear.presentation import Finding


@dataclass(frozen=True, slots=True)
class AppliedException:
    """One exact unexpired exception matched to a scanner finding.

    The severity and its source are those of the finding the exception
    covered, so a review can see whether a vendor or NVD rating was excepted.
    """

    image: str
    component: str
    advisory: str
    expires: str
    severity: str | None = None
    severity_source: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the evidence representation."""
        return {
            "image": self.image,
            "component": self.component,
            "advisory": self.advisory,
            "expires": self.expires,
            "severity": self.severity,
            "severitySource": self.severity_source,
        }


@dataclass(frozen=True, slots=True)
class AppliedConfigurationException:
    """One unexpired configuration exception matched to a failed check on a path."""

    image: str
    path: str
    checks: tuple[str, ...]
    target: str
    check: str
    expires: str

    def to_dict(self) -> dict[str, object]:
        """Return the evidence representation."""
        return {
            "image": self.image,
            "path": self.path,
            "checks": list(self.checks),
            "target": self.target,
            "check": self.check,
            "expires": self.expires,
        }


def path_pattern_matches(pattern: str, target: str) -> bool:
    """Match an image path against a relative glob.

    `*` and `?` stay within one path segment, `**` spans any number of
    segments. Leading slashes are ignored on both sides because scanners and
    configurations spell image paths inconsistently.
    """
    return _pattern_regex(pattern).fullmatch(target.lstrip("/")) is not None


def _pattern_regex(pattern: str) -> re.Pattern[str]:
    parts: list[str] = []
    for segment in pattern.lstrip("/").split("/"):
        if segment == "**":
            parts.append("(?:[^/]+/)*")
            continue
        piece = "".join(
            "[^/]*" if char == "*" else "[^/]" if char == "?" else re.escape(char)
            for char in segment
        )
        parts.append(piece + "/")
    body = "".join(parts)
    body = body.removesuffix("/") if not pattern.endswith("/") else body
    return re.compile(body)


@dataclass(frozen=True, slots=True)
class FixableVulnerability:
    """One structured fixable HIGH or CRITICAL scanner observation.

    `severity` is the rating the scanner selected; `severity_source` names
    where it came from (a distribution vendor or NVD) and `vendor_severities`
    keeps every rating the scanner saw, because vendors and NVD often disagree.
    """

    component: str
    advisory: str
    severity: str
    fixed_version: str
    finding: Finding | None
    severity_source: str | None = None
    vendor_severities: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class PackageAssessment:
    """Whether the scanner assessed the operating-system packages it inventoried.

    A report that names an operating system but contains no package result
    proves only that the scanner has no vulnerability data for it. That is an
    unassessed inventory, never a clean one.
    """

    status: str
    operating_system: str | None
    packages: int
    reason: str | None = None
    exception: PackageAssessmentException | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the evidence representation."""
        return {
            "status": self.status,
            "operatingSystem": self.operating_system,
            "packages": self.packages,
            "reason": self.reason,
            "exception": None if self.exception is None else self.exception.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ScanEvaluation:
    """Policy findings and exact exceptions applied to one Trivy report."""

    findings: tuple[Finding, ...]
    applied_exceptions: tuple[AppliedException, ...]
    fixable_vulnerabilities: tuple[FixableVulnerability, ...]
    applied_runtime_requirements: tuple[dict[str, object], ...] = ()
    package_assessment: PackageAssessment | None = None
    applied_configuration_exceptions: tuple[AppliedConfigurationException, ...] = ()

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
    runtime: RuntimeConfig | None = None,
    expect_packages: bool = False,
    package_assessment_exception: PackageAssessmentException | None = None,
    configuration_exceptions: tuple[ConfigurationException, ...] = (),
) -> ScanEvaluation:
    """Reject secrets, failed misconfigurations and unexcepted fixable vulnerabilities.

    With ``expect_packages`` the report must also assess the operating-system
    packages it inventoried; an unassessed inventory rejects unless a reviewed,
    unexpired ``package_assessment_exception`` applies.
    """
    report = object_value(value, label="Trivy report")
    results_value = report.get("Results", [])
    results = array_value(results_value, label="Trivy results")
    findings: list[Finding] = []
    applied: list[AppliedException] = []
    applied_configuration: list[AppliedConfigurationException] = []
    vulnerabilities: list[FixableVulnerability] = []
    runtime_requirements: list[dict[str, object]] = []
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
            if (
                identifier in {"DS-0002", "DS002", "AVD-DS-0002"}
                and runtime is not None
                and runtime.user == 0
                and runtime.root_requirement is not None
            ):
                runtime_requirements.append(
                    {
                        "checkId": identifier,
                        "requirement": "root_requirement",
                        **runtime.root_requirement.to_dict(),
                    }
                )
                continue
            matched_exception, expired_exception = _match_configuration_exception(
                image_id=image_id,
                target=location,
                identifier=identifier,
                exceptions=configuration_exceptions,
                today=today,
            )
            if matched_exception is not None:
                applied_configuration.append(matched_exception)
                continue
            if expired_exception:
                findings.append(
                    Finding(
                        "CC0503",
                        "error",
                        f"Configuration exception expired for {identifier}",
                        location,
                    )
                )
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
            severity_source, vendor_severities = _severity_provenance(vulnerability)
            by_source = f" (severity by {severity_source})" if severity_source else ""
            matched, expired = _match_exception(
                image_id=image_id,
                component=component,
                advisory=advisory,
                exceptions=exceptions,
                today=today,
                severity=severity,
                severity_source=severity_source,
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
                    f"Fixable {severity} vulnerability {advisory} in {component}"
                    f"{by_source}",
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
                    severity_source=severity_source,
                    vendor_severities=vendor_severities,
                )
            )
    assessment = None
    if expect_packages:
        assessment = _assess_packages(
            report, results, package_assessment_exception, today=today
        )
        if assessment.status == "unassessed" and assessment.exception is None:
            findings.append(Finding("CC0506", "error", _unassessed_message(assessment)))
    return ScanEvaluation(
        package_assessment=assessment,
        applied_runtime_requirements=tuple(runtime_requirements),
        findings=tuple(
            sorted(
                findings,
                key=lambda item: (item.check_id, item.location or "", item.message),
            )
        ),
        applied_exceptions=tuple(
            sorted(applied, key=lambda item: (item.component, item.advisory))
        ),
        applied_configuration_exceptions=tuple(
            sorted(applied_configuration, key=lambda item: (item.target, item.check))
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
    severity: str | None = None,
    severity_source: str | None = None,
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
        AppliedException(
            item.image,
            item.component,
            item.advisory,
            item.expires,
            severity=severity,
            severity_source=severity_source,
        ),
        False,
    )


def _severity_provenance(
    vulnerability: dict[str, object],
) -> tuple[str | None, tuple[tuple[str, str], ...]]:
    """Return Trivy's selected severity source and every vendor rating it saw."""
    source_value = vulnerability.get("SeveritySource")
    source = source_value if isinstance(source_value, str) and source_value else None
    vendor_value = vulnerability.get("VendorSeverity")
    ratings: list[tuple[str, str]] = []
    if isinstance(vendor_value, dict):
        for name, rating in vendor_value.items():
            if isinstance(name, str) and name:
                ratings.append((name, str(rating).upper()))
    return source, tuple(sorted(ratings))


def _match_configuration_exception(
    *,
    image_id: str,
    target: str | None,
    identifier: str,
    exceptions: tuple[ConfigurationException, ...],
    today: date,
) -> tuple[AppliedConfigurationException | None, bool]:
    if target is None:
        return None, False
    candidates = [
        item
        for item in exceptions
        if item.image == image_id
        and path_pattern_matches(item.path, target)
        and (not item.checks or identifier in item.checks)
    ]
    if not candidates:
        return None, False
    # The most specific declaration decides: named checks before blanket paths.
    item = sorted(candidates, key=lambda entry: (not entry.checks, entry.path))[0]
    try:
        expiry = date.fromisoformat(item.expires)
    except ValueError as exc:
        raise OperationalError(
            f"Configuration exception has invalid expiry: {item.expires}"
        ) from exc
    if expiry < today:
        return None, True
    return (
        AppliedConfigurationException(
            image=item.image,
            path=item.path,
            checks=item.checks,
            target=target.lstrip("/"),
            check=identifier,
            expires=item.expires,
        ),
        False,
    )


JAVA_PURL_PREFIX = "pkg:maven/"
"""Package URL prefix Trivy gives jar, pom, Gradle and sbt artifacts alike."""


def java_artifacts(document: object) -> int:
    """Count the distinct Maven package URLs one SPDX document inventories.

    Their presence is what makes Trivy's Java database relevant: the index
    identifies jar artifacts that carry no embedded Maven coordinates, so an
    image without any Java artifact is assessed no differently by a stale one.
    """
    spdx = object_value(document, label="SPDX document")
    locators: set[str] = set()
    for raw_package in _array_or_empty(spdx.get("packages"), label="SPDX packages"):
        package = object_value(raw_package, label="SPDX package")
        for raw_reference in _array_or_empty(
            package.get("externalRefs"), label="SPDX external references"
        ):
            reference = object_value(raw_reference, label="SPDX external reference")
            if reference.get("referenceType") != "purl":
                continue
            locator = reference.get("referenceLocator")
            if isinstance(locator, str) and locator.startswith(JAVA_PURL_PREFIX):
                locators.add(locator)
    return len(locators)


def _array_or_empty(value: object, *, label: str) -> list[object]:
    if value is None:
        return []
    return array_value(value, label=label)


def _assess_packages(
    report: dict[str, object],
    results: list[object],
    exception: PackageAssessmentException | None,
    *,
    today: date,
) -> PackageAssessment:
    metadata = report.get("Metadata")
    operating_system: str | None = None
    if isinstance(metadata, dict) and isinstance(metadata.get("OS"), dict):
        family = metadata["OS"].get("Family")
        name = metadata["OS"].get("Name")
        if isinstance(family, str) and family:
            operating_system = (
                family if not isinstance(name, str) else f"{family} {name}".strip()
            )
    package_results = [
        result
        for result in results
        if isinstance(result, dict) and result.get("Class") == "os-pkgs"
    ]
    packages = sum(
        len(packages_value)
        for result in package_results
        if isinstance(packages_value := result.get("Packages"), list)
    )
    if operating_system is None or package_results:
        return PackageAssessment("assessed", operating_system, packages)
    reason = (
        f"the scanner inventoried {operating_system} but produced no package "
        "vulnerability result for it"
    )
    if exception is None:
        return PackageAssessment("unassessed", operating_system, 0, reason)
    try:
        expiry = date.fromisoformat(exception.expires)
    except ValueError as exc:
        raise OperationalError(
            f"Package assessment exception has invalid expiry: {exception.expires}"
        ) from exc
    if expiry < today:
        return PackageAssessment(
            "unassessed",
            operating_system,
            0,
            f"{reason}; the package assessment exception expired on {exception.expires}",
        )
    return PackageAssessment("unassessed", operating_system, 0, reason, exception)


def _unassessed_message(assessment: PackageAssessment) -> str:
    return (
        f"Package vulnerability assessment not established: {assessment.reason}. "
        "Declare a reviewed [images.package_assessment_exception] or change the base image"
    )
