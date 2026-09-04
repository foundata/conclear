from datetime import date

from conclear.config import VulnerabilityException
from conclear.scan_policy import evaluate_trivy_report


def exception(expires: str) -> VulnerabilityException:
    return VulnerabilityException(
        image="app",
        component="libssl",
        advisory="CVE-2026-0001",
        rationale="Not reachable",
        reachability="No call path",
        exposure="Local only",
        compensating_controls="Seccomp",
        owner="security@example.com",
        expires=expires,
        review_trigger="Package update",
    )


def report() -> object:
    return {
        "Results": [
            {
                "Target": "app",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "libssl",
                        "Severity": "CRITICAL",
                        "FixedVersion": "2.0",
                    }
                ],
                "Secrets": None,
                "Misconfigurations": [],
            }
        ]
    }


def test_scan_policy_applies_only_exact_unexpired_exception() -> None:
    evaluation = evaluate_trivy_report(
        report(),
        image_id="app",
        exceptions=(exception("2026-12-31"),),
        today=date(2026, 8, 31),
    )
    assert evaluation.accepted
    assert evaluation.applied_exceptions[0].advisory == "CVE-2026-0001"


def test_scan_policy_rejects_expired_exception() -> None:
    evaluation = evaluate_trivy_report(
        report(),
        image_id="app",
        exceptions=(exception("2026-01-01"),),
        today=date(2026, 8, 31),
    )
    assert not evaluation.accepted
    assert evaluation.findings[0].check_id == "CC0503"


def test_scan_policy_rejects_secrets_and_failed_misconfiguration() -> None:
    value = {
        "Results": [
            {
                "Target": "context",
                "Secrets": [{"RuleID": "private-key"}],
                "Misconfigurations": [{"ID": "CFG-1", "Status": "FAIL"}],
            }
        ]
    }
    evaluation = evaluate_trivy_report(
        value, image_id="app", exceptions=(), today=date(2026, 8, 31)
    )
    assert [finding.check_id for finding in evaluation.findings] == [
        "CC0501",
        "CC0501",
    ]


def test_scan_policy_ignores_only_the_inapplicable_healthcheck_check() -> None:
    value = {
        "Results": [
            {
                "Target": "Containerfile",
                "Misconfigurations": [
                    {"ID": "DS-0026", "Status": "FAIL"},
                    {"ID": "DS-0002", "Status": "FAIL"},
                    {"ID": "DS-0001", "Status": "PASS"},
                ],
            }
        ]
    }
    evaluation = evaluate_trivy_report(
        value, image_id="app", exceptions=(), today=date(2026, 8, 31)
    )
    assert [finding.message for finding in evaluation.findings] == [
        "Configuration finding DS-0002"
    ]
