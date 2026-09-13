from datetime import date

from conclear.config import PackageAssessmentException, VulnerabilityException
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


def image_report(*, os_family: str | None, package_result: bool) -> object:
    metadata = {} if os_family is None else {"OS": {"Family": os_family, "Name": "43"}}
    results: list[object] = [
        {
            "Target": "subject",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [],
        }
    ]
    if package_result:
        results.insert(
            0,
            {
                "Target": "subject (fedora 43)",
                "Class": "os-pkgs",
                "Type": os_family,
                "Packages": [{"Name": "bash"}, {"Name": "systemd"}],
                "Vulnerabilities": [],
            },
        )
    return {"ArtifactType": "container_image", "Metadata": metadata, "Results": results}


def assessment_exception(expires: str) -> PackageAssessmentException:
    return PackageAssessmentException(
        rationale="Trivy has no vulnerability data for Fedora.",
        owner="platform@example.com",
        review_trigger="Scanner coverage or base image changes.",
        expires=expires,
    )


def test_scan_policy_records_an_assessed_package_inventory() -> None:
    evaluation = evaluate_trivy_report(
        image_report(os_family="alma", package_result=True),
        image_id="app",
        exceptions=(),
        today=date(2026, 1, 1),
        expect_packages=True,
    )

    assert evaluation.findings == ()
    assert evaluation.package_assessment is not None
    assert evaluation.package_assessment.to_dict() == {
        "status": "assessed",
        "operatingSystem": "alma 43",
        "packages": 2,
        "reason": None,
        "exception": None,
    }


def test_scan_policy_rejects_an_inventory_the_scanner_did_not_assess() -> None:
    evaluation = evaluate_trivy_report(
        image_report(os_family="fedora", package_result=False),
        image_id="app",
        exceptions=(),
        today=date(2026, 1, 1),
        expect_packages=True,
    )

    assert [item.check_id for item in evaluation.findings] == ["CC0506"]
    assert "fedora 43" in evaluation.findings[0].message
    assert evaluation.package_assessment is not None
    assert evaluation.package_assessment.status == "unassessed"
    assert evaluation.package_assessment.exception is None
    assert not evaluation.accepted


def test_scan_policy_applies_an_unexpired_package_assessment_exception() -> None:
    exception = assessment_exception("2026-12-31")
    evaluation = evaluate_trivy_report(
        image_report(os_family="fedora", package_result=False),
        image_id="app",
        exceptions=(),
        today=date(2026, 1, 1),
        expect_packages=True,
        package_assessment_exception=exception,
    )

    assert evaluation.findings == ()
    assert evaluation.accepted
    assert evaluation.package_assessment is not None
    assert evaluation.package_assessment.status == "unassessed"
    assert evaluation.package_assessment.exception == exception
    assert evaluation.package_assessment.to_dict()["exception"] == exception.to_dict()


def test_scan_policy_rejects_an_expired_package_assessment_exception() -> None:
    evaluation = evaluate_trivy_report(
        image_report(os_family="fedora", package_result=False),
        image_id="app",
        exceptions=(),
        today=date(2026, 1, 1),
        expect_packages=True,
        package_assessment_exception=assessment_exception("2025-12-31"),
    )

    assert [item.check_id for item in evaluation.findings] == ["CC0506"]
    assert "expired on 2025-12-31" in evaluation.findings[0].message


def test_scan_policy_does_not_assess_reports_without_an_operating_system() -> None:
    evaluation = evaluate_trivy_report(
        image_report(os_family=None, package_result=False),
        image_id="app",
        exceptions=(),
        today=date(2026, 1, 1),
        expect_packages=True,
    )

    assert evaluation.findings == ()
    assert evaluation.package_assessment is not None
    assert evaluation.package_assessment.status == "assessed"
    assert evaluation.package_assessment.operating_system is None


def test_scan_policy_leaves_filesystem_reports_unassessed_by_default() -> None:
    evaluation = evaluate_trivy_report(
        image_report(os_family="fedora", package_result=False),
        image_id="app",
        exceptions=(),
        today=date(2026, 1, 1),
    )

    assert evaluation.findings == ()
    assert evaluation.package_assessment is None
