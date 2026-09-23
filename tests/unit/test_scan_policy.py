from dataclasses import replace
from datetime import date

import pytest

from conclear.config import (
    ConfigurationException,
    PackageAssessmentException,
    VulnerabilityException,
)
from conclear.errors import OperationalError
from conclear.scan_policy import (
    evaluate_trivy_report,
    java_artifacts,
    path_pattern_matches,
)


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


def configuration_exception(
    expires: str, *, path: str, checks: tuple[str, ...] = ()
) -> ConfigurationException:
    return ConfigurationException(
        image="app",
        path=path,
        checks=checks,
        rationale="Template data shipped inside an installed package.",
        owner="security@example.com",
        review_trigger="ansible-core package update",
        expires=expires,
    )


def misconfiguration_report() -> object:
    return {
        "Results": [
            {
                "Target": "usr/lib/python3/dist-packages/ansible/galaxy/data/apb/Dockerfile.j2",
                "Misconfigurations": [
                    {"ID": "DS-0001", "Status": "FAIL"},
                    {"ID": "DS-0011", "Status": "FAIL"},
                ],
            },
            {
                "Target": "etc/app/Dockerfile",
                "Misconfigurations": [{"ID": "DS-0001", "Status": "FAIL"}],
                "Secrets": [{"RuleID": "aws-access-key-id"}],
            },
        ]
    }


def test_path_patterns_match_segments_and_directory_spans() -> None:
    assert path_pattern_matches("**/Dockerfile.j2", "usr/lib/x/Dockerfile.j2")
    assert path_pattern_matches("**/Dockerfile.j2", "Dockerfile.j2")
    assert path_pattern_matches(
        "usr/lib/*/data/**/Dockerfile.*", "usr/lib/py/data/a/b/Dockerfile.j2"
    )
    assert path_pattern_matches("/etc/app/Dockerfile", "etc/app/Dockerfile")
    assert not path_pattern_matches("usr/*/Dockerfile.j2", "usr/lib/x/Dockerfile.j2")
    assert not path_pattern_matches("etc/app/Dockerfile", "etc/app/Dockerfile.j2")
    assert not path_pattern_matches("etc/app/Dockerfil?", "etc/app/Dockerfile.j2")


def test_scan_policy_applies_configuration_exceptions_only_to_matching_paths() -> None:
    evaluation = evaluate_trivy_report(
        misconfiguration_report(),
        image_id="app",
        exceptions=(),
        today=date(2026, 6, 1),
        configuration_exceptions=(
            configuration_exception(
                "2026-12-31",
                path="usr/lib/python3/dist-packages/ansible/galaxy/data/**/Dockerfile.j2",
                checks=("DS-0001", "DS-0011"),
            ),
        ),
    )

    assert [(item.check_id, item.message) for item in evaluation.findings] == [
        ("CC0501", "Configuration finding DS-0001"),
        ("CC0501", "Secret finding aws-access-key-id"),
    ]
    assert [item.location for item in evaluation.findings] == ["etc/app/Dockerfile"] * 2
    assert [
        (item.target, item.check)
        for item in evaluation.applied_configuration_exceptions
    ] == [
        (
            "usr/lib/python3/dist-packages/ansible/galaxy/data/apb/Dockerfile.j2",
            "DS-0001",
        ),
        (
            "usr/lib/python3/dist-packages/ansible/galaxy/data/apb/Dockerfile.j2",
            "DS-0011",
        ),
    ]
    assert evaluation.applied_configuration_exceptions[0].to_dict()["checks"] == [
        "DS-0001",
        "DS-0011",
    ]


def test_scan_policy_limits_configuration_exceptions_to_named_checks() -> None:
    evaluation = evaluate_trivy_report(
        misconfiguration_report(),
        image_id="app",
        exceptions=(),
        today=date(2026, 6, 1),
        configuration_exceptions=(
            configuration_exception(
                "2026-12-31", path="**/Dockerfile.j2", checks=("DS-0011",)
            ),
        ),
    )

    assert sorted(
        (item.location, item.message)
        for item in evaluation.findings
        if item.check_id == "CC0501"
    ) == [
        ("etc/app/Dockerfile", "Configuration finding DS-0001"),
        ("etc/app/Dockerfile", "Secret finding aws-access-key-id"),
        (
            "usr/lib/python3/dist-packages/ansible/galaxy/data/apb/Dockerfile.j2",
            "Configuration finding DS-0001",
        ),
    ]
    assert [item.check for item in evaluation.applied_configuration_exceptions] == [
        "DS-0011"
    ]


def test_scan_policy_rejects_an_expired_configuration_exception() -> None:
    evaluation = evaluate_trivy_report(
        misconfiguration_report(),
        image_id="app",
        exceptions=(),
        today=date(2027, 1, 1),
        configuration_exceptions=(
            configuration_exception("2026-12-31", path="**/Dockerfile.j2"),
        ),
    )

    expired = [item for item in evaluation.findings if item.check_id == "CC0503"]
    assert [item.message for item in expired] == [
        "Configuration exception expired for DS-0001",
        "Configuration exception expired for DS-0011",
    ]
    assert evaluation.applied_configuration_exceptions == ()
    assert not evaluation.accepted


def test_scan_policy_ignores_configuration_exceptions_of_other_images() -> None:
    other = replace(
        configuration_exception("2026-12-31", path="**/Dockerfile.j2"), image="other"
    )
    evaluation = evaluate_trivy_report(
        misconfiguration_report(),
        image_id="app",
        exceptions=(),
        today=date(2026, 6, 1),
        configuration_exceptions=(other,),
    )

    assert len([item for item in evaluation.findings if item.check_id == "CC0501"]) == 4


def test_scan_policy_records_the_severity_source_and_vendor_ratings() -> None:
    rated: dict[str, object] = {
        "Results": [
            {
                "Target": "app",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0002",
                        "PkgName": "perl-base",
                        "Severity": "critical",
                        "SeveritySource": "debian",
                        "VendorSeverity": {"nvd": "HIGH", "debian": "CRITICAL"},
                        "FixedVersion": "5.40.1-1",
                    }
                ],
                "Secrets": None,
                "Misconfigurations": [],
            }
        ]
    }

    rejected = evaluate_trivy_report(
        rated, image_id="app", exceptions=(), today=date(2026, 8, 31)
    )
    [vulnerability] = rejected.fixable_vulnerabilities
    assert vulnerability.severity_source == "debian"
    assert vulnerability.vendor_severities == (("debian", "CRITICAL"), ("nvd", "HIGH"))
    assert rejected.findings[0].message == (
        "Fixable CRITICAL vulnerability CVE-2026-0002 in perl-base (severity by debian)"
    )

    excepted = evaluate_trivy_report(
        rated,
        image_id="app",
        exceptions=(
            VulnerabilityException(
                image="app",
                component="perl-base",
                advisory="CVE-2026-0002",
                rationale="Not reachable",
                reachability="No network path",
                exposure="None",
                compensating_controls="Seccomp",
                owner="security@example.com",
                expires="2026-12-31",
                review_trigger="Package update",
            ),
        ),
        today=date(2026, 8, 31),
    )
    assert excepted.applied_exceptions[0].to_dict() == {
        "image": "app",
        "component": "perl-base",
        "advisory": "CVE-2026-0002",
        "expires": "2026-12-31",
        "severity": "CRITICAL",
        "severitySource": "debian",
    }

    unsourced = evaluate_trivy_report(
        report(), image_id="app", exceptions=(), today=date(2026, 8, 31)
    )
    assert unsourced.fixable_vulnerabilities[0].severity_source is None
    assert "(severity by" not in unsourced.findings[0].message


def spdx(*packages: dict[str, object]) -> dict[str, object]:
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": list(packages),
    }


def package(identifier: str, *locators: str) -> dict[str, object]:
    return {
        "SPDXID": identifier,
        "name": identifier,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": locator,
            }
            for locator in locators
        ],
    }


def test_java_artifacts_counts_distinct_maven_package_urls() -> None:
    document = spdx(
        package("a", "pkg:maven/org.example/one@1.0.0"),
        package("b", "pkg:maven/org.example/two@2.0.0"),
        package("c", "pkg:maven/org.example/one@1.0.0"),
    )

    assert java_artifacts(document) == 2


def test_java_artifacts_ignores_other_ecosystems_and_reference_types() -> None:
    document = spdx(
        package("rpm", "pkg:rpm/fedora/bash@5.2"),
        package("npm", "pkg:npm/left-pad@1.3.0"),
        {
            "SPDXID": "advisory",
            "name": "advisory",
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "advisory",
                    "referenceLocator": "pkg:maven/org.example/decoy@1.0.0",
                }
            ],
        },
    )

    assert java_artifacts(document) == 0


def test_java_artifacts_tolerates_packages_without_external_references() -> None:
    document = spdx({"SPDXID": "plain", "name": "plain"})

    assert java_artifacts(document) == 0
    assert java_artifacts({"spdxVersion": "SPDX-2.3"}) == 0


def test_java_artifacts_rejects_a_document_that_is_not_an_object() -> None:
    with pytest.raises(OperationalError, match="SPDX document"):
        java_artifacts(["packages"])
