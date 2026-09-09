"""Doctor uses real provider parsers but never provider write operations."""

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from conclear.adapters.quay import QuayAdapter
from conclear.config import ReleaseImageConfig, load_repository_config
from conclear.registry_policy import CandidateCleanupMode, TagProtectionMode
from conclear.services.registry_diagnostics import (
    DiagnosticStatus,
    RegistryCheck,
    diagnose_registry,
)
from conclear.values import CANDIDATE_TAG_PATTERN
from tests.registry_policy_fixtures import STRICT_POLICY

TAG_POLICY = {"tagPattern": r"[0-9]+\.[0-9]+\.[0-9]+", "tagPatternMatches": True}
RETENTION = {
    "uuid": "candidate-policy",
    "method": "creation_date",
    "value": "1d",
    "tagPattern": CANDIDATE_TAG_PATTERN,
    "tagPatternMatches": True,
}


@pytest.fixture
def image(repository_factory: Callable[..., Path]) -> ReleaseImageConfig:
    return load_repository_config(repository_factory() / "conclear.toml").release_image(
        "app"
    )


def _diagnose(
    image: ReleaseImageConfig,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    protection: TagProtectionMode = TagProtectionMode.REQUIRED,
    cleanup: CandidateCleanupMode = CandidateCleanupMode.AUTO_PRUNE,
    version: str | None = "1.2.3",
) -> dict[str, RegistryCheck]:
    policy = replace(
        STRICT_POLICY,
        tag_protection=replace(
            STRICT_POLICY.tag_protection,
            mode=protection,
            rationale="Provider lacks selective protection."
            if protection is TagProtectionMode.NOT_ENFORCED
            else None,
            owner="test operator"
            if protection is TagProtectionMode.NOT_ENFORCED
            else None,
        ),
        candidate_cleanup=replace(STRICT_POLICY.candidate_cleanup, mode=cleanup),
    )

    def read_only(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET", "doctor must never write"
        return handler(request)

    with httpx.Client(transport=httpx.MockTransport(read_only)) as client:
        control = QuayAdapter(
            api_url="https://quay.io/api/v1",
            registry="quay.io",
            token_provider=lambda: "private-token",
            client=client,
        )
        return {
            check.name: check
            for check in diagnose_registry(image, policy, control, version=version)
        }


def _healthy(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/tag/"):
        return httpx.Response(200, json={"tags": []})
    policies = (
        [RETENTION] if request.url.path.endswith("/autoprunepolicy/") else [TAG_POLICY]
    )
    return httpx.Response(200, json={"policies": policies})


@pytest.mark.parametrize("protection", list(TagProtectionMode))
@pytest.mark.parametrize("cleanup", list(CandidateCleanupMode))
def test_only_selected_policy_apis_are_read(
    image: ReleaseImageConfig,
    protection: TagProtectionMode,
    cleanup: CandidateCleanupMode,
) -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/immutabilitypolicy/"):
            assert protection is TagProtectionMode.REQUIRED
        if request.url.path.endswith("/autoprunepolicy/"):
            assert cleanup is CandidateCleanupMode.AUTO_PRUNE
        return _healthy(request)

    checks = _diagnose(image, handler, protection=protection, cleanup=cleanup)

    assert len(checks) == 6
    assert all(check.status is not DiagnosticStatus.FAILED for check in checks.values())
    assert checks["tagPolicy"].status is (
        DiagnosticStatus.CHECKED
        if protection is TagProtectionMode.REQUIRED
        else DiagnosticStatus.NOT_CHECKED
    )
    if protection is TagProtectionMode.REQUIRED:
        assert "/api/v1/organization/example/immutabilitypolicy/" in paths
    assert checks["candidateRetention"].status is (
        DiagnosticStatus.CHECKED
        if cleanup is CandidateCleanupMode.AUTO_PRUNE
        else DiagnosticStatus.NOT_CHECKED
    )
    for name in ("tagExpiration", "registryWrites", "policyEnforcement"):
        assert checks[name].status is DiagnosticStatus.NOT_CHECKED


@pytest.mark.parametrize(
    "policies", [[], [{**RETENTION, "value": "999d"}], [RETENTION]]
)
def test_retention_distinguishes_creation_from_existing_coverage(
    image: ReleaseImageConfig, policies: list[dict[str, object]]
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/autoprunepolicy/"):
            return httpx.Response(200, json={"policies": policies})
        return _healthy(request)

    result = _diagnose(image, handler)["candidateRetention"]
    assert result.status is DiagnosticStatus.CHECKED
    assert result.to_dict()["policyCreationRequired"] is (policies != [RETENTION])


@pytest.mark.parametrize("version", [None, "1.2.3"])
@pytest.mark.parametrize("endpoint", ["immutabilitypolicy", "autoprunepolicy"])
@pytest.mark.parametrize(
    "failure", [401, 403, 404, 405, 500, "json", "shape", "timeout"]
)
def test_selected_api_failures_are_reported_without_hiding_other_checks(
    image: ReleaseImageConfig, endpoint: str, failure: int | str, version: str | None
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if not request.url.path.endswith(f"/{endpoint}/"):
            return _healthy(request)
        if isinstance(failure, int):
            return httpx.Response(failure, text="private-token")
        if failure == "timeout":
            raise httpx.ReadTimeout("private-token", request=request)
        if failure == "json":
            return httpx.Response(200, text="private-token")
        return httpx.Response(200, json={"policies": "private-token"})

    checks = _diagnose(image, handler, version=version)
    failed_name = (
        "tagPolicy" if endpoint == "immutabilitypolicy" else "candidateRetention"
    )
    assert checks[failed_name].status is DiagnosticStatus.FAILED
    assert checks[failed_name].code == (
        "CC0604" if failed_name == "tagPolicy" else "CC0603"
    )
    assert checks["tagRead"].status is DiagnosticStatus.CHECKED
    assert len(checks) == 6
    assert "private-token" not in str([check.to_dict() for check in checks.values()])


def test_missing_version_is_incomplete_even_when_policies_are_readable(
    image: ReleaseImageConfig,
) -> None:
    check = _diagnose(image, _healthy, version=None)["tagPolicy"]
    assert check.status is DiagnosticStatus.NOT_CHECKED
    assert "--version" in check.message


def test_literal_version_tags_do_not_need_a_version_argument(
    image: ReleaseImageConfig,
) -> None:
    image = replace(image, release=replace(image.release, version_tags=("1.2.3",)))
    assert (
        _diagnose(image, _healthy, version=None)["tagPolicy"].status
        is DiagnosticStatus.CHECKED
    )


def test_tag_read_failure_does_not_hide_retention_observation(
    image: ReleaseImageConfig,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/tag/"):
            return httpx.Response(403)
        return _healthy(request)

    checks = _diagnose(image, handler)
    assert checks["tagRead"].status is DiagnosticStatus.FAILED
    assert checks["candidateRetention"].status is DiagnosticStatus.CHECKED


@pytest.mark.parametrize("pattern", [".*", "unrelated", "["])
def test_invalid_or_nonselective_protection_fails(
    image: ReleaseImageConfig, pattern: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/immutabilitypolicy/"):
            return httpx.Response(
                200, json={"policies": [{**TAG_POLICY, "tagPattern": pattern}]}
            )
        return _healthy(request)

    assert _diagnose(image, handler)["tagPolicy"].status is DiagnosticStatus.FAILED


def test_inherited_policy_can_supply_version_coverage(
    image: ReleaseImageConfig,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/repository/example/app/immutabilitypolicy/":
            return httpx.Response(200, json={"policies": []})
        return _healthy(request)

    assert _diagnose(image, handler)["tagPolicy"].status is DiagnosticStatus.CHECKED


def test_malformed_retention_age_fails(image: ReleaseImageConfig) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/autoprunepolicy/"):
            return httpx.Response(
                200, json={"policies": [{**RETENTION, "value": "bad"}]}
            )
        return _healthy(request)

    assert (
        _diagnose(image, handler)["candidateRetention"].status
        is DiagnosticStatus.FAILED
    )
