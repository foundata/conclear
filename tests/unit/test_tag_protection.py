from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from conclear.adapters.quay import QuayAdapter
from conclear.errors import OperationalError, UnsupportedOperationError
from conclear.services import promotion
from conclear.values import OCIReference
from conclear.workspace import ResourceKind, RunState
from tests.unit.test_publication_resume import Scenario
from tests.unit.test_release_workflow import Harness

VERSION_POLICY: dict[str, object] = {
    "uuid": "versions",
    "tagPattern": r"v?[0-9]+\.[0-9]+\.[0-9]+",
    "tagPatternMatches": True,
}


def check_policies(
    repo: list[dict[str, object]],
    org: list[dict[str, object]],
    *,
    individually_protected: bool = False,
) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        if request.url.path.endswith("/tag/"):
            tags = (
                [
                    {
                        "name": request.url.params["specificTag"],
                        "manifest_digest": "sha256:" + "a" * 64,
                        "immutable": True,
                    }
                ]
                if individually_protected
                else []
            )
            return httpx.Response(200, json={"tags": tags})
        policies = org if "/organization/" in request.url.path else repo
        return httpx.Response(200, json={"policies": policies})

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        adapter = QuayAdapter(
            api_url="https://quay.io/api/v1",
            registry="quay.io",
            token_provider=lambda: "token",
            client=client,
        )
        adapter.verify_tag_policy(
            OCIReference.parse("quay.io/example/app"),
            version_tags=("1.2.3", "v1.2.3"),
            mutable_tags=("latest", "1.2.3-candidate.example"),
        )


@pytest.mark.parametrize("scope", ["repository", "organization"])
def test_accepts_selective_policy_in_either_scope(scope: str) -> None:
    check_policies(
        [VERSION_POLICY] if scope == "repository" else [],
        [VERSION_POLICY] if scope == "organization" else [],
    )


def test_accepts_inverse_policy_with_quay_fullmatch_semantics() -> None:
    check_policies(
        [
            {
                **VERSION_POLICY,
                "tagPattern": r"latest|.*-candidate\..*",
                "tagPatternMatches": False,
            }
        ],
        [],
    )


@pytest.mark.parametrize(
    "policy",
    [
        [],
        [{**VERSION_POLICY, "tagPattern": "1.2"}],
        [{**VERSION_POLICY, "tagPattern": ".*"}],
    ],
)
def test_rejects_missing_or_nonselective_policy(
    policy: list[dict[str, object]],
) -> None:
    with pytest.raises(OperationalError, match="selective tag immutability"):
        check_policies(policy, [])


def test_inherited_policy_cannot_freeze_candidates_or_latest() -> None:
    with pytest.raises(OperationalError, match="protected mutable tags"):
        check_policies([VERSION_POLICY], [{**VERSION_POLICY, "tagPattern": ".*"}])


def test_existing_individually_protected_moving_tag_is_rejected() -> None:
    with pytest.raises(OperationalError, match="individually protected"):
        check_policies([VERSION_POLICY], [], individually_protected=True)


@pytest.mark.parametrize("pattern", ["[", "x" * 257])
def test_rejects_unusable_policy_patterns(pattern: str) -> None:
    with pytest.raises(OperationalError):
        check_policies([{**VERSION_POLICY, "tagPattern": pattern}], [])


def test_matching_timeout_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*args: Any, **kwargs: Any) -> None:
        raise TimeoutError

    monkeypatch.setattr("conclear.adapters.quay.regex.fullmatch", timeout)
    with pytest.raises(OperationalError, match="Unable to verify"):
        check_policies([VERSION_POLICY], [])


@pytest.mark.parametrize("status", [401, 403, 404, 405])
def test_unavailable_policy_api_is_fatal(status: int) -> None:
    with httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(status))
    ) as client:
        adapter = QuayAdapter(
            api_url="https://quay.io/api/v1",
            registry="quay.io",
            token_provider=lambda: "token",
            client=client,
        )
        with pytest.raises(
            UnsupportedOperationError, match="unavailable or unauthorized"
        ):
            adapter.verify_tag_policy(
                OCIReference.parse("quay.io/example/app"),
                version_tags=("1.2.3",),
                mutable_tags=("latest",),
            )


def test_policy_failure_precedes_any_candidate_upload(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = Scenario(tmp_path, repository_factory)

    def unavailable(*args: Any, **kwargs: Any) -> None:
        raise UnsupportedOperationError("policy unavailable")

    monkeypatch.setattr(scenario.registry_control, "verify_tag_policy", unavailable)
    with pytest.raises(UnsupportedOperationError):
        scenario.publish()
    assert scenario.tags == {}
    assert scenario.workspace.journal.entries() == ()


def test_policy_is_rechecked_before_any_final_tag_write(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    original = promotion.promote_candidate

    def check_again(*args: Any, **kwargs: Any) -> Any:
        def unavailable(*args: Any, **kwargs: Any) -> None:
            raise UnsupportedOperationError("policy removed")

        monkeypatch.setattr(
            kwargs["registry_control"], "verify_tag_policy", unavailable
        )
        return original(*args, **kwargs)

    monkeypatch.setattr("conclear.services.release.promote_candidate", check_again)
    with pytest.raises(UnsupportedOperationError, match="policy removed"):
        harness.complete()
    assert "1.2.3" not in harness.runtime.registry.tags
    assert "latest" not in harness.runtime.registry.tags
    assert harness.workspace.load().state is RunState.INCOMPLETE


def test_retry_rejects_a_moving_tag_protected_after_the_policy_check(
    tmp_path: Path, repository_factory: Callable[..., Path]
) -> None:
    scenario = Scenario(tmp_path, repository_factory)
    digest = scenario.observation.graph.digest
    scenario.workspace.journal.plan(
        resource_id="tag-latest",
        kind=ResourceKind.TAG_WRITE,
        identifier=str(scenario.image.repository.with_tag("latest")),
        ephemeral=False,
        metadata={
            "digest": str(digest),
            "versionTag": False,
            "registryProtectionRequired": False,
        },
    )
    scenario.tags["latest"] = digest
    scenario.registry_control.immutable.add("latest")
    with pytest.raises(OperationalError, match=r"Moving tag.*immutable") as caught:
        promotion._write_release_tag(
            "latest",
            digest,
            scenario.image,
            scenario.workspace,
            scenario.registry_control,
            scenario.registry,
            None,
            immutable=False,
            require_protection=False,
            authorize_tag_write=lambda: None,
        )
    assert caught.value.code == "CC0604"
    assert "latest" in scenario.registry_control.immutable
