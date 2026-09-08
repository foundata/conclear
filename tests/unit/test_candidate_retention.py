import json
import re
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from conclear.adapters.quay import QuayAdapter
from conclear.errors import OperationalError, UnsupportedOperationError
from conclear.registry_control import CandidateRetentionObservation
from conclear.values import CANDIDATE_TAG_PATTERN, OCIReference, candidate_tag
from conclear.workspace import ResourceStatus
from tests.unit.test_publication_resume import Scenario

REPOSITORY = OCIReference.parse("quay.io/example/app")
AGE = timedelta(days=7)
POLICY: dict[str, object] = {
    "uuid": "candidate-policy",
    "method": "creation_date",
    "value": "7d",
    "tagPattern": CANDIDATE_TAG_PATTERN,
    "tagPatternMatches": True,
}


@pytest.fixture
def scenario(tmp_path: Path, repository_factory: Callable[..., Path]) -> Scenario:
    return Scenario(tmp_path, repository_factory)


class RetentionAPI:
    def __init__(
        self, policies: list[dict[str, object]], *, write: str = "success"
    ) -> None:
        self.policies = policies
        self.write = write
        self.methods: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/repository/example/app/autoprunepolicy/"
        self.methods.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, json={"policies": self.policies})
        assert request.method == "POST"
        body = json.loads(request.content)
        assert body == {
            key: value for key, value in POLICY.items() if key != "uuid"
        } | {"value": "604800s"}
        if self.write not in {"ignored", "timeout-missing"}:
            self.policies.append({**body, "uuid": "created-policy"})
        if self.write.startswith("timeout"):
            raise httpx.ReadTimeout("lost acknowledgement", request=request)
        return httpx.Response(
            400 if self.write == "duplicate" else 201, json={"uuid": "created-policy"}
        )


@pytest.mark.parametrize("write", ["success", "timeout-applied", "duplicate"])
def test_quay_observes_retention_after_creation_without_retrying_writes(
    write: str,
) -> None:
    unrelated = {**POLICY, "tagPattern": "^release", "uuid": "unrelated"}
    api = RetentionAPI([unrelated], write=write)
    with httpx.Client(transport=httpx.MockTransport(api)) as client:
        adapter = QuayAdapter(
            api_url="https://quay.io/api/v1",
            registry="quay.io",
            token_provider=lambda: "token",
            client=client,
        )
        observed = adapter.ensure_candidate_retention(REPOSITORY, AGE)
    assert observed == CandidateRetentionObservation(
        REPOSITORY, "created-policy", CANDIDATE_TAG_PATTERN, AGE
    )
    assert api.methods == ["GET", "POST", "GET"]
    assert api.policies[0] == unrelated


def test_quay_reuses_stricter_candidate_policy_without_mutation() -> None:
    api = RetentionAPI([{**POLICY, "value": "24h"}])
    with httpx.Client(transport=httpx.MockTransport(api)) as client:
        adapter = QuayAdapter(
            api_url="https://quay.io/api/v1",
            registry="quay.io",
            token_provider=lambda: "token",
            client=client,
        )
        observed = adapter.ensure_candidate_retention(REPOSITORY, AGE)
    assert observed.maximum_age == timedelta(days=1)
    assert api.methods == ["GET"]


@pytest.mark.parametrize("write", ["ignored", "timeout-missing"])
def test_quay_refuses_unobserved_retention(write: str) -> None:
    api = RetentionAPI([], write=write)
    with httpx.Client(transport=httpx.MockTransport(api)) as client:
        adapter = QuayAdapter(
            api_url="https://quay.io/api/v1",
            registry="quay.io",
            token_provider=lambda: "token",
            client=client,
        )
        with pytest.raises(OperationalError, match="did not retain"):
            adapter.ensure_candidate_retention(REPOSITORY, AGE)
    assert api.methods == ["GET", "POST", "GET"]


@pytest.mark.parametrize("status", [401, 403, 404, 405])
def test_quay_requires_available_authorized_retention_api(status: int) -> None:
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
            adapter.ensure_candidate_retention(REPOSITORY, AGE)


@pytest.mark.parametrize(
    "change",
    [
        {"tagPatternMatches": False},
        {"tagPattern": ".*"},
        {"value": "8d"},
        {"method": "number_of_tags", "value": 1},
    ],
)
def test_quay_does_not_accept_noncovering_policies(change: dict[str, object]) -> None:
    api = RetentionAPI([{**POLICY, **change}], write="ignored")
    with httpx.Client(transport=httpx.MockTransport(api)) as client:
        adapter = QuayAdapter(
            api_url="https://quay.io/api/v1",
            registry="quay.io",
            token_provider=lambda: "token",
            client=client,
        )
        with pytest.raises(OperationalError, match="did not retain"):
            adapter.ensure_candidate_retention(REPOSITORY, AGE)


@pytest.mark.parametrize("version", [None, "1.2.3", "v2026.09.08", "A" * 81])
def test_retention_pattern_covers_generated_tags_only(version: str | None) -> None:
    tag = candidate_tag(
        version=version, run_id="01arz3ndektsv4rrffq69g5fav", source_revision="a" * 40
    )
    assert re.fullmatch(CANDIDATE_TAG_PATTERN, tag)
    for release_tag in (
        "latest",
        "stable",
        "1.2.3",
        "candidate",
        "1.2.3-candidate.unowned",
    ):
        assert re.fullmatch(CANDIDATE_TAG_PATTERN, release_tag) is None


@pytest.mark.parametrize("failure", [OperationalError, KeyboardInterrupt])
def test_lost_upload_acknowledgement_leaves_candidate_under_independent_retention(
    scenario: Scenario, monkeypatch: pytest.MonkeyPatch, failure: type[BaseException]
) -> None:
    original = scenario.registry.copy_layout_to_registry

    def lose_acknowledgement(**arguments: Any) -> None:
        assert scenario.registry_control.retention is not None
        original(**arguments)
        raise failure("upload acknowledgement lost")

    monkeypatch.setattr(
        scenario.registry, "copy_layout_to_registry", lose_acknowledgement
    )
    with pytest.raises(failure):
        scenario.publish()
    assert scenario.tags[scenario.tag] == scenario.observation.graph.digest
    assert scenario.registry_control.expirations == {}
    retained = scenario.registry_control.retention
    assert retained is not None and re.fullmatch(retained.tag_pattern, scenario.tag)
    assert retained.maximum_age <= scenario.image.release_limits.candidate_lifetime
    entry = scenario.workspace.journal.entries()[0]
    assert entry.status in {ResourceStatus.FAILED, ResourceStatus.PLANNED}
    assert entry.metadata["retention"] == retained.to_dict()


def test_unavailable_retention_stops_before_upload(
    scenario: Scenario, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*_args: object) -> CandidateRetentionObservation:
        raise UnsupportedOperationError("retention unavailable")

    monkeypatch.setattr(
        scenario.registry_control, "ensure_candidate_retention", unavailable
    )
    with pytest.raises(UnsupportedOperationError):
        scenario.publish()
    assert scenario.tags == {}
    assert scenario.workspace.journal.entries() == ()


@pytest.mark.parametrize(
    "change",
    [
        {"tag_pattern": ".*"},
        {"maximum_age": timedelta(days=8)},
        {"maximum_age": timedelta(0)},
        {"repository": OCIReference.parse("quay.io/example/other")},
        {"policy_id": ""},
    ],
)
def test_publication_validates_retention_observation_before_upload(
    scenario: Scenario, monkeypatch: pytest.MonkeyPatch, change: dict[str, Any]
) -> None:
    observation = CandidateRetentionObservation(
        REPOSITORY, "policy", CANDIDATE_TAG_PATTERN, AGE
    )
    monkeypatch.setattr(
        scenario.registry_control,
        "ensure_candidate_retention",
        lambda *_args: replace(observation, **change),
    )
    with pytest.raises(OperationalError, match="did not establish candidate retention"):
        scenario.publish()
    assert scenario.tags == {}
