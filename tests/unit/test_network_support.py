"""External tests fail closed after selection and never infer resource ownership."""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from conclear.errors import OperationalError
from conclear.jsonutil import atomic_write_json, load_json
from conclear.registry_control import TagObservation
from conclear.registry_policy import CandidateCleanupMode, TagProtectionMode
from conclear.values import Digest, OCIReference
from tests.network import test_quay_candidate as candidate_tests
from tests.network_support import authorized_environment, external_path, owned_tag

REPOSITORY = "quay.io/example/disposable"
CANDIDATE = REPOSITORY + ":owned-candidate"
DIGEST = Digest("sha256:" + "a" * 64)


@pytest.fixture
def authorized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    manifest = tmp_path / "resources.json"
    token = tmp_path / "token"
    token.write_text("test-token", encoding="utf-8")
    atomic_write_json(
        manifest,
        {
            "run_id": "test",
            "workspace": str(tmp_path),
            "created": {
                "registry_repositories": [REPOSITORY],
                "registry_tags": [
                    CANDIDATE,
                    REPOSITORY + ":1.2.3",
                    REPOSITORY + ":latest",
                ],
            },
        },
    )
    environment = {
        "CONCLEAR_TEST_NETWORK_AUTHORIZED": "yes",
        "CONCLEAR_TEST_RUN_ID": "test",
        "CONCLEAR_TEST_RESOURCE_MANIFEST": str(manifest),
        "CONCLEAR_TEST_QUAY_REPOSITORY": REPOSITORY,
        "CONCLEAR_TEST_QUAY_TOKEN_FILE": str(token),
        "CONCLEAR_TEST_QUAY_CANDIDATE": CANDIDATE,
        "CONCLEAR_TEST_QUAY_CANDIDATE_DIGEST": str(DIGEST),
        "CONCLEAR_TEST_QUAY_VERSION_TAG": REPOSITORY + ":1.2.3",
        "CONCLEAR_TEST_QUAY_MOVING_TAG": REPOSITORY + ":latest",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    return environment


def test_unrequested_network_test_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONCLEAR_TEST_NETWORK_AUTHORIZED", raising=False)
    with pytest.raises(pytest.skip.Exception):
        authorized_environment({})


def test_selected_test_fails_for_missing_inputs(
    authorized: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CONCLEAR_TEST_RUN_ID")
    with pytest.raises(pytest.fail.Exception, match="authorized network test needs"):
        authorized_environment({})


@pytest.mark.parametrize("field", ["run_id", "registry_repositories", "registry_tags"])
def test_owned_inputs_cannot_be_inferred(
    authorized: dict[str, str], field: str
) -> None:
    path = Path(authorized["CONCLEAR_TEST_RESOURCE_MANIFEST"])
    manifest = load_json(path)
    if field == "run_id":
        manifest[field] = "other"
    else:
        manifest["created"][field] = []
    atomic_write_json(path, manifest)
    with pytest.raises(pytest.fail.Exception, match="does not own"):
        values = authorized_environment({"candidate": "CONCLEAR_TEST_QUAY_CANDIDATE"})
        owned_tag(values, "candidate")


def test_inputs_inside_repository_are_rejected() -> None:
    with pytest.raises(pytest.fail.Exception, match="outside the repository"):
        external_path(str(Path(__file__).resolve()))


@pytest.mark.parametrize("protection", list(TagProtectionMode))
@pytest.mark.parametrize("cleanup", list(CandidateCleanupMode))
def test_baseline_never_depends_on_immutability_or_retention(
    authorized: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    protection: TagProtectionMode,
    cleanup: CandidateCleanupMode,
) -> None:
    monkeypatch.setenv("CONCLEAR_TEST_TAG_PROTECTION", protection.value)
    monkeypatch.setenv("CONCLEAR_TEST_CANDIDATE_CLEANUP", cleanup.value)
    methods: list[str] = []
    observation: TagObservation | None = TagObservation(
        "owned-candidate", DIGEST, None, False
    )
    monkeypatch.setattr(
        candidate_tests,
        "datetime",
        SimpleNamespace(now=lambda _: datetime(2026, 9, 10, tzinfo=UTC)),
    )

    def expire(
        repository: OCIReference, tag: str, expiration: datetime
    ) -> TagObservation:
        nonlocal observation
        methods.append("expire")
        observation = TagObservation(tag, DIGEST, expiration, False)
        return observation

    def remove(*_args: Any) -> None:
        nonlocal observation
        methods.append("delete")
        observation = None

    control = SimpleNamespace(
        observe_tag=lambda *_: observation,
        enforce_candidate_lifetime=expire,
        remove_tag=remove,
        close=lambda: None,
    )
    monkeypatch.setattr(candidate_tests, "_quay", lambda _: control)
    candidate_tests.test_real_quay_candidate_honors_selected_cleanup()
    assert methods == (
        ["delete"] if cleanup is CandidateCleanupMode.MANUAL else ["expire", "delete"]
    )


@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("control_name", ["protection", "retention"])
def test_optional_provider_checks_fail_instead_of_skipping_when_selected(
    authorized: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    selected: bool,
    control_name: str,
) -> None:
    monkeypatch.setenv(
        "CONCLEAR_TEST_TAG_PROTECTION", "required" if selected else "not-enforced"
    )
    monkeypatch.setenv(
        "CONCLEAR_TEST_CANDIDATE_CLEANUP", "auto-prune" if selected else "manual"
    )

    def unavailable(*_args: Any, **_kwargs: Any) -> None:
        raise OperationalError("provider API unavailable")

    control = SimpleNamespace(
        verify_tag_policy=unavailable,
        ensure_candidate_retention=unavailable,
        close=lambda: None,
    )
    monkeypatch.setattr(candidate_tests, "_quay", lambda _: control)
    test: Callable[[], None] = (
        candidate_tests.test_real_quay_selected_version_policy
        if control_name == "protection"
        else candidate_tests.test_real_quay_selected_auto_prune_policy
    )
    with pytest.raises(OperationalError if selected else pytest.skip.Exception):
        test()
