"""Explicit registry modes preserve release authorization and tag identity."""

from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from conclear.errors import InvalidInvocationError, OperationalError, RuleRejectionError
from conclear.jsonutil import load_json
from conclear.registry_policy import (
    CandidateCleanupMode,
    CandidateCleanupPolicy,
    RegistryPolicy,
    TagProtectionMode,
    TagProtectionPolicy,
)
from conclear.release_profile import load_release_profile
from conclear.services import release
from conclear.services.promotion import promote_candidate
from conclear.values import Digest
from conclear.workspace import ResourceKind, ResourceStatus, RunState
from tests.registry_policy_fixtures import REGISTRY_POLICY_TOML, STRICT_POLICY
from tests.unit.test_publication_resume import NOW, Scenario
from tests.unit.test_release_profile import _profile_text
from tests.unit.test_release_workflow import Harness


def reviewed_policy(mode: CandidateCleanupMode) -> RegistryPolicy:
    return RegistryPolicy(
        TagProtectionPolicy(
            TagProtectionMode.NOT_ENFORCED,
            "Selective protection is unavailable on the reviewed deployment.",
            "release maintainer",
        ),
        CandidateCleanupPolicy(
            mode, "release maintainer", "Review abandoned runs daily."
        ),
    )


def unavailable(*_args: object, **_kwargs: object) -> Any:
    raise OperationalError("Selected provider control is unavailable")


@pytest.fixture
def harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_factory: Callable[..., Path],
) -> Harness:
    root = repository_factory()
    config = root / "conclear.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            'moving_tags = ["stable"]', 'moving_tags = ["latest"]'
        ),
        encoding="utf-8",
    )
    result = Harness(tmp_path, monkeypatch, lambda: root)
    result.profile = replace(
        result.profile,
        registry=replace(
            result.profile.registry, policy=reviewed_policy(CandidateCleanupMode.MANUAL)
        ),
    )
    return result


@pytest.mark.parametrize("cleanup", tuple(CandidateCleanupMode))
@pytest.mark.parametrize("protection", tuple(TagProtectionMode))
def test_complete_release_observes_only_selected_controls(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    cleanup: CandidateCleanupMode,
    protection: TagProtectionMode,
) -> None:
    policy = reviewed_policy(cleanup)
    if protection is TagProtectionMode.REQUIRED:
        policy = replace(policy, tag_protection=STRICT_POLICY.tag_protection)
    harness.profile = replace(
        harness.profile, registry=replace(harness.profile.registry, policy=policy)
    )
    control = harness.runtime.registry_control
    harness.runtime.registry.tags["latest"] = Digest("sha256:" + "9" * 64)
    if protection is TagProtectionMode.NOT_ENFORCED:
        monkeypatch.setattr(control, "verify_tag_policy", unavailable)
        monkeypatch.setattr(control, "ensure_tag_immutable", unavailable)
    if cleanup is not CandidateCleanupMode.AUTO_PRUNE:
        monkeypatch.setattr(control, "ensure_candidate_retention", unavailable)
    if cleanup is CandidateCleanupMode.MANUAL:
        monkeypatch.setattr(control, "enforce_candidate_lifetime", unavailable)

    result = harness.complete()

    assert result.candidate_deleted
    assert (
        harness.runtime.registry.tags["latest"]
        == harness.runtime.registry.tags["1.2.3"]
    )
    assert result.immutability_enabled is (protection is TagProtectionMode.REQUIRED)
    assert harness.workspace.load().state is RunState.PROMOTED
    summary = load_json(harness.workspace.root / "summary.json")
    assert isinstance(summary, dict)
    assert summary["registryPolicy"] == policy.to_dict()
    verification = load_json(
        harness.workspace.root / "records" / "release-verification.json"
    )
    assert isinstance(verification, dict)
    payload = verification["payload"]
    assert isinstance(payload, dict)
    assert payload["registryPolicy"] == policy.to_dict()
    assert payload["candidateAuthorization"] == summary["candidateAuthorization"]


@pytest.mark.parametrize(
    "cleanup", (CandidateCleanupMode.TAG_EXPIRATION, CandidateCleanupMode.AUTO_PRUNE)
)
def test_selected_cleanup_errors_never_fall_back(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    cleanup: CandidateCleanupMode,
) -> None:
    harness.profile = replace(
        harness.profile,
        registry=replace(harness.profile.registry, policy=reviewed_policy(cleanup)),
    )
    operation = (
        "enforce_candidate_lifetime"
        if cleanup is CandidateCleanupMode.TAG_EXPIRATION
        else "ensure_candidate_retention"
    )
    monkeypatch.setattr(harness.runtime.registry_control, operation, unavailable)

    with pytest.raises(OperationalError, match="control is unavailable"):
        harness.complete()
    assert "1.2.3" not in harness.runtime.registry.tags
    assert harness.workspace.load().state is RunState.INCOMPLETE


def test_reviewed_absence_still_rejects_conflicting_version_tags(
    harness: Harness,
) -> None:
    other = Digest("sha256:" + "9" * 64)
    harness.runtime.registry.tags["1.2.3"] = other
    with pytest.raises(RuleRejectionError, match="already names another digest"):
        harness.complete()
    assert harness.runtime.registry.tags["1.2.3"] == other


def test_manual_cleanup_failure_preserves_completed_release(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(harness.runtime.registry_control, "remove_tag", unavailable)
    result = harness.complete()
    assert not result.candidate_deleted
    assert harness.workspace.load().state is RunState.PROMOTED
    assert any(item.check_id == "CC0605" for item in result.findings)
    candidate = next(
        entry
        for entry in harness.workspace.journal.entries()
        if entry.kind is ResourceKind.CANDIDATE_REFERENCE
    )
    assert candidate.status is ResourceStatus.CREATED


@pytest.mark.parametrize("change", ("deadline", "policy"))
def test_promotion_rejects_changed_signed_authorization(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    original = promote_candidate

    def changed(published: Any, *args: Any, **kwargs: Any) -> Any:
        altered = (
            replace(published, expiration=published.expiration + timedelta(hours=1))
            if change == "deadline"
            else replace(published, policy=STRICT_POLICY)
        )
        if change == "policy":
            harness.runtime.registry_control.expirations[published.reference.tag] = (
                published.expiration
            )
        return original(altered, *args, **kwargs)

    monkeypatch.setattr(release, "promote_candidate", changed)
    with pytest.raises(RuleRejectionError, match="differs from signed verification"):
        harness.complete()
    assert "1.2.3" not in harness.runtime.registry.tags


@pytest.mark.parametrize("remote_expiration", (None, NOW + timedelta(days=30)))
def test_remote_expiration_cannot_extend_original_authorization(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    remote_expiration: Any,
) -> None:
    original = promote_candidate

    def expired(published: Any, *args: Any, **kwargs: Any) -> Any:
        tag = published.reference.tag
        if remote_expiration is None:
            harness.runtime.registry_control.expirations.pop(tag, None)
        else:
            harness.runtime.registry_control.expirations[tag] = remote_expiration
        kwargs["now"] = published.expiration
        return original(published, *args, **kwargs)

    monkeypatch.setattr(release, "promote_candidate", expired)
    with pytest.raises(RuleRejectionError, match="authorization expired"):
        harness.complete()
    assert "1.2.3" not in harness.runtime.registry.tags


def test_manual_resume_keeps_preupload_deadline_after_lost_acknowledgement(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = Scenario(tmp_path, repository_factory)
    scenario.policy = reviewed_policy(CandidateCleanupMode.MANUAL)
    original = scenario.registry.copy_layout_to_registry

    def lost_ack(**kwargs: Any) -> None:
        entry = scenario.workspace.journal.entries()[0]
        assert entry.metadata["expiration"] == "2026-01-08T00:00:00Z"
        assert entry.metadata["registryPolicy"] == scenario.policy.to_dict()
        original(**kwargs)
        raise OperationalError("acknowledgement lost")

    monkeypatch.setattr(scenario.registry, "copy_layout_to_registry", lost_ack)
    monkeypatch.setattr(
        scenario.registry_control, "enforce_candidate_lifetime", unavailable
    )
    monkeypatch.setattr(
        scenario.registry_control, "ensure_candidate_retention", unavailable
    )
    with pytest.raises(OperationalError, match="acknowledgement lost"):
        scenario.publish()
    assert scenario.workspace.journal.entries()[0].status is ResourceStatus.FAILED
    published = scenario.publish(now=NOW + timedelta(hours=1))
    assert published.expiration == NOW + timedelta(days=7)
    assert scenario.registry_control.expirations == {}


def test_resume_rejects_changed_policy(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
) -> None:
    scenario = Scenario(tmp_path, repository_factory)
    scenario.journal_attempt()
    scenario.tags[scenario.tag] = scenario.observation.graph.digest
    scenario.policy = reviewed_policy(CandidateCleanupMode.MANUAL)
    with pytest.raises(InvalidInvocationError, match="policy changed"):
        scenario.publish()


def test_candidate_authorization_rejects_ambiguous_check_time(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
) -> None:
    scenario = Scenario(tmp_path, repository_factory)
    scenario.policy = reviewed_policy(CandidateCleanupMode.MANUAL)
    published = scenario.publish()
    with pytest.raises(InvalidInvocationError, match="timezone-aware"):
        published.require_current(NOW.replace(tzinfo=None))


def test_candidate_deadline_is_rechecked_between_tag_writes(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = repository_factory()
    config = root / "conclear.toml"
    config.write_text(
        config.read_text(encoding="utf-8")
        .replace(
            "[images.release]",
            '[images.limits]\ncandidate_lifetime = "1h"\n\n[images.release]',
        )
        .replace('moving_tags = ["stable"]', 'moving_tags = ["latest"]'),
        encoding="utf-8",
    )
    run = Harness(tmp_path, monkeypatch, lambda: root)
    run.profile = replace(
        run.profile,
        registry=replace(
            run.profile.registry, policy=reviewed_policy(CandidateCleanupMode.MANUAL)
        ),
    )

    def slow(*args: Any, **kwargs: Any) -> Any:
        kwargs["clock"] = lambda: (
            NOW + timedelta(hours=1) if "1.2.3" in run.runtime.registry.tags else NOW
        )
        return promote_candidate(*args, **kwargs)

    monkeypatch.setattr(release, "promote_candidate", slow)
    with pytest.raises(RuleRejectionError, match="Candidate expired during promotion"):
        run.complete()
    assert "1.2.3" in run.runtime.registry.tags
    assert "latest" not in run.runtime.registry.tags
    assert run.workspace.load().state is RunState.REJECTED


@pytest.mark.parametrize("mode", tuple(CandidateCleanupMode))
def test_profile_parses_reviewed_absence_and_cleanup_modes(
    tmp_path: Path, mode: CandidateCleanupMode
) -> None:
    key = tmp_path / "cosign.pub"
    key.write_text("public", encoding="utf-8")
    key.chmod(0o600)
    directory = tmp_path / "conclear"
    directory.mkdir()
    path = directory / "release.toml"
    policy_text = f'''tag_protection = {{mode = "not-enforced", rationale = "Unavailable on this deployment.", owner = "ops"}}
candidate_cleanup = {{mode = "{mode.value}", owner = "ops", procedure = "Review abandoned runs daily."}}
'''
    path.write_text(
        _profile_text('ci_context = "omit"', f'cosign_public_key = "{key}"').replace(
            REGISTRY_POLICY_TOML, policy_text
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    policy = load_release_profile("release", config_home=tmp_path).registry.policy
    assert policy.tag_protection.mode is TagProtectionMode.NOT_ENFORCED
    assert policy.tag_protection.owner == "ops"
    assert policy.candidate_cleanup.mode is mode


@pytest.mark.parametrize("mode", tuple(CandidateCleanupMode))
def test_registry_policy_round_trip(mode: CandidateCleanupMode) -> None:
    policy = reviewed_policy(mode)
    assert RegistryPolicy.from_dict(policy.to_dict()) == policy
    value = policy.to_dict()
    value["unreviewedFallback"] = True
    with pytest.raises(InvalidInvocationError, match="unknown or missing"):
        RegistryPolicy.from_dict(value)


@pytest.mark.parametrize(
    "policy_text",
    (
        "",
        'tag_protection = {mode = "not-enforced"}\ncandidate_cleanup = {mode = "manual", owner = "ops", procedure = "Review runs."}',
        REGISTRY_POLICY_TOML.replace(
            'mode = "required"', 'mode = "required", rationale = "exception"'
        ),
        REGISTRY_POLICY_TOML.replace('owner = "test operator"', 'owner = " "'),
        REGISTRY_POLICY_TOML.replace(
            'procedure = "Review abandoned candidates."', 'procedure = " "'
        ),
        REGISTRY_POLICY_TOML.replace(
            'mode = "auto-prune"', 'mode = "automatic-fallback"'
        ),
    ),
)
def test_profile_requires_complete_explicit_registry_choices(
    tmp_path: Path, policy_text: str
) -> None:
    key = tmp_path / "cosign.pub"
    key.write_text("public", encoding="utf-8")
    key.chmod(0o600)
    directory = tmp_path / "conclear"
    directory.mkdir()
    path = directory / "release.toml"
    path.write_text(
        _profile_text('ci_context = "omit"', f'cosign_public_key = "{key}"').replace(
            REGISTRY_POLICY_TOML, policy_text
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(InvalidInvocationError):
        load_release_profile("release", config_home=tmp_path)
