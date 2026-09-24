from pathlib import Path

import pytest

from conclear.adapters.ci import (
    CIContextAbsent,
    CIContextInvalid,
    ObservedCIContext,
    observe_ci_context,
)
from conclear.commands import common as common_commands
from conclear.errors import OperationalError
from conclear.jsonutil import load_json
from conclear.records import SourceIdentity
from conclear.release_profile import (
    BuilderConfig,
    CIContextPolicy,
    QuayRegistryConfig,
    RegistryProvider,
    ReleaseProfile,
)
from conclear.services.ci_context import resolve_ci_context
from tests.registry_policy_fixtures import STRICT_POLICY

REVISION = "a" * 40


def _profile(tmp_path: Path, policy: CIContextPolicy) -> ReleaseProfile:
    return ReleaseProfile(
        name="test",
        ci_context=policy,
        builder=BuilderConfig(
            "https://foundata.com/en/projects/conclear/builder/simple-v1/"
        ),
        auth_file=None,
        registry=QuayRegistryConfig(
            RegistryProvider.QUAY,
            "quay.io",
            "https://quay.io/api/v1",
            None,
            policy=STRICT_POLICY,
        ),
        cosign_private_key=None,
        cosign_public_key=tmp_path / "cosign.pub",
        cosign_passphrase_file=None,
        configuration_digest="sha256:" + "1" * 64,
        public_key_digest="sha256:" + "2" * 64,
        allowed_source_origins=("https://forge.internal.example/foundata/",),
    )


def test_omit_policy_does_not_inspect_the_process_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_observation(_environment: object) -> None:
        raise AssertionError("CI environment must not be inspected")

    monkeypatch.setattr(common_commands, "observe_ci_context", fail_observation)

    assert common_commands.ci_context(_profile(tmp_path, CIContextPolicy.OMIT)) is None


def test_command_helper_leaves_required_policy_decisions_to_the_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invalid = CIContextInvalid("gitlab-ci", "incomplete context")
    monkeypatch.setattr(
        common_commands,
        "observe_ci_context",
        lambda _environment: invalid,
    )

    assert (
        common_commands.ci_context(_profile(tmp_path, CIContextPolicy.REQUIRE))
        is invalid
    )


@pytest.mark.parametrize(
    ("environment", "provider", "server", "repository", "run_id"),
    [
        (
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_API_URL": "https://api.github.com",
                "GITHUB_SERVER_URL": "https://github.com",
                "GITHUB_REPOSITORY": "foundata/example",
                "GITHUB_SHA": REVISION,
                "GITHUB_RUN_ID": "101",
            },
            "github-actions",
            "https://github.com",
            "foundata/example",
            "101",
        ),
        (
            {
                "GITLAB_CI": "true",
                "CI_SERVER_URL": "https://gitlab.com",
                "CI_PROJECT_PATH": "foundata/example",
                "CI_COMMIT_SHA": REVISION,
                "CI_PIPELINE_ID": "102",
            },
            "gitlab-ci",
            "https://gitlab.com",
            "foundata/example",
            "102",
        ),
        (
            {
                "GITEA_ACTIONS": "true",
                "GITHUB_ACTIONS": "true",
                "GITHUB_SERVER_URL": "https://gitea.example.com",
                "GITHUB_REPOSITORY": "foundata/example",
                "GITHUB_SHA": REVISION,
                "GITHUB_RUN_ID": "103",
            },
            "gitea-actions",
            "https://gitea.example.com",
            "foundata/example",
            "103",
        ),
        (
            {
                "FORGEJO_ACTIONS": "true",
                "GITHUB_ACTIONS": "true",
                "FORGEJO_SERVER_URL": "https://forgejo.example.com",
                "FORGEJO_REPOSITORY": "foundata/example",
                "FORGEJO_SHA": REVISION,
                "FORGEJO_RUN_ID": "104",
            },
            "forgejo-actions",
            "https://forgejo.example.com",
            "foundata/example",
            "104",
        ),
        (
            {
                "CI": "woodpecker",
                "CI_SYSTEM_NAME": "woodpecker",
                "CI_FORGE_URL": "https://forge.example.com",
                "CI_REPO": "foundata/example",
                "CI_COMMIT_SHA": REVISION,
                "CI_PIPELINE_NUMBER": "105",
            },
            "woodpecker-ci",
            "https://forge.example.com",
            "foundata/example",
            "105",
        ),
    ],
)
def test_supported_ci_providers_are_normalized(
    environment: dict[str, str],
    provider: str,
    server: str,
    repository: str,
    run_id: str,
) -> None:
    observation = observe_ci_context(environment)

    assert observation == ObservedCIContext(
        provider=provider,
        server=server,
        repository=repository,
        revision=REVISION,
        run_id=run_id,
    )


def test_ci_provider_compatibility_markers_do_not_create_ambiguity() -> None:
    observation = observe_ci_context(
        {
            "FORGEJO_ACTIONS": "true",
            "GITHUB_ACTIONS": "true",
            "FORGEJO_SERVER_URL": "https://forgejo.example.com",
            "FORGEJO_REPOSITORY": "foundata/example",
            "FORGEJO_SHA": REVISION,
            "FORGEJO_RUN_ID": "106",
        }
    )

    assert isinstance(observation, ObservedCIContext)
    assert observation.provider == "forgejo-actions"


def test_absent_and_ambiguous_ci_providers_are_typed_observations() -> None:
    assert isinstance(observe_ci_context({}), CIContextAbsent)
    assert isinstance(
        observe_ci_context(
            {
                "GITLAB_CI": "true",
                "GITHUB_ACTIONS": "true",
            }
        ),
        CIContextInvalid,
    )

    malformed = observe_ci_context(
        {
            "GITLAB_CI": "true",
            "CI_SERVER_URL": "https://gitlab.com",
            "CI_PROJECT_PATH": "https://gitlab.com/foundata/example",
            "CI_COMMIT_SHA": REVISION,
            "CI_PIPELINE_ID": "111",
        }
    )
    assert isinstance(malformed, CIContextInvalid)


def test_legacy_github_compatible_variables_do_not_impersonate_github() -> None:
    observation = observe_ci_context(
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_API_URL": "https://forgejo.example.com/api/v1",
            "GITHUB_SERVER_URL": "https://forgejo.example.com",
            "GITHUB_REPOSITORY": "foundata/example",
            "GITHUB_SHA": REVISION,
            "GITHUB_RUN_ID": "110",
        }
    )

    assert isinstance(observation, CIContextInvalid)
    assert "provider-specific marker" in observation.diagnostic


def test_observe_policy_omits_inconsistent_context_and_keeps_diagnostics(
    tmp_path: Path,
) -> None:
    diagnostic = tmp_path / "ci-context.json"
    observation = ObservedCIContext(
        provider="gitlab-ci",
        server="https://gitlab.internal.example",
        repository="foundata/example",
        revision="b" * 40,
        run_id="107",
    )

    result = resolve_ci_context(
        observation,
        policy=CIContextPolicy.OBSERVE,
        source=SourceIdentity(
            "https://foundata.com/en/projects/example/#source", REVISION
        ),
        origin="https://gitlab.internal.example/foundata/example",
        diagnostic_path=diagnostic,
    )

    assert result is None
    diagnostic_value = load_json(diagnostic)
    assert diagnostic_value["status"] == "ignored"
    assert diagnostic_value["ciContext"]["server"] == (
        "https://gitlab.internal.example"
    )


def test_required_ci_context_rejects_absence_and_checkout_disagreement(
    tmp_path: Path,
) -> None:
    # The public source URL is a project page; only the Git origin is compared
    # with the provider's repository claim.
    source = SourceIdentity(
        "https://foundata.com/en/projects/example/#source", REVISION
    )
    origin = "https://gitlab.com/foundata/example"
    with pytest.raises(OperationalError, match="Required"):
        resolve_ci_context(
            CIContextAbsent(),
            policy=CIContextPolicy.REQUIRE,
            source=source,
            origin=origin,
            diagnostic_path=tmp_path / "absent.json",
        )

    with pytest.raises(OperationalError, match="revision differs"):
        resolve_ci_context(
            ObservedCIContext(
                provider="gitlab-ci",
                server="https://gitlab.com",
                repository="foundata/example",
                revision="b" * 40,
                run_id="108",
            ),
            policy=CIContextPolicy.REQUIRE,
            source=source,
            origin=origin,
            diagnostic_path=tmp_path / "mismatch.json",
        )

    with pytest.raises(OperationalError, match="repository differs"):
        resolve_ci_context(
            ObservedCIContext(
                provider="gitlab-ci",
                server="https://gitlab.com",
                repository="foundata/other",
                revision=REVISION,
                run_id="112",
            ),
            policy=CIContextPolicy.REQUIRE,
            source=source,
            origin=origin,
            diagnostic_path=tmp_path / "repository-mismatch.json",
        )

    invalid_diagnostic = tmp_path / "invalid.json"
    with pytest.raises(OperationalError, match="malformed provider context"):
        resolve_ci_context(
            CIContextInvalid("gitlab-ci", "malformed provider context"),
            policy=CIContextPolicy.REQUIRE,
            source=source,
            origin=origin,
            diagnostic_path=invalid_diagnostic,
        )
    assert load_json(invalid_diagnostic) == {
        "schemaVersion": 1,
        "status": "rejected",
        "reason": "malformed provider context",
        "provider": "gitlab-ci",
    }


def test_matching_ci_context_has_provider_neutral_public_shape(tmp_path: Path) -> None:
    context = resolve_ci_context(
        ObservedCIContext(
            provider="woodpecker-ci",
            server="https://forge.internal.example",
            repository="foundata/example",
            revision=REVISION,
            run_id="109",
        ),
        policy=CIContextPolicy.OBSERVE,
        source=SourceIdentity(
            "https://foundata.com/en/projects/example/#source", REVISION
        ),
        origin="https://forge.internal.example/foundata/example",
        diagnostic_path=tmp_path / "ci-context.json",
    )

    assert context is not None
    assert context.to_public_dict() == {
        "provider": "woodpecker-ci",
        "source": "provider-environment",
        "repository": "foundata/example",
        "revision": REVISION,
        "runId": "109",
    }
