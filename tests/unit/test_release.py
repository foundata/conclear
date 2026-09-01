import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import conclear.provenance as provenance_module
import conclear.records as records_module
import conclear.services.assembly as assembly_module
import conclear.services.publication as publication_module
from conclear.config import (
    CIContextPolicy,
    QuayRegistryConfig,
    RegistryProvider,
    ReleaseProfile,
    load_repository_config,
)
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import sha256_bytes
from conclear.records import SourceIdentity
from conclear.services import release
from conclear.services.release import ReleaseRequest
from conclear.values import OCIReference
from conclear.workspace import RunState, RunWorkspace
from tests.release_fakes import FakeRuntime


class FixedIdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def profile(tmp_path: Path) -> ReleaseProfile:
    return ReleaseProfile(
        name="production",
        ci_context=CIContextPolicy.OMIT,
        auth_file=None,
        registry=QuayRegistryConfig(
            RegistryProvider.QUAY,
            "quay.io",
            "https://quay.io/api/v1",
            tmp_path / "quay-token",
        ),
        cosign_private_key=str(tmp_path / "cosign.key"),
        cosign_public_key=tmp_path / "cosign.pub",
        passphrase_file=None,
        configuration_digest="sha256:" + "a" * 64,
        public_key_digest="sha256:" + "b" * 64,
    )


def workspace(
    tmp_path: Path, profile_value: ReleaseProfile, state: RunState
) -> RunWorkspace:
    source_root = tmp_path / "repository"
    source_root.mkdir()
    result = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={
            "sourceRoot": str(source_root),
            "sourceRevision": "a" * 40,
            "sourceRepository": "https://github.com/example/project",
            "image": "app",
            "version": "1.2.3",
            "profile": profile_value.name,
            "profileConfigurationDigest": profile_value.configuration_digest,
            "profilePublicKeyDigest": profile_value.public_key_digest,
        },
        id_factory=FixedIdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    if state is RunState.CREATED:
        return result
    for next_state in (
        RunState.QUALIFIED,
        RunState.ASSEMBLED,
        RunState.PUBLISHED,
        RunState.ATTESTED,
        RunState.VERIFIED,
        RunState.PROMOTED,
    ):
        if state is RunState.REJECTED:
            result.transition(RunState.REJECTED)
            break
        result.transition(next_state)
        if next_state is state:
            break
    return result


@pytest.mark.parametrize("terminal_state", [RunState.REJECTED, RunState.PROMOTED])
def test_resume_release_refuses_terminal_state_before_continuing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_state: RunState,
) -> None:
    profile_value = profile(tmp_path)
    run_workspace = workspace(tmp_path, profile_value, terminal_state)
    source_run = SimpleNamespace(workspace=run_workspace)
    monkeypatch.setattr(release, "open_source_run", lambda **_kwargs: source_run)

    def unexpected_continue(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("terminal run entered release continuation")

    monkeypatch.setattr(release, "_continue_release", unexpected_continue)

    with pytest.raises(InvalidInvocationError, match="terminal state"):
        release.resume_release(
            run_workspace.run_id,
            repository=tmp_path / "repository",
            profile=profile_value,
            state_home=tmp_path / "state",
            cache_home=tmp_path / "cache",
            passphrase=None,
            ci_context=None,
        )


def test_release_does_not_promote_until_verification_transitions_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_value = profile(tmp_path)
    run_workspace = workspace(tmp_path, profile_value, RunState.ATTESTED)
    published = SimpleNamespace(immutable_reference=object())
    image = SimpleNamespace(repository=object())
    repository = SimpleNamespace(image=lambda _image_id: image)
    runtime = SimpleNamespace(
        skopeo=lambda: object(),
        cosign=lambda: object(),
    )
    registry_control = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(release, "load_candidate", lambda *_args: object())
    monkeypatch.setattr(release, "load_release_evidence", lambda *_args: object())
    monkeypatch.setattr(release, "load_published", lambda *_args: published)
    monkeypatch.setattr(
        release,
        "create_registry_control",
        lambda _profile, *, destinations: registry_control,
    )
    monkeypatch.setattr(release, "validate_registry_destinations", lambda *_args: None)
    monkeypatch.setattr(release, "signer_identity", lambda *_args: ("key", "id"))
    monkeypatch.setattr(release, "verify_candidate", lambda *_args, **_kwargs: None)

    def unexpected_promotion(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("promotion ran before verification completed")

    monkeypatch.setattr(release, "promote_candidate", unexpected_promotion)
    request = ReleaseRequest(
        repository=tmp_path / "repository",
        revision="a" * 40,
        image_id="app",
        version="1.2.3",
        profile=profile_value,
        state_home=tmp_path / "state",
        cache_home=tmp_path / "cache",
        passphrase=None,
        ci_context=None,
    )

    with pytest.raises(OperationalError, match="did not reach the verified state"):
        release._continue_release(
            request,
            repository=cast(Any, repository),
            workspace=run_workspace,
            runtime=cast(Any, runtime),
            source=cast(Any, object()),
            source_time=datetime(2026, 1, 1, tzinfo=UTC),
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            now_factory=lambda: datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_release_rejects_invalid_version_before_source_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = ReleaseRequest(
        repository=tmp_path / "repository",
        revision="a" * 40,
        image_id="app",
        version="invalid version",
        profile=profile(tmp_path),
        state_home=tmp_path / "state",
        cache_home=tmp_path / "cache",
        passphrase=None,
        ci_context=None,
    )

    def unexpected_source_isolation(**_kwargs: object) -> None:
        raise AssertionError("invalid version reached source isolation")

    monkeypatch.setattr(release, "create_source_run", unexpected_source_isolation)

    with pytest.raises(InvalidInvocationError, match="Invalid release version"):
        release.execute_release(request)


def test_full_release_rejects_unsupported_registry_before_qualification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_value = profile(tmp_path)
    run_workspace = workspace(tmp_path, profile_value, RunState.CREATED)
    image = SimpleNamespace(repository=OCIReference.parse("docker.io/example/app"))
    repository = SimpleNamespace(image=lambda _image_id: image)

    def unexpected_qualification(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unsupported registry reached qualification")

    monkeypatch.setattr(release, "_qualify_release", unexpected_qualification)
    request = ReleaseRequest(
        repository=tmp_path / "repository",
        revision="a" * 40,
        image_id="app",
        version="1.2.3",
        profile=profile_value,
        state_home=tmp_path / "state",
        cache_home=tmp_path / "cache",
        passphrase=None,
        ci_context=None,
    )

    with pytest.raises(InvalidInvocationError, match=r"does not support docker\.io"):
        release._continue_release(
            request,
            repository=cast(Any, repository),
            workspace=run_workspace,
            runtime=cast(Any, object()),
            source=cast(Any, object()),
            source_time=datetime(2026, 1, 1, tzinfo=UTC),
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            now_factory=lambda: datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_execute_release_drives_every_phase_to_verified_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_factory: Any,
) -> None:
    identity = ApplicationIdentity(source_revision="c" * 40)
    monkeypatch.setattr(records_module, "IDENTITY", identity)
    monkeypatch.setattr(provenance_module, "IDENTITY", identity)
    monkeypatch.setattr(assembly_module, "IDENTITY", identity)
    monkeypatch.setattr(publication_module, "IDENTITY", identity)
    source_root = repository_factory()
    repository = load_repository_config(source_root / "conclear.toml")
    profile_value = profile(tmp_path)
    profile_value.cosign_public_key.write_text("test public key\n", encoding="utf-8")
    profile_value.cosign_public_key.chmod(0o600)
    run_workspace = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={
            "sourceRoot": str(source_root.resolve()),
            "sourceRevision": "b" * 40,
            "sourceRepository": repository.project.source,
            "configurationDigest": sha256_bytes(repository.raw_bytes),
            "image": "app",
            "version": "1.2.3",
            "profile": profile_value.name,
            "profileConfigurationDigest": profile_value.configuration_digest,
            "profilePublicKeyDigest": profile_value.public_key_digest,
        },
        id_factory=FixedIdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    pin_digest = repository.image("app").pins[0].reference.digest
    assert pin_digest is not None
    runtime = FakeRuntime(pin_digest)
    source_run = SimpleNamespace(
        workspace=run_workspace,
        repository=repository,
        runtime=runtime,
        source=SourceIdentity(repository.project.source, "b" * 40),
        source_time=datetime(2026, 1, 1, tzinfo=UTC),
    )
    monkeypatch.setattr(release, "create_source_run", lambda **_kwargs: source_run)
    monkeypatch.setattr(
        release,
        "create_registry_control",
        lambda _profile, *, destinations: runtime.registry_control,
    )

    result = release.execute_release(
        ReleaseRequest(
            repository=source_root,
            revision="b" * 40,
            image_id="app",
            version="1.2.3",
            profile=profile_value,
            state_home=tmp_path / "state",
            cache_home=tmp_path / "cache",
            passphrase=None,
            ci_context=None,
        ),
        now_factory=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert run_workspace.load().state is RunState.PROMOTED
    assert result.candidate_deleted
    assert result.subject.endswith("@" + result.tags[0][1])
    assert [tag for tag, _digest in result.tags] == ["1.2.3", "stable"]
    assert runtime.signer.signatures == {result.subject}
    assert runtime.registry_control.closed
    summary = json.loads(
        (run_workspace.root / "summary.json").read_text(encoding="utf-8")
    )
    assert summary["state"] == "promoted"
    assert summary["subject"] == result.subject


def test_resume_release_rejects_changed_trust_profile_before_continuing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_profile = profile(tmp_path)
    run_workspace = workspace(tmp_path, original_profile, RunState.ATTESTED)
    source_run = SimpleNamespace(workspace=run_workspace)
    monkeypatch.setattr(release, "open_source_run", lambda **_kwargs: source_run)

    def unexpected_continue(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("changed resume inputs entered release continuation")

    monkeypatch.setattr(release, "_continue_release", unexpected_continue)

    with pytest.raises(InvalidInvocationError, match="trust profile changed"):
        release.resume_release(
            run_workspace.run_id,
            repository=tmp_path / "repository",
            profile=replace(
                original_profile,
                configuration_digest="sha256:" + "9" * 64,
            ),
            state_home=tmp_path / "state",
            cache_home=tmp_path / "cache",
            passphrase=None,
            ci_context=None,
        )


@pytest.mark.parametrize(
    ("failure", "state", "failure_value"),
    (
        (
            RuleRejectionError("scan rejected", code="CC0502"),
            RunState.REJECTED,
            {
                "type": "ruleRejection",
                "message": "scan rejected",
                "checkId": "CC0502",
            },
        ),
        (
            OperationalError("registry unavailable"),
            RunState.INCOMPLETE,
            {"type": "operationalFailure", "message": "registry unavailable"},
        ),
        (
            KeyboardInterrupt(),
            RunState.INCOMPLETE,
            {"type": "interrupted", "message": "Release was interrupted"},
        ),
        (
            RuntimeError("credential=/secret/value"),
            RunState.INCOMPLETE,
            {"type": "internalError", "message": "Release failed unexpectedly"},
        ),
    ),
)
def test_release_failure_writes_safe_terminal_summary(
    tmp_path: Path,
    failure: BaseException,
    state: RunState,
    failure_value: dict[str, object],
) -> None:
    run_workspace = workspace(tmp_path, profile(tmp_path), RunState.CREATED)

    release._finish_failure(
        run_workspace,
        failure,
        datetime(2026, 1, 2, tzinfo=UTC),
    )

    assert run_workspace.load().state is state
    assert json.loads(
        (run_workspace.root / "summary.json").read_text(encoding="utf-8")
    ) == {
        "failure": failure_value,
        "runId": run_workspace.run_id,
        "schemaVersion": 1,
        "state": state.value,
    }
