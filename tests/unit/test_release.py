from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from conclear.config import ReleaseMode, ReleaseProfile
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.services import release
from conclear.services.release import ReleaseRequest
from conclear.workspace import RunState, RunWorkspace


class FixedIdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def profile(tmp_path: Path) -> ReleaseProfile:
    return ReleaseProfile(
        name="production",
        mode=ReleaseMode.LOCAL,
        auth_file=None,
        quay_token_file=tmp_path / "quay-token",
        cosign_private_key=str(tmp_path / "cosign.key"),
        cosign_public_key=tmp_path / "cosign.pub",
        passphrase_file=None,
        quay_api_url="https://quay.io/api/v1",
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
            "mode": profile_value.mode.value,
            "profileConfigurationDigest": profile_value.configuration_digest,
            "profilePublicKeyDigest": profile_value.public_key_digest,
        },
        id_factory=FixedIdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
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
            ci_identity=None,
        )


def test_release_does_not_promote_until_verification_transitions_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_value = profile(tmp_path)
    run_workspace = workspace(tmp_path, profile_value, RunState.ATTESTED)
    published = SimpleNamespace(immutable_reference=object())
    image = object()
    repository = SimpleNamespace(image=lambda _image_id: image)
    runtime = SimpleNamespace(
        skopeo=lambda: object(),
        cosign=lambda: object(),
    )
    quay = SimpleNamespace(close=lambda: None)
    monkeypatch.setattr(release, "load_candidate", lambda *_args: object())
    monkeypatch.setattr(release, "load_release_evidence", lambda *_args: object())
    monkeypatch.setattr(release, "load_published", lambda *_args: published)
    monkeypatch.setattr(release, "quay_adapter", lambda _profile: quay)
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
        ci_identity=None,
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
