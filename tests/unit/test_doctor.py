import platform
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast, override

import pytest

import conclear.services.doctor as doctor_module
from conclear.config import load_repository_config
from conclear.dependencies import DOCTOR_SCOPES
from conclear.errors import ExitStatus, InvalidInvocationError, OperationalError
from conclear.services.doctor import DoctorScope, diagnose_environment
from conclear.values import Platform
from tests.registry_policy_fixtures import STRICT_POLICY
from tests.release_fakes import FakeRegistryControl


class _FakeTool:
    def __init__(self, calls: list[str], name: str) -> None:
        self.calls = calls
        self.name = name

    def info(self, *, root: Path, runroot: Path) -> dict[str, object]:
        del root, runroot
        self.calls.append(f"{self.name}.info")
        return {}

    def initialize(self) -> None:
        self.calls.append(f"{self.name}.initialize")


class _FakeRuntime:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[str] = []
        self.identities: tuple[object, ...] = ()

    def buildah(self) -> _FakeTool:
        return _FakeTool(self.calls, "buildah")

    def podman(self) -> _FakeTool:
        return _FakeTool(self.calls, "podman")

    def cosign(self) -> _FakeTool:
        return _FakeTool(self.calls, "cosign")

    def assert_unchanged(self) -> None:
        self.calls.append("assert_unchanged")


class _UnexpectedRegistryControl:
    @property
    def provider(self) -> str:
        return "quay"

    def observe_tag(self, repository: object, tag: str) -> None:
        del repository, tag
        pytest.fail("doctor must not probe the registry in this scope")


class _FakeRegistryControl(FakeRegistryControl):
    def __init__(self) -> None:
        super().__init__({})
        self.observed = 0

    @override
    def observe_tag(self, repository: object, tag: str) -> None:
        del repository, tag
        self.observed += 1


def _profile(**changes: Any) -> Any:
    values: dict[str, Any] = {
        "name": "production",
        "auth_file": Path("/secure/auth.json"),
        "cosign_private_key": "/secure/cosign.key",
        "registry": SimpleNamespace(
            token_file=Path("/secure/quay.token"), policy=STRICT_POLICY
        ),
    }
    values.update(changes)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"auth_file": None}, "has no auth_file for registry writes"),
        ({"cosign_private_key": None}, "has no Cosign signing key"),
    ],
)
def test_release_scope_refuses_a_profile_that_cannot_write_or_sign(
    repository_factory: Any, tmp_path: Path, changes: dict[str, Any], expected: str
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")
    runtime = _FakeRuntime(tmp_path)

    with pytest.raises(InvalidInvocationError, match=expected):
        diagnose_environment(
            repository,
            cast(Any, runtime),
            scope=DoctorScope.RELEASE,
            profile=_profile(**changes),
            registry_control=cast(Any, _UnexpectedRegistryControl()),
        )
    assert runtime.calls == []


def test_qualify_scope_accepts_a_profile_without_write_or_signing_inputs(
    repository_factory: Any, tmp_path: Path
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")

    observation = diagnose_environment(
        repository,
        cast(Any, _FakeRuntime(tmp_path)),
        scope=DoctorScope.QUALIFY,
        profile=_profile(auth_file=None, cosign_private_key=None),
    )

    assert observation.scope is DoctorScope.QUALIFY


def test_scopes_match_the_declared_doctor_scopes() -> None:
    assert tuple(item.value for item in DoctorScope) == tuple(DOCTOR_SCOPES)


def test_release_scope_probes_registry_and_sigstore(
    repository_factory: Any, tmp_path: Path
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")
    registry_control = _FakeRegistryControl()
    runtime = _FakeRuntime(tmp_path)

    observation = diagnose_environment(
        repository,
        cast(Any, runtime),
        scope=DoctorScope.RELEASE,
        profile=_profile(),
        registry_control=cast(Any, registry_control),
        version="1.2.3",
    )

    assert observation.scope is DoctorScope.RELEASE
    assert observation.registry_provider == "quay"
    assert observation.registry_access and observation.sigstore_access
    assert registry_control.observed == len(repository.images)
    assert runtime.calls == [
        "buildah.info",
        "podman.info",
        "cosign.initialize",
        "assert_unchanged",
    ]


def test_release_scope_needs_a_profile_and_registry_backend(
    repository_factory: Any, tmp_path: Path
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")

    with pytest.raises(InvalidInvocationError, match="needs a release profile"):
        diagnose_environment(
            repository, cast(Any, _FakeRuntime(tmp_path)), scope=DoctorScope.RELEASE
        )


def test_qualify_scope_checks_storage_and_execution_only(
    repository_factory: Any, tmp_path: Path
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")
    runtime = _FakeRuntime(tmp_path)

    observation = diagnose_environment(
        repository,
        cast(Any, runtime),
        scope=DoctorScope.QUALIFY,
        registry_control=cast(Any, _UnexpectedRegistryControl()),
    )

    assert observation.scope is DoctorScope.QUALIFY
    assert observation.registry_provider is None
    assert not observation.registry_access and not observation.sigstore_access
    assert runtime.calls == ["buildah.info", "podman.info", "assert_unchanged"]


def test_check_scope_touches_no_storage_registry_or_signing(
    repository_factory: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")
    runtime = _FakeRuntime(tmp_path)
    monkeypatch.setattr(
        doctor_module,
        "binfmt_handler",
        lambda architecture: pytest.fail("check scope must not inspect binfmt"),
    )

    observation = diagnose_environment(
        repository, cast(Any, runtime), scope=DoctorScope.CHECK
    )

    assert observation.scope is DoctorScope.CHECK
    assert observation.emulated_architectures == ()
    assert runtime.calls == ["assert_unchanged"]


@pytest.mark.parametrize("scope", [DoctorScope.QUALIFY, DoctorScope.RELEASE])
def test_missing_binfmt_handler_is_an_operational_failure(
    repository_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scope: DoctorScope,
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")
    image = repository.release_image("app")
    repository = replace(
        repository,
        images=(
            replace(
                image,
                platforms=(
                    Platform.parse("linux/amd64"),
                    Platform.parse("linux/arm64"),
                ),
            ),
        ),
    )
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(doctor_module, "binfmt_handler", lambda architecture: None)

    with pytest.raises(OperationalError) as raised:
        diagnose_environment(
            repository,
            cast(Any, _FakeRuntime(tmp_path)),
            scope=scope,
            profile=_profile(),
            registry_control=cast(Any, _UnexpectedRegistryControl()),
        )

    assert raised.value.exit_status is ExitStatus.OPERATIONAL_FAILURE
    assert raised.value.code is None


def test_check_scope_needs_no_repository_configuration(tmp_path: Path) -> None:
    observation = diagnose_environment(
        None, cast(Any, _FakeRuntime(tmp_path)), scope=DoctorScope.CHECK
    )

    assert observation.scope is DoctorScope.CHECK


def test_other_scopes_require_the_repository_configuration(tmp_path: Path) -> None:
    with pytest.raises(InvalidInvocationError, match="needs the repository"):
        diagnose_environment(
            None, cast(Any, _FakeRuntime(tmp_path)), scope=DoctorScope.QUALIFY
        )
