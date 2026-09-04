import platform
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

import conclear.services.doctor as doctor_module
from conclear.config import load_repository_config
from conclear.errors import ExitStatus, OperationalError
from conclear.services.doctor import diagnose_environment
from conclear.values import Platform


class _FakeTool:
    def info(self, *, root: Path, runroot: Path) -> dict[str, object]:
        del root, runroot
        return {}

    def initialize(self) -> None:
        pass


class _FakeRuntime:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._tool = _FakeTool()
        self.identities: tuple[object, ...] = ()

    def buildah(self) -> _FakeTool:
        return self._tool

    def podman(self) -> _FakeTool:
        return self._tool

    def cosign(self) -> _FakeTool:
        return self._tool

    def assert_unchanged(self) -> None:
        pass


class _UnexpectedRegistryControl:
    @property
    def provider(self) -> str:
        return "quay"

    def observe_tag(self, repository: object, tag: str) -> None:
        del repository, tag
        pytest.fail("doctor must reject missing binfmt before probing the registry")


class _FakeRegistryControl:
    def __init__(self) -> None:
        self.observed = 0

    @property
    def provider(self) -> str:
        return "quay"

    def observe_tag(self, repository: object, tag: str) -> None:
        del repository, tag
        self.observed += 1


def test_doctor_reports_selected_registry_backend(
    repository_factory: Any, tmp_path: Path
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")
    registry_control = _FakeRegistryControl()

    observation = diagnose_environment(
        repository,
        cast(Any, object()),
        cast(Any, _FakeRuntime(tmp_path)),
        registry_control=cast(Any, registry_control),
    )

    assert observation.registry_provider == "quay"
    assert observation.registry_access
    assert registry_control.observed == len(repository.images)


def test_missing_binfmt_handler_is_an_operational_failure(
    repository_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")
    image = repository.image("app")
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
            cast(Any, object()),
            cast(Any, _FakeRuntime(tmp_path)),
            registry_control=cast(Any, _UnexpectedRegistryControl()),
        )

    assert raised.value.exit_status is ExitStatus.OPERATIONAL_FAILURE
    assert raised.value.code is None
