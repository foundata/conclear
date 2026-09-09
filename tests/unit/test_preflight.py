"""The closure preflight gates every test dependency before any build."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from conclear.config import load_repository_config
from conclear.errors import InvalidInvocationError
from conclear.pins import PinStore
from conclear.services.preflight import ClosurePreflight, preflight_image_closure
from conclear.values import Digest, OCIReference
from tests.unit.test_config import _image_text

NOW = datetime(2026, 1, 1, tzinfo=UTC)
BASE = "quay.io/example/base:1@sha256:" + "a" * 64
HELPER_BASE = "quay.io/example/helper-base:2@sha256:" + "b" * 64


class Hadolint:
    def check(self, containerfile: Path, *, config_directory: Path) -> list[Any]:
        return []


class Resolver:
    def __init__(self, digests: dict[str, str]) -> None:
        self.digests = digests
        self.requests: list[str] = []

    def resolve_digest(self, reference: OCIReference) -> Digest:
        self.requests.append(str(reference))
        return Digest(self.digests[str(reference)])


def _containerfile(base: str) -> str:
    return (
        f"FROM {base} AS helper\n"
        'LABEL org.opencontainers.image.source="https://github.com/example/app"\n'
        "USER 10001:10001\n"
        'ENTRYPOINT ["/helper"]\n'
    )


def _helper_repository(
    repository_factory: Callable[..., Path],
    *,
    containerfile: str,
    pins: tuple[str, ...],
    limits: str = "",
) -> Path:
    root = repository_factory()
    (root / "Containerfile.helper").write_text(containerfile, encoding="utf-8")
    tables = "".join(
        f'\n[[images.pins]]\nreference = "{pin.split("@")[0]}"\ntag_intent = "immutable-version"\n'
        for pin in pins
    )
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8").replace(
        "[images.release]",
        '[images.test]\ndependencies = ["helper"]\n\n[images.release]',
    )
    path.write_text(
        content
        + _image_text(
            "helper",
            releasable=False,
            keys='containerfile = "Containerfile.helper"\n',
            tables=tables + limits,
        ),
        encoding="utf-8",
    )
    return root


def _preflight(
    root: Path, tmp_path: Path, resolver: Resolver, *, store: PinStore | None = None
) -> ClosurePreflight:
    repository = load_repository_config(root / "conclear.toml")
    return preflight_image_closure(
        repository,
        repository.release_image("app"),
        hadolint=cast(Any, Hadolint()),
        store=store or PinStore(tmp_path / "state"),
        resolver=resolver,
        now=NOW,
    )


def test_closure_preflight_gates_every_dependency_and_resolves_a_shared_tag_once(
    repository_factory: Callable[..., Path], tmp_path: Path
) -> None:
    root = _helper_repository(
        repository_factory, containerfile=_containerfile(BASE), pins=(BASE,)
    )
    resolver = Resolver({"quay.io/example/base:1": "sha256:" + "a" * 64})

    preflight = _preflight(root, tmp_path, resolver)

    assert preflight.accepted
    assert preflight.findings == ()
    assert [item.image.image_id for item in preflight.images] == ["helper", "app"]
    assert resolver.requests == ["quay.io/example/base:1"]
    assert [
        (str(item.reference), str(item.observed_digest))
        for image in preflight.images
        for item in image.pin_observations
    ] == [(BASE, "sha256:" + "a" * 64)] * 2


def test_closure_preflight_rejects_an_undeclared_dependency_input_before_resolving(
    repository_factory: Callable[..., Path], tmp_path: Path
) -> None:
    root = _helper_repository(
        repository_factory, containerfile=_containerfile(HELPER_BASE), pins=()
    )
    resolver = Resolver({"quay.io/example/base:1": "sha256:" + "a" * 64})

    preflight = _preflight(root, tmp_path, resolver)

    assert not preflight.accepted
    assert preflight.primary.accepted
    errors = [
        item for item in preflight.dependencies[0].findings if item.severity == "error"
    ]
    assert [item.check_id for item in errors] == ["CC0203"]
    assert HELPER_BASE in errors[0].message
    assert [item.image for item in preflight.findings if item.severity == "error"] == [
        "helper"
    ]
    assert resolver.requests == []
    assert all(item.pin_observations == () for item in preflight.images)


def test_closure_preflight_rejects_an_unpinned_dependency_input(
    repository_factory: Callable[..., Path], tmp_path: Path
) -> None:
    root = _helper_repository(
        repository_factory,
        containerfile=_containerfile("quay.io/example/helper-base:2"),
        pins=(),
    )
    resolver = Resolver({"quay.io/example/base:1": "sha256:" + "a" * 64})

    preflight = _preflight(root, tmp_path, resolver)

    assert not preflight.accepted
    assert any(item.severity == "error" for item in preflight.dependencies[0].findings)
    assert resolver.requests == []


def test_closure_configuration_rejects_an_unused_dependency_pin_before_resolving(
    repository_factory: Callable[..., Path], tmp_path: Path
) -> None:
    root = _helper_repository(
        repository_factory, containerfile=_containerfile(BASE), pins=(BASE, HELPER_BASE)
    )
    resolver = Resolver({"quay.io/example/base:1": "sha256:" + "a" * 64})

    with pytest.raises(InvalidInvocationError, match="exactly one digest") as caught:
        _preflight(root, tmp_path, resolver)
    assert caught.value.code == "CC0203"
    assert resolver.requests == []


def test_closure_preflight_applies_each_dependency_pin_limit(
    repository_factory: Callable[..., Path], tmp_path: Path
) -> None:
    root = _helper_repository(
        repository_factory,
        containerfile=_containerfile(HELPER_BASE),
        pins=(HELPER_BASE,),
        limits='\n[images.limits]\npin_divergence = "1h"\n',
    )
    store = PinStore(tmp_path / "state")
    repository = load_repository_config(root / "conclear.toml")
    resolver = Resolver(
        {
            "quay.io/example/base:1": "sha256:" + "a" * 64,
            "quay.io/example/helper-base:2": "sha256:" + "c" * 64,
        }
    )
    store.check(
        repository.image("helper").pins[0],
        resolver=resolver,
        maximum_divergence=timedelta(hours=1),
        now=NOW - timedelta(hours=2),
    )

    preflight = _preflight(root, tmp_path, resolver, store=store)

    assert preflight.primary.accepted
    assert not preflight.accepted
    [error] = [item for item in preflight.pin_findings if item.severity == "error"]
    assert error.check_id == "CC0204"
    assert error.location == HELPER_BASE
    assert error.image == "helper"
    assert "1:00:00" in error.message
    assert sorted(resolver.requests[1:]) == [
        "quay.io/example/base:1",
        "quay.io/example/helper-base:2",
    ]


def test_closure_preflight_checks_transitive_dependencies_dependency_first(
    repository_factory: Callable[..., Path], tmp_path: Path
) -> None:
    root = repository_factory()
    (root / "Containerfile.helper").write_text(_containerfile(BASE), encoding="utf-8")
    (root / "Containerfile.tool").write_text(
        _containerfile(HELPER_BASE), encoding="utf-8"
    )
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8").replace(
        "[images.release]",
        '[images.test]\ndependencies = ["helper"]\n\n[images.release]',
    )
    path.write_text(
        content
        + _image_text(
            "helper",
            releasable=True,
            dependencies=("tool",),
            keys='containerfile = "Containerfile.helper"\n',
            tables=(
                f'\n[[images.pins]]\nreference = "{BASE.split("@")[0]}"\n'
                'tag_intent = "immutable-version"\n'
            ),
        )
        + _image_text(
            "tool",
            releasable=False,
            keys='containerfile = "Containerfile.tool"\n',
            tables=(
                f'\n[[images.pins]]\nreference = "{HELPER_BASE.split("@")[0]}"\n'
                'tag_intent = "immutable-version"\n'
                '\n[images.limits]\npin_divergence = "1h"\n'
            ),
        ),
        encoding="utf-8",
    )
    repository = load_repository_config(path)
    assert repository.image("helper").releasable
    store = PinStore(tmp_path / "state")
    resolver = Resolver(
        {
            "quay.io/example/base:1": "sha256:" + "a" * 64,
            "quay.io/example/helper-base:2": "sha256:" + "c" * 64,
        }
    )
    store.check(
        repository.image("tool").pins[0],
        resolver=resolver,
        maximum_divergence=timedelta(hours=1),
        now=NOW - timedelta(hours=2),
    )
    resolver.requests.clear()

    preflight = preflight_image_closure(
        repository,
        repository.release_image("app"),
        hadolint=cast(Any, Hadolint()),
        store=store,
        resolver=resolver,
        now=NOW,
    )

    assert [item.image.image_id for item in preflight.images] == [
        "tool",
        "helper",
        "app",
    ]
    assert resolver.requests == [
        "quay.io/example/helper-base:2",
        "quay.io/example/base:1",
    ]
    assert [item.accepted for item in preflight.images] == [False, True, True]
    [error] = [item for item in preflight.findings if item.severity == "error"]
    assert (error.check_id, error.image, error.location) == (
        "CC0204",
        "tool",
        HELPER_BASE,
    )
    assert all(
        observation.checked_at == NOW
        for image in preflight.images
        for observation in image.pin_observations
    )
