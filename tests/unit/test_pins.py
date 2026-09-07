from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conclear.config import PinConfig, PinIntent
from conclear.errors import OperationalError
from conclear.pins import MemoizedPinResolver, PinStore
from conclear.values import Digest, OCIReference


class Resolver:
    def __init__(self, digest: str) -> None:
        self.digest = Digest(digest)

    def resolve_digest(self, reference: OCIReference) -> Digest:
        assert reference.tag == "1"
        assert reference.digest is None
        return self.digest


def pin(intent: PinIntent = PinIntent.MOVING_RELEASE_LINE) -> PinConfig:
    return PinConfig(
        OCIReference.parse(
            "quay.io/example/base:1@sha256:" + "a" * 64,
            require_tag=True,
            require_digest=True,
        ),
        intent,
    )


def test_pin_store_initializes_and_then_rejects_expired_divergence(
    tmp_path: Path,
) -> None:
    store = PinStore(tmp_path)
    resolver = Resolver("sha256:" + "b" * 64)
    started = datetime(2026, 1, 1, tzinfo=UTC)

    first = store.check(
        pin(), resolver=resolver, maximum_divergence=timedelta(days=7), now=started
    )
    expired = store.check(
        pin(),
        resolver=resolver,
        maximum_divergence=timedelta(days=7),
        now=started + timedelta(days=7),
    )

    assert first.history_initialized
    assert first.accepted
    assert not expired.accepted
    assert expired.findings[0].check_id == "CC0204"


def test_pin_store_preserves_divergence_start_across_upstream_rebuilds(
    tmp_path: Path,
) -> None:
    store = PinStore(tmp_path)
    started = datetime(2026, 1, 1, tzinfo=UTC)

    first = store.check(
        pin(),
        resolver=Resolver("sha256:" + "b" * 64),
        maximum_divergence=timedelta(days=7),
        now=started,
    )
    expired = store.check(
        pin(),
        resolver=Resolver("sha256:" + "c" * 64),
        maximum_divergence=timedelta(days=7),
        now=started + timedelta(days=7),
    )

    assert first.divergence_since == started
    assert expired.divergence_since == started
    assert not expired.accepted
    assert expired.findings[0].check_id == "CC0204"


def test_immutable_tag_change_always_requires_review(tmp_path: Path) -> None:
    observation = PinStore(tmp_path).check(
        pin(PinIntent.IMMUTABLE_VERSION),
        resolver=Resolver("sha256:" + "b" * 64),
        maximum_divergence=timedelta(days=7),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert observation.findings[0].check_id == "CC0205"
    assert observation.findings[0].severity == "warning"


def test_pin_store_refuses_stale_observation(tmp_path: Path) -> None:
    store = PinStore(tmp_path)
    checked = datetime(2026, 1, 1, tzinfo=UTC)
    store.check(
        pin(),
        resolver=Resolver("sha256:" + "a" * 64),
        maximum_divergence=timedelta(days=7),
        now=checked,
    )

    with pytest.raises(OperationalError, match="stale"):
        store.load_fresh(
            pin(), maximum_age=timedelta(hours=24), now=checked + timedelta(days=2)
        )


def test_memoized_resolver_resolves_each_readable_tag_once() -> None:
    class Counting:
        def __init__(self) -> None:
            self.requests: list[str] = []

        def resolve_digest(self, reference: OCIReference) -> Digest:
            self.requests.append(str(reference))
            return Digest("sha256:" + str(len(self.requests)) * 64)

    inner = Counting()
    resolver = MemoizedPinResolver(inner)
    first = OCIReference.parse("quay.io/example/base:1")
    second = OCIReference.parse("quay.io/example/base:2")

    assert resolver.resolve_digest(first) == resolver.resolve_digest(first)
    assert resolver.resolve_digest(second) != resolver.resolve_digest(first)
    assert inner.requests == [str(first), str(second)]
