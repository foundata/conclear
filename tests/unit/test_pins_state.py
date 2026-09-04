"""Durable pin observations refuse malformed, foreign and future state."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from conclear.errors import OperationalError
from conclear.pins import PinObservation, PinStore
from conclear.presentation import Finding
from conclear.values import Digest, OCIReference
from tests.unit.test_pins import Resolver, pin

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def stored(tmp_path: Path) -> tuple[PinStore, Path]:
    store = PinStore(tmp_path)
    store.check(
        pin(),
        resolver=Resolver("sha256:" + "a" * 64),
        maximum_divergence=timedelta(days=7),
        now=NOW,
    )
    (path,) = list((tmp_path / "conclear" / "pins").glob("*.json"))
    return store, path


def rewrite(path: Path, mutate: Any) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_durable_pin_state_corruption_is_an_operational_failure(tmp_path: Path) -> None:
    store, path = stored(tmp_path)
    original = path.read_bytes()

    def expect(mutate: Any, message: str) -> None:
        rewrite(path, mutate)
        with pytest.raises(OperationalError, match=message):
            store.load_fresh(pin(), maximum_age=timedelta(days=1), now=NOW)
        path.write_bytes(original)

    expect(lambda value: value.update(schemaVersion=2), "malformed")
    expect(
        lambda value: value.update(
            reference="quay.io/example/other:1@sha256:" + "a" * 64
        ),
        "identity does not match",
    )
    expect(lambda value: value.update(findings={}), "findings are malformed")
    expect(lambda value: value.update(findings=[1]), "finding is malformed")
    expect(
        lambda value: value.update(
            findings=[
                {
                    "checkId": "CC0204",
                    "severity": "error",
                    "message": "x",
                    "location": 3,
                }
            ]
        ),
        "location is malformed",
    )
    expect(lambda value: value.update(checkedAt="soon"), "timestamp is malformed")
    expect(
        lambda value: value.update(checkedAt="2026-01-01T00:00:00"),
        "not timezone-aware",
    )
    expect(lambda value: value.update(historyInitialized="yes"), "boolean field")
    expect(lambda value: value.update(pinnedDigest=""), "string field")
    expect(
        lambda value: value.update(
            observedDigest="sha256:" + "b" * 64, divergenceSince=None
        ),
        "does not match observed digest",
    )


def test_fresh_observations_respect_age_and_ordering(tmp_path: Path) -> None:
    store, _ = stored(tmp_path)

    loaded = store.load_fresh(pin(), maximum_age=timedelta(days=1), now=NOW)
    assert loaded.observed_digest == Digest("sha256:" + "a" * 64)

    with pytest.raises(OperationalError, match="in the future"):
        store.load_fresh(
            pin(), maximum_age=timedelta(days=1), now=NOW - timedelta(seconds=1)
        )
    with pytest.raises(OperationalError, match="No durable pin observation"):
        PinStore(tmp_path / "empty").load_fresh(
            pin(), maximum_age=timedelta(days=1), now=NOW
        )
    with pytest.raises(OperationalError, match="in the future"):
        store.check(
            pin(),
            resolver=Resolver("sha256:" + "a" * 64),
            maximum_divergence=timedelta(days=7),
            now=NOW - timedelta(days=1),
        )
    with pytest.raises(OperationalError, match="timezone-aware"):
        store.check(
            pin(),
            resolver=Resolver("sha256:" + "a" * 64),
            maximum_divergence=timedelta(days=7),
            now=datetime(2026, 1, 2),  # noqa: DTZ001
        )


def test_divergence_start_cannot_move_into_the_future(tmp_path: Path) -> None:
    store, path = stored(tmp_path)
    store.check(
        pin(),
        resolver=Resolver("sha256:" + "b" * 64),
        maximum_divergence=timedelta(days=7),
        now=NOW + timedelta(days=1),
    )
    rewrite(path, lambda value: value.update(divergenceSince="2026-01-10T00:00:00Z"))

    with pytest.raises(OperationalError, match="start time is in the future"):
        store.check(
            pin(),
            resolver=Resolver("sha256:" + "b" * 64),
            maximum_divergence=timedelta(days=7),
            now=NOW + timedelta(days=2),
        )


def test_observation_invariants_reject_inconsistent_values() -> None:
    reference = OCIReference.parse(
        "quay.io/example/base:1@sha256:" + "a" * 64,
        require_tag=True,
        require_digest=True,
    )
    digest = Digest("sha256:" + "a" * 64)
    with pytest.raises(OperationalError, match="tagged digest reference"):
        PinObservation(
            OCIReference.parse("quay.io/example/base:1"),
            digest,
            digest,
            NOW,
            None,
            True,
            (),
        )
    with pytest.raises(OperationalError, match="differs from its reference"):
        PinObservation(
            reference, Digest("sha256:" + "b" * 64), digest, NOW, None, True, ()
        )
    with pytest.raises(OperationalError, match="timezone-aware"):
        PinObservation(reference, digest, digest, datetime(2026, 1, 1), None, True, ())  # noqa: DTZ001
    with pytest.raises(
        OperationalError, match="divergence time must be timezone-aware"
    ):
        PinObservation(
            reference,
            digest,
            Digest("sha256:" + "b" * 64),
            NOW,
            datetime(2026, 1, 1),  # noqa: DTZ001
            True,
            (),
        )
    with pytest.raises(OperationalError, match="does not match observed digest"):
        PinObservation(reference, digest, digest, NOW, NOW, True, ())
    observation = PinObservation(
        reference,
        digest,
        Digest("sha256:" + "b" * 64),
        NOW,
        NOW,
        False,
        (Finding("CC0205", "warning", "review"),),
    )
    assert observation.accepted
    assert observation.to_dict()["divergenceSince"] == "2026-01-01T00:00:00Z"
