"""Per-component Trivy database freshness and the Java database verdict."""

from datetime import UTC, datetime

import pytest

from conclear.database import (
    database_freshness,
    evaluate_java_database,
    require_database_fresh_at,
)
from conclear.errors import OperationalError, RuleRejectionError
from tests.unit.test_runtime_inputs import database_metadata

NOW = datetime(2026, 1, 1, 12, tzinfo=UTC)
FRESH = "2026-01-02T00:00:00Z"
EXPIRED = "2025-12-31T00:00:00Z"


def test_freshness_judges_each_component_separately() -> None:
    both = database_freshness(database_metadata(FRESH), NOW)
    java_stale = database_freshness(
        database_metadata(FRESH, java_next_update=EXPIRED), NOW
    )

    assert (both.vulnerability, both.java) == (True, True)
    assert (java_stale.vulnerability, java_stale.java) == (True, False)
    assert java_stale.java_next_update == datetime(2025, 12, 31, tzinfo=UTC)


def test_freshness_rejects_metadata_without_a_java_component() -> None:
    metadata = database_metadata(FRESH)
    del metadata["java"]

    with pytest.raises(OperationalError, match="java database metadata is malformed"):
        database_freshness(metadata, NOW)


def test_required_freshness_rejects_only_the_vulnerability_component_by_default() -> (
    None
):
    metadata = database_metadata(FRESH, java_next_update=EXPIRED)

    freshness = require_database_fresh_at(metadata, NOW)

    assert freshness.java is False


def test_required_freshness_rejects_a_stale_vulnerability_component() -> None:
    with pytest.raises(RuleRejectionError, match="vulnerability database") as caught:
        require_database_fresh_at(database_metadata(EXPIRED), NOW)

    assert caught.value.code == "CC0505"


def test_required_freshness_rejects_a_required_stale_java_component() -> None:
    metadata = database_metadata(FRESH, java_next_update=EXPIRED)

    with pytest.raises(RuleRejectionError, match="Java artifacts") as caught:
        require_database_fresh_at(metadata, NOW, java_required=True)

    assert caught.value.code == "CC0507"


def test_java_verdict_is_silent_without_java_artifacts() -> None:
    metadata = database_metadata(FRESH, java_next_update=EXPIRED)

    evidence = evaluate_java_database(
        metadata, at=NOW, artifacts=0, accepted_stale=False
    )

    assert evidence.finding is None
    assert evidence.to_dict() == {
        "fresh": False,
        "required": False,
        "acceptedStale": False,
        "artifacts": 0,
    }


def test_java_verdict_is_silent_with_a_fresh_java_database() -> None:
    evidence = evaluate_java_database(
        database_metadata(FRESH), at=NOW, artifacts=4, accepted_stale=False
    )

    assert evidence.finding is None
    assert evidence.to_dict() == {
        "fresh": True,
        "required": True,
        "acceptedStale": False,
        "artifacts": 4,
    }


def test_java_verdict_rejects_java_artifacts_against_a_stale_java_database() -> None:
    metadata = database_metadata(FRESH, java_next_update=EXPIRED)

    evidence = evaluate_java_database(
        metadata, at=NOW, artifacts=2, accepted_stale=False
    )

    assert evidence.finding is not None
    assert evidence.finding.check_id == "CC0507"
    assert evidence.finding.severity == "error"
    assert "2 Java artifacts" in evidence.finding.message
    assert "2025-12-31T00:00:00Z" in evidence.finding.message
    assert evidence.to_dict() == {
        "fresh": False,
        "required": True,
        "acceptedStale": False,
        "artifacts": 2,
    }


def test_java_verdict_warns_once_the_maintainer_accepted_the_risk() -> None:
    metadata = database_metadata(FRESH, java_next_update=EXPIRED)

    evidence = evaluate_java_database(
        metadata, at=NOW, artifacts=2, accepted_stale=True
    )

    assert evidence.finding is not None
    assert evidence.finding.check_id == "CC0507"
    assert evidence.finding.severity == "warning"
    assert evidence.to_dict() == {
        "fresh": False,
        "required": True,
        "acceptedStale": True,
        "artifacts": 2,
    }


def test_java_verdict_uses_the_supplied_instant_not_the_wall_clock() -> None:
    metadata = database_metadata(FRESH, java_next_update="2026-01-01T06:00:00Z")

    before = evaluate_java_database(
        metadata,
        at=datetime(2026, 1, 1, 5, tzinfo=UTC),
        artifacts=1,
        accepted_stale=False,
    )
    after = evaluate_java_database(
        metadata,
        at=datetime(2026, 1, 1, 7, tzinfo=UTC),
        artifacts=1,
        accepted_stale=False,
    )

    assert before.fresh is True
    assert before.finding is None
    assert after.fresh is False
    assert after.finding is not None
