from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from conclear.adapters.trivy import DatabaseObservation
from conclear.database import select_database_by_digest
from conclear.errors import OperationalError, RuleRejectionError
from conclear.freshness import (
    QUALIFICATION_WINDOW,
    QualificationWindow,
    common_window,
    evidence_window,
)
from conclear.jsonutil import load_json
from conclear.records import format_timestamp, validate_record
from conclear.services import release
from conclear.services.assembly import assemble_candidate
from conclear.services.promotion import promote_candidate
from conclear.services.qualification import qualify_platform
from conclear.values import Digest
from conclear.workspace import RunState
from tests.release_fakes import FakeBaseResolver
from tests.unit.test_assembly_verification import Scenario as AssemblyScenario
from tests.unit.test_publication_resume import Scenario as PublicationScenario
from tests.unit.test_qualification import (
    DATABASE_METADATA,
    Builder,
    Runtime,
    Scanner,
    closure_preflight,
    hook_runner,
    inputs,
)
from tests.unit.test_release_workflow import Harness
from tests.unit.test_runtime_inputs import FakeDatabase, database_metadata

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_window_is_one_day_and_exact_expiry_rejects() -> None:
    assert QUALIFICATION_WINDOW == timedelta(hours=24)
    window = QualificationWindow.start(NOW)
    window.require_current(
        NOW + QUALIFICATION_WINDOW - timedelta(seconds=1), phase="publication"
    )
    with pytest.raises(RuleRejectionError, match="expired before publication"):
        window.require_current(NOW + QUALIFICATION_WINDOW, phase="publication")


def test_window_rejects_future_start() -> None:
    with pytest.raises(RuleRejectionError, match="future"):
        QualificationWindow.start(NOW).require_current(
            NOW - timedelta(seconds=1), phase="qualification"
        )


def test_compiled_limit_can_shorten_but_never_renew_recorded_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    window = QualificationWindow.start(NOW)
    monkeypatch.setattr("conclear.freshness.QUALIFICATION_WINDOW", timedelta(hours=2))
    historical = QualificationWindow.from_dict(window.to_dict())
    assert historical == window
    with pytest.raises(RuleRejectionError):
        historical.require_current(NOW + timedelta(hours=2), phase="publication")
    monkeypatch.setattr("conclear.freshness.QUALIFICATION_WINDOW", timedelta(days=2))
    with pytest.raises(RuleRejectionError):
        historical.require_current(NOW + timedelta(days=1), phase="publication")


@pytest.mark.parametrize(
    "started_at", [None, NOW - timedelta(days=30), NOW + timedelta(days=1)]
)
def test_digest_selection_cannot_bless_old_data_or_renew_a_window(
    tmp_path: Path, started_at: datetime | None
) -> None:
    digest = Digest("sha256:" + "a" * 64)
    selected = DatabaseObservation(
        tmp_path, str(digest), database_metadata("2026-01-01T06:00:00Z")
    )
    adapter = FakeDatabase(selected, selected)
    with pytest.raises(RuleRejectionError):
        select_database_by_digest(
            adapter,
            tmp_path,
            expected_digest=digest,
            now=NOW + timedelta(hours=12),
            qualification_started_at=started_at,
        )
    assert adapter.refreshes == 0


def test_pinned_worker_can_finish_after_next_update_within_original_window(
    tmp_path: Path,
) -> None:
    digest = Digest("sha256:" + "a" * 64)
    selected = DatabaseObservation(
        tmp_path, str(digest), database_metadata("2026-01-01T06:00:00Z")
    )
    adapter = FakeDatabase(selected, selected)
    assert (
        select_database_by_digest(
            adapter,
            tmp_path,
            expected_digest=digest,
            now=NOW + timedelta(hours=12),
            qualification_started_at=NOW,
        )
        is selected
    )
    assert adapter.refreshes == 0
    with pytest.raises(RuleRejectionError, match="expired"):
        select_database_by_digest(
            adapter,
            tmp_path,
            expected_digest=digest,
            now=NOW + timedelta(days=1),
            qualification_started_at=NOW,
        )


def payload(start: datetime = NOW) -> dict[str, Any]:
    return {
        "qualificationWindow": QualificationWindow.start(start).to_dict(),
        "testImageDependencies": [],
        "effectiveLimits": {
            "pinFreshnessSeconds": 86400,
            "pinDivergenceSeconds": 604800,
        },
        "pinObservations": [],
        "appliedExceptions": [],
        "packageAssessment": {
            "status": "assessed",
            "operatingSystem": "debian 13",
            "packages": 1,
            "reason": None,
            "exception": None,
        },
    }


@pytest.mark.parametrize("dependency", [False, True])
def test_pin_freshness_shortens_approval_for_every_image(dependency: bool) -> None:
    value = payload()
    image = payload() if dependency else value
    image["pinObservations"] = [
        {"checkedAt": format_timestamp(NOW - timedelta(hours=23))}
    ]
    if dependency:
        value["testImageDependencies"] = [image]
    assert evidence_window(value).expires_at == NOW + timedelta(hours=1)


def test_pin_divergence_deadline_is_not_extended_by_recent_resolution() -> None:
    value = payload()
    value["pinObservations"] = [
        {
            "checkedAt": format_timestamp(NOW),
            "divergenceSince": format_timestamp(
                NOW - timedelta(days=7) + timedelta(hours=1)
            ),
        }
    ]
    assert evidence_window(value).expires_at == NOW + timedelta(hours=1)


def test_applied_exception_expires_at_end_of_its_utc_date() -> None:
    value = payload(NOW + timedelta(hours=23))
    value["appliedExceptions"] = [{"expires": "2026-01-01"}]
    assert evidence_window(value).expires_at == NOW + timedelta(days=1)


def test_common_window_keeps_earliest_start_and_expiry() -> None:
    early = QualificationWindow.start(NOW)
    later = QualificationWindow(NOW + timedelta(hours=2), NOW + timedelta(hours=3))
    assert common_window((early, later)) == QualificationWindow(NOW, later.expires_at)


def test_delayed_assembly_rejects_without_creating_a_candidate(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = AssemblyScenario(tmp_path, repository_factory, monkeypatch)
    transport = scenario.transport()
    with pytest.raises(RuleRejectionError, match="expired before assembly"):
        assemble_candidate(
            (transport,),
            repository=scenario.repository,
            image=scenario.image,
            workspace=scenario.workspace,
            version="1.2.3",
            source_time=NOW,
            tools=(scenario.tool,),
            now=NOW + timedelta(days=1),
            clock=lambda: NOW + timedelta(days=1),
        )
    assert scenario.workspace.load().state is RunState.QUALIFIED
    assert scenario.workspace.journal.entries() == ()
    # Historical record validation remains available after release approval expires.
    validate_record(load_json(transport.record_path))


@pytest.mark.parametrize("resume", [False, True])
def test_expired_qualification_prevents_upload_and_publication_resume(
    tmp_path: Path, repository_factory: Callable[..., Path], resume: bool
) -> None:
    scenario = PublicationScenario(tmp_path, repository_factory)
    if resume:
        scenario.journal_attempt()
        scenario.tags[scenario.tag] = scenario.observation.graph.digest
    before = dict(scenario.tags)
    with pytest.raises(RuleRejectionError, match="expired before publication"):
        scenario.publish(now=NOW + timedelta(days=1))
    assert scenario.tags == before
    assert scenario.registry_control.retention is None


@pytest.mark.parametrize(
    "phase", ["publish_candidate", "verify_candidate", "promote_candidate"]
)
def test_delayed_release_phase_cannot_renew_qualification(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    original = getattr(release, phase)

    def delayed(*args: Any, **kwargs: Any) -> Any:
        return original(*args, **{**kwargs, "now": NOW + timedelta(days=1)})

    monkeypatch.setattr(release, phase, delayed)
    with pytest.raises(RuleRejectionError, match="Qualification expired"):
        harness.complete()
    assert "1.2.3" not in harness.runtime.registry.tags
    assert "stable" not in harness.runtime.registry.tags


@pytest.mark.parametrize(
    "phase",
    [
        "assemble_candidate",
        "publish_candidate",
        "verify_candidate",
        "promote_candidate",
    ],
)
def test_phase_started_before_expiry_cannot_complete_after_deadline(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    original = getattr(release, phase)

    def slow(*args: Any, **kwargs: Any) -> Any:
        return original(*args, **{**kwargs, "clock": lambda: NOW + timedelta(days=1)})

    monkeypatch.setattr(release, phase, slow)
    with pytest.raises(RuleRejectionError, match="Qualification expired"):
        harness.complete()
    tags = harness.runtime.registry.tags
    assert "1.2.3" not in tags
    assert "stable" not in tags
    if phase == "publish_candidate":
        assert not tags


def test_promotion_rechecks_deadline_between_version_and_moving_tag_writes(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    original = promote_candidate

    def current_time() -> datetime:
        if "1.2.3" in harness.runtime.registry.tags:
            return NOW + timedelta(days=1)
        return NOW

    def slow(*args: Any, **kwargs: Any) -> Any:
        return original(*args, **{**kwargs, "clock": current_time})

    monkeypatch.setattr(release, "promote_candidate", slow)
    with pytest.raises(RuleRejectionError, match="expired before promotion"):
        harness.complete()
    assert "1.2.3" in harness.runtime.registry.tags
    assert "1.2.3" in harness.runtime.registry_control.immutable
    assert "stable" not in harness.runtime.registry.tags


def test_publication_resume_rechecks_deadline_after_remote_graph_copy(
    tmp_path: Path, repository_factory: Callable[..., Path]
) -> None:
    scenario = PublicationScenario(tmp_path, repository_factory)
    scenario.journal_attempt()
    scenario.tags[scenario.tag] = scenario.observation.graph.digest
    with pytest.raises(RuleRejectionError, match="expired before publication resume"):
        scenario.publish(clock=lambda: NOW + timedelta(days=1))
    assert scenario.workspace.load().state is RunState.ASSEMBLED


def test_qualification_cannot_complete_after_its_window(
    tmp_path: Path, repository_factory: Callable[..., Path]
) -> None:
    value = inputs(repository_factory(), tmp_path)
    with pytest.raises(
        RuleRejectionError, match="expired before qualification completion"
    ):
        qualify_platform(
            value,
            builder=Builder(),
            base_resolver=FakeBaseResolver(),
            runtime=Runtime(),
            hooks=hook_runner(value),
            scanner=Scanner(),
            database=DatabaseObservation(
                tmp_path, "sha256:" + "e" * 64, DATABASE_METADATA
            ),
            preflight=closure_preflight(value),
            now=NOW,
            record_clock=lambda: NOW + timedelta(days=1),
        )
    assert not list((value.workspace.root / "records").glob("platform-qualification-*"))


def test_resume_preserves_original_database_selection_and_start(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    original = qualify_platform

    def interrupted(*args: Any, **kwargs: Any) -> Any:
        raise OperationalError("worker interrupted")

    monkeypatch.setattr(release, "qualify_platform", interrupted)
    with pytest.raises(OperationalError, match="worker interrupted"):
        harness.complete()
    recorded = harness.workspace.load().immutable_inputs
    assert recorded["qualificationStartedAt"] == format_timestamp(NOW)
    monkeypatch.setattr(release, "qualify_platform", original)
    calls: list[dict[str, Any]] = []

    def exact(*args: Any, **kwargs: Any) -> DatabaseObservation:
        calls.append(kwargs)
        return DatabaseObservation(
            tmp_path, recorded["qualificationDatabaseDigest"], DATABASE_METADATA
        )

    monkeypatch.setattr(release, "select_database_by_digest", exact)
    harness.resume()
    assert calls[0]["qualification_started_at"] == NOW
    assert str(calls[0]["expected_digest"]) == recorded["qualificationDatabaseDigest"]


def test_expired_resume_cannot_promote_a_signed_approval(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    original = promote_candidate

    def interrupted(*args: Any, **kwargs: Any) -> Any:
        raise OperationalError("promotion interrupted")

    monkeypatch.setattr(release, "promote_candidate", interrupted)
    with pytest.raises(OperationalError, match="promotion interrupted"):
        harness.complete()
    monkeypatch.setattr(release, "promote_candidate", original)
    monkeypatch.setattr(release, "cleanup_run", lambda *args, **kwargs: None)
    with pytest.raises(RuleRejectionError, match="expired before promotion"):
        harness.resume(now_factory=lambda: NOW + timedelta(days=1))
    assert "1.2.3" not in harness.runtime.registry.tags
    assert "stable" not in harness.runtime.registry.tags
