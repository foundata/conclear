"""Publication resume and attestation-retry paths driven by the ownership journal."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from conclear.config import load_repository_config
from conclear.errors import InvalidInvocationError, OperationalError, RuleRejectionError
from conclear.jsonutil import atomic_write_json
from conclear.layout_assembly import PlatformLayout, assemble_layout
from conclear.registry_control import TagObservation
from conclear.services.assembly import CandidateResult
from conclear.services.publication import publish_candidate
from conclear.values import Digest, OCIReference, Platform, candidate_tag
from conclear.workspace import ResourceKind, ResourceStatus, RunState, RunWorkspace
from tests.unit.test_publication import (
    FakeRegistry,
    FakeRegistryControl,
    IdFactory,
    platform_layout,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


class Scenario:
    def __init__(self, tmp_path: Path, repository_factory: Callable[..., Path]) -> None:
        repository = load_repository_config(repository_factory() / "conclear.toml")
        self.image = repository.image("app")
        self.workspace = RunWorkspace.create(
            state_home=tmp_path / "state",
            immutable_inputs={"sourceRevision": "b" * 40},
            id_factory=IdFactory(),
            now=NOW,
        )
        self.workspace.transition(RunState.QUALIFIED)
        self.workspace.transition(RunState.ASSEMBLED)
        layout = platform_layout(tmp_path / "qualified", "amd64")
        self.observation = assemble_layout(
            (PlatformLayout(Platform.parse("linux/amd64"), layout, "qualified"),),
            output_path=tmp_path / "candidate",
            output_reference="candidate",
        )
        record = self.workspace.root / "records" / "release-candidate.json"
        digest = atomic_write_json(record, {"accepted": True})
        self.tag = candidate_tag(
            version="1.2.3", run_id=self.workspace.run_id, source_revision="b" * 40
        )
        self.candidate = CandidateResult(
            record, digest, self.observation, self.tag, (), ()
        )
        self.tags: dict[str, Digest] = {}
        self.registry = FakeRegistry(self.observation.graph, self.tags)
        self.registry_control = FakeRegistryControl(self.tags)
        self.tagged = self.image.repository.with_tag(self.tag)

    def journal_attempt(
        self,
        *,
        digest: str | None = None,
        expiration: object = "2026-01-08T00:00:00Z",
        status: ResourceStatus = ResourceStatus.FAILED,
    ) -> None:
        metadata: dict[str, object] = {
            "digest": str(self.observation.graph.digest) if digest is None else digest
        }
        if expiration is not None:
            metadata["expiration"] = expiration
        self.workspace.journal.plan(
            resource_id="candidate",
            kind=ResourceKind.CANDIDATE_REFERENCE,
            identifier=str(self.tagged),
            ephemeral=True,
            metadata=metadata,
        )
        if status is not ResourceStatus.PLANNED:
            self.workspace.journal.update("candidate", status)

    def publish(self, *, now: datetime = NOW) -> Any:
        return publish_candidate(
            self.candidate,
            image=self.image,
            workspace=self.workspace,
            registry=self.registry,
            registry_control=self.registry_control,
            auth_file=None,
            now=now,
        )


@pytest.fixture
def scenario(tmp_path: Path, repository_factory: Callable[..., Path]) -> Scenario:
    return Scenario(tmp_path, repository_factory)


def test_resume_reuses_only_a_candidate_that_still_names_the_accepted_digest(
    scenario: Scenario,
) -> None:
    scenario.journal_attempt()
    scenario.tags[scenario.tag] = scenario.observation.graph.digest
    scenario.registry_control.expirations[scenario.tag] = datetime(
        2026, 1, 8, tzinfo=UTC
    )

    published = scenario.publish(now=datetime(2026, 1, 2, tzinfo=UTC))

    assert published.immutable_reference.digest == scenario.observation.graph.digest
    assert published.expiration == datetime(2026, 1, 8, tzinfo=UTC)
    assert scenario.registry.copied_layout_paths == [
        scenario.workspace.root / "layouts" / "app" / "remote-published-resume"
    ]
    entry = scenario.workspace.journal.entries()[0]
    assert entry.status is ResourceStatus.CREATED
    assert entry.metadata["immutabilityEnabled"] is False
    assert scenario.workspace.load().state is RunState.PUBLISHED


def test_resume_re_enforces_a_missing_expiration_before_continuing(
    scenario: Scenario,
) -> None:
    scenario.journal_attempt()
    scenario.tags[scenario.tag] = scenario.observation.graph.digest

    scenario.publish(now=datetime(2026, 1, 2, tzinfo=UTC))

    assert scenario.registry_control.expirations[scenario.tag] == datetime(
        2026, 1, 8, tzinfo=UTC
    )


def test_resume_refuses_a_candidate_whose_remote_digest_changed(
    scenario: Scenario,
) -> None:
    scenario.journal_attempt()
    scenario.tags[scenario.tag] = Digest("sha256:" + "9" * 64)

    with pytest.raises(InvalidInvocationError, match="cannot be reused"):
        scenario.publish()
    assert scenario.workspace.load().state is RunState.ASSEMBLED

    del scenario.tags[scenario.tag]
    with pytest.raises(InvalidInvocationError, match="cannot be reused"):
        scenario.publish()


def test_resume_rejects_malformed_or_expired_ownership_records(
    scenario: Scenario,
) -> None:
    scenario.tags[scenario.tag] = scenario.observation.graph.digest

    scenario.journal_attempt(digest="sha256:" + "8" * 64)
    with pytest.raises(InvalidInvocationError, match="digest journal is malformed"):
        scenario.publish()
    scenario.workspace.journal.update("candidate", ResourceStatus.REMOVED)

    scenario.journal_attempt(expiration=None)
    with pytest.raises(
        InvalidInvocationError, match="expiration journal must be a UTC RFC 3339"
    ):
        scenario.publish()
    scenario.workspace.journal.update("candidate", ResourceStatus.REMOVED)

    scenario.journal_attempt(expiration="not a time")
    with pytest.raises(
        InvalidInvocationError, match="expiration journal must be a UTC RFC 3339"
    ):
        scenario.publish()
    scenario.workspace.journal.update("candidate", ResourceStatus.REMOVED)

    scenario.journal_attempt()
    with pytest.raises(RuleRejectionError, match="expired before resume") as caught:
        scenario.publish(now=datetime(2026, 1, 8, tzinfo=UTC))
    assert caught.value.code == "CC0603"
    assert scenario.workspace.load().state is RunState.ASSEMBLED


def test_resume_requires_registry_control_to_agree_with_the_transport_view(
    scenario: Scenario,
) -> None:
    scenario.journal_attempt()
    scenario.tags[scenario.tag] = scenario.observation.graph.digest
    original_observe = scenario.registry_control.observe_tag
    scenario.registry_control.observe_tag = lambda repository, tag: None  # type: ignore[method-assign]

    with pytest.raises(OperationalError, match="differs during resume"):
        scenario.publish()

    scenario.registry_control.observe_tag = original_observe  # type: ignore[method-assign]

    def other_digest(repository: OCIReference, tag: str, expiration: datetime) -> Any:
        return _observation_with(original_observe(repository, tag), "7")

    scenario.registry_control.enforce_candidate_lifetime = other_digest  # type: ignore[method-assign]
    with pytest.raises(OperationalError, match="lifetime update observed another"):
        scenario.publish()


def test_ambiguous_candidate_ownership_journal_is_rejected(scenario: Scenario) -> None:
    scenario.journal_attempt()
    scenario.workspace.journal.plan(
        resource_id="candidate-second",
        kind=ResourceKind.CANDIDATE_REFERENCE,
        identifier=str(scenario.tagged),
        ephemeral=True,
        metadata={"digest": str(scenario.observation.graph.digest)},
    )

    with pytest.raises(InvalidInvocationError, match="ambiguous"):
        scenario.publish()


def test_publication_requires_assembled_state(scenario: Scenario) -> None:
    scenario.workspace.transition(RunState.PUBLISHED)

    with pytest.raises(InvalidInvocationError, match="requires assembled state"):
        scenario.publish()


def test_publication_records_unsupported_immutability_without_failing(
    scenario: Scenario,
) -> None:
    from conclear.errors import UnsupportedOperationError

    def unsupported(repository: OCIReference, tag: str) -> TagObservation:
        raise UnsupportedOperationError("immutability is not offered")

    scenario.registry_control.ensure_tag_immutable = unsupported  # type: ignore[method-assign]

    published = scenario.publish()

    assert published.immutability_enabled is False
    assert scenario.workspace.journal.entries()[0].metadata["immutabilityEnabled"] is (
        False
    )
    assert published.expiration == NOW + timedelta(days=7)


def _observation_with(observation: Any, character: str) -> Any:
    return TagObservation(
        observation.name,
        Digest("sha256:" + character * 64),
        observation.expiration,
        observation.immutable,
    )
