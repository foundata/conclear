"""Candidate publication with graph verification and a bounded lifetime.

`publish_candidate` copies the accepted subject to one unused generated
candidate tag, compares the complete remote descriptor graph with the accepted
one and enforces the candidate lifetime through the registry control plane.
The module also owns the remote-graph and retry-journal checks that the later
phases in `conclear.services.attestation`, `conclear.services.verification`
and `conclear.services.promotion` reuse.
"""

import logging
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.skopeo import RegistryCopyObservation
from conclear.config import ReleaseImageConfig
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.oci import OCIGraph, graph_fingerprint
from conclear.records import (
    format_timestamp,
    parse_timestamp,
)
from conclear.registry_control import CandidateRetentionObservation, RegistryControl
from conclear.services.assembly import CandidateResult
from conclear.values import CANDIDATE_TAG_PATTERN, Digest, OCIReference
from conclear.workspace import (
    ResourceEntry,
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
)

LOGGER = logging.getLogger(__name__)


class Registry(Protocol):
    """Skopeo operations used by publication workflows."""

    def resolve_digest(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest:
        """Resolve one registry reference."""
        ...

    def resolve_optional(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest | None:
        """Resolve an unambiguously optional tag."""
        ...

    def copy_layout_to_registry(
        self,
        *,
        layout_path: Path,
        layout_reference: str,
        destination: OCIReference,
        auth_file: Path | None,
    ) -> None:
        """Copy one complete local graph."""
        ...

    def copy_registry_to_layout(
        self,
        *,
        source: OCIReference,
        layout_path: Path,
        layout_reference: str,
        auth_file: Path | None,
    ) -> RegistryCopyObservation:
        """Copy and validate one complete remote graph."""
        ...


@dataclass(frozen=True, slots=True)
class PublishedCandidate:
    """A graph-verified candidate with a registry-enforced lifetime."""

    reference: OCIReference
    immutable_reference: OCIReference
    graph: OCIGraph
    expiration: datetime
    immutability_enabled: bool


def publish_candidate(
    candidate: CandidateResult,
    *,
    image: ReleaseImageConfig,
    workspace: RunWorkspace,
    registry: Registry,
    registry_control: RegistryControl,
    auth_file: Path | None,
    now: datetime,
) -> PublishedCandidate:
    """Publish one unused candidate, verify its graph and set bounded expiration."""
    if workspace.load().state is not RunState.ASSEMBLED:
        raise InvalidInvocationError("Candidate publication requires assembled state")
    tagged = image.repository.with_tag(candidate.candidate_tag)
    if re.fullmatch(CANDIDATE_TAG_PATTERN, candidate.candidate_tag) is None:
        raise InvalidInvocationError("Candidate name is outside the retention pattern")
    registry_control.verify_tag_policy(
        image.repository,
        immutable_tags=image.release.render_immutable(
            workspace.load().immutable_inputs.get("version") or None
        ),
        mutable_tags=(candidate.candidate_tag, *image.release.moving_tags),
    )
    existing_entries = [
        item
        for item in workspace.journal.entries()
        if item.kind is ResourceKind.CANDIDATE_REFERENCE
        and item.identifier == str(tagged)
    ]
    if existing_entries:
        if len(existing_entries) != 1:
            raise InvalidInvocationError("Candidate ownership journal is ambiguous")
        return _resume_published_candidate(
            candidate,
            tagged=tagged,
            entry=existing_entries[0],
            image=image,
            workspace=workspace,
            registry=registry,
            registry_control=registry_control,
            auth_file=auth_file,
            now=now,
        )
    if registry.resolve_optional(tagged, auth_file=auth_file) is not None:
        raise OperationalError(f"Generated candidate tag is already in use: {tagged}")
    retention = _require_candidate_retention(image, registry_control)
    expiration = now.astimezone(UTC) + image.release_limits.candidate_lifetime
    workspace.journal.plan(
        resource_id="candidate",
        kind=ResourceKind.CANDIDATE_REFERENCE,
        identifier=str(tagged),
        ephemeral=True,
        metadata={
            "digest": str(candidate.observation.graph.digest),
            "expiration": format_timestamp(expiration),
            "retention": retention.to_dict(),
        },
    )
    try:
        registry.copy_layout_to_registry(
            layout_path=candidate.observation.path,
            layout_reference=candidate.observation.reference,
            destination=tagged,
            auth_file=auth_file,
        )
        remote_digest = registry.resolve_digest(tagged, auth_file=auth_file)
        if remote_digest != candidate.observation.graph.digest:
            raise OperationalError(
                f"Published digest {remote_digest} differs from accepted {candidate.observation.graph.digest}"
            )
        expiration_observation = registry_control.enforce_candidate_lifetime(
            image.repository, candidate.candidate_tag, expiration
        )
        if expiration_observation.digest != remote_digest:
            raise OperationalError(
                "Registry candidate-lifetime update observed another digest"
            )
        if expiration_observation.immutable:
            raise OperationalError(
                "Candidate must remain mutable for independent expiry", code="CC0603"
            )
        immutable = image.repository.with_digest(remote_digest)
        remote = registry.copy_registry_to_layout(
            source=immutable,
            layout_path=workspace.root
            / "layouts"
            / image.image_id
            / "remote-published",
            layout_reference="published",
            auth_file=auth_file,
        )
        _require_same_graph(candidate.observation.graph, remote.graph)
    except Exception:
        workspace.journal.mark_failed("candidate")
        raise
    workspace.journal.update(
        "candidate",
        ResourceStatus.CREATED,
        metadata={
            "digest": str(remote_digest),
            "expiration": format_timestamp(expiration),
            "immutabilityEnabled": False,
        },
    )
    workspace.transition(RunState.PUBLISHED, now=now)
    return PublishedCandidate(tagged, immutable, remote.graph, expiration, False)


def _resume_published_candidate(
    candidate: CandidateResult,
    *,
    tagged: OCIReference,
    entry: ResourceEntry,
    image: ReleaseImageConfig,
    workspace: RunWorkspace,
    registry: Registry,
    registry_control: RegistryControl,
    auth_file: Path | None,
    now: datetime,
) -> PublishedCandidate:
    expected_value = entry.metadata.get("digest")
    if expected_value != str(candidate.observation.graph.digest):
        raise InvalidInvocationError("Candidate digest journal is malformed")
    observed = registry.resolve_optional(tagged, auth_file=auth_file)
    if observed != candidate.observation.graph.digest:
        raise InvalidInvocationError(
            "Attempted candidate cannot be reused; start a new release run"
        )
    expiration = parse_timestamp(
        entry.metadata.get("expiration"),
        "Candidate expiration journal",
        error=InvalidInvocationError,
    )
    if now.astimezone(UTC) >= expiration:
        raise RuleRejectionError("Candidate expired before resume", code="CC0603")
    tag_observation = registry_control.observe_tag(
        image.repository, candidate.candidate_tag
    )
    if tag_observation is None or tag_observation.digest != observed:
        raise OperationalError("Registry candidate state differs during resume")
    if tag_observation.immutable:
        raise OperationalError(
            "Candidate must remain mutable for independent expiry", code="CC0603"
        )
    retention = _require_candidate_retention(image, registry_control)
    if tag_observation.expiration != expiration:
        tag_observation = registry_control.enforce_candidate_lifetime(
            image.repository, candidate.candidate_tag, expiration
        )
        if tag_observation.digest != observed:
            raise OperationalError(
                "Registry candidate-lifetime update observed another digest"
            )
    immutable = image.repository.with_digest(observed)
    remote = registry.copy_registry_to_layout(
        source=immutable,
        layout_path=workspace.root
        / "layouts"
        / image.image_id
        / "remote-published-resume",
        layout_reference="published",
        auth_file=auth_file,
    )
    _require_same_graph(candidate.observation.graph, remote.graph)
    workspace.journal.update(
        "candidate",
        ResourceStatus.CREATED,
        metadata={
            "digest": str(observed),
            "expiration": format_timestamp(expiration),
            "immutabilityEnabled": tag_observation.immutable,
            "retention": retention.to_dict(),
        },
    )
    workspace.transition(RunState.PUBLISHED, now=now)
    return PublishedCandidate(
        tagged, immutable, remote.graph, expiration, tag_observation.immutable
    )


def _require_candidate_retention(
    image: ReleaseImageConfig, registry_control: RegistryControl
) -> CandidateRetentionObservation:
    retention = registry_control.ensure_candidate_retention(
        image.repository, image.release_limits.candidate_lifetime
    )
    if (
        retention.repository != image.repository
        or not retention.policy_id
        or retention.tag_pattern != CANDIDATE_TAG_PATTERN
        or not 0
        < retention.maximum_age.total_seconds()
        <= image.release_limits.candidate_lifetime.total_seconds()
    ):
        raise OperationalError(
            "Registry did not establish candidate retention before upload",
            code="CC0603",
        )
    return retention


def require_remote_graph_unchanged(
    published: PublishedCandidate,
    registry: Registry,
    auth_file: Path | None,
    *,
    workspace: RunWorkspace,
    image: ReleaseImageConfig,
    phase: str,
) -> None:
    """Fail unless the candidate tag and its complete remote graph are unchanged."""
    observed = registry.resolve_digest(published.reference, auth_file=auth_file)
    if observed != published.graph.digest:
        raise OperationalError("Candidate tag changed after publication")
    layout_root = workspace.root / "layouts" / image.image_id / "remote-verification"
    layout_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"{phase}-", dir=layout_root) as directory:
        remote = registry.copy_registry_to_layout(
            source=published.immutable_reference,
            layout_path=Path(directory) / "layout",
            layout_reference=phase,
            auth_file=auth_file,
        )
        _require_same_graph(published.graph, remote.graph)


def _require_same_graph(expected: OCIGraph, observed: OCIGraph) -> None:
    if (
        graph_fingerprint(expected) != graph_fingerprint(observed)
        or expected.platforms != observed.platforms
        or expected.digest != observed.digest
    ):
        raise OperationalError(
            "Remote OCI descriptor graph differs from accepted graph"
        )


def retry_entry(
    workspace: RunWorkspace,
    *,
    resource_id: str,
    kind: ResourceKind,
    identifier: str,
    metadata: dict[str, object],
) -> ResourceEntry | None:
    """Return the journal entry of a retried remote write, or None on first use.

    A retry is accepted only when the recorded kind, identifier and metadata
    match the current inputs exactly and the resource was neither ephemeral
    nor already removed.
    """
    matches = [
        entry
        for entry in workspace.journal.entries()
        if entry.resource_id == resource_id
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise InvalidInvocationError(f"Resource journal is ambiguous: {resource_id}")
    entry = matches[0]
    if (
        entry.kind is not kind
        or entry.identifier != identifier
        or entry.ephemeral
        or entry.metadata != metadata
        or entry.status is ResourceStatus.REMOVED
    ):
        raise InvalidInvocationError(f"Resource retry inputs changed: {resource_id}")
    return entry
