"""Release-run workspaces, state transitions and ownership journals."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from ulid import ULID

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.fileio import locked_file
from conclear.jsonutil import atomic_write_json, canonical_json_bytes, load_json
from conclear.values import validate_run_id

_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)


class IdFactory(Protocol):
    """Create lowercase release-run identifiers."""

    def create(self) -> str:
        """Return a new lowercase ULID."""
        ...


class UlidFactory:
    """Create run identifiers with python-ulid."""

    def create(self) -> str:
        """Return a new lowercase ULID."""
        return validate_run_id(str(ULID()).lower())


class RunState(StrEnum):
    """Monotonic release-run states."""

    CREATED = "created"
    QUALIFIED = "qualified"
    ASSEMBLED = "assembled"
    PUBLISHED = "published"
    ATTESTED = "attested"
    VERIFIED = "verified"
    PROMOTED = "promoted"
    REJECTED = "rejected"
    INCOMPLETE = "incomplete"


_NEXT_STATES: dict[RunState, frozenset[RunState]] = {
    RunState.CREATED: frozenset(
        {RunState.QUALIFIED, RunState.REJECTED, RunState.INCOMPLETE}
    ),
    RunState.QUALIFIED: frozenset(
        {RunState.ASSEMBLED, RunState.REJECTED, RunState.INCOMPLETE}
    ),
    RunState.ASSEMBLED: frozenset(
        {RunState.PUBLISHED, RunState.REJECTED, RunState.INCOMPLETE}
    ),
    RunState.PUBLISHED: frozenset(
        {RunState.ATTESTED, RunState.REJECTED, RunState.INCOMPLETE}
    ),
    RunState.ATTESTED: frozenset(
        {RunState.VERIFIED, RunState.REJECTED, RunState.INCOMPLETE}
    ),
    RunState.VERIFIED: frozenset(
        {RunState.PROMOTED, RunState.REJECTED, RunState.INCOMPLETE}
    ),
    RunState.PROMOTED: frozenset(),
    RunState.REJECTED: frozenset(),
    RunState.INCOMPLETE: frozenset(),
}


class ResourceKind(StrEnum):
    """Kinds of resources that a run may own."""

    LOCAL_PATH = "localPath"
    GIT_WORKTREE = "gitWorktree"
    BUILDAH_STORAGE = "buildahStorage"
    PODMAN_IMPORT = "podmanImport"
    TEST_INPUTS = "testInputs"
    CANDIDATE_REFERENCE = "candidateReference"
    TAG_WRITE = "tagWrite"
    SIGNATURE = "signature"
    ATTESTATION = "attestation"


class ResourceStatus(StrEnum):
    """Mutation status recorded before and after each external change."""

    PLANNED = "planned"
    CREATED = "created"
    FAILED = "failed"
    REMOVED = "removed"


@dataclass(frozen=True, slots=True)
class ResourceEntry:
    """One run-owned or durable external resource."""

    resource_id: str
    kind: ResourceKind
    identifier: str
    ephemeral: bool
    status: ResourceStatus
    metadata: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        """Return the journal representation."""
        return {
            "resourceId": self.resource_id,
            "kind": self.kind.value,
            "identifier": self.identifier,
            "ephemeral": self.ephemeral,
            "status": self.status.value,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class RunSnapshot:
    """Validated immutable and mutable release-run state."""

    run_id: str
    state: RunState
    created_at: str
    updated_at: str
    immutable_inputs: dict[str, str]
    resume_state: RunState | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the persisted run state object."""
        value: dict[str, object] = {
            "schemaVersion": 1,
            "runId": self.run_id,
            "state": self.state.value,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "immutableInputs": dict(sorted(self.immutable_inputs.items())),
        }
        if self.resume_state is not None:
            value["resumeState"] = self.resume_state.value
        return value


@dataclass(frozen=True, slots=True)
class RunWorkspace:
    """Paths and state operations for one release run."""

    root: Path
    run_id: str

    @classmethod
    def create(
        cls,
        *,
        state_home: Path,
        immutable_inputs: dict[str, str],
        id_factory: IdFactory | None = None,
        now: datetime | None = None,
    ) -> "RunWorkspace":
        """Create a private release workspace and initial state atomically."""
        run_id = (id_factory or UlidFactory()).create()
        validate_run_id(run_id)
        root = state_home / "conclear" / "runs" / run_id
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=False)
            for relative in (
                "logs",
                "layouts",
                "reports",
                "records",
                "exports/sbom",
            ):
                (root / relative).mkdir(mode=0o700, parents=True, exist_ok=False)
        except OSError as exc:
            raise OperationalError(f"Unable to create run workspace {root}") from exc
        timestamp = _timestamp(now or datetime.now(UTC))
        snapshot = RunSnapshot(
            run_id=run_id,
            state=RunState.CREATED,
            created_at=timestamp,
            updated_at=timestamp,
            immutable_inputs=dict(immutable_inputs),
        )
        atomic_write_json(root / "run.json", snapshot.to_dict())
        atomic_write_json(
            root / "resources.json",
            {"schemaVersion": 1, "runId": run_id, "resources": []},
        )
        return cls(root=root, run_id=run_id)

    @classmethod
    def open(cls, *, state_home: Path, run_id: str) -> "RunWorkspace":
        """Open an existing workspace by validated run identifier."""
        validate_run_id(run_id)
        root = state_home / "conclear" / "runs" / run_id
        try:
            resolved_root = root.resolve(strict=True)
            resolved_runs = (state_home / "conclear" / "runs").resolve(strict=True)
            resolved_root.relative_to(resolved_runs)
        except (OSError, RuntimeError, ValueError) as exc:
            raise InvalidInvocationError(
                f"Unknown or unsafe run workspace: {run_id}"
            ) from exc
        workspace = cls(root=resolved_root, run_id=run_id)
        if workspace.load().run_id != run_id:
            raise InvalidInvocationError(
                "Run state identity does not match its workspace"
            )
        return workspace

    def load(self) -> RunSnapshot:
        """Load and validate current run state."""
        return _parse_snapshot(load_json(self.root / "run.json"))

    def validate_resume(self, expected_inputs: dict[str, str]) -> RunSnapshot:
        """Refuse resume when any immutable input differs."""
        snapshot = self.load()
        if snapshot.state in {RunState.REJECTED, RunState.PROMOTED}:
            raise InvalidInvocationError(
                f"Run {self.run_id} cannot resume from terminal state {snapshot.state.value}"
            )
        if snapshot.immutable_inputs != expected_inputs:
            changed = sorted(
                key
                for key in snapshot.immutable_inputs.keys() | expected_inputs.keys()
                if snapshot.immutable_inputs.get(key) != expected_inputs.get(key)
            )
            raise InvalidInvocationError(
                f"Run {self.run_id} immutable inputs changed: {', '.join(changed)}"
            )
        return snapshot

    def bind_immutable_inputs(
        self, additions: dict[str, str], *, now: datetime | None = None
    ) -> RunSnapshot:
        """Bind newly observed startup inputs before the run leaves created state."""
        if not additions or any(
            not key or not value for key, value in additions.items()
        ):
            raise InvalidInvocationError("Immutable input additions cannot be empty")
        with locked_file(self.root / ".run.lock", label="run state"):
            snapshot = self.load()
            if snapshot.state is not RunState.CREATED:
                raise InvalidInvocationError(
                    "Immutable inputs can only be bound while a run is created"
                )
            conflicts = [
                key
                for key, value in additions.items()
                if key in snapshot.immutable_inputs
                and snapshot.immutable_inputs[key] != value
            ]
            if conflicts:
                raise InvalidInvocationError(
                    "Immutable inputs conflict: " + ", ".join(sorted(conflicts))
                )
            updated = RunSnapshot(
                run_id=snapshot.run_id,
                state=snapshot.state,
                created_at=snapshot.created_at,
                updated_at=_timestamp(now or datetime.now(UTC)),
                immutable_inputs={**snapshot.immutable_inputs, **additions},
            )
            atomic_write_json(self.root / "run.json", updated.to_dict())
            return updated

    def resume(
        self,
        expected_inputs: dict[str, str],
        *,
        now: datetime | None = None,
    ) -> RunSnapshot:
        """Validate immutable inputs and restore an interrupted stable state."""
        with locked_file(self.root / ".run.lock", label="run state"):
            snapshot = self.validate_resume(expected_inputs)
            if snapshot.state is not RunState.INCOMPLETE:
                return snapshot
            if snapshot.resume_state is None:
                raise InvalidInvocationError(
                    f"Run {self.run_id} has no recorded state from which to resume"
                )
            resumed = RunSnapshot(
                run_id=snapshot.run_id,
                state=snapshot.resume_state,
                created_at=snapshot.created_at,
                updated_at=_timestamp(now or datetime.now(UTC)),
                immutable_inputs=snapshot.immutable_inputs,
            )
            atomic_write_json(self.root / "run.json", resumed.to_dict())
            return resumed

    def transition(
        self, state: RunState, *, now: datetime | None = None
    ) -> RunSnapshot:
        """Atomically apply one permitted monotonic state transition."""
        with locked_file(self.root / ".run.lock", label="run state"):
            snapshot = self.load()
            if state == snapshot.state:
                if state in {RunState.REJECTED, RunState.PROMOTED}:
                    raise InvalidInvocationError(
                        f"Run is already in terminal state {state.value}"
                    )
                return snapshot
            if state not in _NEXT_STATES[snapshot.state]:
                raise InvalidInvocationError(
                    f"Invalid run transition {snapshot.state.value} -> {state.value}"
                )
            updated = RunSnapshot(
                run_id=snapshot.run_id,
                state=state,
                created_at=snapshot.created_at,
                updated_at=_timestamp(now or datetime.now(UTC)),
                immutable_inputs=snapshot.immutable_inputs,
                resume_state=(snapshot.state if state is RunState.INCOMPLETE else None),
            )
            atomic_write_json(self.root / "run.json", updated.to_dict())
            return updated

    @property
    def journal(self) -> "ResourceJournal":
        """Return the workspace ownership journal."""
        return ResourceJournal(self.root / "resources.json", self.run_id)


class ResourceJournal:
    """Atomically record resource ownership before and after mutations."""

    def __init__(self, path: Path, run_id: str) -> None:
        """Bind a journal to one run-owned file."""
        self._path = path
        self._run_id = validate_run_id(run_id)
        self._lock_path = path.with_suffix(".lock")

    def entries(self) -> tuple[ResourceEntry, ...]:
        """Load all validated journal entries."""
        value = load_json(self._path)
        if not isinstance(value, dict) or value.get("schemaVersion") != 1:
            raise OperationalError("Resource journal is malformed")
        if value.get("runId") != self._run_id:
            raise OperationalError("Resource journal belongs to another run")
        resources = value.get("resources")
        if not isinstance(resources, list):
            raise OperationalError("Resource journal entries are malformed")
        return tuple(_parse_resource(item) for item in resources)

    def plan(
        self,
        *,
        resource_id: str,
        kind: ResourceKind,
        identifier: str,
        ephemeral: bool,
        metadata: dict[str, object] | None = None,
    ) -> ResourceEntry:
        """Record intended ownership before the external mutation starts."""
        if not resource_id or not identifier:
            raise InvalidInvocationError("Resource id and identifier cannot be empty")
        resource_metadata = {} if metadata is None else dict(metadata)
        try:
            canonical_json_bytes(resource_metadata)
        except (TypeError, ValueError) as exc:
            raise InvalidInvocationError(
                "Resource metadata must be valid JSON"
            ) from exc
        entry = ResourceEntry(
            resource_id=resource_id,
            kind=kind,
            identifier=identifier,
            ephemeral=ephemeral,
            status=ResourceStatus.PLANNED,
            metadata=resource_metadata,
        )
        with locked_file(self._lock_path, label="resource journal"):
            entries = list(self.entries())
            matches = [item for item in entries if item.resource_id == resource_id]
            if matches:
                previous = matches[0]
                if (
                    previous.status is not ResourceStatus.REMOVED
                    or previous.kind is not kind
                    or previous.identifier != identifier
                    or previous.ephemeral is not ephemeral
                ):
                    raise InvalidInvocationError(
                        f"Resource id is already recorded: {resource_id}"
                    )
                entries[entries.index(previous)] = entry
                self._write(entries)
                return entry
            entries.append(entry)
            self._write(entries)
        return entry

    def update(
        self,
        resource_id: str,
        status: ResourceStatus,
        *,
        metadata: dict[str, object] | None = None,
    ) -> ResourceEntry:
        """Record the observed result after a resource mutation."""
        with locked_file(self._lock_path, label="resource journal"):
            entries = list(self.entries())
            matches = [entry for entry in entries if entry.resource_id == resource_id]
            if len(matches) != 1:
                raise InvalidInvocationError(f"Unknown resource id: {resource_id}")
            previous = matches[0]
            allowed = {
                ResourceStatus.PLANNED: {
                    ResourceStatus.CREATED,
                    ResourceStatus.FAILED,
                    ResourceStatus.REMOVED,
                },
                ResourceStatus.CREATED: {ResourceStatus.REMOVED, ResourceStatus.FAILED},
                ResourceStatus.FAILED: {ResourceStatus.CREATED, ResourceStatus.REMOVED},
                ResourceStatus.REMOVED: set(),
            }
            if status != previous.status and status not in allowed[previous.status]:
                raise InvalidInvocationError(
                    f"Invalid resource transition {previous.status.value} -> {status.value}"
                )
            merged_metadata = dict(previous.metadata)
            if metadata is not None:
                merged_metadata.update(metadata)
            try:
                canonical_json_bytes(merged_metadata)
            except (TypeError, ValueError) as exc:
                raise InvalidInvocationError(
                    "Resource metadata must be valid JSON"
                ) from exc
            updated = ResourceEntry(
                resource_id=previous.resource_id,
                kind=previous.kind,
                identifier=previous.identifier,
                ephemeral=previous.ephemeral,
                status=status,
                metadata=merged_metadata,
            )
            entries[entries.index(previous)] = updated
            self._write(entries)
            return updated

    def cleanup_candidates(self) -> tuple[ResourceEntry, ...]:
        """Return only current run-owned ephemeral resources that may exist."""
        return tuple(
            entry
            for entry in self.entries()
            if entry.ephemeral
            and entry.status
            in {
                ResourceStatus.PLANNED,
                ResourceStatus.CREATED,
                ResourceStatus.FAILED,
            }
        )

    def _write(self, entries: list[ResourceEntry]) -> None:
        atomic_write_json(
            self._path,
            {
                "schemaVersion": 1,
                "runId": self._run_id,
                "resources": [entry.to_dict() for entry in entries],
            },
        )


def _parse_snapshot(value: object) -> RunSnapshot:
    if not isinstance(value, dict) or value.get("schemaVersion") != 1:
        raise OperationalError("Run state is malformed")
    inputs = value.get("immutableInputs")
    if not isinstance(inputs, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in inputs.items()
    ):
        raise OperationalError("Run immutable inputs are malformed")
    resume_value = value.get("resumeState")
    try:
        state = RunState(_string(value.get("state"), "state"))
        resume_state = (
            RunState(_string(resume_value, "resumeState"))
            if resume_value is not None
            else None
        )
        if (state is RunState.INCOMPLETE) != (resume_state is not None):
            raise OperationalError("Interrupted run state has invalid resume metadata")
        if resume_state in {RunState.REJECTED, RunState.INCOMPLETE, RunState.PROMOTED}:
            raise OperationalError("Interrupted run has an invalid resume state")
        return RunSnapshot(
            run_id=validate_run_id(_string(value.get("runId"), "runId")),
            state=state,
            created_at=_state_timestamp(value.get("createdAt"), "createdAt"),
            updated_at=_state_timestamp(value.get("updatedAt"), "updatedAt"),
            immutable_inputs=inputs,
            resume_state=resume_state,
        )
    except ValueError as exc:
        raise OperationalError("Run state contains an unknown state") from exc


def _parse_resource(value: object) -> ResourceEntry:
    if not isinstance(value, dict):
        raise OperationalError("Resource journal entry is malformed")
    metadata = value.get("metadata")
    if not isinstance(metadata, dict) or any(
        not isinstance(key, str) for key in metadata
    ):
        raise OperationalError("Resource metadata is malformed")
    try:
        return ResourceEntry(
            resource_id=_string(value.get("resourceId"), "resourceId"),
            kind=ResourceKind(_string(value.get("kind"), "kind")),
            identifier=_string(value.get("identifier"), "identifier"),
            ephemeral=_boolean(value.get("ephemeral"), "ephemeral"),
            status=ResourceStatus(_string(value.get("status"), "status")),
            metadata=metadata,
        )
    except ValueError as exc:
        raise OperationalError(
            "Resource journal contains an unknown enum value"
        ) from exc


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OperationalError("Workspace timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _state_timestamp(value: object, name: str) -> str:
    timestamp = _string(value, name)
    if _TIMESTAMP_PATTERN.fullmatch(timestamp) is None:
        raise OperationalError(f"State field {name} must be a UTC RFC 3339 timestamp")
    try:
        datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise OperationalError(f"State field {name} timestamp is malformed") from exc
    return timestamp


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise OperationalError(f"State field {name} must be a non-empty string")
    return value


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise OperationalError(f"State field {name} must be a boolean")
    return value
