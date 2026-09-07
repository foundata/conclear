"""Verified all-or-nothing application of pin-update proposals.

`apply_pin_proposal` consumes a proposal produced by `conclear.pin_updates`
without resolving anything. It completes a read-only preflight against the
current worktree, then replaces only the proposed byte spans through
same-directory temporary files. Any detected failure restores every target to
its exact original bytes. This module is the only code that rewrites
repository files.
"""

import os
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from conclear.checks import MAX_CONTAINERFILE_BYTES
from conclear.config import (
    MAX_CONFIG_BYTES,
    PinIntent,
    RepositoryConfig,
    load_repository_config,
)
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.fileio import read_regular_file
from conclear.jsonutil import sha256_bytes
from conclear.pin_occurrences import (
    CONFIGURATION_NAME,
    Snapshot,
    confined_target,
    discover_occurrences,
)
from conclear.pin_updates import PinUpdateProposal, ProposedFile, require_aware
from conclear.records import SourceIdentity


class ApplicationStatus(StrEnum):
    """Outcomes of a verified proposal application."""

    APPLIED = "applied"
    ALREADY_APPLIED = "already-applied"
    NO_CHANGE = "no-change"


class WritePhase(StrEnum):
    """Phases at which an injected filesystem fault may be raised."""

    PREPARE = "prepare"
    WRITE = "write"
    FLUSH = "flush"
    REPLACE = "replace"
    VERIFY = "verify"


FaultHook = Callable[[WritePhase, Path], None]


@dataclass(frozen=True, slots=True)
class ApplicationOutcome:
    """The result of one verified proposal application."""

    status: ApplicationStatus
    changed_paths: tuple[str, ...]
    proposal: PinUpdateProposal


def apply_pin_proposal(
    proposal: PinUpdateProposal,
    *,
    repository_root: Path,
    source: SourceIdentity,
    now: datetime,
    fault_hook: FaultHook | None = None,
) -> ApplicationOutcome:
    """Verify a proposal against the current worktree and apply it all-or-nothing."""
    require_aware(now, "application time")
    try:
        root = repository_root.resolve(strict=True)
    except OSError as exc:
        raise InvalidInvocationError(
            f"Repository root is unavailable: {repository_root}"
        ) from exc
    if proposal.source.repository != source.repository:
        raise InvalidInvocationError(
            "Proposal repository does not match the current repository",
            code="CC0207",
        )
    if proposal.source.revision != source.revision:
        raise InvalidInvocationError(
            "Proposal Git revision does not match the current revision",
            code="CC0207",
        )
    targets = _read_targets(root, proposal)
    configuration = read_regular_file(
        root / CONFIGURATION_NAME,
        maximum_bytes=MAX_CONFIG_BYTES,
        label="repository configuration",
    )
    if proposal.files and all(
        sha256_bytes(targets[item.path]) == item.result_sha256
        for item in proposal.files
    ):
        return ApplicationOutcome(ApplicationStatus.ALREADY_APPLIED, (), proposal)
    if sha256_bytes(configuration) != proposal.configuration_digest:
        raise InvalidInvocationError(
            "Proposal configuration digest does not match the current configuration",
            code="CC0207",
        )
    if not proposal.files:
        return ApplicationOutcome(ApplicationStatus.NO_CHANGE, (), proposal)
    results: dict[str, bytes] = {}
    for item in proposal.files:
        current = targets[item.path]
        if sha256_bytes(current) != item.sha256:
            raise InvalidInvocationError(
                f"Target file digest changed since the proposal: {item.path}",
                code="CC0207",
            )
        result = item.apply_to(current)
        if sha256_bytes(result) != item.result_sha256:
            raise InvalidInvocationError(
                f"Proposed result digest does not match the computed result: {item.path}",
                code="CC0207",
            )
        _prove_only_spans_change(current, result, item)
        results[item.path] = result
    repository = load_repository_config(root / CONFIGURATION_NAME)
    _reject_stale(proposal, repository, now)
    snapshot = discover_occurrences(repository, proposal.image_ids)
    _compare_snapshot(snapshot, proposal, expect_applied=False)
    modes = {path: _target_mode(root, path) for path in results}
    _replace_all(root, results, modes, fault_hook)
    try:
        _verify_result(root, proposal, results, fault_hook)
    except (
        OSError,
        OperationalError,
        InvalidInvocationError,
        RuleRejectionError,
    ) as exc:
        _restore(root, {path: targets[path] for path in results}, modes, exc)
        raise OperationalError(
            f"Applied files failed verification and were restored: {exc}"
        ) from exc
    return ApplicationOutcome(
        ApplicationStatus.APPLIED, tuple(sorted(results)), proposal
    )


def _read_targets(root: Path, proposal: PinUpdateProposal) -> dict[str, bytes]:
    targets: dict[str, bytes] = {}
    for item in proposal.files:
        resolved = confined_target(root, item.path)
        limit = (
            MAX_CONFIG_BYTES
            if item.path == CONFIGURATION_NAME
            else MAX_CONTAINERFILE_BYTES
        )
        targets[item.path] = read_regular_file(
            resolved, maximum_bytes=limit, label=f"proposal target {item.path}"
        )
    return targets


def _target_mode(root: Path, relative: str) -> int:
    try:
        return stat.S_IMODE(os.lstat(root / relative).st_mode)
    except OSError as exc:
        raise OperationalError(f"Unable to inspect {relative}") from exc


def _prove_only_spans_change(current: bytes, result: bytes, item: ProposedFile) -> None:
    cursor_old = 0
    cursor_new = 0
    for edit in item.edits:
        if (
            current[cursor_old : edit.start]
            != result[cursor_new : cursor_new + edit.start - cursor_old]
        ):
            raise InvalidInvocationError(
                f"Proposed result changes bytes outside the proposed spans: {item.path}",
                code="CC0207",
            )
        cursor_new += edit.start - cursor_old + len(edit.new_text.encode("utf-8"))
        cursor_old = edit.end
    if current[cursor_old:] != result[cursor_new:]:
        raise InvalidInvocationError(
            f"Proposed result changes bytes outside the proposed spans: {item.path}",
            code="CC0207",
        )


def _reject_stale(
    proposal: PinUpdateProposal, repository: RepositoryConfig, now: datetime
) -> None:
    known = {image.image_id: image for image in repository.images}
    missing = sorted(set(proposal.image_ids) - known.keys())
    if missing:
        raise InvalidInvocationError(
            "Proposal names images that no longer exist: " + ", ".join(missing),
            code="CC0207",
        )
    limit = min(
        known[image_id].pin_limits.pin_freshness for image_id in proposal.image_ids
    )
    for lookup in proposal.lookups:
        age = now.astimezone(UTC) - lookup.resolved_at.astimezone(UTC)
        if age < timedelta(0):
            raise OperationalError("Proposal resolution time is in the future")
        if age > limit:
            raise OperationalError(
                f"Proposal resolution is stale for {lookup.original_reference}: "
                f"resolved {age} ago, limit {limit}"
            )


def _compare_snapshot(
    snapshot: Snapshot, proposal: PinUpdateProposal, *, expect_applied: bool
) -> None:
    """Prove that the current occurrences and dependency set equal the proposal.

    Old and new references differ only in their equally long digest, so every
    span keeps its byte offsets after application.
    """
    if snapshot.image_ids != proposal.image_ids:
        raise InvalidInvocationError(
            "Proposal image set does not match the current configuration",
            code="CC0207",
        )
    replacements = {
        str(item.original_reference): str(item.resolved_reference)
        for item in proposal.lookups
        if item.changed
    }
    current_names = set(replacements.values() if expect_applied else replacements)
    expected = {
        (
            item.path,
            edit.start,
            edit.end,
            edit.new_text if expect_applied else edit.old_text,
        )
        for item in proposal.files
        for edit in item.edits
    }
    observed = {
        (item.path, item.start, item.end, str(item.reference))
        for item in snapshot.occurrences
        if str(item.reference) in current_names
    }
    if observed != expected:
        raise InvalidInvocationError(
            "Proposal occurrences do not match the current repository state",
            code="CC0207",
        )
    originals = {resolved: original for original, resolved in replacements.items()}
    current: dict[str, tuple[set[str], PinIntent]] = {}
    for occurrence in snapshot.occurrences:
        reference = str(occurrence.reference)
        key = originals.get(reference, reference) if expect_applied else reference
        image_ids, _ = current.setdefault(key, (set(), snapshot.intents[reference]))
        image_ids.add(occurrence.image_id)
    if {
        key: (tuple(sorted(ids)), intent) for key, (ids, intent) in current.items()
    } != {
        str(item.original_reference): (item.image_ids, item.tag_intent)
        for item in proposal.lookups
    }:
        raise InvalidInvocationError(
            "Proposal dependency set does not match the current configuration",
            code="CC0207",
        )


def _replace_all(
    root: Path,
    results: dict[str, bytes],
    modes: dict[str, int],
    fault_hook: FaultHook | None,
) -> None:
    originals: dict[str, bytes] = {}
    replaced: list[str] = []
    temporary_files: list[Path] = []
    try:
        for path in sorted(results):
            target = root / path
            originals[path] = target.read_bytes()
            _hook(fault_hook, WritePhase.PREPARE, target)
            descriptor, temporary_name = tempfile.mkstemp(
                dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
            )
            temporary = Path(temporary_name)
            temporary_files.append(temporary)
            os.fchmod(descriptor, modes[path])
            with os.fdopen(descriptor, "wb") as stream:
                _hook(fault_hook, WritePhase.WRITE, target)
                stream.write(results[path])
                stream.flush()
                _hook(fault_hook, WritePhase.FLUSH, target)
                os.fsync(stream.fileno())
            _hook(fault_hook, WritePhase.REPLACE, target)
            temporary.replace(target)
            temporary_files.remove(temporary)
            replaced.append(path)
            _fsync_directory(target.parent)
    except OSError as exc:
        for temporary in temporary_files:
            temporary.unlink(missing_ok=True)
        _restore(root, {path: originals[path] for path in replaced}, modes, exc)
        raise OperationalError(
            f"Unable to apply the pin update proposal; every target was restored: {exc}"
        ) from exc


def _verify_result(
    root: Path,
    proposal: PinUpdateProposal,
    results: dict[str, bytes],
    fault_hook: FaultHook | None,
) -> None:
    for item in proposal.files:
        target = root / item.path
        _hook(fault_hook, WritePhase.VERIFY, target)
        content = read_regular_file(
            target,
            maximum_bytes=max(MAX_CONFIG_BYTES, MAX_CONTAINERFILE_BYTES),
            label=item.path,
        )
        if content != results[item.path] or sha256_bytes(content) != item.result_sha256:
            raise OperationalError(
                f"Applied file does not match the proposal: {item.path}"
            )
    repository = load_repository_config(root / CONFIGURATION_NAME)
    snapshot = discover_occurrences(repository, proposal.image_ids)
    _compare_snapshot(snapshot, proposal, expect_applied=True)


def _restore(
    root: Path, originals: dict[str, bytes], modes: dict[str, int], cause: Exception
) -> None:
    failed: list[str] = []
    for path, content in originals.items():
        target = root / path
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
            )
            os.fchmod(descriptor, modes[path])
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            Path(temporary_name).replace(target)
            _fsync_directory(target.parent)
        except OSError:
            failed.append(path)
    if failed:
        raise OperationalError(
            "Pin update application failed and these targets could not be restored: "
            + ", ".join(sorted(failed))
        ) from cause


def _hook(fault_hook: FaultHook | None, phase: WritePhase, path: Path) -> None:
    if fault_hook is not None:
        fault_hook(phase, path)


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
