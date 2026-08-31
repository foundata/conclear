"""Durable authoritative rescan clocks outside application repositories."""

import fcntl
import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import IO

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import atomic_write_json, load_json
from conclear.values import Digest, OCIReference, Platform

MAX_RESCAN_HISTORY_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True, order=True)
class RemediationFindingKey:
    """One platform-specific vulnerability remediation identity."""

    platform: Platform
    component: str
    advisory: str

    def to_dict(self) -> dict[str, str]:
        """Return the durable representation."""
        return {
            "platform": str(self.platform),
            "component": self.component,
            "advisory": self.advisory,
        }


@dataclass(frozen=True, slots=True)
class RescanHistoryEntry:
    """One post-attachment verified authoritative rescan observation."""

    record_digest: str
    verified_at: datetime
    active_findings: tuple[RemediationFindingKey, ...]

    def __post_init__(self) -> None:
        """Validate the stored digest, time and finding identities."""
        Digest(self.record_digest)
        if self.verified_at.tzinfo is None or self.verified_at.utcoffset() is None:
            raise ValueError("Rescan verification time must be timezone-aware")
        if self.active_findings != tuple(sorted(set(self.active_findings))):
            raise ValueError("Rescan active findings must be unique and sorted")

    def to_dict(self) -> dict[str, object]:
        """Return the durable representation."""
        return {
            "recordDigest": self.record_digest,
            "verifiedAt": _timestamp(self.verified_at),
            "activeFindings": [item.to_dict() for item in self.active_findings],
        }


class RescanHistoryStore:
    """Append and link authoritative rescan clocks for one immutable subject."""

    def __init__(self, state_home: Path) -> None:
        """Use a protected durable state root outside project checkouts."""
        self._root = state_home / "conclear" / "rescans"

    def linked_history(
        self, subject: OCIReference, requested_previous: str | None
    ) -> tuple[RescanHistoryEntry, ...]:
        """Return history only when the caller links the exact latest result."""
        entries = self._load(subject)
        if not entries:
            if requested_previous is not None:
                Digest(requested_previous)
                raise InvalidInvocationError(
                    "Previous rescan result is not present in durable history"
                )
            return ()
        if requested_previous is None:
            raise InvalidInvocationError(
                "A previous result digest is required for this released subject"
            )
        Digest(requested_previous)
        if requested_previous != entries[-1].record_digest:
            raise InvalidInvocationError(
                "Previous result digest is not the latest authoritative rescan"
            )
        return entries

    def record(
        self,
        subject: OCIReference,
        entry: RescanHistoryEntry,
        *,
        expected_previous: str | None,
    ) -> None:
        """Append one successfully verified result under an exact prior link."""
        path = self._path(subject)
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with _locked_file(path.with_suffix(".lock")):
            entries = list(self._load(subject))
            current = entries[-1].record_digest if entries else None
            if current != expected_previous:
                raise OperationalError(
                    "Authoritative rescan history changed during the invocation"
                )
            if entries and entry.verified_at < entries[-1].verified_at:
                raise OperationalError("Rescan verification clock moved backwards")
            if any(item.record_digest == entry.record_digest for item in entries):
                raise OperationalError("Rescan result digest is already recorded")
            entries.append(entry)
            atomic_write_json(
                path,
                {
                    "schemaVersion": 1,
                    "subject": str(subject),
                    "results": [item.to_dict() for item in entries],
                },
            )

    def _load(self, subject: OCIReference) -> tuple[RescanHistoryEntry, ...]:
        path = self._path(subject)
        try:
            path_stat = path.lstat()
        except FileNotFoundError:
            return ()
        except OSError as exc:
            raise OperationalError("Unable to inspect rescan history") from exc
        if not stat.S_ISREG(path_stat.st_mode):
            raise OperationalError("Rescan history is not a regular file")
        value = load_json(path, maximum_bytes=MAX_RESCAN_HISTORY_BYTES)
        if not isinstance(value, dict) or value.get("schemaVersion") != 1:
            raise OperationalError("Rescan history is malformed")
        if value.get("subject") != str(subject):
            raise OperationalError("Rescan history identifies another subject")
        raw_results = value.get("results")
        if not isinstance(raw_results, list):
            raise OperationalError("Rescan history results are malformed")
        entries = tuple(_entry(item) for item in raw_results)
        if len({item.record_digest for item in entries}) != len(entries):
            raise OperationalError("Rescan history contains duplicate results")
        if any(
            later.verified_at < earlier.verified_at
            for earlier, later in pairwise(entries)
        ):
            raise OperationalError("Rescan history verification times are unordered")
        return entries

    def _path(self, subject: OCIReference) -> Path:
        if subject.digest is None or subject.tag is not None:
            raise InvalidInvocationError(
                "Rescan history requires an immutable digest subject"
            )
        key = hashlib.sha256(str(subject).encode("utf-8")).hexdigest()
        return self._root / f"{key}.json"


def _entry(value: object) -> RescanHistoryEntry:
    if not isinstance(value, dict):
        raise OperationalError("Rescan history entry is malformed")
    raw_findings = value.get("activeFindings")
    if not isinstance(raw_findings, list):
        raise OperationalError("Rescan history findings are malformed")
    findings: list[RemediationFindingKey] = []
    for raw_finding in raw_findings:
        if not isinstance(raw_finding, dict):
            raise OperationalError("Rescan history finding is malformed")
        findings.append(
            RemediationFindingKey(
                platform=Platform.parse(_string(raw_finding.get("platform"))),
                component=_string(raw_finding.get("component")),
                advisory=_string(raw_finding.get("advisory")),
            )
        )
    try:
        return RescanHistoryEntry(
            record_digest=_string(value.get("recordDigest")),
            verified_at=_parse_timestamp(_string(value.get("verifiedAt"))),
            active_findings=tuple(sorted(findings)),
        )
    except (InvalidInvocationError, ValueError) as exc:
        raise OperationalError("Rescan history entry contains invalid values") from exc


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise OperationalError("Rescan history string is malformed")
    return value


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperationalError("Rescan history timestamp is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OperationalError("Rescan history timestamp lacks a timezone")
    return parsed.astimezone(UTC)


@contextmanager
def _locked_file(path: Path) -> Iterator[IO[bytes]]:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OperationalError("Rescan history lock is not a regular file")
        stream = os.fdopen(descriptor, "r+b")
        descriptor = None
        with stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            yield stream
    except OSError as exc:
        raise OperationalError(f"Unable to lock rescan history {path}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
