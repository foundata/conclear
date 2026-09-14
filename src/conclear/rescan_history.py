"""Durable authoritative rescan clocks outside application repositories."""

import hashlib
import stat
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from pathlib import Path

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.fileio import locked_file
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    load_json,
    sha256_bytes,
)
from conclear.parsing import object_value
from conclear.records import format_timestamp, parse_timestamp, validate_record
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
    release_record_digest: str
    verified_at: datetime
    active_findings: tuple[RemediationFindingKey, ...]

    def __post_init__(self) -> None:
        """Validate the stored digest, time and finding identities."""
        Digest(self.record_digest)
        Digest(self.release_record_digest)
        if self.verified_at.tzinfo is None or self.verified_at.utcoffset() is None:
            raise OperationalError("Rescan verification time must be timezone-aware")
        if self.active_findings != tuple(sorted(set(self.active_findings))):
            raise OperationalError("Rescan active findings must be unique and sorted")

    def to_dict(self) -> dict[str, object]:
        """Return the durable representation."""
        return {
            "recordDigest": self.record_digest,
            "releaseRecordDigest": self.release_record_digest,
            "verifiedAt": format_timestamp(self.verified_at),
            "activeFindings": [item.to_dict() for item in self.active_findings],
        }


@dataclass(frozen=True, slots=True)
class _LinkedRecord:
    entry: RescanHistoryEntry
    previous_digest: str | None


class RescanHistoryStore:
    """Append and link authoritative rescan clocks for one immutable subject."""

    def __init__(self, state_home: Path) -> None:
        """Use a protected durable state root outside project checkouts."""
        self._root = state_home / "conclear" / "rescans"

    def linked_history(
        self, subject: OCIReference, requested_previous: str | None
    ) -> tuple[RescanHistoryEntry, ...]:
        """Return history only when the caller links the exact latest result."""
        return _require_latest(self._load(subject), requested_previous)

    def synchronize(
        self,
        subject: OCIReference,
        authoritative: tuple[RescanHistoryEntry, ...],
        requested_previous: str | None,
    ) -> tuple[RescanHistoryEntry, ...]:
        """Reconcile a cache prefix with verified attestations and require its tip."""
        path = self._path(subject)
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with locked_file(path.with_suffix(".lock"), label="rescan history"):
            cached = self._load(subject)
            if cached and not authoritative:
                raise OperationalError(
                    "Registry holds none of the signed rescan attestations recorded "
                    "in durable history for this subject"
                )
            if (
                len(cached) > len(authoritative)
                or cached != authoritative[: len(cached)]
            ):
                raise OperationalError(
                    "Durable rescan history conflicts with signed attestations"
                )
            if cached != authoritative:
                self._write(path, subject, authoritative)
        return _require_latest(authoritative, requested_previous)

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
        with locked_file(path.with_suffix(".lock"), label="rescan history"):
            entries = list(self._load(subject))
            current = entries[-1].record_digest if entries else None
            if current != expected_previous:
                raise OperationalError(
                    "Authoritative rescan history changed during the invocation"
                )
            if entries and entry.verified_at < entries[-1].verified_at:
                raise OperationalError("Rescan verification clock moved backwards")
            _require_same_anchor((*entries, entry))
            if any(item.record_digest == entry.record_digest for item in entries):
                raise OperationalError("Rescan result digest is already recorded")
            entries.append(entry)
            self._write(path, subject, tuple(entries))

    @staticmethod
    def _write(
        path: Path,
        subject: OCIReference,
        entries: tuple[RescanHistoryEntry, ...],
    ) -> None:
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
        _require_same_anchor(entries)
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


def history_from_records(
    records: tuple[dict[str, object], ...], subject: OCIReference
) -> tuple[RescanHistoryEntry, ...]:
    """Reconstruct one complete authoritative chain from signed rescan records."""
    linked: list[_LinkedRecord] = []
    digests: set[str] = set()
    for record in records:
        try:
            validate_record(record)
        except InvalidInvocationError as exc:
            raise OperationalError("Signed rescan record is malformed") from exc
        if record.get("recordType") != "rescanResult":
            raise OperationalError("Signed rescan history has the wrong record type")
        payload = object_value(record.get("payload"), "rescan payload")
        if payload.get("subject") != str(subject):
            raise OperationalError("Signed rescan history names another subject")
        if payload.get("authoritative") is not True:
            raise OperationalError("Signed rescan history contains a diagnostic result")
        record_digest = sha256_bytes(canonical_json_bytes(record))
        if record_digest in digests:
            continue
        digests.add(record_digest)
        previous_digest = payload.get("previousResultDigest")
        if previous_digest is not None:
            if not isinstance(previous_digest, str):
                raise OperationalError("Signed rescan history link is malformed")
            try:
                Digest(previous_digest)
            except InvalidInvocationError as exc:
                raise OperationalError(
                    "Signed rescan history link is malformed"
                ) from exc
        remediation = object_value(payload.get("remediation"), "rescan remediation")
        raw_findings = remediation.get("findings")
        if not isinstance(raw_findings, list):
            raise OperationalError("Signed rescan remediation findings are malformed")
        findings = tuple(sorted(_finding(item) for item in raw_findings))
        try:
            entry = RescanHistoryEntry(
                record_digest=record_digest,
                release_record_digest=_string(payload.get("releaseRecordDigest")),
                verified_at=parse_timestamp(
                    record.get("createdAt"), "Rescan history timestamp"
                ),
                active_findings=findings,
            )
        except ValueError as exc:
            raise OperationalError(
                "Signed rescan history contains invalid values"
            ) from exc
        linked.append(_LinkedRecord(entry, previous_digest))

    chain: list[RescanHistoryEntry] = []
    previous: str | None = None
    remaining = list(linked)
    while remaining:
        matches = [item for item in remaining if item.previous_digest == previous]
        if len(matches) != 1:
            raise OperationalError(
                "Signed rescan attestations do not form one complete chain"
            )
        selected = matches[0]
        if chain and selected.entry.verified_at < chain[-1].verified_at:
            raise OperationalError("Signed rescan history timestamps are unordered")
        chain.append(selected.entry)
        remaining.remove(selected)
        previous = selected.entry.record_digest
    _require_same_anchor(tuple(chain))
    return tuple(chain)


def _require_same_anchor(entries: tuple[RescanHistoryEntry, ...]) -> None:
    if len({entry.release_record_digest for entry in entries}) > 1:
        raise OperationalError("Rescan history changes its release record anchor")


def _require_latest(
    entries: tuple[RescanHistoryEntry, ...], requested_previous: str | None
) -> tuple[RescanHistoryEntry, ...]:
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
            release_record_digest=_string(value.get("releaseRecordDigest")),
            verified_at=parse_timestamp(
                value.get("verifiedAt"), "Rescan history timestamp"
            ),
            active_findings=tuple(sorted(findings)),
        )
    except (InvalidInvocationError, ValueError) as exc:
        raise OperationalError("Rescan history entry contains invalid values") from exc


def _finding(value: object) -> RemediationFindingKey:
    finding = object_value(value, "rescan remediation finding")
    try:
        return RemediationFindingKey(
            platform=Platform.parse(_string(finding.get("platform"))),
            component=_string(finding.get("component")),
            advisory=_string(finding.get("advisory")),
        )
    except InvalidInvocationError as exc:
        raise OperationalError("Rescan remediation finding is malformed") from exc


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise OperationalError("Rescan history string is malformed")
    return value
