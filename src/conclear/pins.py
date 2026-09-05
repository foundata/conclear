"""Durable external image pin observations and divergence policy."""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from conclear.config import ImageConfig, PinConfig, PinIntent
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.fileio import locked_file
from conclear.jsonutil import atomic_write_json, load_json
from conclear.presentation import Finding
from conclear.values import Digest, OCIReference


class PinResolver(Protocol):
    """Resolve a readable image tag at an adapter boundary."""

    def resolve_digest(self, reference: OCIReference) -> Digest:
        """Return the current immutable manifest digest."""
        ...


@dataclass(frozen=True, slots=True)
class PinObservation:
    """One current tag resolution and its durable divergence history."""

    reference: OCIReference
    pinned_digest: Digest
    observed_digest: Digest
    checked_at: datetime
    divergence_since: datetime | None
    history_initialized: bool
    findings: tuple[Finding, ...]

    def __post_init__(self) -> None:
        """Validate temporal and digest relationships in one observation."""
        if self.reference.digest is None or self.reference.tag is None:
            raise OperationalError("Pin observations require a tagged digest reference")
        if self.pinned_digest != self.reference.digest:
            raise OperationalError("Pin observation digest differs from its reference")
        if self.checked_at.tzinfo is None or self.checked_at.utcoffset() is None:
            raise OperationalError("Pin observation time must be timezone-aware")
        if self.divergence_since is not None and (
            self.divergence_since.tzinfo is None
            or self.divergence_since.utcoffset() is None
        ):
            raise OperationalError("Pin divergence time must be timezone-aware")
        if (self.observed_digest == self.pinned_digest) != (
            self.divergence_since is None
        ):
            raise OperationalError("Pin divergence time does not match observed digest")

    @property
    def accepted(self) -> bool:
        """Return whether the observation has no rejecting error finding."""
        return not any(finding.severity == "error" for finding in self.findings)

    def to_dict(self) -> dict[str, object]:
        """Return the evidence representation of this observation."""
        value: dict[str, object] = {
            "reference": str(self.reference),
            "pinnedDigest": str(self.pinned_digest),
            "observedDigest": str(self.observed_digest),
            "checkedAt": _timestamp(self.checked_at),
            "divergenceSince": (
                None
                if self.divergence_since is None
                else _timestamp(self.divergence_since)
            ),
            "historyInitialized": self.history_initialized,
            "findings": [finding.to_dict() for finding in self.findings],
        }
        return value


class PinStore:
    """Atomically update pin observations outside the project checkout."""

    def __init__(self, state_home: Path) -> None:
        """Use one protected durable state root."""
        self._root = state_home / "conclear" / "pins"

    def check(
        self,
        pin: PinConfig,
        *,
        resolver: PinResolver,
        maximum_divergence: timedelta,
        now: datetime,
    ) -> PinObservation:
        """Resolve, update and evaluate one declared tag and digest pin."""
        if now.tzinfo is None or now.utcoffset() is None:
            raise OperationalError("Pin observation time must be timezone-aware")
        reference = pin.reference
        if reference.tag is None or reference.digest is None:
            raise OperationalError("Pin checks require a tag and digest")
        readable = OCIReference(
            registry=reference.registry,
            repository=reference.repository,
            tag=reference.tag,
        )
        observed = resolver.resolve_digest(readable)
        path = self._path(reference)
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with locked_file(path.with_suffix(".lock"), label="durable pin state"):
            previous = self._load_optional(path, reference)
            if previous is not None and previous.checked_at > now.astimezone(UTC):
                raise OperationalError("Pin observation time is in the future")
            initialized = previous is None
            divergence_since: datetime | None = None
            if observed != reference.digest:
                if (
                    previous is not None
                    and previous.observed_digest != previous.pinned_digest
                ):
                    divergence_since = previous.divergence_since
                if divergence_since is None:
                    divergence_since = now
                elif divergence_since > now.astimezone(UTC):
                    raise OperationalError("Pin divergence start time is in the future")
            findings = _evaluate_divergence(
                pin,
                observed=observed,
                divergence_since=divergence_since,
                maximum=maximum_divergence,
                now=now,
            )
            result = PinObservation(
                reference=reference,
                pinned_digest=reference.digest,
                observed_digest=observed,
                checked_at=now,
                divergence_since=divergence_since,
                history_initialized=initialized,
                findings=findings,
            )
            atomic_write_json(path, {"schemaVersion": 1, **result.to_dict()})
            return result

    def load_fresh(
        self,
        pin: PinConfig,
        *,
        maximum_age: timedelta,
        now: datetime,
    ) -> PinObservation:
        """Load one observation only while it remains within the freshness bound."""
        observation = self._load_optional(self._path(pin.reference), pin.reference)
        if observation is None:
            raise OperationalError(
                f"No durable pin observation exists for {pin.reference}"
            )
        age = now.astimezone(UTC) - observation.checked_at.astimezone(UTC)
        if age < timedelta(0):
            raise OperationalError("Pin observation time is in the future")
        if age > maximum_age:
            raise OperationalError(f"Pin observation is stale for {pin.reference}")
        return observation

    def _path(self, reference: OCIReference) -> Path:
        key = hashlib.sha256(str(reference).encode()).hexdigest()
        return self._root / f"{key}.json"

    @staticmethod
    def _load_optional(path: Path, reference: OCIReference) -> PinObservation | None:
        if not path.exists():
            return None
        value = load_json(path)
        if not isinstance(value, dict) or value.get("schemaVersion") != 1:
            raise OperationalError("Durable pin state is malformed")
        try:
            stored_reference = OCIReference.parse(_string(value.get("reference")))
            if stored_reference != reference:
                raise OperationalError("Durable pin state identity does not match")
            findings_value = value.get("findings")
            if not isinstance(findings_value, list):
                raise OperationalError("Durable pin findings are malformed")
            findings = tuple(_parse_finding(item) for item in findings_value)
            divergence_value = value.get("divergenceSince")
            observation = PinObservation(
                reference=stored_reference,
                pinned_digest=Digest(_string(value.get("pinnedDigest"))),
                observed_digest=Digest(_string(value.get("observedDigest"))),
                checked_at=_parse_timestamp(value.get("checkedAt")),
                divergence_since=(
                    _parse_timestamp(divergence_value)
                    if divergence_value is not None
                    else None
                ),
                history_initialized=_boolean(value.get("historyInitialized")),
                findings=findings,
            )
            if (
                observation.observed_digest != observation.pinned_digest
                and observation.divergence_since is None
            ):
                raise OperationalError("Divergent pin state has no start timestamp")
            return observation
        except (InvalidInvocationError, ValueError) as exc:
            raise OperationalError("Durable pin state contains invalid values") from exc


def check_image_pins(
    store: PinStore,
    image: ImageConfig,
    *,
    resolver: PinResolver,
    now: datetime,
) -> tuple[PinObservation, ...]:
    """Run the pin gate for every declared pin of one image at one instant."""
    return tuple(
        store.check(
            pin,
            resolver=resolver,
            maximum_divergence=image.limits.pin_divergence,
            now=now,
        )
        for pin in image.pins
    )


def _evaluate_divergence(
    pin: PinConfig,
    *,
    observed: Digest,
    divergence_since: datetime | None,
    maximum: timedelta,
    now: datetime,
) -> tuple[Finding, ...]:
    if pin.reference.digest == observed:
        return ()
    findings: list[Finding] = []
    if pin.tag_intent is PinIntent.IMMUTABLE_VERSION:
        findings.append(
            Finding(
                check_id="CC0205",
                severity="warning",
                message=(
                    f"Immutable-version tag changed from {pin.reference.digest} to {observed}; "
                    "supply-chain review is required"
                ),
                location=str(pin.reference),
            )
        )
    if divergence_since is None:
        raise OperationalError("Divergent pin has no start timestamp")
    if now.astimezone(UTC) - divergence_since.astimezone(UTC) >= maximum:
        findings.append(
            Finding(
                check_id="CC0204",
                severity="error",
                message=f"Pinned image tag has diverged for the maximum {maximum}",
                location=str(pin.reference),
            )
        )
    return tuple(findings)


def _parse_finding(value: object) -> Finding:
    if not isinstance(value, dict):
        raise OperationalError("Durable pin finding is malformed")
    location = value.get("location")
    if location is not None and not isinstance(location, str):
        raise OperationalError("Durable pin finding location is malformed")
    return Finding(
        check_id=_string(value.get("checkId")),
        severity=_string(value.get("severity")),
        message=_string(value.get("message")),
        location=location,
    )


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    text = _string(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperationalError("Durable pin timestamp is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OperationalError("Durable pin timestamp is not timezone-aware")
    return parsed


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise OperationalError("Durable pin string field is malformed")
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise OperationalError("Durable pin boolean field is malformed")
    return value
