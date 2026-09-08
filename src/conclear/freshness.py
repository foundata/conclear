"""Bounded validity of time-sensitive release qualification evidence."""

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta

from conclear.errors import InvalidInvocationError, RuleRejectionError
from conclear.parsing import Narrower
from conclear.records import format_timestamp, parse_timestamp

# One working day accommodates native workers and local review. Changing this
# limit changes release policy; repository configuration cannot extend it.
QUALIFICATION_WINDOW = timedelta(hours=24)

_narrow = Narrower(InvalidInvocationError)


@dataclass(frozen=True, slots=True)
class QualificationWindow:
    """An approval interval that assembly, publication and retry cannot extend."""

    started_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        """Reject ambiguous clocks and invalid intervals, including historical ones."""
        for value in (self.started_at, self.expires_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise InvalidInvocationError(
                    "Qualification clocks must be timezone-aware"
                )
        if self.started_at >= self.expires_at:
            raise InvalidInvocationError(
                "Qualification window must have positive duration"
            )

    @classmethod
    def start(cls, started_at: datetime) -> "QualificationWindow":
        """Start the compiled window at the original database selection time."""
        return cls(started_at, started_at + QUALIFICATION_WINDOW)

    @classmethod
    def from_dict(cls, value: object) -> "QualificationWindow":
        """Read a recorded interval without renewing it or imposing today's age."""
        window = _narrow.object_value(value, "qualification window")
        return cls(
            parse_timestamp(
                window.get("startedAt"),
                "qualification start",
                error=InvalidInvocationError,
            ),
            parse_timestamp(
                window.get("expiresAt"),
                "qualification expiry",
                error=InvalidInvocationError,
            ),
        )

    def to_dict(self) -> dict[str, str]:
        """Return the public timestamps retained in release evidence."""
        return {
            "startedAt": format_timestamp(self.started_at),
            "expiresAt": format_timestamp(self.expires_at),
        }

    def require_current(self, now: datetime, *, phase: str) -> None:
        """Refuse future or expired evidence at a release authorization boundary."""
        if now.tzinfo is None or now.utcoffset() is None:
            raise InvalidInvocationError(
                "Qualification check time must be timezone-aware"
            )
        if now < self.started_at:
            raise RuleRejectionError(
                "Qualification start is in the future", code="CC0505"
            )
        deadline = min(self.expires_at, self.started_at + QUALIFICATION_WINDOW)
        if now >= deadline:
            raise RuleRejectionError(
                f"Qualification expired before {phase} at {format_timestamp(deadline)}; "
                "start a new qualification with a fresh common database snapshot",
                code="CC0505",
            )


def evidence_window(payload: dict[str, object]) -> QualificationWindow:
    """Bound a recorded window by every image's pins and applied exceptions.

    This reads historical facts only. Call require_current at a release gate,
    not while inspecting or rescanning a previously published subject.
    """
    window = QualificationWindow.from_dict(payload.get("qualificationWindow"))
    deadlines = [window.expires_at]
    dependencies = _narrow.array_value(
        payload.get("testImageDependencies"), "test dependencies"
    )
    images = (
        payload,
        *(_narrow.object_value(item, "test dependency") for item in dependencies),
    )
    for image in images:
        limits = _narrow.object_value(image.get("effectiveLimits"), "pin limits")
        seconds = limits.get("pinFreshnessSeconds")
        if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds <= 0:
            raise InvalidInvocationError("Pin freshness limit is malformed")
        for raw in _narrow.array_value(
            image.get("pinObservations"), "pin observations"
        ):
            observation = _narrow.object_value(raw, "pin observation")
            checked_at = parse_timestamp(
                observation.get("checkedAt"),
                "pin check time",
                error=InvalidInvocationError,
            )
            deadlines.append(checked_at + timedelta(seconds=seconds))
            if observation.get("divergenceSince") is not None:
                divergence = parse_timestamp(
                    observation["divergenceSince"],
                    "pin divergence start",
                    error=InvalidInvocationError,
                )
                divergence_seconds = _narrow.integer_value(
                    limits.get("pinDivergenceSeconds"), "pin divergence limit"
                )
                deadlines.append(divergence + timedelta(seconds=divergence_seconds))
    for raw in _narrow.array_value(
        payload.get("appliedExceptions"), "applied exceptions"
    ):
        exception = _narrow.object_value(raw, "applied exception")
        expires = _narrow.string_value(exception.get("expires"), "exception expiry")
        try:
            deadlines.append(
                datetime.combine(date.fromisoformat(expires), time(), UTC)
                + timedelta(days=1)
            )
        except (ValueError, OverflowError) as exc:
            raise InvalidInvocationError("Exception expiry is malformed") from exc
    return QualificationWindow(window.started_at, min(deadlines))


def common_window(windows: tuple[QualificationWindow, ...]) -> QualificationWindow:
    """Keep the earliest start and deadline across the required platforms."""
    if not windows:
        raise InvalidInvocationError("Release has no qualification window")
    return QualificationWindow(
        min(item.started_at for item in windows),
        min(item.expires_at for item in windows),
    )
