"""Domain failure categories and public exit statuses."""

from collections.abc import Sequence
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from conclear.presentation import Finding


class ExitStatus(IntEnum):
    """Public process exit statuses."""

    SUCCESS = 0
    OPERATIONAL_FAILURE = 1
    RULE_REJECTION = 2
    INVALID_INVOCATION = 64


class ConClearError(RuntimeError):
    """Base class for expected application failures."""

    exit_status: ExitStatus
    error_type: str

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        findings: Sequence["Finding"] = (),
    ) -> None:
        """Create an expected failure with an optional stable check code.

        `findings` carries the concrete findings behind an aggregate failure,
        such as the platform findings behind a rejected qualification, so the
        command result names the cause instead of only the summary.
        """
        super().__init__(message)
        self.code = code
        self.findings: tuple[Finding, ...] = tuple(findings)
        self.run_id: str | None = None


class OperationalError(ConClearError):
    """Report an inability to establish or complete an operation."""

    exit_status = ExitStatus.OPERATIONAL_FAILURE
    error_type = "operationalFailure"


class UnsupportedOperationError(OperationalError):
    """Report an optional external control that is conclusively unsupported."""


class CommandTimeoutError(OperationalError):
    """Report an external command that exceeded its explicit timeout."""

    def __init__(self, message: str, *, stdout: str = "", stderr: str = "") -> None:
        """Retain only already redacted bounded command output."""
        super().__init__(message)
        self.stdout = stdout
        self.stderr = stderr


class CommandExecutionError(OperationalError):
    """Report an external command that returned a failure status."""

    def __init__(
        self,
        message: str,
        *,
        returncode: int | None = None,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        """Retain only already redacted bounded command output."""
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class RuleRejectionError(ConClearError):
    """Report observed content that violates an effective rule."""

    exit_status = ExitStatus.RULE_REJECTION
    error_type = "ruleRejection"


class InvalidInvocationError(ConClearError):
    """Report invalid command input or configuration."""

    exit_status = ExitStatus.INVALID_INVOCATION
    error_type = "invalidInvocation"


def bind_failed_run(failure: BaseException, run_id: str) -> None:
    """Name the run whose journaled resources a failure leaves behind.

    Every exception instance carries the identity, so an interrupt or an
    internal error raised inside a created run is reported like an expected
    failure.
    """
    if isinstance(failure, ConClearError):
        failure.run_id = run_id
    else:
        failure.__dict__["run_id"] = run_id


def failed_run_id(failure: BaseException) -> str | None:
    """Return the run bound to a failure or to the failure it was raised from."""
    for candidate in (failure, failure.__cause__):
        if candidate is None:
            continue
        value = candidate.__dict__.get("run_id")
        if isinstance(value, str) and value:
            return value
    return None
