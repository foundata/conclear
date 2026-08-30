"""Domain failure categories and public exit statuses."""

from enum import IntEnum


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

    def __init__(self, message: str, *, code: str | None = None) -> None:
        """Create an expected failure with an optional stable check code."""
        super().__init__(message)
        self.code = code


class OperationalError(ConClearError):
    """Report an inability to establish or complete an operation."""

    exit_status = ExitStatus.OPERATIONAL_FAILURE
    error_type = "operationalFailure"


class RuleRejectionError(ConClearError):
    """Report observed content that violates an effective rule."""

    exit_status = ExitStatus.RULE_REJECTION
    error_type = "ruleRejection"


class InvalidInvocationError(ConClearError):
    """Report invalid command input or configuration."""

    exit_status = ExitStatus.INVALID_INVOCATION
    error_type = "invalidInvocation"
