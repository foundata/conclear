"""Policy decisions for optional CI correlation context."""

from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.ci import (
    CIContextAbsent,
    CIContextInvalid,
    CIContextObservation,
    ObservedCIContext,
)
from conclear.config import normalize_source_url
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import atomic_write_json
from conclear.records import SourceIdentity
from conclear.release_profile import CIContextPolicy


@dataclass(frozen=True, slots=True)
class PublicCIContext:
    """Provider-neutral correlation metadata safe for public evidence."""

    provider: str
    repository: str
    revision: str
    run_id: str

    def to_public_dict(self) -> dict[str, object]:
        """Return the stable public record representation."""
        return {
            "provider": self.provider,
            "source": "provider-environment",
            "repository": self.repository,
            "revision": self.revision,
            "runId": self.run_id,
        }


def resolve_ci_context(
    observation: CIContextObservation | None,
    *,
    policy: CIContextPolicy,
    source: SourceIdentity,
    diagnostic_path: Path,
) -> PublicCIContext | None:
    """Apply profile policy and bind optional context to the isolated checkout."""
    if policy is CIContextPolicy.OMIT:
        return None
    if observation is None or isinstance(observation, CIContextAbsent):
        reason = "No supported CI provider context was observed"
        _write_diagnostic(
            diagnostic_path, status=_failure_status(policy), reason=reason
        )
        return _handle_failure(policy, reason)
    if isinstance(observation, CIContextInvalid):
        _write_diagnostic(
            diagnostic_path,
            status=_failure_status(policy),
            reason=observation.diagnostic,
            provider=observation.provider,
        )
        return _handle_failure(policy, observation.diagnostic)

    disagreement = _context_disagreement(observation, source)
    _write_diagnostic(
        diagnostic_path,
        status="recorded" if disagreement is None else _failure_status(policy),
        reason=disagreement,
        context=observation,
    )
    if disagreement is not None:
        return _handle_failure(policy, disagreement)
    return PublicCIContext(
        provider=observation.provider,
        repository=observation.repository,
        revision=observation.revision,
        run_id=observation.run_id,
    )


def _context_disagreement(
    observation: ObservedCIContext, source: SourceIdentity
) -> str | None:
    try:
        claimed_source = normalize_source_url(
            f"{observation.server}/{observation.repository}"
        )
    except InvalidInvocationError:
        return "Observed CI repository is malformed"
    if claimed_source != source.repository:
        return "Observed CI repository differs from the isolated checkout"
    if observation.revision != source.revision:
        return "Observed CI revision differs from the isolated checkout"
    return None


def _handle_failure(policy: CIContextPolicy, reason: str) -> PublicCIContext | None:
    if policy is CIContextPolicy.REQUIRE:
        raise OperationalError(f"Required CI context is unavailable: {reason}")
    return None


def _failure_status(policy: CIContextPolicy) -> str:
    return "rejected" if policy is CIContextPolicy.REQUIRE else "ignored"


def _write_diagnostic(
    path: Path,
    *,
    status: str,
    reason: str | None,
    provider: str | None = None,
    context: ObservedCIContext | None = None,
) -> None:
    payload: dict[str, object] = {"schemaVersion": 1, "status": status}
    if reason is not None:
        payload["reason"] = reason
    if context is not None:
        payload["ciContext"] = {
            "provider": context.provider,
            "source": "provider-environment",
            "server": context.server,
            "repository": context.repository,
            "revision": context.revision,
            "runId": context.run_id,
        }
    elif provider is not None:
        payload["provider"] = provider
    atomic_write_json(path, payload)
