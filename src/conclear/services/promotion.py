"""Promotion of the verified digest to the configured release tags.

`promote_candidate` repeats the release-verification check against the signed
statement, applies every version and moving release tag to the verified
digest through the registry control plane, verifies each tag through the
transport view and finally removes the ConClear-owned candidate tag. It refuses
to repoint a version tag that already names another digest. Registry-enforced
protection is verified when the protected profile requires it.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from conclear.config import ReleaseImageConfig
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.freshness import QualificationWindow
from conclear.jsonutil import load_json
from conclear.parsing import object_value
from conclear.presentation import Finding
from conclear.registry_control import RegistryControl
from conclear.registry_policy import (
    CandidateCleanupMode,
    TagProtectionMode,
    policy_findings,
)
from conclear.services.attestation import Signer, require_verified_statement
from conclear.services.publication import PublishedCandidate, Registry, retry_entry
from conclear.services.verification import VerificationResult
from conclear.values import Digest
from conclear.workspace import ResourceKind, ResourceStatus, RunState, RunWorkspace


@dataclass(frozen=True, slots=True)
class PromotionResult:
    """Observed final tag mappings and candidate cleanup result."""

    tags: tuple[tuple[str, Digest], ...]
    candidate_deleted: bool
    findings: tuple[Finding, ...] = ()
    immutability_enabled: bool = True


def promote_candidate(
    published: PublishedCandidate,
    verification: VerificationResult,
    *,
    image: ReleaseImageConfig,
    version: str | None,
    workspace: RunWorkspace,
    registry_control: RegistryControl,
    registry: Registry,
    signer: Signer,
    public_key: Path,
    auth_file: Path | None,
    now: datetime,
    clock: Callable[[], datetime],
) -> PromotionResult:
    """Repeat verification, apply exact digest tags and remove the candidate tag."""
    if workspace.load().state is not RunState.VERIFIED:
        raise InvalidInvocationError("Promotion requires verified state")
    tag_state = registry_control.observe_tag(
        image.repository, published.reference.tag or ""
    )
    if tag_state is None or tag_state.digest != published.graph.digest:
        raise OperationalError("Candidate tag changed before promotion")
    published.require_current(now)
    if (
        tag_state.expiration is None
        and published.policy.candidate_cleanup.mode is not CandidateCleanupMode.MANUAL
    ):
        raise OperationalError("Candidate expiration is missing before promotion")
    expiration = min(published.expiration, tag_state.expiration or published.expiration)
    if now.astimezone(UTC) >= expiration:
        raise RuleRejectionError("Candidate expired before promotion", code="CC0603")
    expected_statement = object_value(
        load_json(verification.statement_path), "release verification statement"
    )
    require_verified_statement(
        signer,
        public_key=public_key,
        subject=verification.subject,
        predicate_type=verification.predicate_type,
        expected=expected_statement,
    )
    predicate = object_value(
        expected_statement.get("predicate"), "release verification"
    )
    payload = object_value(predicate.get("payload"), "release verification payload")
    if (
        payload.get("candidateAuthorization") != published.authorization()
        or payload.get("registryPolicy") != published.policy.to_dict()
    ):
        raise RuleRejectionError(
            "Candidate authorization or registry policy differs from signed verification",
            code="CC0603",
        )
    window = QualificationWindow.from_dict(payload.get("qualificationWindow"))
    window.require_current(now, phase="promotion")

    def authorize_tag_write() -> None:
        checked_at = clock()
        window.require_current(checked_at, phase="promotion")
        if checked_at.astimezone(UTC) >= expiration:
            raise RuleRejectionError(
                "Candidate expired during promotion", code="CC0603"
            )

    authorize_tag_write()
    version_tags = image.release.render_versions(version)
    moving_tags = image.release.moving_tags
    require_protection = (
        published.policy.tag_protection.mode is TagProtectionMode.REQUIRED
    )
    if require_protection:
        registry_control.verify_tag_policy(
            image.repository,
            version_tags=version_tags,
            mutable_tags=(published.reference.tag or "", *moving_tags),
        )
    observed: list[tuple[str, Digest]] = []
    protected = require_protection and bool(version_tags)
    for tag in version_tags:
        current = registry_control.observe_tag(image.repository, tag)
        authorize_tag_write()
        if current is not None and current.digest != published.graph.digest:
            raise RuleRejectionError(
                f"Version release tag already names another digest: {tag}",
                code="CC0604",
            )
        if current is not None:
            resource_id = f"tag-{tag}"
            if any(
                entry.resource_id == resource_id
                for entry in workspace.journal.entries()
            ):
                protected = (
                    _write_release_tag(
                        tag,
                        published.graph.digest,
                        image,
                        workspace,
                        registry_control,
                        registry,
                        auth_file,
                        immutable=True,
                        require_protection=require_protection,
                        authorize_tag_write=authorize_tag_write,
                    )
                    and protected
                )
                observed.append((tag, published.graph.digest))
                continue
            if require_protection and not current.immutable:
                protected = (
                    _protect_release_tag(
                        registry_control, image, tag, expected_digest=current.digest
                    )
                    and protected
                )
            resolved = registry.resolve_digest(
                image.repository.with_tag(tag), auth_file=auth_file
            )
            if resolved != published.graph.digest:
                raise OperationalError(
                    f"Adopted release tag {tag} has conflicting registry observations"
                )
            observed.append((tag, current.digest))
            continue
        protected = (
            _write_release_tag(
                tag,
                published.graph.digest,
                image,
                workspace,
                registry_control,
                registry,
                auth_file,
                immutable=True,
                require_protection=require_protection,
                authorize_tag_write=authorize_tag_write,
            )
            and protected
        )
        observed.append((tag, published.graph.digest))
    for tag in moving_tags:
        _write_release_tag(
            tag,
            published.graph.digest,
            image,
            workspace,
            registry_control,
            registry,
            auth_file,
            immutable=False,
            require_protection=False,
            authorize_tag_write=authorize_tag_write,
        )
        observed.append((tag, published.graph.digest))
    authorize_tag_write()
    workspace.transition(RunState.PROMOTED, now=clock())
    try:
        if tag_state.immutable:
            mutable = registry_control.ensure_tag_mutable(
                image.repository, published.reference.tag or ""
            )
            if mutable.digest != published.graph.digest:
                raise OperationalError(
                    "Candidate tag changed while removing immutability"
                )
        registry_control.remove_tag(image.repository, published.reference.tag or "")
        workspace.journal.update("candidate", ResourceStatus.REMOVED)
    except Exception:
        return PromotionResult(
            tuple(observed),
            False,
            (
                *policy_findings(published.policy),
                Finding(
                    "CC0605",
                    "error",
                    "Verified digest was promoted but candidate cleanup failed",
                ),
            ),
            immutability_enabled=protected,
        )
    else:
        return PromotionResult(
            tuple(observed),
            True,
            policy_findings(published.policy),
            immutability_enabled=protected,
        )


def _write_release_tag(
    tag: str,
    digest: Digest,
    image: ReleaseImageConfig,
    workspace: RunWorkspace,
    registry_control: RegistryControl,
    registry: Registry,
    auth_file: Path | None,
    *,
    immutable: bool,
    require_protection: bool,
    authorize_tag_write: Callable[[], None],
) -> bool:
    """Write or adopt one release tag and return whether the registry protects it."""
    resource_id = f"tag-{tag}"
    tagged = image.repository.with_tag(tag)
    metadata = {
        "digest": str(digest),
        "versionTag": immutable,
        "registryProtectionRequired": require_protection,
    }
    existing = retry_entry(
        workspace,
        resource_id=resource_id,
        kind=ResourceKind.TAG_WRITE,
        identifier=str(tagged),
        metadata=metadata,
    )
    if existing is not None:
        current = registry_control.observe_tag(image.repository, tag)
        if current is not None and current.digest == digest:
            if not immutable and current.immutable:
                raise OperationalError(
                    f"Moving tag was unexpectedly made immutable: {tag}", code="CC0604"
                )
            resolved = registry.resolve_digest(tagged, auth_file=auth_file)
            if resolved != digest:
                raise OperationalError(
                    f"Release tag {tag} has conflicting registry observations"
                )
            protected = require_protection
            if require_protection and not current.immutable:
                authorize_tag_write()
                protected = _protect_release_tag(
                    registry_control, image, tag, expected_digest=digest
                )
            workspace.journal.update(resource_id, ResourceStatus.CREATED)
            return protected
        if existing.status is ResourceStatus.CREATED:
            raise OperationalError(f"Recorded release tag changed after write: {tag}")
    else:
        workspace.journal.plan(
            resource_id=resource_id,
            kind=ResourceKind.TAG_WRITE,
            identifier=str(tagged),
            ephemeral=False,
            metadata=metadata,
        )
    try:
        authorize_tag_write()
        result = registry_control.assign_tag(image.repository, tag, digest)
        resolved = registry.resolve_digest(tagged, auth_file=auth_file)
        if result.digest != digest or resolved != digest:
            raise OperationalError(
                f"Release tag {tag} did not resolve to verified digest"
            )
        protected = require_protection
        if require_protection:
            if not result.immutable:
                raise OperationalError(
                    f"Release tag was not protected on assignment: {tag}", code="CC0604"
                )
        elif not immutable and result.immutable:
            raise OperationalError(
                f"Moving tag was unexpectedly made immutable: {tag}", code="CC0604"
            )
    except Exception:
        workspace.journal.mark_failed(resource_id)
        raise
    workspace.journal.update(resource_id, ResourceStatus.CREATED)
    return protected


def _protect_release_tag(
    registry_control: RegistryControl,
    image: ReleaseImageConfig,
    tag: str,
    *,
    expected_digest: Digest,
) -> bool:
    """Require verified protection when adopting an existing final tag."""
    result = registry_control.ensure_tag_immutable(image.repository, tag)
    if result.digest != expected_digest or not result.immutable:
        raise OperationalError(f"Immutable release tag was not protected: {tag}")
    return True
