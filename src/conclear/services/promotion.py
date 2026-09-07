"""Promotion of the verified digest to the configured release tags.

`promote_candidate` repeats the release-verification check against the signed
statement, applies every immutable and moving release tag to the verified
digest through the registry control plane, verifies each tag through the
transport view and finally removes the ConClear-owned candidate tag. It refuses
to repoint an immutable tag that already names another digest and reports a
registry that cannot protect tags without failing the promotion.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from conclear.config import ImageConfig
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
    UnsupportedOperationError,
)
from conclear.jsonutil import load_json
from conclear.parsing import object_value
from conclear.presentation import Finding
from conclear.registry_control import RegistryControl
from conclear.services.attestation import Signer, require_downloaded_statement
from conclear.services.publication import PublishedCandidate, Registry, retry_entry
from conclear.services.verification import VerificationResult
from conclear.values import Digest, OCIReference
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
    image: ImageConfig,
    version: str | None,
    workspace: RunWorkspace,
    registry_control: RegistryControl,
    registry: Registry,
    signer: Signer,
    public_key: Path,
    auth_file: Path | None,
    now: datetime,
) -> PromotionResult:
    """Repeat verification, apply exact digest tags and remove the candidate tag."""
    if workspace.load().state is not RunState.VERIFIED:
        raise InvalidInvocationError("Promotion requires verified state")
    tag_state = registry_control.observe_tag(
        image.repository, published.reference.tag or ""
    )
    if tag_state is None or tag_state.digest != published.graph.digest:
        raise OperationalError("Candidate tag changed before promotion")
    if tag_state.expiration is None:
        raise OperationalError("Candidate expiration is missing before promotion")
    if now.astimezone(UTC) >= tag_state.expiration:
        raise RuleRejectionError("Candidate expired before promotion", code="CC0603")
    signer.verify_attestation(
        subject=verification.subject,
        public_key=public_key,
        predicate_type=verification.predicate_type,
    )
    expected_statement = object_value(
        load_json(verification.statement_path), "release verification statement"
    )
    require_downloaded_statement(
        signer,
        subject=verification.subject,
        predicate_type=verification.predicate_type,
        expected=expected_statement,
    )
    immutable_tags = tuple(
        _render_tag(item, version) for item in image.release.immutable_tags
    )
    moving_tags = image.release.moving_tags
    if set(immutable_tags) & set(moving_tags):
        raise InvalidInvocationError(
            "Immutable and moving release tags must be disjoint"
        )
    observed: list[tuple[str, Digest]] = []
    protected = True
    for tag in immutable_tags:
        current = registry_control.observe_tag(image.repository, tag)
        if current is not None and current.digest != published.graph.digest:
            raise RuleRejectionError(
                f"Immutable release tag already names another digest: {tag}",
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
                    )
                    and protected
                )
                observed.append((tag, published.graph.digest))
                continue
            if not current.immutable:
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
        )
        observed.append((tag, published.graph.digest))
    workspace.transition(RunState.PROMOTED, now=now)
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
                Finding(
                    "CC0605",
                    "error",
                    "Verified digest was promoted but candidate cleanup failed",
                ),
            ),
            immutability_enabled=protected,
        )
    else:
        return PromotionResult(tuple(observed), True, immutability_enabled=protected)


def _write_release_tag(
    tag: str,
    digest: Digest,
    image: ImageConfig,
    workspace: RunWorkspace,
    registry_control: RegistryControl,
    registry: Registry,
    auth_file: Path | None,
    *,
    immutable: bool,
) -> bool:
    """Write or adopt one release tag and return whether the registry protects it."""
    resource_id = f"tag-{tag}"
    tagged = image.repository.with_tag(tag)
    metadata = {"digest": str(digest), "immutable": immutable}
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
            resolved = registry.resolve_digest(tagged, auth_file=auth_file)
            if resolved != digest:
                raise OperationalError(
                    f"Release tag {tag} has conflicting registry observations"
                )
            protected = True
            if immutable and not current.immutable:
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
        result = registry_control.assign_tag(image.repository, tag, digest)
        resolved = registry.resolve_digest(tagged, auth_file=auth_file)
        if result.digest != digest or resolved != digest:
            raise OperationalError(
                f"Release tag {tag} did not resolve to verified digest"
            )
        protected = True
        if immutable:
            protected = _protect_release_tag(
                registry_control, image, tag, expected_digest=digest
            )
    except Exception:
        workspace.journal.mark_failed(resource_id)
        raise
    workspace.journal.update(resource_id, ResourceStatus.CREATED)
    return protected


def _protect_release_tag(
    registry_control: RegistryControl,
    image: ImageConfig,
    tag: str,
    *,
    expected_digest: Digest,
) -> bool:
    """Enable registry tag protection where the backend enforces it.

    Returns False when the backend reports the control as unavailable; the
    verified digest stays in place and ConClear's own refusal to repoint an
    immutable version tag remains the enforced control.
    """
    try:
        result = registry_control.ensure_tag_immutable(image.repository, tag)
    except UnsupportedOperationError:
        return False
    if result.digest != expected_digest or not result.immutable:
        raise OperationalError(f"Immutable release tag was not protected: {tag}")
    return True


def _render_tag(template: str, version: str | None) -> str:
    if "{version}" in template:
        if version is None:
            raise InvalidInvocationError(
                "Version-dependent release tag requires --version"
            )
        rendered = template.replace("{version}", version)
    else:
        rendered = template
    OCIReference("registry.invalid", "validation").with_tag(rendered)
    return rendered
