"""Complete isolated release orchestration."""

import platform as host_platform
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import override

from conclear.adapters.ci import CIContextObservation
from conclear.adapters.cosign import CosignAdapter
from conclear.adapters.registry_backends import (
    create_registry_control,
    validate_registry_destinations,
)
from conclear.artifacts import (
    load_candidate,
    load_provenance_materials,
    load_published,
    load_release_evidence,
    load_verification,
    qualification_transport,
    qualification_transports,
)
from conclear.config import ReleaseImageConfig, RepositoryConfig
from conclear.database import (
    select_database_by_digest,
    select_fresh_database,
    trivy_cache_root,
)
from conclear.dependencies import command_tools
from conclear.errors import (
    ConClearError,
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
    bind_failed_run,
)
from conclear.jsonutil import atomic_write_json, sha256_bytes
from conclear.pins import PinResolver, PinStore
from conclear.presentation import Finding
from conclear.provenance import ProvenanceInput, generate_provenance
from conclear.records import (
    SourceIdentity,
    Verdict,
    format_timestamp,
    parse_timestamp,
    utc_now,
)
from conclear.release_profile import ReleaseProfile
from conclear.runtime import ApplicationRuntime
from conclear.services.assembly import assemble_candidate
from conclear.services.attestation import attest_candidate
from conclear.services.ci_context import resolve_ci_context
from conclear.services.cleanup import cleanup_run
from conclear.services.preflight import preflight_image_closure
from conclear.services.promotion import PromotionResult, promote_candidate
from conclear.services.publication import PublishedCandidate, publish_candidate
from conclear.services.qualification import qualify_platform
from conclear.services.qualification_inputs import QualificationInputs
from conclear.services.run_context import (
    create_source_run,
    finish_run_failure,
    hook_runner,
    open_source_run,
)
from conclear.services.verification import verify_candidate
from conclear.source_integrity import require_source_integrity
from conclear.values import (
    Digest,
    OCIReference,
    Platform,
    validate_release_version,
)
from conclear.workspace import (
    IdFactory,
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
    UlidFactory,
)


@dataclass(frozen=True, slots=True)
class ReleaseRequest:
    """User-selected source and release naming inputs."""

    repository: Path
    revision: str
    image_id: str | None
    version: str | None
    profile: ReleaseProfile
    state_home: Path
    cache_home: Path
    passphrase: str | None
    ci_context: CIContextObservation | None


@dataclass(frozen=True, slots=True)
class ReleaseResult:
    """Completed release identity and observed promotion result."""

    run_id: str
    workspace: Path
    subject: str
    tags: tuple[tuple[str, str], ...]
    candidate_deleted: bool
    findings: tuple[Finding, ...] = ()
    immutability_enabled: bool = True


class AuthenticatedPinResolver(PinResolver):
    """Resolve readable pin tags through explicit registry authentication."""

    def __init__(self, runtime: ApplicationRuntime, auth_file: Path | None) -> None:
        """Bind the resolver to one immutable Skopeo tool and auth file."""
        self._registry = runtime.skopeo()
        self._auth_file = auth_file

    @override
    def resolve_digest(self, reference: OCIReference) -> Digest:
        return self._registry.resolve_digest(reference, auth_file=self._auth_file)


def execute_release(
    request: ReleaseRequest,
    *,
    id_factory: IdFactory | None = None,
    now_factory: Callable[[], datetime] = utc_now,
) -> ReleaseResult:
    """Run the complete release state machine from detached checkout to promotion."""
    if request.version is not None:
        validate_release_version(request.version)
    source_run = create_source_run(
        source_root=request.repository,
        selector=request.revision,
        image_id=request.image_id,
        version=request.version,
        state_home=request.state_home,
        names=command_tools("release"),
        profile_name=request.profile.name,
        additional_inputs=_profile_inputs(request.profile),
        allowed_origins=request.profile.allowed_source_origins,
        id_factory=id_factory or UlidFactory(),
        now=now_factory(),
    )
    workspace = source_run.workspace
    try:
        result = _continue_release(
            request,
            repository=source_run.repository,
            workspace=workspace,
            runtime=source_run.runtime,
            source=source_run.source,
            origin=source_run.origin,
            source_time=source_run.source_time,
            now_factory=now_factory,
        )
    except BaseException as exc:
        _finish_failure(workspace, exc, now_factory())
        bind_failed_run(exc, workspace.run_id)
        raise
    return result


def resume_release(
    run_id: str,
    *,
    repository: Path,
    profile: ReleaseProfile,
    state_home: Path,
    cache_home: Path,
    passphrase: str | None,
    ci_context: CIContextObservation | None,
    now_factory: Callable[[], datetime] = utc_now,
) -> ReleaseResult:
    """Resume a non-terminal release after revalidating every immutable input."""
    source_run = open_source_run(
        state_home=state_home,
        run_id=run_id,
        names=command_tools("release"),
        allowed_origins=profile.allowed_source_origins,
    )
    workspace = source_run.workspace
    snapshot = workspace.load()
    expected = snapshot.immutable_inputs
    workspace.validate_resume(expected)
    source_root = repository.resolve(strict=True)
    if expected.get("sourceRoot") != str(source_root):
        raise InvalidInvocationError("Resume source repository differs from the run")
    if expected.get("profile") != profile.name:
        raise InvalidInvocationError("Resume profile differs from the run")
    for key, value in _profile_inputs(profile).items():
        if expected.get(key) != value:
            raise InvalidInvocationError("Resume release trust profile changed")
    image_id = expected.get("image")
    revision = expected.get("sourceRevision")
    if image_id is None or revision is None:
        raise InvalidInvocationError("Run immutable source inputs are incomplete")
    if snapshot.state is RunState.INCOMPLETE:
        image = source_run.repository.release_image(image_id)
        protected_resources = {
            "source-worktree",
            f"candidate-layout-{image.image_id}",
        }
        for platform in image.platforms:
            record_path = (
                workspace.root
                / "records"
                / f"platform-qualification-{platform.key}.json"
            )
            if record_path.is_file():
                qualification_transport(workspace, image, platform)
                protected_resources.add(f"layout-{image.image_id}-{platform.key}")
        registry_control = create_registry_control(
            profile, destinations=(image.repository,)
        )
        try:
            cleanup_run(
                workspace,
                buildah=source_run.runtime.buildah(),
                podman=source_run.runtime.podman(),
                registry_control=registry_control,
                git=source_run.runtime.git(),
                statuses=frozenset(
                    {
                        ResourceStatus.PLANNED,
                        ResourceStatus.CREATED,
                        ResourceStatus.FAILED,
                    }
                ),
                excluded_kinds=frozenset(
                    {ResourceKind.CANDIDATE_REFERENCE, ResourceKind.RUNTIME_DIRECTORY}
                ),
                excluded_resource_ids=frozenset(protected_resources),
            )
        finally:
            registry_control.close()
        workspace.resume(expected, now=now_factory())
    request = ReleaseRequest(
        repository=source_root,
        revision=revision,
        image_id=image_id,
        version=expected.get("version") or None,
        profile=profile,
        state_home=state_home,
        cache_home=cache_home,
        passphrase=passphrase,
        ci_context=ci_context,
    )
    try:
        return _continue_release(
            request,
            repository=source_run.repository,
            workspace=workspace,
            runtime=source_run.runtime,
            source=source_run.source,
            origin=source_run.origin,
            source_time=source_run.source_time,
            now_factory=now_factory,
        )
    except BaseException as exc:
        _finish_failure(workspace, exc, now_factory())
        bind_failed_run(exc, workspace.run_id)
        raise


def _continue_release(
    request: ReleaseRequest,
    *,
    repository: RepositoryConfig,
    workspace: RunWorkspace,
    runtime: ApplicationRuntime,
    source: SourceIdentity,
    origin: str,
    source_time: datetime,
    now_factory: Callable[[], datetime],
) -> ReleaseResult:
    image = repository.release_image(request.image_id)
    image.release.render_versions(request.version)
    validate_registry_destinations(request.profile, (image.repository,))
    require_source_integrity(workspace, repository.path.parent)
    public_ci_context = resolve_ci_context(
        request.ci_context,
        policy=request.profile.ci_context,
        source=source,
        origin=origin,
        diagnostic_path=workspace.root / "reports" / "ci-context.json",
    )
    if workspace.load().state is RunState.CREATED:
        _qualify_release(
            request,
            repository=repository,
            workspace=workspace,
            runtime=runtime,
            source=source,
            source_time=source_time,
            now_factory=now_factory,
        )
    if workspace.load().state is RunState.QUALIFIED:
        candidate = assemble_candidate(
            qualification_transports(workspace, image),
            source_time=source_time,
            repository=repository,
            image=image,
            workspace=workspace,
            version=request.version,
            tools=runtime.identities,
            now=now_factory(),
            clock=now_factory,
        )
    if (
        workspace.load().state is RunState.ASSEMBLED
        and not (workspace.root / "records" / "provenance.json").is_file()
    ):
        generate_release_provenance(
            workspace, repository, image, source=source, now=now_factory()
        )
    candidate = load_candidate(workspace, image)
    evidence = load_release_evidence(workspace, image)
    private_key = request.profile.cosign_private_key
    if private_key is None:
        raise InvalidInvocationError("Release profile has no Cosign signing key")
    registry = runtime.skopeo()
    signer = runtime.cosign(auth_file=request.profile.auth_file)
    registry_control = create_registry_control(
        request.profile, destinations=(image.repository,)
    )
    try:
        if workspace.load().state is RunState.ASSEMBLED:
            publish_candidate(
                candidate,
                image=image,
                policy=request.profile.registry.policy,
                workspace=workspace,
                registry=registry,
                registry_control=registry_control,
                auth_file=request.profile.auth_file,
                now=now_factory(),
                clock=now_factory,
            )
        published = load_published(workspace, candidate, image)
        if workspace.load().state is RunState.PUBLISHED:
            attest_candidate(
                published,
                evidence,
                image=image,
                workspace=workspace,
                signer=signer,
                private_key=private_key,
                public_key=request.profile.cosign_public_key,
                passphrase=request.passphrase,
                passphrase_path=request.profile.passphrase_file,
                registry=registry,
                auth_file=request.profile.auth_file,
                now=now_factory(),
            )
        if workspace.load().state is RunState.ATTESTED:
            mode, key_id = signer_identity(request.profile, signer)
            verify_candidate(
                published,
                candidate,
                evidence,
                workspace=workspace,
                image=image,
                profile=request.profile,
                signer=signer,
                registry=registry,
                auth_file=request.profile.auth_file,
                private_key=private_key,
                passphrase=request.passphrase,
                signer_mode=mode,
                signer_key_id=key_id,
                host_architecture=host_platform.machine(),
                ci_context=public_ci_context,
                now=now_factory(),
                clock=now_factory,
            )
        if workspace.load().state is not RunState.VERIFIED:
            raise OperationalError("Release did not reach the verified state")
        verification = load_verification(
            workspace, image, published.immutable_reference
        )
        promotion = promote_candidate(
            published,
            verification,
            image=image,
            version=request.version,
            workspace=workspace,
            registry_control=registry_control,
            registry=registry,
            signer=signer,
            public_key=request.profile.cosign_public_key,
            auth_file=request.profile.auth_file,
            now=now_factory(),
            clock=now_factory,
        )
        return _write_summary(workspace, published, promotion)
    finally:
        registry_control.close()


def _qualify_release(
    request: ReleaseRequest,
    *,
    repository: RepositoryConfig,
    workspace: RunWorkspace,
    runtime: ApplicationRuntime,
    source: SourceIdentity,
    source_time: datetime,
    now_factory: Callable[[], datetime],
) -> None:
    image = repository.release_image(request.image_id)
    preflight = preflight_image_closure(
        repository,
        image,
        hadolint=runtime.hadolint(),
        store=PinStore(request.state_home),
        resolver=AuthenticatedPinResolver(runtime, request.profile.auth_file),
        now=now_factory(),
    )
    static_rejection = next(
        (item for item in preflight.static_findings if item.severity == "error"),
        None,
    )
    if static_rejection is not None:
        raise RuleRejectionError(
            f"Static image checks rejected the release: {static_rejection.image}",
            code=static_rejection.check_id,
        )
    pin_rejection = next(
        (item for item in preflight.pin_findings if item.severity == "error"), None
    )
    if pin_rejection is not None:
        raise RuleRejectionError(
            f"External image pin checks rejected the release: {pin_rejection.image}",
            code=pin_rejection.check_id,
        )
    immutable_inputs = workspace.load().immutable_inputs
    started_value = immutable_inputs.get("qualificationStartedAt")
    if started_value is None:
        database = select_fresh_database(
            runtime.trivy(), trivy_cache_root(request.cache_home), now=now_factory()
        )
        qualification_started_at = now_factory()
        workspace.bind_immutable_inputs(
            {
                "qualificationStartedAt": format_timestamp(qualification_started_at),
                "qualificationDatabaseDigest": database.digest,
            }
        )
    else:
        qualification_started_at = parse_timestamp(
            started_value, "qualification start", error=InvalidInvocationError
        )
        database = select_database_by_digest(
            runtime.trivy(),
            trivy_cache_root(request.cache_home),
            expected_digest=Digest(
                immutable_inputs.get("qualificationDatabaseDigest", "")
            ),
            now=now_factory(),
            qualification_started_at=qualification_started_at,
        )
    hooks = hook_runner(runtime, repository, workspace)
    ordered_platforms = tuple(
        sorted(
            image.platforms,
            key=lambda item: (item != Platform.parse("linux/amd64"), item),
        )
    )
    for platform in ordered_platforms:
        record_path = (
            workspace.root / "records" / f"platform-qualification-{platform.key}.json"
        )
        if record_path.is_file():
            qualification_transport(workspace, image, platform)
            continue
        runtime.assert_unchanged()
        result = qualify_platform(
            QualificationInputs(
                repository=repository,
                image=image,
                workspace=workspace,
                source=source,
                source_time=source_time,
                version=request.version,
                platform=platform,
                tools=runtime.identities,
                auth_file=request.profile.auth_file,
                host_architecture=host_platform.machine(),
            ),
            builder=runtime.buildah(),
            runtime=runtime.podman(),
            hooks=hooks,
            scanner=runtime.trivy(),
            database=database,
            preflight=preflight,
            now=now_factory(),
            qualification_started_at=qualification_started_at,
            record_clock=now_factory,
        )
        if result.verdict is Verdict.REJECTED:
            rejecting_finding = next(
                finding for finding in result.findings if finding.severity == "error"
            )
            raise RuleRejectionError(
                f"Platform qualification rejected {platform}",
                code=rejecting_finding.check_id,
            )
        if result.verdict is Verdict.INCOMPLETE:
            raise OperationalError(f"Platform qualification was incomplete: {platform}")
    workspace.transition(RunState.QUALIFIED, now=now_factory())


def generate_release_provenance(
    workspace: RunWorkspace,
    repository: RepositoryConfig,
    image: ReleaseImageConfig,
    *,
    source: SourceIdentity,
    now: datetime,
) -> str:
    """Write the SLSA provenance for the run's accepted candidate and return its digest.

    The builder identity, version and start time come from the run's recorded
    immutable inputs, never from the caller, so the `provenance` command and
    the release workflow produce identical statements.

    Raises:
        InvalidInvocationError: If the run was created without a release
            profile and therefore has no builder identity.
    """
    snapshot = workspace.load()
    builder_id = snapshot.immutable_inputs.get("builderId")
    if builder_id is None:
        raise InvalidInvocationError(
            "Provenance requires a run initialized with a release profile"
        )
    candidate = load_candidate(workspace, image)
    materials = load_provenance_materials(workspace, image)
    return generate_provenance(
        ProvenanceInput(
            subject_name=image.repository.repository_name,
            subject_digest=candidate.observation.graph.digest,
            platform_manifests=candidate.observation.platform_manifests,
            source_repository=source.repository,
            source_revision=source.revision,
            configuration_digest=Digest(sha256_bytes(repository.raw_bytes)),
            builder_id=builder_id,
            image_id=image.image_id,
            version=snapshot.immutable_inputs.get("version") or None,
            run_id=workspace.run_id,
            started_at=parse_timestamp(
                snapshot.created_at, "Run creation time", error=InvalidInvocationError
            ),
            finished_at=now,
            materials=materials,
        ),
        workspace.root / "records" / "provenance.json",
    )


def profile_inputs(profile: ReleaseProfile) -> dict[str, str]:
    """Return non-secret immutable inputs for one release trust profile."""
    return _profile_inputs(profile)


def _profile_inputs(profile: ReleaseProfile) -> dict[str, str]:
    return {
        "builderId": profile.builder.id,
        "profileConfigurationDigest": profile.configuration_digest,
        "profilePublicKeyDigest": profile.public_key_digest,
    }


def signer_identity(profile: ReleaseProfile, signer: CosignAdapter) -> tuple[str, str]:
    """Derive the recorded signer mode and external trust identity."""
    key = profile.cosign_private_key or ""
    if key.startswith("pkcs11:"):
        return "hsm", key
    if "://" in key:
        return "kms", key
    return "managed-key", signer.public_key_fingerprint(profile.cosign_public_key)


def _write_summary(
    workspace: RunWorkspace,
    published: PublishedCandidate,
    promotion: PromotionResult,
) -> ReleaseResult:
    subject = published.immutable_reference
    tags = tuple((tag, str(digest)) for tag, digest in promotion.tags)
    atomic_write_json(
        workspace.root / "summary.json",
        {
            "schemaVersion": 1,
            "runId": workspace.run_id,
            "state": workspace.load().state.value,
            "subject": str(subject),
            "tags": [{"tag": tag, "digest": digest} for tag, digest in tags],
            "immutabilityEnabled": promotion.immutability_enabled,
            "registryPolicy": published.policy.to_dict(),
            "candidateAuthorization": published.authorization(),
            "candidateDeleted": promotion.candidate_deleted,
        },
        mode=0o644,
    )
    return ReleaseResult(
        workspace.run_id,
        workspace.root,
        str(subject),
        tags,
        promotion.candidate_deleted,
        promotion.findings,
        immutability_enabled=promotion.immutability_enabled,
    )


def _finish_failure(
    workspace: RunWorkspace, failure: BaseException, now: datetime
) -> None:
    if workspace.load().state is RunState.PROMOTED:
        return
    finish_run_failure(workspace, failure, now=now)
    snapshot = workspace.load()
    failure_value: dict[str, object]
    if isinstance(failure, ConClearError):
        failure_value = {
            "type": failure.error_type,
            "message": str(failure),
        }
        if failure.code is not None:
            failure_value["checkId"] = failure.code
    elif isinstance(failure, KeyboardInterrupt):
        failure_value = {
            "type": "interrupted",
            "message": "Release was interrupted",
        }
    else:
        failure_value = {
            "type": "internalError",
            "message": "Release failed unexpectedly",
        }
    atomic_write_json(
        workspace.root / "summary.json",
        {
            "schemaVersion": 1,
            "runId": workspace.run_id,
            "state": snapshot.state.value,
            "failure": failure_value,
        },
        mode=0o644,
    )
