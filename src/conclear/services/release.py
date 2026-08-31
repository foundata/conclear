"""Complete isolated release orchestration."""

import platform as host_platform
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import override

from conclear.adapters.quay import QuayAdapter
from conclear.artifacts import (
    load_candidate,
    load_provenance_materials,
    load_published,
    load_release_evidence,
    load_verification,
    qualification_transport,
    qualification_transports,
)
from conclear.config import ReleaseMode, ReleaseProfile, RepositoryConfig
from conclear.database import select_fresh_database
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.hooks import HookRunner
from conclear.jsonutil import atomic_write_json, sha256_bytes
from conclear.pins import PinResolver, PinStore
from conclear.provenance import ProvenanceInput, generate_provenance
from conclear.records import SourceIdentity, Verdict
from conclear.runtime import ApplicationRuntime
from conclear.secrets import token_provider
from conclear.services.assembly import CandidateResult, assemble_candidate
from conclear.services.checking import check_image
from conclear.services.cleanup import cleanup_run
from conclear.services.publication import (
    PromotionResult,
    attest_candidate,
    promote_candidate,
    publish_candidate,
    verify_candidate,
)
from conclear.services.qualification import (
    QualificationInputs,
    qualify_platform,
)
from conclear.services.run_context import create_source_run, open_source_run
from conclear.tools import ToolName
from conclear.values import Digest, OCIReference, Platform
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
    image_id: str
    version: str | None
    profile: ReleaseProfile
    state_home: Path
    cache_home: Path
    passphrase: str | None
    ci_identity: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class ReleaseResult:
    """Completed release identity and observed promotion result."""

    run_id: str
    workspace: Path
    subject: str
    tags: tuple[tuple[str, str], ...]


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
    now_factory: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ReleaseResult:
    """Run the complete release state machine from detached checkout to promotion."""
    started_at = now_factory()
    source_run = create_source_run(
        source_root=request.repository,
        selector=request.revision,
        image_id=request.image_id,
        version=request.version,
        state_home=request.state_home,
        names=tuple(ToolName),
        profile_name=request.profile.name,
        mode=request.profile.mode.value,
        additional_inputs=_profile_inputs(request.profile),
        id_factory=id_factory or UlidFactory(),
        now=started_at,
    )
    workspace = source_run.workspace
    try:
        result = _continue_release(
            request,
            repository=source_run.repository,
            workspace=workspace,
            runtime=source_run.runtime,
            source=source_run.source,
            source_time=source_run.source_time,
            started_at=started_at,
            now_factory=now_factory,
        )
    except BaseException as exc:
        _finish_failure(workspace, exc, now_factory())
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
    ci_identity: dict[str, object] | None,
    now_factory: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ReleaseResult:
    """Resume a non-terminal release after revalidating every immutable input."""
    source_run = open_source_run(
        state_home=state_home,
        run_id=run_id,
        names=tuple(ToolName),
    )
    workspace = source_run.workspace
    snapshot = workspace.load()
    source_root = repository.resolve(strict=True)
    expected = snapshot.immutable_inputs
    if expected.get("sourceRoot") != str(source_root):
        raise InvalidInvocationError("Resume source repository differs from the run")
    if (
        expected.get("profile") != profile.name
        or expected.get("mode") != profile.mode.value
    ):
        raise InvalidInvocationError("Resume profile differs from the run")
    for key, value in _profile_inputs(profile).items():
        if expected.get(key) != value:
            raise InvalidInvocationError("Resume release trust profile changed")
    image_id = expected.get("image")
    revision = expected.get("sourceRevision")
    if image_id is None or revision is None:
        raise InvalidInvocationError("Run immutable source inputs are incomplete")
    if snapshot.state is RunState.INCOMPLETE:
        image = source_run.repository.image(image_id)
        protected_resources = {"source-worktree"}
        for platform in image.platforms:
            record_path = (
                workspace.root
                / "records"
                / f"platform-qualification-{platform.key}.json"
            )
            if record_path.is_file():
                qualification_transport(workspace, image, platform)
                protected_resources.add(f"layout-{platform.key}")
        quay = quay_adapter(profile)
        try:
            cleanup_run(
                workspace,
                buildah=source_run.runtime.buildah(),
                podman=source_run.runtime.podman(),
                quay=quay,
                git=source_run.runtime.git(),
                statuses=frozenset(
                    {
                        ResourceStatus.PLANNED,
                        ResourceStatus.CREATED,
                        ResourceStatus.FAILED,
                    }
                ),
                excluded_kinds=frozenset({ResourceKind.CANDIDATE_REFERENCE}),
                excluded_resource_ids=frozenset(protected_resources),
            )
        finally:
            quay.close()
        workspace.resume(expected, now=now_factory())
    started_at = _parse_timestamp(workspace.load().created_at)
    request = ReleaseRequest(
        repository=source_root,
        revision=revision,
        image_id=image_id,
        version=expected.get("version") or None,
        profile=profile,
        state_home=state_home,
        cache_home=cache_home,
        passphrase=passphrase,
        ci_identity=ci_identity,
    )
    try:
        return _continue_release(
            request,
            repository=source_run.repository,
            workspace=workspace,
            runtime=source_run.runtime,
            source=source_run.source,
            source_time=source_run.source_time,
            started_at=started_at,
            now_factory=now_factory,
        )
    except BaseException as exc:
        _finish_failure(workspace, exc, now_factory())
        raise


def _continue_release(
    request: ReleaseRequest,
    *,
    repository: RepositoryConfig,
    workspace: RunWorkspace,
    runtime: ApplicationRuntime,
    source: SourceIdentity,
    source_time: datetime,
    started_at: datetime,
    now_factory: Callable[[], datetime],
) -> ReleaseResult:
    image = repository.image(request.image_id)
    if request.profile.mode is ReleaseMode.LOCAL and request.ci_identity is not None:
        raise InvalidInvocationError("Local releases cannot include CI identity")
    if request.profile.mode is ReleaseMode.CI and request.ci_identity is None:
        raise InvalidInvocationError("CI releases require observed CI identity")
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
            repository=repository,
            image=image,
            workspace=workspace,
            version=request.version,
            tools=runtime.identities,
            now=now_factory(),
        )
    if (
        workspace.load().state is RunState.ASSEMBLED
        and not (workspace.root / "records" / "provenance.json").is_file()
    ):
        candidate_for_provenance = load_candidate(workspace, image)
        _generate_release_provenance(
            candidate_for_provenance,
            request=request,
            repository=repository,
            workspace=workspace,
            source=source,
            started_at=started_at,
            now=now_factory(),
        )
    candidate = load_candidate(workspace, image)
    evidence = load_release_evidence(workspace, image)
    private_key = request.profile.cosign_private_key
    if private_key is None:
        raise InvalidInvocationError("Release profile has no Cosign signing key")
    registry = runtime.skopeo()
    signer = runtime.cosign()
    quay = quay_adapter(request.profile)
    try:
        if workspace.load().state is RunState.ASSEMBLED:
            publish_candidate(
                candidate,
                image=image,
                workspace=workspace,
                registry=registry,
                quay=quay,
                auth_file=request.profile.auth_file,
                now=now_factory(),
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
                ci_identity=request.ci_identity,
                now=now_factory(),
            )
        verification = load_verification(
            workspace, image, published.immutable_reference
        )
        promotion = promote_candidate(
            published,
            verification,
            image=image,
            version=request.version,
            workspace=workspace,
            quay=quay,
            registry=registry,
            signer=signer,
            public_key=request.profile.cosign_public_key,
            auth_file=request.profile.auth_file,
            now=now_factory(),
        )
        return _write_summary(workspace, published.immutable_reference, promotion)
    finally:
        quay.close()


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
    image = repository.image(request.image_id)
    preflight = check_image(image, runtime.hadolint())
    if not preflight.accepted:
        raise RuleRejectionError(
            "Static image checks rejected the release", code="CC0101"
        )
    pin_store = PinStore(request.state_home)
    pin_resolver = AuthenticatedPinResolver(runtime, request.profile.auth_file)
    pin_observations = tuple(
        pin_store.check(
            pin,
            resolver=pin_resolver,
            maximum_divergence=image.limits.pin_divergence,
            now=now_factory(),
        )
        for pin in image.pins
    )
    if any(not item.accepted for item in pin_observations):
        raise RuleRejectionError(
            "External image pin checks rejected the release", code="CC0204"
        )
    database = select_fresh_database(
        runtime.trivy(),
        request.cache_home / "conclear" / "trivy",
        now=now_factory(),
    )
    hooks = HookRunner(
        runner=runtime.runner,
        environment=runtime.environment,
        source_root=repository.path.parent,
        log_directory=workspace.root / "logs",
    )
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
            pin_observations=pin_observations,
            preflight_findings=preflight.findings,
            now=now_factory(),
        )
        if result.verdict is Verdict.REJECTED:
            raise RuleRejectionError(
                f"Platform qualification rejected {platform}", code="CC0502"
            )
        if result.verdict is Verdict.INCOMPLETE:
            raise OperationalError(f"Platform qualification was incomplete: {platform}")
    workspace.transition(RunState.QUALIFIED, now=now_factory())


def _generate_release_provenance(
    candidate: CandidateResult,
    *,
    request: ReleaseRequest,
    repository: object,
    workspace: RunWorkspace,
    source: SourceIdentity,
    started_at: datetime,
    now: datetime,
) -> None:
    from conclear.config import RepositoryConfig

    if not isinstance(repository, RepositoryConfig):
        raise TypeError("repository must be RepositoryConfig")
    materials = load_provenance_materials(workspace, repository.image(request.image_id))
    generate_provenance(
        ProvenanceInput(
            subject_name=repository.image(request.image_id).repository.repository_name,
            subject_digest=candidate.observation.graph.digest,
            platform_manifests=candidate.observation.platform_manifests,
            source_repository=source.repository,
            source_revision=source.revision,
            configuration_digest=Digest(sha256_bytes(repository.raw_bytes)),
            image_id=request.image_id,
            version=request.version,
            run_id=workspace.run_id,
            mode=request.profile.mode.value,
            started_at=started_at,
            finished_at=now,
            materials=materials,
        ),
        workspace.root / "records" / "provenance.json",
    )


def quay_adapter(profile: ReleaseProfile) -> QuayAdapter:
    """Construct a Quay adapter from one protected release profile."""
    token_path = profile.quay_token_file
    if token_path is None:
        raise InvalidInvocationError("Release profile has no Quay API token")
    return QuayAdapter(
        api_url=profile.quay_api_url,
        token_provider=lambda: token_provider(token_path),
    )


def profile_inputs(profile: ReleaseProfile) -> dict[str, str]:
    """Return non-secret immutable inputs for one release trust profile."""
    return _profile_inputs(profile)


def _profile_inputs(profile: ReleaseProfile) -> dict[str, str]:
    return {
        "profileConfigurationDigest": profile.configuration_digest,
        "profilePublicKeyDigest": profile.public_key_digest,
    }


def signer_identity(profile: ReleaseProfile, signer: object) -> tuple[str, str]:
    """Derive the recorded signer mode and external trust identity."""
    from conclear.adapters.cosign import CosignAdapter

    if not isinstance(signer, CosignAdapter):
        raise TypeError("signer must be CosignAdapter")
    key = profile.cosign_private_key or ""
    if key.startswith("pkcs11:"):
        return "hsm", key
    if "://" in key:
        return "kms", key
    return "managed-key", signer.public_key_fingerprint(profile.cosign_public_key)


def _write_summary(
    workspace: RunWorkspace,
    subject: object,
    promotion: PromotionResult,
) -> ReleaseResult:
    from conclear.values import OCIReference

    if not isinstance(subject, OCIReference):
        raise TypeError("subject must be OCIReference")
    tags = tuple((tag, str(digest)) for tag, digest in promotion.tags)
    atomic_write_json(
        workspace.root / "summary.json",
        {
            "schemaVersion": 1,
            "runId": workspace.run_id,
            "state": workspace.load().state.value,
            "subject": str(subject),
            "tags": [{"tag": tag, "digest": digest} for tag, digest in tags],
        },
        mode=0o644,
    )
    return ReleaseResult(workspace.run_id, workspace.root, str(subject), tags)


def _finish_failure(
    workspace: RunWorkspace, failure: BaseException, now: datetime
) -> None:
    state = workspace.load().state
    if state in {RunState.PROMOTED, RunState.REJECTED, RunState.INCOMPLETE}:
        return
    target = (
        RunState.REJECTED
        if isinstance(failure, RuleRejectionError)
        else RunState.INCOMPLETE
    )
    workspace.transition(target, now=now)


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidInvocationError("Run creation time is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InvalidInvocationError("Run creation time lacks a timezone")
    return parsed
