"""Provenance, registry publication and complete release commands."""

import platform as host_platform
from datetime import UTC, datetime
from pathlib import Path

import click

from conclear.adapters.registry_backends import create_registry_control
from conclear.artifacts import (
    load_candidate,
    load_published,
    load_release_evidence,
    load_verification,
)
from conclear.config import ImageConfig
from conclear.errors import InvalidInvocationError
from conclear.presentation import CommandResult, ResultStatus
from conclear.release_profile import ReleaseProfile
from conclear.services.ci_context import resolve_ci_context
from conclear.services.publication import (
    attest_candidate,
    promote_candidate,
    publish_candidate,
    verify_candidate,
)
from conclear.services.release import (
    ReleaseRequest,
    execute_release,
    generate_release_provenance,
    profile_inputs,
    resume_release,
    signer_identity,
)
from conclear.services.run_context import SourceRun, open_source_run
from conclear.tools import ToolName
from conclear.workspace import RunState

from .common import (
    cache_home,
    ci_context,
    emit,
    format_option,
    passphrase_option,
    profile,
    required_profile_option,
    signing_passphrase,
    state_home,
)


@click.command("provenance")
@click.argument("run_id")
@format_option
def provenance_command(run_id: str, output_format: str) -> None:
    """Generate SLSA Provenance v1 for one accepted candidate."""
    source_run = open_source_run(state_home=state_home(), run_id=run_id, names=())
    if source_run.workspace.load().state is not RunState.ASSEMBLED:
        raise InvalidInvocationError("Provenance requires assembled state")
    snapshot = source_run.workspace.load()
    image = source_run.repository.image(snapshot.immutable_inputs["image"])
    path = source_run.workspace.root / "records" / "provenance.json"
    if path.is_file():
        digest = load_release_evidence(source_run.workspace, image).provenance_digest
    else:
        digest = generate_release_provenance(
            source_run.workspace,
            source_run.repository,
            image,
            source=source_run.source,
            now=datetime.now(UTC),
        )
    emit(
        CommandResult(
            "provenance",
            ResultStatus.SUCCESS,
            "Release provenance generated",
            data={"path": str(path), "digest": digest},
        ),
        output_format,
    )


@click.command("publish")
@click.argument("run_id")
@required_profile_option
@format_option
def publish_command(run_id: str, profile_name: str, output_format: str) -> None:
    """Publish one accepted candidate and verify its complete remote graph."""
    source_run, selected = _remote_run(run_id, profile_name)
    image = _image(source_run)
    candidate = load_candidate(source_run.workspace, image)
    load_release_evidence(source_run.workspace, image)
    registry_control = create_registry_control(
        selected, destinations=(image.repository,)
    )
    try:
        result = publish_candidate(
            candidate,
            image=image,
            workspace=source_run.workspace,
            registry=source_run.runtime.skopeo(),
            registry_control=registry_control,
            auth_file=selected.auth_file,
            now=datetime.now(UTC),
        )
    finally:
        registry_control.close()
    emit(
        CommandResult(
            "publish",
            ResultStatus.SUCCESS,
            "Candidate published and graph-verified",
            data={
                "reference": str(result.reference),
                "digest": str(result.graph.digest),
                "expiration": result.expiration.isoformat(),
                "immutabilityEnabled": result.immutability_enabled,
            },
        ),
        output_format,
    )


@click.command("attest")
@click.argument("run_id")
@required_profile_option
@passphrase_option
@format_option
def attest_command(
    run_id: str,
    profile_name: str,
    passphrase_fd: int | None,
    output_format: str,
) -> None:
    """Attach SPDX and provenance and sign every unique subject digest."""
    source_run, selected = _remote_run(run_id, profile_name)
    key = _private_key(selected)
    passphrase = signing_passphrase(selected, passphrase_fd, required=True)
    image = _image(source_run)
    candidate = load_candidate(source_run.workspace, image)
    published = load_published(source_run.workspace, candidate, image)
    evidence = load_release_evidence(source_run.workspace, image)
    attest_candidate(
        published,
        evidence,
        image=image,
        workspace=source_run.workspace,
        signer=source_run.runtime.cosign(),
        private_key=key,
        public_key=selected.cosign_public_key,
        passphrase=passphrase,
        passphrase_path=selected.passphrase_file,
        registry=source_run.runtime.skopeo(),
        auth_file=selected.auth_file,
        now=datetime.now(UTC),
    )
    emit(
        CommandResult(
            "attest",
            ResultStatus.SUCCESS,
            "Candidate evidence and signatures attached",
            data={"subject": str(published.immutable_reference)},
        ),
        output_format,
    )


@click.command("verify")
@click.argument("run_id")
@required_profile_option
@passphrase_option
@format_option
def verify_command(
    run_id: str,
    profile_name: str,
    passphrase_fd: int | None,
    output_format: str,
) -> None:
    """Verify remote evidence and attach signed release verification."""
    source_run, selected = _remote_run(run_id, profile_name)
    key = _private_key(selected)
    passphrase = signing_passphrase(selected, passphrase_fd, required=True)
    image = _image(source_run)
    candidate = load_candidate(source_run.workspace, image)
    published = load_published(source_run.workspace, candidate, image)
    evidence = load_release_evidence(source_run.workspace, image)
    signer = source_run.runtime.cosign()
    mode, key_id = signer_identity(selected, signer)
    public_ci_context = resolve_ci_context(
        ci_context(selected),
        policy=selected.ci_context,
        source=evidence.source,
        diagnostic_path=source_run.workspace.root / "reports" / "ci-context.json",
    )
    result = verify_candidate(
        published,
        candidate,
        evidence,
        workspace=source_run.workspace,
        image=image,
        profile=selected,
        signer=signer,
        registry=source_run.runtime.skopeo(),
        auth_file=selected.auth_file,
        private_key=key,
        passphrase=passphrase,
        signer_mode=mode,
        signer_key_id=key_id,
        host_architecture=host_platform.machine(),
        ci_context=public_ci_context,
        now=datetime.now(UTC),
    )
    emit(
        CommandResult(
            "verify",
            ResultStatus.SUCCESS,
            "Candidate and release evidence verified",
            data={"record": str(result.record_path), "digest": result.record_digest},
        ),
        output_format,
    )


@click.command("promote")
@click.argument("run_id")
@click.option("release_version", "--version")
@required_profile_option
@format_option
def promote_command(
    run_id: str,
    release_version: str | None,
    profile_name: str,
    output_format: str,
) -> None:
    """Apply release tags to only the verified digest and remove the candidate."""
    source_run, selected = _remote_run(run_id, profile_name)
    image = _image(source_run)
    candidate = load_candidate(source_run.workspace, image)
    published = load_published(source_run.workspace, candidate, image)
    verification = load_verification(
        source_run.workspace, image, published.immutable_reference
    )
    registry_control = create_registry_control(
        selected, destinations=(image.repository,)
    )
    try:
        recorded_version = (
            source_run.workspace.load().immutable_inputs.get("version") or None
        )
        if release_version is not None and release_version != recorded_version:
            raise click.UsageError("--version differs from the recorded run input")
        result = promote_candidate(
            published,
            verification,
            image=image,
            version=recorded_version,
            workspace=source_run.workspace,
            registry_control=registry_control,
            registry=source_run.runtime.skopeo(),
            signer=source_run.runtime.cosign(),
            public_key=selected.cosign_public_key,
            auth_file=selected.auth_file,
            now=datetime.now(UTC),
        )
    finally:
        registry_control.close()
    emit(
        CommandResult(
            "promote",
            ResultStatus.SUCCESS,
            (
                "Verified digest promoted"
                if result.candidate_deleted
                else "Verified digest promoted; candidate cleanup failed"
            ),
            findings=result.findings,
            data={
                "tags": [
                    {"tag": tag, "digest": str(digest)} for tag, digest in result.tags
                ],
                "candidateDeleted": result.candidate_deleted,
            },
        ),
        output_format,
    )


@click.command("release")
@click.option(
    "source_root",
    "--source",
    type=click.Path(path_type=Path),
    default=Path(),
    show_default=True,
)
@click.option("selector", "--revision")
@click.option("image_id", "--image")
@click.option("release_version", "--version")
@required_profile_option
@click.option("resume_id", "--resume")
@passphrase_option
@format_option
def release_command(
    source_root: Path,
    selector: str | None,
    image_id: str | None,
    release_version: str | None,
    profile_name: str,
    resume_id: str | None,
    passphrase_fd: int | None,
    output_format: str,
) -> None:
    """Execute or resume the complete isolated release through promotion."""
    selected = profile(profile_name)
    _private_key(selected)
    passphrase = signing_passphrase(selected, passphrase_fd, required=True)
    observed_ci = ci_context(selected)
    if resume_id is not None:
        if selector is not None or image_id is not None or release_version is not None:
            raise click.UsageError(
                "--resume uses recorded revision, image and version inputs"
            )
        result = resume_release(
            resume_id,
            repository=source_root,
            profile=selected,
            state_home=state_home(),
            cache_home=cache_home(),
            passphrase=passphrase,
            ci_context=observed_ci,
        )
    else:
        if selector is None or image_id is None:
            raise click.UsageError("--revision and --image are required")
        result = execute_release(
            ReleaseRequest(
                repository=source_root,
                revision=selector,
                image_id=image_id,
                version=release_version,
                profile=selected,
                state_home=state_home(),
                cache_home=cache_home(),
                passphrase=passphrase,
                ci_context=observed_ci,
            )
        )
    emit(
        CommandResult(
            "release",
            ResultStatus.SUCCESS,
            (
                "Release completed and verified digest promoted"
                if result.candidate_deleted
                else "Verified digest promoted; candidate cleanup failed"
            ),
            findings=result.findings,
            data={
                "runId": result.run_id,
                "workspace": str(result.workspace),
                "subject": result.subject,
                "tags": [{"tag": tag, "digest": digest} for tag, digest in result.tags],
                "candidateDeleted": result.candidate_deleted,
            },
        ),
        output_format,
    )


def _remote_run(run_id: str, profile_name: str) -> tuple[SourceRun, ReleaseProfile]:
    selected = profile(profile_name)
    source_run = open_source_run(
        state_home=state_home(), run_id=run_id, names=tuple(ToolName)
    )
    inputs = source_run.workspace.load().immutable_inputs
    if inputs.get("profile") != selected.name:
        raise InvalidInvocationError("Release profile differs from recorded run input")
    if any(inputs.get(key) != value for key, value in profile_inputs(selected).items()):
        raise InvalidInvocationError(
            "Release trust profile differs from recorded input"
        )
    return source_run, selected


def _image(source_run: SourceRun) -> ImageConfig:
    image_id = source_run.workspace.load().immutable_inputs["image"]
    return source_run.repository.image(image_id)


def _private_key(selected: ReleaseProfile) -> str:
    key = selected.cosign_private_key
    if key is None:
        raise InvalidInvocationError("Release profile has no Cosign signing key")
    return key
