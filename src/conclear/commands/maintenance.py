"""Read-only diagnostics, rescans and ownership cleanup commands."""

from datetime import UTC, datetime
from pathlib import Path

import click

from conclear.adapters.ci import ObservedCIContext
from conclear.adapters.registry_control import create_registry_control
from conclear.config import load_repository_config, normalize_observed_source_url
from conclear.database import select_fresh_database
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import sha256_bytes
from conclear.pin_application import ApplicationStatus, apply_pin_proposal
from conclear.pin_updates import (
    PinUpdateProposal,
    load_proposal,
    propose_pin_updates,
)
from conclear.pins import PinStore
from conclear.presentation import CommandResult, ResultStatus
from conclear.records import SourceIdentity
from conclear.registry_control import RegistryControl
from conclear.rescan_history import RescanHistoryEntry, RescanHistoryStore
from conclear.runtime import ApplicationRuntime
from conclear.services.cleanup import cleanup_run
from conclear.services.doctor import diagnose_environment
from conclear.services.release import AuthenticatedPinResolver, profile_inputs
from conclear.services.rescan import (
    RescanSigning,
    rescan_release,
    verified_rescan_history,
)
from conclear.tools import ToolName
from conclear.triage import load_triage
from conclear.values import OCIReference
from conclear.workspace import RunWorkspace

from .common import (
    cache_home,
    ci_context,
    command_runtime,
    emit,
    format_option,
    profile,
    signing_passphrase,
    state_home,
)


@click.command("doctor")
@click.option(
    "config_path",
    "--config",
    type=click.Path(path_type=Path),
    default=Path("conclear.toml"),
    show_default=True,
)
@click.option("profile_name", "--profile", required=True)
@format_option
def doctor_command(config_path: Path, profile_name: str, output_format: str) -> None:
    """Validate the release environment without publishing or signing."""
    repository = load_repository_config(config_path)
    selected = profile(profile_name)
    registry_control = create_registry_control(
        selected,
        destinations=tuple(image.repository for image in repository.images),
    )
    try:
        with command_runtime(tuple(ToolName)) as runtime:
            observation = diagnose_environment(
                repository,
                selected,
                runtime,
                registry_control=registry_control,
            )
    finally:
        registry_control.close()
    observed_ci = ci_context(selected)
    emit(
        CommandResult(
            "doctor",
            ResultStatus.SUCCESS,
            "Release environment is ready",
            data={
                "tools": list(observation.tools),
                "nativeArchitecture": observation.native_architecture,
                "emulatedArchitectures": list(observation.emulated_architectures),
                "registryProvider": observation.registry_provider,
                "registryAccess": observation.registry_access,
                "sigstoreAccess": observation.sigstore_access,
                "ciContextPolicy": selected.ci_context.value,
                "ciContextObserved": isinstance(observed_ci, ObservedCIContext),
                **(
                    {"ciProvider": observed_ci.provider}
                    if isinstance(observed_ci, ObservedCIContext)
                    else {}
                ),
            },
        ),
        output_format,
    )


@click.group("pins")
def pins_group() -> None:
    """Inspect durable external image pin observations."""


@pins_group.command("check")
@click.option(
    "config_path",
    "--config",
    type=click.Path(path_type=Path),
    default=Path("conclear.toml"),
    show_default=True,
)
@click.option("image_id", "--image", required=True)
@click.option("profile_name", "--profile")
@format_option
def pins_check_command(
    config_path: Path,
    image_id: str,
    profile_name: str | None,
    output_format: str,
) -> None:
    """Resolve pins, update durable history and report divergence."""
    repository = load_repository_config(config_path)
    image = repository.image(image_id)
    selected = profile(profile_name) if profile_name else None
    auth_file = selected.auth_file if selected else None
    with command_runtime((ToolName.SKOPEO,)) as runtime:
        resolver = AuthenticatedPinResolver(runtime, auth_file)
        store = PinStore(state_home())
        observations = tuple(
            store.check(
                pin,
                resolver=resolver,
                maximum_divergence=image.limits.pin_divergence,
                now=datetime.now(UTC),
            )
            for pin in image.pins
        )
    findings = tuple(
        finding for observation in observations for finding in observation.findings
    )
    accepted = all(observation.accepted for observation in observations)
    emit(
        CommandResult(
            "pins check",
            ResultStatus.SUCCESS if accepted else ResultStatus.RULE_REJECTION,
            "Image pins are current" if accepted else "Image pins were rejected",
            findings=findings,
            data={"observations": [item.to_dict() for item in observations]},
        ),
        output_format,
    )


@pins_group.command("propose")
@click.option(
    "config_path",
    "--config",
    type=click.Path(path_type=Path),
    default=Path("conclear.toml"),
    show_default=True,
)
@click.option(
    "image_ids",
    "--image",
    multiple=True,
    help="Limit the proposal to these image IDs; every image sharing one of "
    "their dependencies must be included. Defaults to every image.",
)
@click.option(
    "output_path",
    "--output",
    type=click.Path(path_type=Path),
    required=True,
    help="New file that receives the proposal. An existing file is never overwritten.",
)
@click.option("profile_name", "--profile")
@format_option
def pins_propose_command(
    config_path: Path,
    image_ids: tuple[str, ...],
    output_path: Path,
    profile_name: str | None,
    output_format: str,
) -> None:
    """Resolve each declared tag once and write a non-mutating update proposal."""
    _require_configuration_name(config_path)
    repository = load_repository_config(config_path)
    selected = profile(profile_name) if profile_name else None
    auth_file = selected.auth_file if selected else None
    if output_path.is_symlink() or output_path.exists():
        raise InvalidInvocationError(f"Proposal output already exists: {output_path}")
    with command_runtime((ToolName.GIT, ToolName.SKOPEO)) as runtime:
        source = _observed_source(runtime, repository.path.parent)
        proposal = propose_pin_updates(
            repository,
            source=source,
            resolver=AuthenticatedPinResolver(runtime, auth_file),
            tools=(runtime.tools[ToolName.SKOPEO].record_identity(),),
            now=lambda: datetime.now(UTC),
            image_ids=tuple(image_ids) or None,
        )
    digest = proposal.write(output_path)
    changed = [item for item in proposal.lookups if item.changed]
    message = (
        f"Proposed {len(changed)} digest update(s) across {len(proposal.files)} file(s)"
        if proposal.changed
        else "Pinned references are current; the proposal changes nothing"
    )
    emit(
        CommandResult(
            "pins propose",
            ResultStatus.SUCCESS,
            message,
            findings=proposal.findings,
            data={
                "proposal": str(output_path),
                "proposalDigest": digest,
                "changed": proposal.changed,
                "reviewRequired": proposal.review_required,
                "lookups": [item.to_dict() for item in proposal.lookups],
                "files": [item.path for item in proposal.files],
            },
            details=(
                *_lookup_details(proposal),
                *(f"file: {item.path}" for item in proposal.files),
                f"proposal: {output_path} ({digest})",
            ),
        ),
        output_format,
    )


@pins_group.command("apply")
@click.option(
    "proposal_path",
    "--proposal",
    type=click.Path(path_type=Path),
    required=True,
    help="Proposal written by pins propose.",
)
@click.option(
    "config_path",
    "--config",
    type=click.Path(path_type=Path),
    default=Path("conclear.toml"),
    show_default=True,
)
@format_option
def pins_apply_command(
    proposal_path: Path, config_path: Path, output_format: str
) -> None:
    """Verify one proposal against the worktree and apply it all-or-nothing."""
    _require_configuration_name(config_path)
    proposal = load_proposal(proposal_path)
    try:
        root = config_path.resolve(strict=True).parent
    except OSError as exc:
        raise InvalidInvocationError(
            f"Repository configuration is unavailable: {config_path}"
        ) from exc
    with command_runtime((ToolName.GIT,)) as runtime:
        source = _observed_source(runtime, root)
    outcome = apply_pin_proposal(
        proposal,
        repository_root=root,
        source=source,
        now=datetime.now(UTC),
    )
    messages = {
        ApplicationStatus.APPLIED: (
            f"Applied the pin update proposal to {len(outcome.changed_paths)} file(s)"
        ),
        ApplicationStatus.ALREADY_APPLIED: (
            "The pin update proposal was already applied; no file changed"
        ),
        ApplicationStatus.NO_CHANGE: (
            "The pin update proposal changes nothing; no file was touched"
        ),
    }
    follow_up = tuple(
        f"conclear pins check --config {config_path} --image {image_id}"
        for image_id in proposal.image_ids
    )
    emit(
        CommandResult(
            "pins apply",
            ResultStatus.SUCCESS,
            messages[outcome.status],
            findings=proposal.findings,
            data={
                "status": outcome.status.value,
                "proposalDigest": proposal.digest(),
                "changedPaths": list(outcome.changed_paths),
                "reviewRequired": proposal.review_required,
                "lookups": [item.to_dict() for item in proposal.lookups],
                "followUp": list(follow_up),
            },
            details=(
                *_lookup_details(proposal),
                *(f"changed: {path}" for path in outcome.changed_paths),
                *(f"next: {command}" for command in follow_up),
            ),
        ),
        output_format,
    )


def _require_configuration_name(config_path: Path) -> None:
    if config_path.name != "conclear.toml":
        raise InvalidInvocationError(
            "Pin update proposals require the repository configuration conclear.toml"
        )


def _observed_source(runtime: ApplicationRuntime, root: Path) -> SourceIdentity:
    observation = runtime.git().observe(root, "HEAD")
    return SourceIdentity(
        repository=normalize_observed_source_url(observation.remote_url),
        revision=observation.revision,
    )


def _lookup_details(proposal: PinUpdateProposal) -> tuple[str, ...]:
    return tuple(
        f"{item.original_reference.repository_name}:{item.original_reference.tag}: "
        f"{item.old_digest} -> {item.new_digest} ({', '.join(item.image_ids)})"
        + (
            " [immutable-version: supply-chain review required]"
            if item.review_required
            else ""
        )
        for item in proposal.lookups
        if item.changed
    )


@click.command("cleanup")
@click.argument("run_id")
@click.option("profile_name", "--profile")
@format_option
def cleanup_command(run_id: str, profile_name: str | None, output_format: str) -> None:
    """Remove only ephemeral resources owned by one release run."""
    workspace = RunWorkspace.open(state_home=state_home(), run_id=run_id)
    runtime = ApplicationRuntime.create(
        workspace.root / "environment",
        names=(ToolName.GIT, ToolName.BUILDAH, ToolName.PODMAN),
    )
    registry_control: RegistryControl | None = None
    if profile_name is not None:
        selected = profile(profile_name)
        inputs = workspace.load().immutable_inputs
        if inputs.get("profile") not in {None, "none", selected.name}:
            raise InvalidInvocationError("Cleanup profile differs from the release run")
        for key, value in profile_inputs(selected).items():
            recorded = inputs.get(key)
            if recorded is not None and recorded != value:
                raise InvalidInvocationError("Cleanup release trust profile changed")
        registry_control = create_registry_control(selected)
    try:
        result = cleanup_run(
            workspace,
            buildah=runtime.buildah(),
            podman=runtime.podman(),
            registry_control=registry_control,
            git=runtime.git(),
        )
    finally:
        if registry_control is not None:
            registry_control.close()
    emit(
        CommandResult(
            "cleanup",
            ResultStatus.SUCCESS,
            "Owned cleanup completed",
            data={"removed": list(result.removed), "retained": list(result.retained)},
        ),
        output_format,
    )


@click.command("rescan")
@click.argument("subject_text")
@click.option(
    "config_path",
    "--config",
    type=click.Path(path_type=Path),
    default=Path("conclear.toml"),
    show_default=True,
)
@click.option("image_id", "--image-id", required=True)
@click.option("profile_name", "--profile", required=True)
@click.option("authoritative", "--authoritative", is_flag=True)
@click.option("passphrase_fd", "--passphrase-fd", type=click.IntRange(min=3))
@click.option("previous_result", "--previous-result")
@click.option("triage_path", "--triage-file", type=click.Path(path_type=Path))
@format_option
def rescan_command(
    subject_text: str,
    config_path: Path,
    image_id: str,
    profile_name: str,
    authoritative: bool,
    passphrase_fd: int | None,
    previous_result: str | None,
    triage_path: Path | None,
    output_format: str,
) -> None:
    """Re-evaluate retained SBOMs for one immutable released subject."""
    subject = OCIReference.parse(
        subject_text, require_digest=True, allow_localhost=False
    )
    if subject.tag is not None:
        raise InvalidInvocationError("Rescan subject cannot include a tag")
    selected = profile(profile_name)
    repository = load_repository_config(config_path)
    image = repository.image(image_id)
    if image.repository.repository_name != subject.repository_name:
        raise InvalidInvocationError(
            "Rescan subject repository differs from the selected image"
        )
    configuration_digest = sha256_bytes(repository.raw_bytes)
    triage = () if triage_path is None else load_triage(triage_path, subject=subject)
    if authoritative and selected.cosign_private_key is None:
        raise InvalidInvocationError("Authoritative rescan requires a signing key")
    passphrase = signing_passphrase(selected, passphrase_fd, required=authoritative)
    workspace = RunWorkspace.create(
        state_home=state_home(),
        immutable_inputs={
            "subject": str(subject),
            "image": image_id,
            "profile": selected.name,
            "configurationDigest": configuration_digest,
            **profile_inputs(selected),
        },
    )
    runtime = ApplicationRuntime.create(
        workspace.root / "environment",
        names=(ToolName.SKOPEO, ToolName.TRIVY, ToolName.COSIGN),
    )
    workspace.bind_immutable_inputs(
        {
            f"tool.{tool.name.value}": f"{tool.version}@{tool.executable_digest}"
            for tool in runtime.tools.values()
        }
    )
    history_store = RescanHistoryStore(state_home())
    attested_history = verified_rescan_history(
        subject,
        signer=runtime.cosign(),
        public_key=selected.cosign_public_key,
    )
    remediation_history = history_store.synchronize(
        subject,
        attested_history,
        previous_result,
    )
    database = select_fresh_database(
        runtime.trivy(),
        cache_home() / "conclear" / "trivy",
        now=datetime.now(UTC),
    )
    signing = (
        RescanSigning(
            selected.cosign_private_key or "",
            selected.cosign_public_key,
            passphrase,
            selected.passphrase_file,
        )
        if authoritative
        else None
    )
    result = rescan_release(
        subject,
        workspace=workspace,
        registry=runtime.skopeo(),
        signer=runtime.cosign(),
        scanner=runtime.trivy(),
        database=database,
        public_key=selected.cosign_public_key,
        auth_file=selected.auth_file,
        tools=runtime.identities,
        image_id=image_id,
        expected_configuration_digest=configuration_digest,
        scope=image.rescan_scope,
        exceptions=image.vulnerability_exceptions,
        triage=triage,
        previous_result_digest=previous_result,
        remediation_limit=image.limits.remediation,
        remediation_history=remediation_history,
        signing=signing,
        now=datetime.now(UTC),
        record_clock=lambda: datetime.now(UTC),
    )
    if result.authoritative:
        if result.verified_at is None:
            raise OperationalError("Authoritative rescan has no verification time")
        history_store.record(
            subject,
            RescanHistoryEntry(
                record_digest=result.record_digest,
                verified_at=_timestamp(result.verified_at),
                active_findings=result.active_findings,
            ),
            expected_previous=previous_result,
        )
    emit(
        CommandResult(
            "rescan",
            (
                ResultStatus.SUCCESS
                if result.verdict.value == "accepted"
                else ResultStatus.RULE_REJECTION
            ),
            "Released subject rescan completed",
            data={
                "runId": workspace.run_id,
                "record": str(result.record_path),
                "recordDigest": result.record_digest,
                "authoritative": result.authoritative,
                "verifiedAt": result.verified_at,
            },
        ),
        output_format,
    )


def _timestamp(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidInvocationError("Rescan verification time is malformed") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise InvalidInvocationError("Rescan verification time lacks a timezone")
    return timestamp.astimezone(UTC)
