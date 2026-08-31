"""Read-only diagnostics, rescans and ownership cleanup commands."""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click

from conclear.adapters.quay import QuayAdapter
from conclear.config import load_repository_config
from conclear.database import select_fresh_database
from conclear.errors import InvalidInvocationError
from conclear.jsonutil import sha256_bytes
from conclear.pins import PinStore
from conclear.presentation import CommandResult, ResultStatus
from conclear.runtime import ApplicationRuntime
from conclear.secrets import token_provider
from conclear.services.cleanup import cleanup_run
from conclear.services.doctor import diagnose_environment
from conclear.services.release import AuthenticatedPinResolver, profile_inputs
from conclear.services.rescan import RescanSigning, rescan_release
from conclear.tools import ToolName
from conclear.triage import load_triage
from conclear.values import OCIReference
from conclear.workspace import RunWorkspace

from .common import (
    cache_home,
    ci_identity,
    command_runtime,
    emit,
    profile,
    signing_passphrase,
    state_home,
)


def _format_option[FC: Callable[..., Any]](function: FC) -> FC:
    return click.option(
        "output_format",
        "--format",
        type=click.Choice(["human", "json"], case_sensitive=True),
        default="human",
        show_default=True,
    )(function)


@click.command("doctor")
@click.option(
    "config_path",
    "--config",
    type=click.Path(path_type=Path),
    default=Path("conclear.toml"),
    show_default=True,
)
@click.option("profile_name", "--profile", required=True)
@_format_option
def doctor_command(config_path: Path, profile_name: str, output_format: str) -> None:
    """Validate the release environment without publishing or signing."""
    repository = load_repository_config(config_path)
    selected = profile(profile_name)
    token_path = selected.quay_token_file
    if token_path is None:
        raise InvalidInvocationError("Doctor requires a Quay API token")
    quay = QuayAdapter(
        api_url=selected.quay_api_url,
        token_provider=lambda: token_provider(token_path),
    )
    try:
        with command_runtime(tuple(ToolName)) as runtime:
            observation = diagnose_environment(repository, selected, runtime, quay=quay)
    finally:
        quay.close()
    observed_ci = ci_identity(selected)
    emit(
        CommandResult(
            "doctor",
            ResultStatus.SUCCESS,
            "Release environment is ready",
            data={
                "tools": list(observation.tools),
                "nativeArchitecture": observation.native_architecture,
                "emulatedArchitectures": list(observation.emulated_architectures),
                "quayAccess": observation.quay_access,
                "sigstoreAccess": observation.sigstore_access,
                "mode": selected.mode.value,
                **({} if observed_ci is None else {"ciIdentity": observed_ci}),
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
@_format_option
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


@click.command("cleanup")
@click.argument("run_id")
@click.option("profile_name", "--profile")
@_format_option
def cleanup_command(run_id: str, profile_name: str | None, output_format: str) -> None:
    """Remove only ephemeral resources owned by one release run."""
    workspace = RunWorkspace.open(state_home=state_home(), run_id=run_id)
    runtime = ApplicationRuntime.create(
        workspace.root / "environment",
        names=(ToolName.GIT, ToolName.BUILDAH, ToolName.PODMAN),
    )
    quay: QuayAdapter | None = None
    if profile_name is not None:
        selected = profile(profile_name)
        inputs = workspace.load().immutable_inputs
        if inputs.get("profile") not in {None, "none", selected.name}:
            raise InvalidInvocationError("Cleanup profile differs from the release run")
        for key, value in profile_inputs(selected).items():
            recorded = inputs.get(key)
            if recorded is not None and recorded != value:
                raise InvalidInvocationError("Cleanup release trust profile changed")
        token_path = selected.quay_token_file
        if token_path is None:
            raise InvalidInvocationError("Cleanup profile has no Quay API token")
        quay = QuayAdapter(
            api_url=selected.quay_api_url,
            token_provider=lambda: token_provider(token_path),
        )
    try:
        result = cleanup_run(
            workspace,
            buildah=runtime.buildah(),
            podman=runtime.podman(),
            quay=quay,
            git=runtime.git(),
        )
    finally:
        if quay is not None:
            quay.close()
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
@_format_option
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
            "mode": selected.mode.value,
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
        signing=signing,
        now=datetime.now(UTC),
        clock=lambda: datetime.now(UTC),
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
