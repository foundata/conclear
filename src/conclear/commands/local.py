"""Static, build, test, evidence, qualification and assembly commands."""

import platform as host_platform
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import click

from conclear.artifacts import qualification_transports
from conclear.config import ReleaseProfile, load_repository_config
from conclear.database import select_database_by_digest, select_fresh_database
from conclear.hooks import HookRunner
from conclear.pins import PinStore
from conclear.presentation import CommandResult, ResultStatus
from conclear.services.assembly import assemble_candidate
from conclear.services.checking import check_image
from conclear.services.local_phases import (
    load_build_evidence,
    write_build_evidence,
)
from conclear.services.qualification import (
    QualificationInputs,
    build_platform,
    generate_evidence,
    qualify_platform,
    test_platform,
)
from conclear.services.release import AuthenticatedPinResolver, profile_inputs
from conclear.services.run_context import (
    SourceRun,
    create_source_run,
    open_source_run,
)
from conclear.tools import ToolName
from conclear.values import Digest, Platform
from conclear.workspace import RunState

from .common import cache_home, command_runtime, emit, profile, state_home


def _format_option[FC: Callable[..., Any]](function: FC) -> FC:
    return click.option(
        "output_format",
        "--format",
        type=click.Choice(["human", "json"], case_sensitive=True),
        default="human",
        show_default=True,
    )(function)


def _source_options[FC: Callable[..., Any]](function: FC) -> FC:
    decorators = (
        click.option(
            "source_root",
            "--source",
            type=click.Path(path_type=Path),
            default=Path(),
            show_default=True,
        ),
        click.option("selector", "--revision", required=True),
        click.option("image_id", "--image", required=True),
        click.option("version", "--version"),
    )
    for decorator in reversed(decorators):
        function = decorator(function)
    return function


@click.command("check")
@click.option(
    "config_path",
    "--config",
    type=click.Path(path_type=Path),
    default=Path("conclear.toml"),
    show_default=True,
)
@click.option("image_id", "--image", required=True)
@_format_option
def check_command(config_path: Path, image_id: str, output_format: str) -> None:
    """Run static Containerfile, context, metadata and pin-declaration checks."""
    repository = load_repository_config(config_path)
    with command_runtime((ToolName.HADOLINT,)) as runtime:
        outcome = check_image(repository.image(image_id), runtime.hadolint())
    emit(
        CommandResult(
            "check",
            ResultStatus.SUCCESS if outcome.accepted else ResultStatus.RULE_REJECTION,
            "Static checks passed" if outcome.accepted else "Static checks rejected",
            findings=outcome.findings,
        ),
        output_format,
    )


@click.command("build")
@_source_options
@click.option("platform_text", "--platform", required=True)
@click.option("profile_name", "--profile")
@_format_option
def build_command(
    source_root: Path,
    selector: str,
    image_id: str,
    version: str | None,
    platform_text: str,
    profile_name: str | None,
    output_format: str,
) -> None:
    """Build one platform into isolated storage and an OCI layout."""
    selected = profile(profile_name) if profile_name else None
    source_run = create_source_run(
        source_root=source_root,
        selector=selector,
        image_id=image_id,
        version=version,
        state_home=state_home(),
        names=(ToolName.BUILDAH,),
        profile_name="none" if selected is None else selected.name,
        mode="local" if selected is None else selected.mode.value,
        additional_inputs=None if selected is None else profile_inputs(selected),
    )
    inputs = _inputs(source_run, platform_text, selected)
    build = build_platform(inputs, source_run.runtime.buildah())
    build_path = write_build_evidence(inputs, build)
    accepted = not any(finding.severity == "error" for finding in build.findings)
    if not accepted:
        source_run.workspace.transition(RunState.REJECTED)
    emit(
        CommandResult(
            "build",
            ResultStatus.SUCCESS if accepted else ResultStatus.RULE_REJECTION,
            (
                f"Built {inputs.platform}"
                if accepted
                else f"Built {inputs.platform}, but metadata was rejected"
            ),
            findings=build.findings,
            data={
                "runId": source_run.workspace.run_id,
                "layout": str(build.observation.layout_path),
                "digest": str(build.observation.graph.digest),
                "buildEvidence": str(build_path),
            },
        ),
        output_format,
    )


@click.command("test")
@click.argument("run_id")
@click.option("platform_text", "--platform", required=True)
@_format_option
def test_command(run_id: str, platform_text: str, output_format: str) -> None:
    """Import one exact layout and run declared constrained tests."""
    source_run = open_source_run(
        state_home=state_home(),
        run_id=run_id,
        names=(ToolName.PODMAN,),
    )
    inputs = _inputs(source_run, platform_text, None)
    build = load_build_evidence(inputs)
    hooks = HookRunner(
        runner=source_run.runtime.runner,
        environment=source_run.runtime.environment,
        source_root=source_run.repository.path.parent,
        log_directory=source_run.workspace.root / "logs",
    )
    result = test_platform(inputs, build, source_run.runtime.podman(), hooks)
    accepted = not result.incomplete and not any(
        finding.severity == "error" for finding in result.findings
    )
    status = (
        ResultStatus.OPERATIONAL_FAILURE
        if result.incomplete
        else ResultStatus.SUCCESS
        if accepted
        else ResultStatus.RULE_REJECTION
    )
    if not accepted:
        source_run.workspace.transition(
            RunState.INCOMPLETE if result.incomplete else RunState.REJECTED
        )
    emit(
        CommandResult(
            "test",
            status,
            (
                "Runtime tests were incomplete"
                if result.incomplete
                else "Runtime tests passed"
                if accepted
                else "Runtime tests did not pass"
            ),
            findings=result.findings,
            data={"reportDigest": result.test_report_digest},
        ),
        output_format,
    )


@click.command("evidence")
@click.argument("run_id")
@click.option("platform_text", "--platform", required=True)
@_format_option
def evidence_command(run_id: str, platform_text: str, output_format: str) -> None:
    """Generate and validate platform scans and SPDX inventory."""
    source_run = open_source_run(
        state_home=state_home(), run_id=run_id, names=(ToolName.TRIVY,)
    )
    inputs = _inputs(source_run, platform_text, None)
    build = load_build_evidence(inputs)
    database = select_fresh_database(
        source_run.runtime.trivy(),
        cache_home() / "conclear" / "trivy",
        now=datetime.now(UTC),
    )
    result = generate_evidence(
        inputs,
        build,
        source_run.runtime.trivy(),
        database,
        today=datetime.now(UTC).date(),
    )
    accepted = not any(finding.severity == "error" for finding in result.findings)
    if not accepted:
        source_run.workspace.transition(RunState.REJECTED)
    emit(
        CommandResult(
            "evidence",
            ResultStatus.SUCCESS if accepted else ResultStatus.RULE_REJECTION,
            "Evidence passed policy" if accepted else "Evidence was rejected",
            findings=result.findings,
            data={
                "sbom": str(result.sbom.path),
                "sbomDigest": result.sbom.digest,
                "scanDigests": [item.digest for item in result.scans],
                "databaseDigest": database.digest,
            },
        ),
        output_format,
    )


@click.command("qualify")
@_source_options
@click.option("platform_text", "--platform", required=True)
@click.option("profile_name", "--profile")
@click.option("database_digest", "--database-digest")
@_format_option
def qualify_command(
    source_root: Path,
    selector: str,
    image_id: str,
    version: str | None,
    platform_text: str,
    profile_name: str | None,
    database_digest: str | None,
    output_format: str,
) -> None:
    """Run all local gates and emit one platform qualification."""
    selected = profile(profile_name) if profile_name else None
    expected_database = None if database_digest is None else Digest(database_digest)
    additional_inputs = {} if selected is None else profile_inputs(selected)
    if expected_database is not None:
        additional_inputs["databaseDigest"] = str(expected_database)
    source_run = create_source_run(
        source_root=source_root,
        selector=selector,
        image_id=image_id,
        version=version,
        state_home=state_home(),
        names=tuple(ToolName),
        profile_name="none" if selected is None else selected.name,
        mode="local" if selected is None else selected.mode.value,
        additional_inputs=additional_inputs or None,
    )
    image = source_run.repository.image(image_id)
    inputs = _inputs(source_run, platform_text, selected)
    preflight = check_image(image, source_run.runtime.hadolint())
    resolver = AuthenticatedPinResolver(
        source_run.runtime, None if selected is None else selected.auth_file
    )
    pin_observations = tuple(
        PinStore(state_home()).check(
            pin,
            resolver=resolver,
            maximum_divergence=image.limits.pin_divergence,
            now=datetime.now(UTC),
        )
        for pin in image.pins
    )
    if not preflight.accepted or any(not item.accepted for item in pin_observations):
        source_run.workspace.transition(RunState.REJECTED)
        findings = preflight.findings + tuple(
            finding for item in pin_observations for finding in item.findings
        )
        emit(
            CommandResult(
                "qualify",
                ResultStatus.RULE_REJECTION,
                "Qualification preflight was rejected",
                findings=findings,
                data={"runId": source_run.workspace.run_id},
            ),
            output_format,
        )
        return
    database_cache = cache_home() / "conclear" / "trivy"
    database = (
        select_fresh_database(
            source_run.runtime.trivy(),
            database_cache,
            now=datetime.now(UTC),
        )
        if expected_database is None
        else select_database_by_digest(
            source_run.runtime.trivy(),
            database_cache,
            expected_digest=expected_database,
        )
    )
    hooks = HookRunner(
        runner=source_run.runtime.runner,
        environment=source_run.runtime.environment,
        source_root=source_run.repository.path.parent,
        log_directory=source_run.workspace.root / "logs",
    )
    result = qualify_platform(
        inputs,
        builder=source_run.runtime.buildah(),
        runtime=source_run.runtime.podman(),
        hooks=hooks,
        scanner=source_run.runtime.trivy(),
        database=database,
        pin_observations=pin_observations,
        preflight_findings=preflight.findings,
        now=datetime.now(UTC),
    )
    target = {
        "accepted": RunState.QUALIFIED,
        "rejected": RunState.REJECTED,
        "incomplete": RunState.INCOMPLETE,
    }[result.verdict.value]
    source_run.workspace.transition(target)
    status = {
        "accepted": ResultStatus.SUCCESS,
        "rejected": ResultStatus.RULE_REJECTION,
        "incomplete": ResultStatus.OPERATIONAL_FAILURE,
    }[result.verdict.value]
    emit(
        CommandResult(
            "qualify",
            status,
            f"Platform qualification is {result.verdict.value}",
            findings=result.findings,
            data={
                "runId": source_run.workspace.run_id,
                "record": str(result.record_path),
                "recordDigest": result.record_digest,
                "layout": str(result.layout_path),
                "databaseDigest": database.digest,
            },
        ),
        output_format,
    )


@click.command("assemble")
@click.argument("run_id")
@click.option("version", "--version")
@_format_option
def assemble_command(run_id: str, version: str | None, output_format: str) -> None:
    """Verify exact platform coverage and assemble a release candidate."""
    source_run = open_source_run(state_home=state_home(), run_id=run_id, names=())
    snapshot = source_run.workspace.load()
    recorded_version = snapshot.immutable_inputs.get("version") or None
    if version is not None and version != recorded_version:
        raise click.UsageError("--version differs from the recorded run input")
    image_id = snapshot.immutable_inputs["image"]
    image = source_run.repository.image(image_id)
    result = assemble_candidate(
        qualification_transports(source_run.workspace, image),
        repository=source_run.repository,
        image=image,
        workspace=source_run.workspace,
        version=recorded_version,
        tools=source_run.runtime.identities,
        now=datetime.now(UTC),
    )
    emit(
        CommandResult(
            "assemble",
            ResultStatus.SUCCESS,
            "Release candidate assembled",
            data={
                "record": str(result.record_path),
                "recordDigest": result.record_digest,
                "layout": str(result.observation.path),
                "subjectDigest": str(result.observation.graph.digest),
                "candidateTag": result.candidate_tag,
            },
        ),
        output_format,
    )


def _inputs(
    source_run: SourceRun,
    platform_text: str,
    selected: ReleaseProfile | None,
) -> QualificationInputs:
    snapshot = source_run.workspace.load()
    image_id = snapshot.immutable_inputs["image"]
    platform = Platform.parse(platform_text)
    image = source_run.repository.image(image_id)
    if platform not in image.platforms:
        raise click.UsageError(f"Platform is not configured for {image_id}: {platform}")
    version = snapshot.immutable_inputs.get("version") or None
    return QualificationInputs(
        repository=source_run.repository,
        image=image,
        workspace=source_run.workspace,
        source=source_run.source,
        source_time=source_run.source_time,
        version=version,
        platform=platform,
        tools=source_run.runtime.identities,
        auth_file=None if selected is None else selected.auth_file,
        host_architecture=host_platform.machine(),
    )
