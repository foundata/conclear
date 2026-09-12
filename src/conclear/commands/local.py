"""Static, build, test, evidence, qualification and assembly commands."""

import platform as host_platform
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click

from conclear.config import load_repository_config
from conclear.database import (
    select_database_by_digest,
    select_fresh_database,
    trivy_cache_root,
)
from conclear.dependencies import command_tools
from conclear.errors import InvalidInvocationError
from conclear.pins import PinStore
from conclear.presentation import CommandResult, ResultStatus
from conclear.records import format_timestamp, parse_timestamp, utc_now
from conclear.release_profile import ReleaseProfile
from conclear.services.assembly import assemble_candidate
from conclear.services.checking import check_image
from conclear.services.local_phases import (
    load_build_evidence,
    write_build_evidence,
)
from conclear.services.preflight import preflight_image_closure
from conclear.services.qualification import (
    build_platform,
    build_test_dependencies,
    qualify_platform,
)
from conclear.services.qualification_inputs import (
    QualificationInputs,
    TestDependencyBuild,
)
from conclear.services.release import AuthenticatedPinResolver, profile_inputs
from conclear.services.run_context import (
    SourceRun,
    create_source_run,
    hook_runner,
    open_source_run,
)
from conclear.services.runtime_tests import test_platform
from conclear.transport import ImportedTransport, import_transport
from conclear.values import Digest, Platform
from conclear.workspace import RunState

from .common import (
    cache_home,
    command_runtime,
    config_option,
    emit,
    format_option,
    owned_run,
    platform_option,
    profile,
    profile_option,
    state_home,
)


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
        click.option("image_id", "--image"),
        click.option("version", "--version"),
    )
    for decorator in reversed(decorators):
        function = decorator(function)
    return function


@click.command("check")
@config_option
@click.option("image_id", "--image")
@format_option
def check_command(config_path: Path, image_id: str | None, output_format: str) -> None:
    """Run static Containerfile, context, metadata and pin-declaration checks."""
    repository = load_repository_config(config_path)
    image = repository.image(image_id)
    with command_runtime(command_tools("check")) as runtime:
        outcome = check_image(image, runtime.hadolint())
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
@platform_option
@profile_option
@format_option
def build_command(
    source_root: Path,
    selector: str,
    image_id: str | None,
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
        names=command_tools("build"),
        profile_name="none" if selected is None else selected.name,
        additional_inputs=None if selected is None else profile_inputs(selected),
        allowed_origins=None if selected is None else selected.allowed_source_origins,
    )
    with owned_run(source_run.workspace):
        inputs = _inputs(source_run, platform_text, selected)
        build = build_platform(inputs, source_run.runtime.buildah())
        build_path = write_build_evidence(inputs, build)
        dependencies = build_test_dependencies(inputs, source_run.runtime.buildah())
        dependency_paths = [
            write_build_evidence(inputs.dependency_inputs(item.image), item.build)
            for item in dependencies
        ]
        build_findings = build.findings + tuple(
            finding for item in dependencies for finding in item.build.findings
        )
        accepted = not any(finding.severity == "error" for finding in build_findings)
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
                findings=build_findings,
                data={
                    "runId": source_run.workspace.run_id,
                    "layout": str(build.observation.layout_path),
                    "digest": str(build.observation.graph.digest),
                    "buildEvidence": str(build_path),
                    "testDependencyEvidence": [str(path) for path in dependency_paths],
                },
            ),
            output_format,
        )


@click.command("test")
@click.argument("run_id")
@platform_option
@format_option
def test_command(run_id: str, platform_text: str, output_format: str) -> None:
    """Import one exact layout and run declared constrained tests."""
    source_run = open_source_run(
        state_home=state_home(),
        run_id=run_id,
        names=command_tools("test"),
    )
    inputs = _inputs(source_run, platform_text, None)
    build = load_build_evidence(inputs)
    dependencies = tuple(
        TestDependencyBuild(
            image=dependency,
            build=load_build_evidence(inputs.dependency_inputs(dependency)),
            source_revision=inputs.source.revision,
            platform=inputs.platform,
        )
        for dependency in inputs.repository.test_dependencies(inputs.image.image_id)
    )
    hooks = hook_runner(source_run.runtime, source_run.repository, source_run.workspace)
    result = test_platform(
        inputs,
        build,
        source_run.runtime.podman(),
        hooks,
        dependencies=dependencies,
    )
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


@click.command("qualify")
@_source_options
@platform_option
@profile_option
@click.option("database_digest", "--database-digest")
@click.option(
    "qualification_start",
    "--qualification-started-at",
    help="Original UTC qualification start shared with a pinned database snapshot.",
)
@format_option
def qualify_command(
    source_root: Path,
    selector: str,
    image_id: str | None,
    version: str | None,
    platform_text: str,
    profile_name: str | None,
    database_digest: str | None,
    qualification_start: str | None,
    output_format: str,
) -> None:
    """Run all local gates and emit one platform qualification."""
    selected = profile(profile_name) if profile_name else None
    expected_database = None if database_digest is None else Digest(database_digest)
    if qualification_start is not None and expected_database is None:
        raise InvalidInvocationError(
            "--qualification-started-at requires --database-digest"
        )
    started_at = (
        None
        if qualification_start is None
        else parse_timestamp(
            qualification_start, "qualification start", error=InvalidInvocationError
        )
    )
    additional_inputs = {} if selected is None else profile_inputs(selected)
    if expected_database is not None:
        additional_inputs["databaseDigest"] = str(expected_database)
    if started_at is not None:
        additional_inputs["qualificationStartedAt"] = format_timestamp(started_at)
    source_run = create_source_run(
        source_root=source_root,
        selector=selector,
        image_id=image_id,
        version=version,
        state_home=state_home(),
        names=command_tools("qualify"),
        profile_name="none" if selected is None else selected.name,
        additional_inputs=additional_inputs or None,
        allowed_origins=None if selected is None else selected.allowed_source_origins,
    )
    with owned_run(source_run.workspace):
        image = source_run.repository.release_image(image_id)
        inputs = _inputs(source_run, platform_text, selected)
        preflight = preflight_image_closure(
            source_run.repository,
            image,
            hadolint=source_run.runtime.hadolint(),
            store=PinStore(state_home()),
            resolver=AuthenticatedPinResolver(
                source_run.runtime, None if selected is None else selected.auth_file
            ),
            now=utc_now(),
        )
        if not preflight.accepted:
            source_run.workspace.transition(RunState.REJECTED)
            emit(
                CommandResult(
                    "qualify",
                    ResultStatus.RULE_REJECTION,
                    "Qualification preflight was rejected",
                    findings=preflight.findings,
                    data={"runId": source_run.workspace.run_id},
                ),
                output_format,
            )
            return
        database_cache = trivy_cache_root(cache_home())
        database = (
            select_fresh_database(
                source_run.runtime.trivy(),
                database_cache,
                now=utc_now(),
            )
            if expected_database is None
            else select_database_by_digest(
                source_run.runtime.trivy(),
                database_cache,
                expected_digest=expected_database,
                now=utc_now(),
                qualification_started_at=started_at,
            )
        )
        hooks = hook_runner(
            source_run.runtime, source_run.repository, source_run.workspace
        )
        result = qualify_platform(
            inputs,
            builder=source_run.runtime.buildah(),
            runtime=source_run.runtime.podman(),
            hooks=hooks,
            scanner=source_run.runtime.trivy(),
            database=database,
            preflight=preflight,
            now=utc_now(),
            qualification_started_at=started_at,
            record_clock=utc_now,
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
                    "qualificationWindow": result.qualification_window.to_dict(),
                },
            ),
            output_format,
        )


@click.command("assemble")
@_source_options
@profile_option
@click.option(
    "transports",
    "--transport",
    type=(click.Path(path_type=Path), str),
    multiple=True,
    required=True,
    metavar="PATH DIGEST",
    help=(
        "One exported qualification transport and the transport digest obtained "
        "independently from its worker; repeat once per required platform."
    ),
)
@format_option
def assemble_command(
    source_root: Path,
    selector: str,
    image_id: str | None,
    version: str | None,
    profile_name: str | None,
    transports: tuple[tuple[Path, str], ...],
    output_format: str,
) -> None:
    """Verify exported qualification transports and assemble a release candidate.

    Creates a new coordinator run from the reviewed source revision, imports
    every transport only after its caller-supplied digest matches, verifies
    each record, layout and evidence payload, requires exactly one accepted
    qualification per required platform and assembles the exact manifest or
    image index under a candidate reference named for the coordinator run.
    """
    selected = profile(profile_name) if profile_name else None
    source_run = create_source_run(
        source_root=source_root,
        selector=selector,
        image_id=image_id,
        version=version,
        state_home=state_home(),
        names=command_tools("assemble"),
        profile_name="none" if selected is None else selected.name,
        additional_inputs=None if selected is None else profile_inputs(selected),
        allowed_origins=None if selected is None else selected.allowed_source_origins,
    )
    workspace = source_run.workspace
    image = source_run.repository.release_image(image_id)
    with owned_run(workspace):
        imported = tuple(
            import_transport(
                path,
                expected_digest=digest,
                workspace=workspace,
                image=image,
                repository=source_run.repository,
                source_time=source_run.source_time,
            )
            for path, digest in transports
        )
        workspace.transition(RunState.QUALIFIED)
        result = assemble_candidate(
            tuple(item.transport for item in imported),
            repository=source_run.repository,
            image=image,
            workspace=workspace,
            version=version,
            tools=source_run.runtime.identities,
            now=utc_now(),
            clock=utc_now,
            source_time=source_run.source_time,
        )
    emit(
        CommandResult(
            "assemble",
            ResultStatus.SUCCESS,
            "Release candidate assembled",
            data={
                "runId": workspace.run_id,
                "record": str(result.record_path),
                "recordDigest": result.record_digest,
                "layout": str(result.observation.path),
                "subjectDigest": str(result.observation.graph.digest),
                "platformManifests": {
                    str(platform): str(digest)
                    for platform, digest in result.observation.platform_manifests
                },
                "candidateTag": result.candidate_tag,
                "transports": [_transport_entry(item) for item in imported],
            },
        ),
        output_format,
    )


def _transport_entry(item: ImportedTransport) -> dict[str, object]:
    return {
        "platform": str(item.platform),
        "workerRunId": item.worker_run_id,
        "transport": str(item.source),
        "kind": item.kind.value,
        "transportDigest": item.transport_digest,
        "manifestDigest": item.manifest_digest,
        "recordDigest": item.record_digest,
    }


def _inputs(
    source_run: SourceRun,
    platform_text: str,
    selected: ReleaseProfile | None,
) -> QualificationInputs:
    snapshot = source_run.workspace.load()
    image_id = snapshot.immutable_inputs["image"]
    platform = Platform.parse(platform_text)
    image = source_run.repository.release_image(image_id)
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
