"""Evidence archive creation retries and independent retained-bundle verification."""

from pathlib import Path

import click

from conclear.archive import ArchiveResult, open_archive, prepare_archive_directory
from conclear.dependencies import command_tools
from conclear.errors import ConClearError, OperationalError, bind_failed_run
from conclear.presentation import CommandResult, ResultStatus
from conclear.release_profile import ReleaseProfile
from conclear.services.archives import create_run_archive, verify_archive_signatures
from conclear.workspace import RunWorkspace

from .common import (
    archive_options,
    cache_home,
    command_runtime,
    emit,
    format_option,
    profile,
    required_profile_option,
    resolve_archive_directory,
    state_home,
)


@click.group("archive")
def archive_group() -> None:
    """Create and verify compressed release and rescan evidence."""


@archive_group.command("create")
@click.argument("run_id")
@required_profile_option
@archive_options
@format_option
def archive_create_command(
    run_id: str,
    profile_name: str,
    archive_directory: Path | None,
    include_image_layers: bool,
    output_format: str,
) -> None:
    """Retry archival of a completed run without publishing or rescanning."""
    selected = profile(profile_name)
    result = archive_completed_run(
        run_id,
        selected=selected,
        directory=resolve_archive_directory(archive_directory, selected),
        include_image_layers=include_image_layers,
    )
    emit(
        CommandResult(
            "archive create",
            ResultStatus.SUCCESS,
            "Evidence archive verified and written",
            data={"runId": run_id, "archive": result.to_dict()},
            details=archive_details(result),
        ),
        output_format,
    )


@archive_group.command("verify")
@click.argument("path", type=click.Path(path_type=Path, dir_okay=False))
@required_profile_option
@format_option
def archive_verify_command(path: Path, profile_name: str, output_format: str) -> None:
    """Verify archive checksums, image metadata and retained Sigstore attestations."""
    selected = profile(profile_name)
    with (
        open_archive(path) as archive,
        command_runtime(command_tools("archive verify")) as runtime,
    ):
        verify_archive_signatures(
            archive, signer=runtime.cosign(), public_key=selected.cosign_public_key
        )
        result = archive.result
        data = {
            "archive": result.to_dict(),
            "subject": str(archive.subject),
            "kind": archive.kind,
            "imageLayers": archive.manifest["imageLayers"],
            "signedEvidenceVerified": True,
        }
    emit(
        CommandResult(
            "archive verify",
            ResultStatus.SUCCESS,
            "Archive contents and retained signatures verified",
            data=data,
            details=archive_details(result),
        ),
        output_format,
    )


def archive_completed_run(
    run_id: str,
    *,
    selected: ReleaseProfile,
    directory: Path,
    include_image_layers: bool,
) -> ArchiveResult:
    """Keep publication success distinct from an independently retryable export."""
    workspace = RunWorkspace.open(state_home=state_home(), run_id=run_id)
    try:
        source_root = workspace.load().immutable_inputs.get("sourceRoot")
        directory = prepare_archive_directory(
            directory,
            excluded=(
                state_home() / "conclear",
                cache_home() / "conclear",
                workspace.root / "source",
                workspace.root / "checkout",
                *((Path(source_root),) if source_root is not None else ()),
            ),
        )
        with command_runtime(command_tools("archive create")) as runtime:
            return create_run_archive(
                workspace,
                directory=directory,
                signer=runtime.cosign(auth_file=selected.auth_file),
                public_key=selected.cosign_public_key,
                include_image_layers=include_image_layers,
            )
    except (ConClearError, OSError) as exc:
        failure = OperationalError(
            f"Archive for run {run_id} is incomplete. Keep the workspace; "
            f"retry conclear archive create {run_id} --profile {selected.name} --archive-dir <directory>. "
            f"{exc}"
        )
        bind_failed_run(failure, run_id)
        raise failure from exc


def archive_details(result: ArchiveResult) -> tuple[str, ...]:
    """Show archive location and identity in human command output."""
    return (
        f"Archive: {result.path}",
        f"SHA-256: {result.digest[7:]} ({result.size} bytes)",
    )
