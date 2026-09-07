"""Read-only adoption assessment command."""

from pathlib import Path

import click

from conclear.dependencies import command_tools
from conclear.fileio import create_new_file
from conclear.presentation import CommandResult, ResultStatus
from conclear.services.adoption import assess_repository

from .common import command_runtime, emit, format_option


@click.command("adopt")
@click.option(
    "source_root",
    "--source",
    type=click.Path(path_type=Path),
    default=Path(),
    show_default=True,
)
@click.option(
    "containerfiles",
    "--containerfile",
    multiple=True,
    help="Containerfile path below the source root; repeatable. Replaces discovery.",
)
@click.option(
    "output_path",
    "--output",
    type=click.Path(path_type=Path),
    help="Write the draft conclear.toml to a new file; an existing file is refused.",
)
@format_option
def adopt_command(
    source_root: Path,
    containerfiles: tuple[str, ...],
    output_path: Path | None,
    output_format: str,
) -> None:
    """Assess an existing repository read-only and draft a conclear.toml to review."""
    with command_runtime(command_tools("adopt")) as runtime:
        assessment = assess_repository(
            source_root, containerfiles=containerfiles, git=runtime.git()
        )
    data = assessment.to_dict()
    if output_path is not None:
        create_new_file(output_path, assessment.draft.encode("utf-8"))
        data["draftPath"] = str(output_path)
    emit(
        CommandResult(
            "adopt",
            ResultStatus.SUCCESS,
            (
                f"Assessed {len(assessment.images)} image(s); "
                f"{len(assessment.decisions)} decision(s) keep the draft invalid"
            ),
            findings=assessment.findings,
            data=data,
            details=assessment.details(),
        ),
        output_format,
    )
