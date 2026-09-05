"""Commands that move accepted platform qualifications between runs."""

from datetime import UTC, datetime
from pathlib import Path

import click

from conclear.presentation import CommandResult, ResultStatus
from conclear.services.run_context import open_source_run
from conclear.transport import TransportKind, export_transport
from conclear.values import Platform

from .common import emit, format_option, platform_option, state_home


@click.group("transport")
def transport_group() -> None:
    """Export accepted platform qualifications for a coordinator to assemble."""


@transport_group.command("export")
@click.argument("run_id")
@platform_option
@click.option(
    "output_path",
    "--output",
    type=click.Path(path_type=Path),
    required=True,
    help="New archive file or directory to create; an existing path is refused.",
)
@click.option(
    "kind",
    "--kind",
    type=click.Choice([item.value for item in TransportKind], case_sensitive=True),
    default=TransportKind.ARCHIVE.value,
    show_default=True,
    help="Write one tar archive or a directory of the same members.",
)
@format_option
def export_command(
    run_id: str,
    platform_text: str,
    output_path: Path,
    kind: str,
    output_format: str,
) -> None:
    """Export one accepted qualification, its layout and evidence as a transport."""
    source_run = open_source_run(state_home=state_home(), run_id=run_id, names=())
    snapshot = source_run.workspace.load()
    image = source_run.repository.image(snapshot.immutable_inputs["image"])
    platform = Platform.parse(platform_text)
    if platform not in image.platforms:
        raise click.UsageError(
            f"Platform is not configured for {image.image_id}: {platform}"
        )
    result = export_transport(
        source_run.workspace,
        image,
        platform,
        destination=output_path,
        kind=TransportKind(kind),
        now=datetime.now(UTC),
    )
    emit(
        CommandResult(
            "transport export",
            ResultStatus.SUCCESS,
            f"Exported the {platform} qualification of run {result.worker_run_id}",
            data={
                "runId": result.worker_run_id,
                "platform": str(platform),
                "transport": str(result.path),
                "kind": result.kind.value,
                "transportDigest": result.transport_digest,
                "manifestDigest": result.manifest_digest,
                "recordDigest": result.record_digest,
                "layoutDigest": result.layout_digest,
                "platformManifestDigest": result.platform_manifest_digest,
                "payloadDigests": list(result.payload_digests),
                "members": len(result.members),
                "totalBytes": result.total_bytes,
            },
        ),
        output_format,
    )
