"""Read-only inspection of effective repository configuration."""

from pathlib import Path

import click

from conclear.config import load_repository_config
from conclear.services.configuration_view import configuration_view

from .common import config_option, emit, format_option, profile, profile_option


@click.group("config")
def config_group() -> None:
    """Inspect repository configuration without building or publishing."""


@config_group.command("show")
@config_option
@click.option("image_id", "--image")
@click.option("version", "--version")
@profile_option
@format_option
def show_command(
    config_path: Path,
    image_id: str | None,
    version: str | None,
    profile_name: str | None,
    output_format: str,
) -> None:
    """Show effective values, defaults and decision reasons for each image."""
    repository = load_repository_config(config_path)
    selected = None if profile_name is None else profile(profile_name)
    emit(
        configuration_view(
            repository, image_id=image_id, version=version, profile=selected
        ),
        output_format,
    )
