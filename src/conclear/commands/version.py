"""Version command and embedded identity presentation."""

import json
import sys
from typing import TextIO

import click

from conclear.identity import IDENTITY, human_version


def write_version(output_format: str, stream: TextIO) -> None:
    """Write embedded version information in the requested public format."""
    if output_format == "json":
        json.dump(IDENTITY.to_public_dict(), stream, ensure_ascii=True, sort_keys=True)
        stream.write("\n")
        return
    stream.write(human_version())
    stream.write("\n")


@click.command("version")
@click.option(
    "output_format",
    "--format",
    type=click.Choice(["human", "json"], case_sensitive=True),
    default="human",
    show_default=True,
)
def version_command(output_format: str) -> None:
    """Report the application and implemented-guide identity."""
    write_version(output_format, sys.stdout)
