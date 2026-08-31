"""Shared Click command paths, output and protected profile helpers."""

import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import click

from conclear.config import ReleaseMode, ReleaseProfile, load_release_profile
from conclear.presentation import CommandResult, present_human, present_json
from conclear.runtime import ApplicationRuntime
from conclear.secrets import read_passphrase
from conclear.tools import ToolName


def state_home() -> Path:
    """Return the configured user state home."""
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))


def cache_home() -> Path:
    """Return the configured user cache home."""
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))


def config_home() -> Path:
    """Return the configured user configuration home."""
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def profile(name: str) -> ReleaseProfile:
    """Load one named protected release profile."""
    return load_release_profile(name, config_home=config_home())


def signing_passphrase(
    selected: ReleaseProfile,
    descriptor: int | None,
    *,
    required: bool,
) -> str | None:
    """Read a signing passphrase only for file-key operations that need one."""
    key = selected.cosign_private_key or ""
    external_key = "://" in key or key.startswith("pkcs11:")
    if not required or external_key:
        if descriptor is not None:
            raise click.UsageError("--passphrase-fd is not used by this operation")
        return None
    return read_passphrase(file=selected.passphrase_file, descriptor=descriptor)


def emit(result: CommandResult, output_format: str) -> None:
    """Present one result and terminate with its stable public status."""
    if output_format == "json":
        present_json(result, sys.stdout)
    else:
        present_human(result, sys.stdout)
    if result.exit_status:
        raise click.exceptions.Exit(int(result.exit_status))


@contextmanager
def command_runtime(names: tuple[ToolName, ...]) -> Iterator[ApplicationRuntime]:
    """Create and remove a command-scoped environment with no external resources."""
    root = state_home() / "conclear" / "commands"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="command-", dir=root) as temporary:
        yield ApplicationRuntime.create(Path(temporary), names=names)


def ci_identity(selected: ReleaseProfile) -> dict[str, object] | None:
    """Observe CI identity only when the protected profile selects CI mode."""
    if selected.mode is ReleaseMode.LOCAL:
        return None
    from conclear.ci import observe_ci_identity

    return observe_ci_identity(os.environ)
