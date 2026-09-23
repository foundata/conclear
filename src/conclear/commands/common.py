"""Shared Click command paths, output and protected profile helpers."""

import os
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import click

from conclear.adapters.ci import (
    CIContextObservation,
    observe_ci_context,
)
from conclear.errors import InvalidInvocationError, bind_failed_run
from conclear.presentation import CommandResult, present_human, present_json
from conclear.release_profile import (
    CIContextPolicy,
    ReleaseProfile,
    load_release_profile,
)
from conclear.runtime import ApplicationRuntime, ToolProblem
from conclear.runtime_directory import remove_runtime_directory
from conclear.secrets import read_passphrase
from conclear.services.run_context import finish_run_failure
from conclear.tools import ToolName
from conclear.workspace import RunWorkspace


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


def format_option[FC: Callable[..., Any]](function: FC) -> FC:
    """Add the shared `--format` choice between human and JSON output."""
    return click.option(
        "output_format",
        "--format",
        type=click.Choice(["human", "json"], case_sensitive=True),
        default="human",
        show_default=True,
    )(function)


def config_option[FC: Callable[..., Any]](function: FC) -> FC:
    """Add the repository configuration path option, defaulting to `conclear.toml`."""
    return click.option(
        "config_path",
        "--config",
        type=click.Path(path_type=Path),
        default=Path("conclear.toml"),
        show_default=True,
    )(function)


def profile_option[FC: Callable[..., Any]](function: FC) -> FC:
    """Add the optional release profile name."""
    return click.option("profile_name", "--profile")(function)


def required_profile_option[FC: Callable[..., Any]](function: FC) -> FC:
    """Add the release profile name for commands that cannot run without one."""
    return click.option("profile_name", "--profile", required=True)(function)


def archive_options[FC: Callable[..., Any]](function: FC) -> FC:
    """Require durable archive storage and make image-layer retention explicit."""
    function = click.option(
        "archive_directory",
        "--archive-dir",
        type=click.Path(path_type=Path, file_okay=False),
        help=(
            "Existing durable directory for the completed evidence tarball; "
            "defaults to the release profile's archive_dir."
        ),
    )(function)
    return click.option(
        "--include-image-layers",
        is_flag=True,
        help="Include image filesystem layers in the archive.",
    )(function)


def platform_option[FC: Callable[..., Any]](function: FC) -> FC:
    """Add the target platform selector; optional when the image declares one."""
    return click.option(
        "platform_text",
        "--platform",
        help="Target platform; defaults to the image's only declared platform.",
    )(function)


def resolve_archive_directory(
    archive_directory: Path | None, profile: ReleaseProfile
) -> Path:
    """Return the archive directory from the option or the profile's archive_dir."""
    if archive_directory is not None:
        return archive_directory
    if profile.archive_dir is not None:
        return profile.archive_dir
    raise InvalidInvocationError(
        "--archive-dir is required because the release profile "
        f"{profile.name} sets no archive_dir"
    )


def passphrase_option[FC: Callable[..., Any]](function: FC) -> FC:
    """Add the inherited file descriptor that supplies a signing passphrase."""
    return click.option("passphrase_fd", "--passphrase-fd", type=click.IntRange(min=3))(
        function
    )


def emit(result: CommandResult, output_format: str) -> None:
    """Present one result and terminate with its stable public status."""
    if output_format == "json":
        present_json(result, sys.stdout)
    else:
        present_human(result, sys.stdout)
    if result.exit_status:
        raise click.exceptions.Exit(int(result.exit_status))


@contextmanager
def owned_run(workspace: RunWorkspace) -> Iterator[None]:
    """Settle and name a created run when the command fails inside it.

    A result the command already presented leaves through Click's ``Exit``
    with the run state the command settled itself. Every other failure moves
    the run to its rejected or incomplete state and carries the run identity
    to the top-level handler, so the failure output names the run whose
    journaled resources `cleanup` can remove.
    """
    try:
        yield
    except click.exceptions.Exit:
        raise
    except BaseException as exc:
        finish_run_failure(workspace, exc)
        bind_failed_run(exc, workspace.run_id)
        raise


@contextmanager
def command_runtime(names: tuple[ToolName, ...]) -> Iterator[ApplicationRuntime]:
    """Create and remove a command-scoped environment with no external resources."""
    with _command_root() as root:
        runtime = ApplicationRuntime.create(root, names=names)
        try:
            yield runtime
        finally:
            runtime.release_tool_images()


@contextmanager
def diagnostic_runtime(
    names: tuple[ToolName, ...],
) -> Iterator[tuple[ApplicationRuntime, tuple[ToolProblem, ...]]]:
    """Like `command_runtime`, but report every unresolved tool instead of the first."""
    with _command_root() as root:
        runtime, problems = ApplicationRuntime.diagnose(root, names=names)
        try:
            yield runtime, problems
        finally:
            runtime.release_tool_images()


@contextmanager
def _command_root() -> Iterator[Path]:
    root = state_home() / "conclear" / "commands"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="command-", dir=root) as temporary:
        try:
            yield Path(temporary)
        finally:
            remove_runtime_directory(Path(temporary))


def ci_context(selected: ReleaseProfile) -> CIContextObservation | None:
    """Observe optional CI context according to protected profile policy."""
    if selected.ci_context is CIContextPolicy.OMIT:
        return None
    return observe_ci_context(os.environ)
