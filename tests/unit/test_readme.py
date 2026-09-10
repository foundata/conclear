"""Keep the README's configuration and command examples usable."""

import re
import shlex
from collections.abc import Callable
from pathlib import Path

import click
import pytest

from conclear.cli import root
from conclear.config import load_repository_config
from conclear.registry_policy import CandidateCleanupMode, TagProtectionMode
from conclear.release_profile import load_release_profile

README = Path(__file__).resolve().parents[2] / "README.md"


def _blocks(language: str) -> list[str]:
    return re.findall(
        rf"^```{language}\n(.*?)^```$",
        README.read_text(encoding="utf-8"),
        re.MULTILINE | re.DOTALL,
    )


def test_readme_repository_example_loads_and_includes_latest(
    repository_factory: Callable[..., Path],
) -> None:
    directory = repository_factory()
    (directory / "conclear.toml").write_text(_blocks("toml")[0], encoding="utf-8")

    image = load_repository_config(directory / "conclear.toml").release_image(None)

    assert image.release.render_versions("1.2.3") == ("1.2.3",)
    assert image.release.moving_tags == ("latest",)
    assert image.pins[0].reference.digest is not None


def test_readme_release_profile_loads_with_protected_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    directory = tmp_path / ".config" / "conclear"
    directory.mkdir(mode=0o700, parents=True)
    for name in ("cosign.pub", "cosign.key", "auth.json", "quay.token"):
        path = directory / name
        path.write_text("test credential\n", encoding="utf-8")
        path.chmod(0o600)
    path = directory / "foundata.toml"
    path.write_text(_blocks("toml")[1], encoding="utf-8")
    path.chmod(0o600)

    profile = load_release_profile("foundata", config_home=directory.parent)

    assert profile.registry.policy.tag_protection.mode is TagProtectionMode.NOT_ENFORCED
    assert (
        profile.registry.policy.candidate_cleanup.mode
        is CandidateCleanupMode.TAG_EXPIRATION
    )
    assert profile.cosign_private_key == str(directory / "cosign.key")


def test_readme_conclear_commands_parse_without_invoking_operations() -> None:
    for block in (*_blocks("sh"), *_blocks("bash")):
        for line in block.replace("\\\n", " ").splitlines():
            if not line.startswith("conclear "):
                continue
            arguments = shlex.split(line)[1:]
            command: click.Command = root
            while isinstance(command, click.Group):
                name = arguments.pop(0)
                child = command.get_command(click.Context(command), name)
                assert child is not None, line
                command = child
            with command.make_context(command.name or "", arguments):
                pass
