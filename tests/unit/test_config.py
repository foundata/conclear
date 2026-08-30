import os
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from conclear.config import load_release_profile, load_repository_config
from conclear.errors import InvalidInvocationError


def test_repository_configuration_is_validated_and_narrowed(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    config = load_repository_config(root / "conclear.toml")
    assert config.project.source == "https://github.com/example/app"
    assert config.image("app").limits.candidate_lifetime == timedelta(days=7)
    assert str(config.image("app").platforms[0]) == "linux/amd64"


def test_repository_configuration_rejects_unknown_keys(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8") + "\nunknown = true\n", encoding="utf-8"
    )
    with pytest.raises(InvalidInvocationError, match="Additional properties"):
        load_repository_config(path)


def test_repository_configuration_cannot_extend_builtin_limits(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8").replace(
        "arm64_omission_reason =",
        'candidate_lifetime = "8d"\narm64_omission_reason =',
    )
    path.write_text(content, encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="exceeds"):
        load_repository_config(path)


def test_release_profile_rejects_group_writable_file(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    profile = profile_directory / "release.toml"
    profile.write_text(
        f'mode = "local"\ncosign_public_key = "{public_key}"\n',
        encoding="utf-8",
    )
    profile.chmod(0o620)
    assert os.getuid() == profile.stat().st_uid
    with pytest.raises(InvalidInvocationError, match="permissions are unsafe"):
        load_release_profile("release", config_home=config_home)
