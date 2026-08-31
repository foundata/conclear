import os
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

import conclear.config as config_module
from conclear.config import (
    load_release_profile,
    load_repository_config,
    normalize_source_url,
)
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


@pytest.mark.parametrize(
    "source",
    (
        "https://user:secret@github.com/example/app",
        "https://github.com/example/../app",
        "https://github.com/example/app?credential=secret",
        "https://github.com:99999/example/app",
        "https://github..com/example/app",
    ),
)
def test_repository_configuration_rejects_ambiguous_source_urls(
    source: str,
) -> None:
    with pytest.raises(InvalidInvocationError):
        normalize_source_url(source)


def test_repository_configuration_rejects_unsafe_container_mount(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8").replace(
        "read_only = true",
        'read_only = true\nwritable_mounts = ["/tmp/../etc"]',
    )
    path.write_text(content, encoding="utf-8")

    with pytest.raises(InvalidInvocationError, match="unsafe container path"):
        load_repository_config(path)


def test_repository_configuration_read_is_bounded(
    repository_factory: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    monkeypatch.setattr(config_module, "MAX_CONFIG_BYTES", path.stat().st_size - 1)

    with pytest.raises(InvalidInvocationError, match="exceeds the size limit"):
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


def test_release_profile_rejects_credentials_in_hsm_handle(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    profile = profile_directory / "release.toml"
    profile.write_text(
        "\n".join(
            (
                'mode = "local"',
                f'cosign_public_key = "{public_key}"',
                'cosign_private_key = "pkcs11:token=test;pin-value=secret"',
            )
        ),
        encoding="utf-8",
    )
    profile.chmod(0o600)

    with pytest.raises(InvalidInvocationError, match="must not contain credentials"):
        load_release_profile("release", config_home=config_home)


def test_release_profile_resolves_file_signing_key(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    private_key = tmp_path / "cosign.key"
    private_key.write_text("private", encoding="utf-8")
    private_key.chmod(0o600)
    profile = profile_directory / "release.toml"
    profile.write_text(
        "\n".join(
            (
                'mode = "local"',
                f'cosign_public_key = "{public_key}"',
                f'cosign_private_key = "{private_key}"',
            )
        ),
        encoding="utf-8",
    )
    profile.chmod(0o600)

    selected = load_release_profile("release", config_home=config_home)

    assert selected.cosign_private_key == str(private_key.resolve())


def test_release_profile_rejects_ambiguous_quay_api_url(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    profile = profile_directory / "release.toml"
    profile.write_text(
        "\n".join(
            (
                'mode = "local"',
                f'cosign_public_key = "{public_key}"',
                'quay_api_url = "https://user:secret@quay.io/api/v1"',
            )
        ),
        encoding="utf-8",
    )
    profile.chmod(0o600)

    with pytest.raises(InvalidInvocationError, match="credential-free HTTPS"):
        load_release_profile("release", config_home=config_home)
