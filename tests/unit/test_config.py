import os
import tomllib
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

import conclear.config as config_module
from conclear.config import (
    BuilderConfig,
    CIContextPolicy,
    QuayRegistryConfig,
    RegistryProvider,
    load_release_profile,
    load_repository_config,
    normalize_source_url,
)
from conclear.errors import InvalidInvocationError


def _profile_text(*root_lines: str, api_url: str | None = None) -> str:
    registry_lines = [
        "",
        "[builder]",
        'id = "https://foundata.com/en/projects/conclear/builder/simple-v1/"',
        "",
        "[registry]",
        'provider = "quay"',
        'host = "quay.io"',
    ]
    if api_url is not None:
        registry_lines.append(f'api_url = "{api_url}"')
    return "\n".join((*root_lines, *registry_lines))


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


def test_candidate_lifetime_is_accepted_only_at_image_scope(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    direct = path.read_text(encoding="utf-8").replace(
        "arm64_omission_reason =",
        'candidate_lifetime = "24h"\narm64_omission_reason =',
    )
    path.write_text(direct, encoding="utf-8")
    assert load_repository_config(path).image("app").limits.candidate_lifetime == (
        timedelta(hours=24)
    )

    nested = direct.replace(
        'candidate_lifetime = "24h"\narm64_omission_reason =',
        "arm64_omission_reason =",
    ).replace(
        "[images.release]",
        '[images.limits]\ncandidate_lifetime = "24h"\n\n[images.release]',
    )
    path.write_text(nested, encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="Additional properties"):
        load_repository_config(path)


@pytest.mark.parametrize(
    ("configured", "replacement"),
    (
        (
            'immutable_tags = ["{version}"]',
            'immutable_tags = ["{version}-candidate.manual"]',
        ),
        ('moving_tags = ["stable"]', 'moving_tags = ["stable-candidate.manual"]'),
    ),
)
def test_repository_configuration_reserves_candidate_tag_namespace(
    repository_factory: Callable[..., Path],
    configured: str,
    replacement: str,
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(configured, replacement),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match=r"owned -candidate\."):
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


@pytest.mark.parametrize(
    "destination", ("docker.io/library/example", "registry.example.com/example")
)
def test_repository_configuration_accepts_non_quay_release_destination(
    repository_factory: Callable[..., Path], destination: str
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'repository = "quay.io/example/app"',
            f'repository = "{destination}"',
        ),
        encoding="utf-8",
    )

    assert (
        load_repository_config(path).image("app").repository.repository_name
        == destination
    )


def test_repository_configuration_read_is_bounded(
    repository_factory: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    monkeypatch.setattr(config_module, "MAX_CONFIG_BYTES", path.stat().st_size - 1)

    with pytest.raises(InvalidInvocationError, match="exceeds the size limit"):
        load_repository_config(path)


def test_repository_configuration_rejects_excessive_toml_nesting(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    nested_table = ".".join(f"level{index}" for index in range(66))
    path.write_text(
        path.read_text(encoding="utf-8") + f"\n[{nested_table}]\nvalue = true\n",
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="nesting limit"):
        load_repository_config(path)


def test_repository_configuration_classifies_parser_recursion(
    repository_factory: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = repository_factory() / "conclear.toml"

    def fail_parse(value: str) -> object:
        del value
        raise RecursionError("injected parser recursion")

    monkeypatch.setattr(tomllib, "loads", fail_parse)

    with pytest.raises(InvalidInvocationError, match="Unable to read"):
        load_repository_config(path)


@pytest.mark.parametrize("policy", tuple(CIContextPolicy))
def test_release_profile_requires_explicit_ci_context_policy(
    tmp_path: Path, policy: CIContextPolicy
) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    profile = profile_directory / "release.toml"
    profile.write_text(
        _profile_text(
            f'ci_context = "{policy.value}"',
            f'cosign_public_key = "{public_key}"',
        ),
        encoding="utf-8",
    )
    profile.chmod(0o600)

    assert load_release_profile("release", config_home=config_home).ci_context is policy


def test_release_profile_parses_explicit_registry_backend(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    token_file = tmp_path / "quay.token"
    token_file.write_text("token", encoding="utf-8")
    token_file.chmod(0o600)
    profile_path = profile_directory / "release.toml"
    profile_path.write_text(
        _profile_text(
            'ci_context = "omit"',
            f'cosign_public_key = "{public_key}"',
        )
        + f'\ntoken_file = "{token_file}"',
        encoding="utf-8",
    )
    profile_path.chmod(0o600)

    selected = load_release_profile("release", config_home=config_home)

    assert selected.registry == QuayRegistryConfig(
        RegistryProvider.QUAY,
        "quay.io",
        "https://quay.io/api/v1",
        token_file.resolve(),
    )
    assert selected.builder == BuilderConfig(
        "https://foundata.com/en/projects/conclear/builder/simple-v1/"
    )


@pytest.mark.parametrize(
    "builder_id",
    (
        "http://foundata.com/en/projects/conclear/builder/simple-v1/",
        "https://user:secret@foundata.com/conclear/builder/",
        "https://foundata.com/conclear/builder/?environment=test",
        "https://foundata.com/conclear/builder/#simple-v1",
        "https://foundata.com/conclear/../admin/",
    ),
)
def test_release_profile_rejects_unsafe_builder_identity(
    tmp_path: Path, builder_id: str
) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    profile_path = profile_directory / "release.toml"
    profile_path.write_text(
        _profile_text(
            'ci_context = "omit"',
            f'cosign_public_key = "{public_key}"',
        ).replace(
            "https://foundata.com/en/projects/conclear/builder/simple-v1/",
            builder_id,
        ),
        encoding="utf-8",
    )
    profile_path.chmod(0o600)

    with pytest.raises(InvalidInvocationError):
        load_release_profile("release", config_home=config_home)


def test_release_profile_rejects_legacy_release_mode(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    profile = profile_directory / "release.toml"
    profile.write_text(
        _profile_text('mode = "local"', f'cosign_public_key = "{public_key}"'),
        encoding="utf-8",
    )
    profile.chmod(0o600)

    with pytest.raises(InvalidInvocationError, match="ci_context"):
        load_release_profile("release", config_home=config_home)


def test_release_profile_rejects_group_writable_file(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    profile = profile_directory / "release.toml"
    profile.write_text(
        _profile_text('ci_context = "omit"', f'cosign_public_key = "{public_key}"'),
        encoding="utf-8",
    )
    profile.chmod(0o620)
    assert os.getuid() == profile.stat().st_uid
    with pytest.raises(
        InvalidInvocationError, match="permissions are unsafe"
    ) as caught:
        load_release_profile("release", config_home=config_home)
    assert caught.value.code == "CC0003"


def test_release_profile_rejects_credentials_in_hsm_handle(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    profile = profile_directory / "release.toml"
    profile.write_text(
        _profile_text(
            'ci_context = "omit"',
            f'cosign_public_key = "{public_key}"',
            'cosign_private_key = "pkcs11:token=test;pin-value=secret"',
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
        _profile_text(
            'ci_context = "omit"',
            f'cosign_public_key = "{public_key}"',
            f'cosign_private_key = "{private_key}"',
        ),
        encoding="utf-8",
    )
    profile.chmod(0o600)

    selected = load_release_profile("release", config_home=config_home)

    assert selected.cosign_private_key == str(private_key.resolve())


def test_release_profile_rejects_ambiguous_registry_api_url(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    profile_directory = config_home / "conclear"
    profile_directory.mkdir(parents=True)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    profile = profile_directory / "release.toml"
    profile.write_text(
        _profile_text(
            'ci_context = "omit"',
            f'cosign_public_key = "{public_key}"',
            api_url="https://user:secret@quay.io/api/v1",
        ),
        encoding="utf-8",
    )
    profile.chmod(0o600)

    with pytest.raises(InvalidInvocationError, match="credential-free HTTPS"):
        load_release_profile("release", config_home=config_home)
