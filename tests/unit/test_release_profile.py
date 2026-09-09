import os
import subprocess
import sys
from pathlib import Path

import pytest

from conclear.errors import InvalidInvocationError
from conclear.release_profile import (
    BuilderConfig,
    CIContextPolicy,
    QuayRegistryConfig,
    RegistryProvider,
    load_release_profile,
)
from tests.registry_policy_fixtures import REGISTRY_POLICY_TOML, STRICT_POLICY


def test_release_profile_import_does_not_load_repository_configuration(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        (
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import sys\n"
            "import conclear.release_profile\n"
            "assert 'conclear.config' not in sys.modules\n",
        ),
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def _profile_text(*root_lines: str, api_url: str | None = None) -> str:
    root_lines = ("schema_version = 1", *root_lines)
    registry_lines = [
        "",
        "[builder]",
        'id = "https://foundata.com/en/projects/conclear/builder/simple-v1/"',
        "",
        "[registry]",
        'provider = "quay"',
        'host = "quay.io"',
        REGISTRY_POLICY_TOML,
    ]
    if api_url is not None:
        registry_lines.append(f'api_url = "{api_url}"')
    return "\n".join((*root_lines, *registry_lines))


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
        policy=STRICT_POLICY,
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


def test_release_profile_requires_its_schema_version(tmp_path: Path) -> None:
    profile_directory = tmp_path / "conclear"
    profile_directory.mkdir(mode=0o700)
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("key", encoding="utf-8")
    public_key.chmod(0o600)
    unversioned = _profile_text(
        'ci_context = "omit"', f'cosign_public_key = "{public_key}"'
    ).replace("schema_version = 1\n", "")
    path = profile_directory / "release.toml"
    path.write_text(unversioned, encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(InvalidInvocationError, match="schema_version"):
        load_release_profile("release", config_home=tmp_path)

    path.write_text(
        unversioned.replace("[builder]", "schema_version = 1\n[builder]"),
        encoding="utf-8",
    )
    assert load_release_profile("release", config_home=tmp_path).schema_version == 1
