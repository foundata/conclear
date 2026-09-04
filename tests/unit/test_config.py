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
    normalize_observed_source_url,
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
    image = config.image("app")
    assert config.project.source == "https://github.com/example/app"
    assert image.limits.candidate_lifetime == timedelta(days=7)
    assert str(image.platforms[0]) == "linux/amd64"
    assert image.containerfile == (root / "Containerfile").resolve()
    assert image.context == root.resolve()
    assert image.native_test_platforms == image.platforms
    assert image.runtime.read_only is True


def test_repository_configuration_accepts_explicit_arm64_v8(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace(
            'platforms = ["linux/amd64"]',
            'platforms = ["linux/amd64", "linux/arm64/v8"]',
        )
        .replace(
            'arm64_omission_reason = "The dependency is not available for arm64."\n',
            "",
        ),
        encoding="utf-8",
    )

    image = load_repository_config(path).image("app")

    assert str(image.platforms[-1]) == "linux/arm64/v8"


def test_repository_configuration_parses_exact_runtime_test_inputs(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    fixture = root / "test-fixture"
    fixture.mkdir()
    (fixture / "input.txt").write_text("input\n", encoding="utf-8")
    path = root / "conclear.toml"
    content = (
        path.read_text(encoding="utf-8")
        .replace(
            "[images.release]",
            """[images.test]
dependencies = ["generator"]

[[images.test.fixtures]]
name = "input"
path = "test-fixture"

[[images.test.outputs]]
name = "result"

[[images.test.preparations]]
name = "generate"
image = "generator"
command = ["/generator", "--input", "/input", "--output", "/output"]
environment = { TEST_MODE = "compatibility" }
expected_exit_status = 0

mounts = [
  { name = "input", target = "/input" },
  { name = "result", target = "/output", read_only = false },
]

[images.test.launch]
arguments = ["serve"]
environment = { SERVICE_MODE = "test" }
mounts = [{ name = "result", target = "/run/result" }]

[images.release]""",
        )
        .replace(
            "user = 10001\nmemory",
            'user = 10001\nwritable_mounts = ["/run/result"]\nmemory',
            1,
        )
    )
    content += _image_text("generator", writable_mount="/output")
    path.write_text(content, encoding="utf-8")

    config = load_repository_config(path)
    image = config.image("app")

    assert [item.image_id for item in config.test_dependencies("app")] == ["generator"]
    assert image.test.launch.arguments == ("serve",)
    assert image.test.preparations[0].command[0] == "/generator"
    assert image.test.fixtures[0].path == fixture.resolve()
    assert [
        (item.source, item.read_only) for item in image.test.preparations[0].mounts
    ] == [
        (config_module.TestMountSource.FIXTURE, True),
        (config_module.TestMountSource.OUTPUT, False),
    ]
    assert image.test.launch.mounts[0].source is config_module.TestMountSource.OUTPUT
    assert image.test.launch.mounts[0].read_only is True


@pytest.mark.parametrize(
    ("dependencies", "include_generator"),
    (
        (("missing",), False),
        (("app",), False),
        (("generator", "generator"), True),
    ),
)
def test_repository_configuration_rejects_invalid_test_dependency_graph(
    repository_factory: Callable[..., Path],
    dependencies: tuple[str, ...],
    include_generator: bool,
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    rendered = ", ".join(f'"{item}"' for item in dependencies)
    content = path.read_text(encoding="utf-8").replace(
        "[images.release]",
        f"[images.test]\ndependencies = [{rendered}]\n\n[images.release]",
    )
    if include_generator:
        content += _image_text("generator")
    path.write_text(content, encoding="utf-8")

    with pytest.raises(InvalidInvocationError):
        load_repository_config(path)


def test_repository_configuration_rejects_test_dependency_cycle(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8").replace(
        "[images.release]",
        '[images.test]\ndependencies = ["generator"]\n\n[images.release]',
    )
    content += _image_text("generator", dependencies=("app",))
    path.write_text(content, encoding="utf-8")

    with pytest.raises(InvalidInvocationError, match="cycle"):
        load_repository_config(path)


def test_repository_configuration_rejects_writable_fixture_mount(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    (root / "fixture").mkdir()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            """[images.test]
[[images.test.fixtures]]
name = "input"
path = "fixture"
[images.test.launch]
mounts = [{ name = "input", target = "/input", read_only = false }]
[images.release]""",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="read_only"):
        load_repository_config(path)


def test_repository_configuration_rejects_undeclared_test_mount_handle(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            """[images.test.launch]
mounts = [{ name = "missing", target = "/input" }]
[images.release]""",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="undeclared fixture or output"):
        load_repository_config(path)


def test_repository_configuration_rejects_secret_test_environment(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            '[images.test.launch]\nenvironment = { API_TOKEN = "not-allowed" }\n\n[images.release]',
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="API_TOKEN"):
        load_repository_config(path)


def test_repository_configuration_rejects_symlinked_test_fixture(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    fixture = root / "fixture"
    fixture.mkdir()
    (root / "fixture-link").symlink_to(fixture, target_is_directory=True)
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            """[images.test]
[[images.test.fixtures]]
name = "input"
path = "fixture-link"
[images.release]""",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="symbolic link"):
        load_repository_config(path)


def test_repository_configuration_rejects_test_fixture_traversal(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            """[images.test]
[[images.test.fixtures]]
name = "input"
path = "../outside"
[images.release]""",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError):
        load_repository_config(path)


@pytest.mark.parametrize("target", ("/proc/input", "/sys", "/dev/keys"))
def test_repository_configuration_rejects_unsafe_test_mount_target(
    repository_factory: Callable[..., Path], target: str
) -> None:
    root = repository_factory()
    (root / "fixture").mkdir()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            f'''[images.test]
[[images.test.fixtures]]
name = "input"
path = "fixture"
[images.test.launch]
mounts = [{{ name = "input", target = "{target}" }}]
[images.release]''',
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="Unsafe test mount"):
        load_repository_config(path)


def test_repository_configuration_rejects_overlapping_test_mount_targets(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    (root / "fixture").mkdir()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            """[images.test]
[[images.test.fixtures]]
name = "first"
path = "fixture"
[[images.test.fixtures]]
name = "second"
path = "fixture"
[images.test.launch]
mounts = [
  { name = "first", target = "/input" },
  { name = "second", target = "/input/nested" },
]
[images.release]""",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="overlapping mount targets"):
        load_repository_config(path)


def test_repository_configuration_rejects_writable_test_gate_override(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            """[images.test]
[[images.test.outputs]]
name = "result"
[[images.test.preparations]]
name = "prepare"
image = "app"
command = ["/app", "prepare"]
mounts = [{ name = "result", target = "/undeclared", read_only = false }]
[images.release]""",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="not declared by image"):
        load_repository_config(path)


@pytest.mark.parametrize("dependency", ("missing", "generator:latest"))
def test_repository_configuration_rejects_undeclared_or_mutable_test_image(
    repository_factory: Callable[..., Path], dependency: str
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            f'[images.test]\ndependencies = ["{dependency}"]\n\n[images.release]',
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError):
        load_repository_config(path)


def test_repository_configuration_rejects_test_dependency_platform_gap(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8").replace(
        "[images.release]",
        '[images.test]\ndependencies = ["generator"]\n\n[images.release]',
    )
    content = content.replace(
        'platforms = ["linux/amd64"]',
        'platforms = ["linux/amd64", "linux/arm64"]',
        1,
    )
    content += _image_text("generator")
    path.write_text(content, encoding="utf-8")

    with pytest.raises(InvalidInvocationError, match="does not cover"):
        load_repository_config(path)


def test_repository_configuration_rejects_undeclared_preparation_image(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            """[images.test]
[[images.test.preparations]]
name = "prepare"
image = "generator"
command = ["/generator", "prepare"]
[images.release]""",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="undeclared test image"):
        load_repository_config(path)


def test_repository_configuration_rejects_test_launch_control_key(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            "[images.test.launch]\nread_only = false\n\n[images.release]",
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="Additional properties"):
        load_repository_config(path)


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
        "[images.release]",
        '[images.limits]\ncandidate_lifetime = "8d"\n\n[images.release]',
    )
    path.write_text(content, encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="exceeds"):
        load_repository_config(path)


def test_candidate_lifetime_is_accepted_only_in_limits(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    nested = path.read_text(encoding="utf-8").replace(
        "[images.release]",
        '[images.limits]\ncandidate_lifetime = "24h"\n\n[images.release]',
    )
    path.write_text(nested, encoding="utf-8")
    assert load_repository_config(path).image("app").limits.candidate_lifetime == (
        timedelta(hours=24)
    )

    direct = (
        path.read_text(encoding="utf-8")
        .replace(
            '[images.limits]\ncandidate_lifetime = "24h"\n\n[images.release]',
            "[images.release]",
        )
        .replace(
            "arm64_omission_reason =",
            'candidate_lifetime = "24h"\narm64_omission_reason =',
        )
    )
    path.write_text(direct, encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="Additional properties"):
        load_repository_config(path)


def test_vulnerability_exception_is_bound_to_its_declaring_image(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            """[[images.vulnerability_exceptions]]
component = "openssl"
advisory = "CVE-2026-0001"
rationale = "The fixed base image is not released yet."
reachability = "The affected cipher suite is disabled."
exposure = "Internal network only."
compensating_controls = "TLS 1.3 only."
owner = "security@example.com"
expires = "2026-12-31"
review_trigger = "Base image update"

[images.release]""",
        ),
        encoding="utf-8",
    )

    exceptions = load_repository_config(path).image("app").vulnerability_exceptions
    assert [item.image for item in exceptions] == ["app"]


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


@pytest.mark.parametrize(
    "source",
    (
        "git@github.com:example/app.git",
        "ssh://git@github.com/example/app.git",
    ),
)
def test_repository_configuration_rejects_ssh_source_identity(source: str) -> None:
    with pytest.raises(InvalidInvocationError, match="credential-free HTTPS"):
        normalize_source_url(source)


@pytest.mark.parametrize(
    "remote",
    (
        "https://GitHub.com/example/app.git/",
        "git@GitHub.com:example/app.git",
        "ssh://git@GitHub.com/example/app.git",
        "git@gitlab.example.com:group/subgroup/app.git",
    ),
)
def test_observed_source_normalizes_supported_git_transports(remote: str) -> None:
    expected = (
        "https://gitlab.example.com/group/subgroup/app"
        if "gitlab" in remote
        else "https://github.com/example/app"
    )

    assert normalize_observed_source_url(remote) == expected


@pytest.mark.parametrize(
    "remote",
    (
        "ssh://alice@github.com/example/app.git",
        "ssh://git:secret@github.com/example/app.git",
        "ssh://git@github.com:22/example/app.git",
        "git@github.com:/srv/git/example/app.git",
        "git@github.com:example/../app.git",
        "git@github.com:app.git",
        "git://github.com/example/app.git",
        "file:///home/example/app",
        "/home/example/app",
    ),
)
def test_observed_source_rejects_ambiguous_git_remotes(remote: str) -> None:
    with pytest.raises(InvalidInvocationError):
        normalize_observed_source_url(remote)


def test_repository_configuration_rejects_unsafe_container_mount(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8").replace(
        "user = 10001",
        'user = 10001\nwritable_mounts = ["/tmp/../etc"]',
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


def _image_text(
    image_id: str,
    *,
    writable_mount: str | None = None,
    dependencies: tuple[str, ...] = (),
) -> str:
    dependency_table = ""
    if dependencies:
        rendered = ", ".join(f'"{item}"' for item in dependencies)
        dependency_table = f"\n[images.test]\ndependencies = [{rendered}]\n"
    writable = (
        "" if writable_mount is None else f'writable_mounts = ["{writable_mount}"]\n'
    )
    return f'''

[[images]]
id = "{image_id}"
repository = "quay.io/example/{image_id}"
platforms = ["linux/amd64"]
arm64_omission_reason = "Only amd64 is required for this test."

[images.release]
immutable_tags = ["{{version}}"]
moving_tags = ["stable"]

[images.runtime]
profile = "one-shot"
user = 10001
{writable}memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
{dependency_table}'''
