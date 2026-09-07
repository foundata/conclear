import tomllib
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

import conclear.config as config_module
from conclear.config import (
    load_repository_config,
    normalize_observed_source_url,
    normalize_source_url,
)
from conclear.errors import InvalidInvocationError
from conclear.values import Platform


def test_repository_configuration_is_validated_and_narrowed(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    config = load_repository_config(root / "conclear.toml")
    image = config.release_image("app")
    assert config.project.source == "https://github.com/example/app"
    assert image.limits.candidate_lifetime == timedelta(days=7)
    assert str(image.platforms[0]) == "linux/amd64"
    assert image.containerfile == (root / "Containerfile").resolve()
    assert image.context == root.resolve()
    assert image.native_test_platforms == image.platforms
    assert image.runtime.read_only is True
    assert image.runtime.root_requirement is None
    assert image.runtime.systemd is None


def test_repository_configuration_accepts_reviewed_root_runtime(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace("user = 10001", "user = 0")
        .replace(
            'health_command = ["/app", "health"]',
            """health_command = ["/app", "health"]

[images.runtime.root_requirement]
rationale = "The application must manage system identities."
owner = "platform@example.com"
review_trigger = "Remove when upstream supports an unprivileged mode."
""",
        ),
        encoding="utf-8",
    )

    runtime = load_repository_config(path).release_image("app").runtime

    assert runtime.user == 0
    assert runtime.root_requirement is not None
    assert runtime.root_requirement.owner == "platform@example.com"


@pytest.mark.parametrize(
    "replacement",
    (
        """[images.runtime]
profile = "service"
user = 0
memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
health_command = ["/app", "health"]
""",
        """[images.runtime]
profile = "service"
user = 10001
memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
health_command = ["/app", "health"]

[images.runtime.root_requirement]
rationale = "No longer applicable."
owner = "platform@example.com"
review_trigger = "Review each release."
""",
        """[images.runtime]
profile = "systemd"
user = 0
memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
health_command = ["/app", "health"]

[images.runtime.root_requirement]
rationale = "Systemd is the image lifecycle manager."
owner = "platform@example.com"
review_trigger = "Review when the image lifecycle changes."
""",
        """[images.runtime]
profile = "systemd"
user = 10001
memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
health_command = ["/app", "health"]

[images.runtime.systemd]
required_units = ["multi-user.target"]
stop_signal = "RTMIN+3"
""",
    ),
)
def test_repository_configuration_rejects_incomplete_root_contract(
    repository_factory: Callable[..., Path], replacement: str
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    original = """[images.runtime]
profile = "service"
user = 10001
memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
health_command = ["/app", "health"]
"""
    path.write_text(
        path.read_text(encoding="utf-8").replace(original, replacement),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError):
        load_repository_config(path)


def test_repository_configuration_narrows_systemd_runtime(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace('profile = "service"\nuser = 10001', 'profile = "systemd"\nuser = 0')
        .replace(
            'health_command = ["/app", "health"]',
            """health_command = ["/app", "health"]

[images.runtime.root_requirement]
rationale = "Systemd is the image lifecycle manager."
owner = "platform@example.com"
review_trigger = "Review when the image lifecycle changes."

[images.runtime.systemd]
required_units = ["multi-user.target", "sshd.service"]
stop_signal = "RTMIN+3"
""",
        ),
        encoding="utf-8",
    )

    runtime = load_repository_config(path).release_image("app").runtime

    assert runtime.profile == "systemd"
    assert runtime.systemd is not None
    assert runtime.systemd.required_units == ("multi-user.target", "sshd.service")
    assert runtime.writable_mounts == (
        "/run",
        "/run/lock",
        "/tmp",
        "/var/log/journal",
    )


def test_repository_configuration_accepts_explicit_arm64_v8(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'platforms = ["linux/amd64"]',
            'platforms = ["linux/amd64", "linux/arm64/v8"]',
        ),
        encoding="utf-8",
    )

    image = load_repository_config(path).release_image("app")

    assert str(image.platforms[-1]) == "linux/arm64/v8"


def test_amd64_only_image_needs_no_arm64_omission_reason(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    content = (root / "conclear.toml").read_text(encoding="utf-8")
    assert "arm64" not in content

    image = load_repository_config(root / "conclear.toml").release_image("app")

    assert [str(item) for item in image.platforms] == ["linux/amd64"]


def test_arm64_omission_reason_is_an_unknown_key(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'platforms = ["linux/amd64"]',
            'platforms = ["linux/amd64"]\narm64_omission_reason = "No arm64 worker."',
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="Additional properties"):
        load_repository_config(path)


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
    image = config.release_image("app")

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
    assert load_repository_config(path).release_image(
        "app"
    ).limits.candidate_lifetime == (timedelta(hours=24))

    direct = (
        path.read_text(encoding="utf-8")
        .replace(
            '[images.limits]\ncandidate_lifetime = "24h"\n\n[images.release]',
            "[images.release]",
        )
        .replace(
            'platforms = ["linux/amd64"]',
            'platforms = ["linux/amd64"]\ncandidate_lifetime = "24h"',
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

    exceptions = (
        load_repository_config(path).release_image("app").vulnerability_exceptions
    )
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


@pytest.mark.parametrize("immutable_path", ("/var/lib/app/config", "/"))
def test_repository_configuration_rejects_immutable_writable_path_overlap(
    repository_factory: Callable[..., Path], immutable_path: str
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "user = 10001",
            'user = 10001\nwritable_mounts = ["/var/lib/app"]\n'
            f'immutable_paths = ["{immutable_path}"]',
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="cannot overlap"):
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
        load_repository_config(path).release_image("app").repository.repository_name
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


def _image_text(
    image_id: str,
    *,
    writable_mount: str | None = None,
    dependencies: tuple[str, ...] = (),
    releasable: bool = True,
    keys: str = "",
    tables: str = "",
) -> str:
    dependency_table = ""
    if dependencies:
        rendered = ", ".join(f'"{item}"' for item in dependencies)
        dependency_table = f"\n[images.test]\ndependencies = [{rendered}]\n"
    writable = (
        "" if writable_mount is None else f'writable_mounts = ["{writable_mount}"]\n'
    )
    destination = (
        f"""repository = "quay.io/example/{image_id}"
platforms = ["linux/amd64"]
{keys}
[images.release]
immutable_tags = ["{{version}}"]
moving_tags = ["stable"]
"""
        if releasable
        else f"""platforms = ["linux/amd64"]
{keys}"""
    )
    return f'''

[[images]]
id = "{image_id}"
{destination}
[images.runtime]
profile = "one-shot"
user = 10001
{writable}memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
{dependency_table}{tables}'''


def _depending_on(root: Path, *images: str, dependencies: str = '"helper"') -> Path:
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8").replace(
        "[images.release]",
        f"[images.test]\ndependencies = [{dependencies}]\n\n[images.release]",
    )
    path.write_text(content + "".join(images), encoding="utf-8")
    return path


def test_test_only_image_omits_the_release_destination_and_cannot_be_selected(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = _depending_on(root, _image_text("helper", releasable=False))

    config = load_repository_config(path)
    helper = config.image("helper")

    assert not helper.releasable
    assert not isinstance(helper, config_module.ReleaseImageConfig)
    assert helper.platforms == (Platform.parse("linux/amd64"),)
    assert helper.hooks == () and helper.vulnerability_exceptions == ()
    assert helper.test.preparations == () and helper.test.launch.arguments == ()
    assert [item.image_id for item in config.test_dependencies("app")] == ["helper"]
    assert [item.image_id for item in config.release_images] == ["app"]
    assert config.release_image("app").releasable
    with pytest.raises(InvalidInvocationError, match="helper is test-only"):
        config.release_image("helper")


def test_launch_may_write_a_declared_output_without_a_preparation(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace("user = 10001\n", 'user = 10001\nwritable_mounts = ["/state"]\n')
        .replace(
            "[images.release]",
            """[[images.test.outputs]]
name = "state"
secret = true

[images.test.launch]
mounts = [{ name = "state", target = "/state", read_only = false }]

[images.release]""",
        ),
        encoding="utf-8",
    )

    test = load_repository_config(path).release_image("app").test

    assert test.preparations == ()
    assert [(item.name, item.secret) for item in test.outputs] == [("state", True)]
    assert [(item.name, item.read_only) for item in test.launch.mounts] == [
        ("state", False)
    ]


def test_released_image_also_serves_as_a_test_dependency(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = _depending_on(root, _image_text("generator"), dependencies='"generator"')

    config = load_repository_config(path)
    generator = config.release_image("generator")

    assert generator.repository.repository_name == "quay.io/example/generator"
    assert generator.release.moving_tags == ("stable",)
    assert config.test_dependencies("app") == (generator,)
    assert [item.image_id for item in config.release_images] == ["app", "generator"]


def test_test_only_images_chain_in_dependency_first_order(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = _depending_on(
        root,
        _image_text("helper", releasable=False, dependencies=("tool",)),
        _image_text("tool", releasable=False),
    )

    config = load_repository_config(path)

    assert [item.image_id for item in config.test_dependencies("app")] == [
        "tool",
        "helper",
    ]
    assert [item.image_id for item in config.release_images] == ["app"]


def test_test_only_image_without_a_dependent_is_rejected(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8") + _image_text("helper", releasable=False),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInvocationError, match="no image depends on it"):
        load_repository_config(path)


@pytest.mark.parametrize(
    ("keys", "tables", "named"),
    [
        ("", '[images.release]\nimmutable_tags = ["1"]\nmoving_tags = []\n', "release"),
        ('native_test_platforms = ["linux/amd64"]\n', "", "native_test_platforms"),
        ('scanner = "trivy"\n', "", "scanner"),
        ('rescan_scope = "full-image"\n', "", "rescan_scope"),
        ("", '[[images.hooks]]\nname = "h"\ncommand = ["/bin/true"]\n', "hooks"),
        (
            "",
            '[images.limits]\ncandidate_lifetime = "24h"\n',
            "limits.candidate_lifetime",
        ),
        ("", '[images.test.launch]\narguments = ["x"]\n', "test.launch"),
        ("", '[[images.test.outputs]]\nname = "out"\n', "test.outputs"),
    ],
)
def test_test_only_image_rejects_keys_only_a_qualified_image_uses(
    repository_factory: Callable[..., Path], keys: str, tables: str, named: str
) -> None:
    root = repository_factory()
    path = _depending_on(
        root, _image_text("helper", releasable=False, keys=keys, tables=tables)
    )

    with pytest.raises(InvalidInvocationError, match=f"test-only.*{named}"):
        load_repository_config(path)


def test_release_destination_without_release_tags_is_rejected(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8")
    start = content.index("[images.release]")
    end = content.index("[images.runtime]")
    path.write_text(content[:start] + content[end:], encoding="utf-8")

    with pytest.raises(InvalidInvocationError, match="release"):
        load_repository_config(path)


@pytest.mark.parametrize("releasable", [True, False])
def test_dependency_platform_gap_applies_to_every_image_kind(
    repository_factory: Callable[..., Path], releasable: bool
) -> None:
    root = repository_factory()
    path = _depending_on(root, _image_text("helper", releasable=releasable))
    content = path.read_text(encoding="utf-8").replace(
        'platforms = ["linux/amd64"]',
        'platforms = ["linux/amd64", "linux/arm64"]',
        1,
    )
    path.write_text(content, encoding="utf-8")

    with pytest.raises(InvalidInvocationError, match="does not cover"):
        load_repository_config(path)


@pytest.mark.parametrize("releasable", [True, False])
def test_dependency_cycle_applies_to_every_image_kind(
    repository_factory: Callable[..., Path], releasable: bool
) -> None:
    root = repository_factory()
    path = _depending_on(
        root, _image_text("helper", releasable=releasable, dependencies=("app",))
    )

    with pytest.raises(InvalidInvocationError, match="cycle"):
        load_repository_config(path)
