"""Repository configuration and release profiles reject every semantic conflict."""

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from conclear.config import load_repository_config, normalize_observed_source_url
from conclear.errors import InvalidInvocationError
from conclear.release_profile import load_release_profile, normalize_builder_id
from tests.registry_policy_fixtures import REGISTRY_POLICY_TOML

DIGEST = "sha256:" + "a" * 64
SECOND_IMAGE = """

[[images]]
id = "generator"
repository = "quay.io/example/generator"
platforms = ["linux/amd64"]

[images.release]
version_tags = ["{version}"]
moving_tags = ["stable"]

[images.runtime]
profile = "one-shot"
user = 10001
writable_mounts = ["/output"]
memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
"""


def _write(root: Path, transform: Callable[[str], str]) -> Path:
    path = root / "conclear.toml"
    path.write_text(transform(path.read_text(encoding="utf-8")), encoding="utf-8")
    return path


def _before_release(addition: str) -> Callable[[str], str]:
    return lambda text: text.replace(
        "[images.release]", addition + "\n[images.release]", 1
    )


@pytest.mark.parametrize(
    ("transform", "message"),
    [
        (
            lambda text: text + SECOND_IMAGE.replace('id = "generator"', 'id = "app"'),
            "must be unique",
        ),
        (
            lambda text: text.replace(
                'platforms = ["linux/amd64"]',
                'platforms = ["linux/amd64", "linux/arm64", "linux/arm64/v8"]',
                1,
            ),
            "duplicate platforms",
        ),
        (
            lambda text: text.replace(
                'platforms = ["linux/amd64"]', 'platforms = ["linux/arm64"]', 1
            ),
            "must include linux/amd64",
        ),
        (
            lambda text: text.replace(
                'platforms = ["linux/amd64"]',
                'platforms = ["linux/amd64"]\nnative_test_platforms = ["linux/arm64"]',
                1,
            ),
            "subset of platforms",
        ),
        (
            lambda text: text.replace(
                'repository = "quay.io/example/app"',
                'repository = "quay.io/example/app:1"',
            ),
            "does not match",
        ),
        (
            _before_release(
                """[[images.vulnerability_exceptions]]
component = "openssl"
advisory = "CVE-2026-0001"
rationale = "r"
reachability = "r"
exposure = "e"
compensating_controls = "c"
owner = "o"
expires = "2026-12-31"
review_trigger = "t"

[[images.vulnerability_exceptions]]
component = "openssl"
advisory = "CVE-2026-0001"
rationale = "r"
reachability = "r"
exposure = "e"
compensating_controls = "c"
owner = "o"
expires = "2026-12-31"
review_trigger = "t"
"""
            ),
            "must be unique",
        ),
        (
            _before_release(
                """[[images.vulnerability_exceptions]]
component = "openssl"
advisory = "CVE-2026-0001"
rationale = "r"
reachability = "r"
exposure = "e"
compensating_controls = "c"
owner = "o"
expires = "2026-13-45"
review_trigger = "t"
"""
            ),
            "not an ISO date",
        ),
        (
            _before_release(
                """[images.test]
[[images.test.fixtures]]
name = "shared"
path = "Containerfile"
[[images.test.outputs]]
name = "shared"
"""
            ),
            "must be distinct",
        ),
        (
            _before_release(
                """[images.test]
[[images.test.outputs]]
name = "result"
[images.test.launch]
environment = { lower_case = "x" }
"""
            ),
            "Invalid",
        ),
        (
            _before_release(
                """[images.test]
[[images.test.outputs]]
name = "result"
[[images.test.preparations]]
name = "prepare"
image = "app"
command = ["/app", "prepare"]
mounts = [
  { name = "result", target = "/out", read_only = false },
  { name = "result", target = "/out", read_only = false },
]
"""
            ),
            "duplicate mount targets",
        ),
        (
            _before_release(
                """[images.test]
[[images.test.outputs]]
name = "result"
[[images.test.preparations]]
name = "consume"
image = "app"
command = ["/app", "consume"]
mounts = [{ name = "result", target = "/in" }]
[[images.test.preparations]]
name = "produce"
image = "app"
command = ["/app", "produce"]
mounts = [{ name = "result", target = "/out", read_only = false }]
"""
            ),
            "before it is produced",
        ),
        (
            _before_release(
                """[images.test]
[[images.test.outputs]]
name = "orphan"
"""
            ),
            "no writable preparation or launch mount",
        ),
        (
            _before_release(
                """[images.test]
[[images.test.outputs]]
name = "scratch"
[images.test.launch]
mounts = [{ name = "scratch", target = "/in" }]
"""
            ),
            "Launch consumes output scratch before it is produced",
        ),
        (
            _before_release(
                """[images.test]
[[images.test.preparations]]
name = "produce"
image = "app"
command = ["/app", "produce"]
[[images.test.preparations]]
name = "produce"
image = "app"
command = ["/app", "again"]
"""
            ),
            "unique names",
        ),
        (
            _before_release(
                """[images.test]
[[images.test.preparations]]
name = "Bad Name"
image = "app"
command = ["/app"]
"""
            ),
            "Invalid",
        ),
        (
            lambda text: text.replace(
                'health_command = ["/app", "health"]',
                'health_command = ["/app", "hea\\u0000lth"]',
            ),
            "contains NUL",
        ),
        (
            lambda text: text.replace(
                'health_command = ["/app", "health"]',
                'writable_mounts = ["/tmp", "/tmp"]\nhealth_command = ["/app", "health"]',
            ),
            "non-unique",
        ),
        (
            lambda text: text.replace(
                'version_tags = ["{version}"]',
                'version_tags = ["{version}", "{version}"]',
            ),
            "Invalid",
        ),
    ],
    ids=[
        "duplicate-image-id",
        "duplicate-semantic-platform",
        "missing-amd64",
        "native-not-subset",
        "tagged-repository",
        "duplicate-exception",
        "exception-expiry",
        "fixture-output-name-clash",
        "environment-name",
        "duplicate-mount-target",
        "consume-before-produce",
        "unwritten-output",
        "launch-reads-unwritten-output",
        "duplicate-preparation-name",
        "preparation-name",
        "nul-in-command",
        "duplicate-writable-mount",
        "duplicate-release-tag",
    ],
)
def test_semantic_configuration_conflicts_are_invalid_invocations(
    repository_factory: Callable[..., Path],
    transform: Callable[[str], str],
    message: str,
) -> None:
    path = _write(repository_factory(), transform)

    with pytest.raises(InvalidInvocationError, match=message):
        load_repository_config(path)


def test_observed_remote_and_builder_identity_parsing_reject_malformed_values() -> None:
    with pytest.raises(InvalidInvocationError, match="malformed"):
        normalize_observed_source_url("https://example.com:notaport/a/b")
    with pytest.raises(InvalidInvocationError, match="canonical HTTPS"):
        normalize_observed_source_url("ftp://example.com/a/b")
    with pytest.raises(InvalidInvocationError, match="malformed"):
        normalize_observed_source_url("git@example.com:/absolute/path")
    with pytest.raises(InvalidInvocationError, match="name a repository"):
        normalize_observed_source_url("git@example.com:single")
    assert (
        normalize_observed_source_url("ssh://git@example.com/org/repo.git")
        == "https://example.com/org/repo"
    )
    with pytest.raises(InvalidInvocationError, match="malformed"):
        normalize_builder_id("https://example.com:badport/builder/")
    with pytest.raises(InvalidInvocationError, match="documentation path"):
        normalize_builder_id("https://example.com/")


def test_release_profile_names_and_files_are_validated(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    (config_home / "conclear").mkdir(parents=True)

    with pytest.raises(InvalidInvocationError, match="Invalid release profile name"):
        load_release_profile("../escape", config_home=config_home)
    with pytest.raises(InvalidInvocationError, match="unavailable"):
        load_release_profile("missing", config_home=config_home)

    profile = config_home / "conclear" / "broken.toml"
    profile.write_text("ci_context = [", encoding="utf-8")
    profile.chmod(0o600)
    with pytest.raises(InvalidInvocationError, match="Unable to read release profile"):
        load_release_profile("broken", config_home=config_home)

    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public", encoding="utf-8")
    public_key.chmod(0o600)
    directory_key = tmp_path / "directory.pub"
    directory_key.mkdir()

    def write_profile(name: str, key: Path, extra: str = "") -> Path:
        path = config_home / "conclear" / f"{name}.toml"
        path.write_text(
            f'schema_version = 1\nci_context = "omit"\ncosign_public_key = "{key}"\n{extra}\n'
            '[builder]\nid = "https://foundata.com/en/projects/conclear/builder/simple-v1/"\n'
            '[registry]\nprovider = "quay"\nhost = "quay.io"\n' + REGISTRY_POLICY_TOML,
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    write_profile("directory", directory_key)
    with pytest.raises(InvalidInvocationError, match="not a regular file"):
        load_release_profile("directory", config_home=config_home)

    write_profile("absent", tmp_path / "absent.pub")
    with pytest.raises(InvalidInvocationError, match="unavailable"):
        load_release_profile("absent", config_home=config_home)

    if os.geteuid() != 0:
        loose = tmp_path / "loose.pub"
        loose.write_text("public", encoding="utf-8")
        loose.chmod(0o644)
        write_profile("loose", loose)
        with pytest.raises(InvalidInvocationError, match="permissions are unsafe"):
            load_release_profile("loose", config_home=config_home)

    api = config_home / "conclear" / "api.toml"
    api.write_text(
        f'schema_version = 1\nci_context = "omit"\ncosign_public_key = "{public_key}"\n'
        '[builder]\nid = "https://foundata.com/en/projects/conclear/builder/simple-v1/"\n'
        '[registry]\nprovider = "quay"\nhost = "quay.io"\napi_url = "https://quay.io"\n'
        + REGISTRY_POLICY_TOML,
        encoding="utf-8",
    )
    api.chmod(0o600)
    with pytest.raises(InvalidInvocationError, match="canonical path"):
        load_release_profile("api", config_home=config_home)
