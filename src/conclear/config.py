"""Validated repository-owned configuration from `conclear.toml`.

Everything here is untrusted repository input: it is schema-validated, then
narrowed into typed values with the bounds and path confinement the guide
requires. Maintainer-controlled release profiles live in the independent
`conclear.release_profile` module. Both readers use the shared primitives in
`conclear.parsing` and `conclear.values`.
"""

import os
import re
import stat
import tomllib
from dataclasses import dataclass
from datetime import date, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from conclear.config_decisions import unresolved_decisions
from conclear.containerfile import MAX_CONTAINERFILE_BYTES, parse_containerfile
from conclear.errors import InvalidInvocationError
from conclear.fileio import read_regular_file
from conclear.parsing import toml_integer, toml_string, toml_table
from conclear.path_safety import contained_path
from conclear.schema import validate_external
from conclear.values import (
    HOST_PATTERN,
    URL_PATH_COMPONENT_PATTERN,
    OCIReference,
    Platform,
    validate_release_version,
)

MAX_PIN_FRESHNESS = timedelta(hours=24)
MAX_PIN_DIVERGENCE = timedelta(days=7)
MAX_CANDIDATE_LIFETIME = timedelta(days=7)
MAX_REMEDIATION = timedelta(days=30)
MAX_CONFIG_BYTES = 4 * 1024 * 1024
_DURATION_PATTERN = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>[hHdDwW])$")
_SCP_GIT_REMOTE_PATTERN = re.compile(r"^git@(?P<host>[^/:@]+):(?P<path>[^?#]+)$")
_TEST_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_ENVIRONMENT_NAME_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_SECRET_ENVIRONMENT_PATTERN = re.compile(
    r"(?:^|_)(?:PASSWORD|PASSPHRASE|SECRET|TOKEN)(?:_|$)"
)
SYSTEMD_WRITABLE_MOUNTS = ("/run", "/run/lock", "/tmp", "/var/log/journal")
SYSTEMD_STOP_SIGNAL = "SIGRTMIN+3"


class PinIntent(StrEnum):
    """Declared behavior expected from a readable image tag."""

    IMMUTABLE_VERSION = "immutable-version"
    MOVING_RELEASE_LINE = "moving-release-line"


@dataclass(frozen=True, slots=True)
class PinLimits:
    """Effective pin intervals after repository narrowing; every image has them."""

    pin_freshness: timedelta = MAX_PIN_FRESHNESS
    pin_divergence: timedelta = MAX_PIN_DIVERGENCE


@dataclass(frozen=True, slots=True)
class ReleaseLimits:
    """Effective candidate and remediation intervals of a releasable image."""

    candidate_lifetime: timedelta = MAX_CANDIDATE_LIFETIME
    remediation: timedelta = MAX_REMEDIATION


@dataclass(frozen=True, slots=True)
class ProjectConfig:
    """Observed project identity."""

    name: str
    source: str


@dataclass(frozen=True, slots=True)
class PinConfig:
    """One effective digest-pinned input bound to its declared tag intent."""

    reference: OCIReference
    tag_intent: PinIntent


@dataclass(frozen=True, slots=True)
class HookConfig:
    """One argument-array repository test hook."""

    name: str
    command: tuple[str, ...]
    timeout_seconds: int
    required: bool


class TestMountSource(StrEnum):
    """Declared source classes for container test mounts."""

    FIXTURE = "fixture"
    OUTPUT = "output"


@dataclass(frozen=True, slots=True)
class TestFixtureConfig:
    """One immutable repository fixture exposed by a stable handle."""

    name: str
    path: Path


@dataclass(frozen=True, slots=True)
class TestOutputConfig:
    """One run-owned output directory, created empty and written during the test."""

    name: str
    secret: bool


@dataclass(frozen=True, slots=True)
class TestMountConfig:
    """One typed container mount from a declared test input."""

    source: TestMountSource
    name: str
    target: str
    read_only: bool


@dataclass(frozen=True, slots=True)
class TestPreparationConfig:
    """One bounded preparation command run inside an exact test image."""

    name: str
    image: str
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    mounts: tuple[TestMountConfig, ...]
    timeout_seconds: int
    expected_exit_status: int


@dataclass(frozen=True, slots=True)
class TestLaunchConfig:
    """Additional inputs supplied to the image's original entrypoint."""

    arguments: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    mounts: tuple[TestMountConfig, ...]
    expected_exit_status: int


@dataclass(frozen=True, slots=True)
class SudoTestConfig:
    """A noninteractive sudo operation and a second, unauthorized caller."""

    user: int
    denied_user: int
    command: tuple[str, ...]
    expected_stdout: str
    target_user: int = 0
    timeout_seconds: int = 30


@dataclass(frozen=True, slots=True)
class TestConfig:
    """Typed test inputs of a qualified image: fixtures, outputs, steps and launch."""

    fixtures: tuple[TestFixtureConfig, ...]
    outputs: tuple[TestOutputConfig, ...]
    preparations: tuple[TestPreparationConfig, ...]
    launch: TestLaunchConfig
    sudo: SudoTestConfig | None = None


@dataclass(frozen=True, slots=True)
class RuntimeRequirement:
    """Owned, reviewed justification for one runtime permission."""

    rationale: str
    owner: str
    review_trigger: str

    def to_dict(self) -> dict[str, object]:
        """Return the reviewed permission's public evidence fields."""
        return {
            "rationale": self.rationale,
            "owner": self.owner,
            "reviewTrigger": self.review_trigger,
        }


@dataclass(frozen=True, slots=True)
class SudoRequirement:
    """Sudo's purpose and scope, independent of the startup user."""

    review: RuntimeRequirement
    mode: str
    scope: str
    setid_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SetIDRequirement:
    """A reviewed set-ID executable other than the declared sudo executable."""

    path: str
    review: RuntimeRequirement


@dataclass(frozen=True, slots=True)
class SystemdConfig:
    """Systemd-specific lifecycle expectations.

    The stop signal is not declared: systemd shuts down on `SIGRTMIN+3` and
    ConClear always sends `SYSTEMD_STOP_SIGNAL` to a systemd container.
    """

    required_units: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """Runtime contract and hardening constraints."""

    profile: str
    user: int
    read_only: bool
    writable_mounts: tuple[str, ...]
    memory: str
    cpus: float
    pids: int
    nofile: int
    health_command: tuple[str, ...]
    immutable_paths: tuple[str, ...]
    capabilities: tuple[str, ...]
    startup_timeout_seconds: int
    shutdown_timeout_seconds: int
    root_requirement: RuntimeRequirement | None = None
    systemd: SystemdConfig | None = None
    sudo_requirement: SudoRequirement | None = None
    writable_root_requirement: RuntimeRequirement | None = None
    setid_requirements: tuple[SetIDRequirement, ...] = ()

    @property
    def no_new_privileges(self) -> bool:
        """Permit exec-time escalation only for the reviewed functional mode."""
        return (
            self.sudo_requirement is None or self.sudo_requirement.mode != "escalation"
        )

    @property
    def setid_paths(self) -> tuple[str, ...]:
        """Return the exact declared set-ID paths, including sudo when required."""
        sudo_paths = (
            () if self.sudo_requirement is None else self.sudo_requirement.setid_paths
        )
        return tuple(
            sorted((*sudo_paths, *(item.path for item in self.setid_requirements)))
        )

    @property
    def requires_restrictive_test(self) -> bool:
        """Return whether functional controls differ from the restrictive defaults."""
        return (
            not self.read_only or bool(self.capabilities) or not self.no_new_privileges
        )


@dataclass(frozen=True, slots=True)
class ReleaseTags:
    """Version tags that must retain their digest, and explicitly moving tags."""

    version_tags: tuple[str, ...]
    moving_tags: tuple[str, ...]

    def render_versions(self, version: str | None) -> tuple[str, ...]:
        """Render final tags and reject overlap with mutable release references."""
        if version is not None:
            validate_release_version(version)
        tags: list[str] = []
        for template in self.version_tags:
            if "{version}" in template and version is None:
                raise InvalidInvocationError(
                    "Version-dependent release tag requires --version"
                )
            tag = template.replace("{version}", version or "")
            OCIReference("registry.invalid", "validation").with_tag(tag)
            if tag in self.moving_tags or "-candidate." in tag:
                raise InvalidInvocationError(
                    "Version and moving or candidate tags must be disjoint"
                )
            if tag in tags:
                raise InvalidInvocationError(f"Rendered version tags collide: {tag}")
            tags.append(tag)
        return tuple(tags)


@dataclass(frozen=True, slots=True)
class VulnerabilityException:
    """One structurally complete vulnerability exception."""

    image: str
    component: str
    advisory: str
    rationale: str
    reachability: str
    exposure: str
    compensating_controls: str
    owner: str
    expires: str
    review_trigger: str


@dataclass(frozen=True, slots=True)
class PackageAssessmentException:
    """A reviewed, expiring acceptance of packages no scanner can assess.

    It exists for images whose operating system the authoritative scanner
    inventories but cannot match against vulnerability data. The evidence then
    states that the packages were not assessed instead of implying a clean scan.
    """

    rationale: str
    owner: str
    review_trigger: str
    expires: str

    def to_dict(self) -> dict[str, object]:
        """Return the evidence representation."""
        return {
            "rationale": self.rationale,
            "owner": self.owner,
            "reviewTrigger": self.review_trigger,
            "expires": self.expires,
        }


@dataclass(frozen=True, slots=True)
class ImageConfig:
    """The common build-image model after schema and semantic validation.

    It holds only what building an image and using it as an exact test
    dependency needs: the identity, build paths, platforms, runtime contract,
    pins, pin limits and the ids of its own test dependencies. An image
    without a repository is test-only and is represented by exactly this type,
    so release-only state cannot exist on it. Only a `ReleaseImageConfig` can
    be selected for a build, qualification, release or rescan.
    """

    image_id: str
    containerfile: Path
    context: Path
    platforms: tuple[Platform, ...]
    runtime: RuntimeConfig
    pins: tuple[PinConfig, ...]
    pin_limits: PinLimits
    test_dependencies: tuple[str, ...]

    @property
    def releasable(self) -> bool:
        """Return whether the image names a release destination."""
        return isinstance(self, ReleaseImageConfig)


@dataclass(frozen=True, slots=True)
class ReleaseImageConfig(ImageConfig):
    """A releasable image: the common model plus qualification and release state.

    This is the only kind of image ConClear scans, qualifies, assembles,
    publishes and rescans, so its destination, tags, native-test requirements,
    rescan policy, complete test inputs, hooks, vulnerability
    exceptions and release limits exist only here. It remains an
    `ImageConfig`, so a released image can also serve as a test dependency.
    """

    repository: OCIReference
    release: ReleaseTags
    native_test_platforms: tuple[Platform, ...]
    rescan_scope: str
    test: TestConfig
    hooks: tuple[HookConfig, ...]
    vulnerability_exceptions: tuple[VulnerabilityException, ...]
    release_limits: ReleaseLimits
    package_assessment_exception: PackageAssessmentException | None = None


@dataclass(frozen=True, slots=True)
class RepositoryConfig:
    """The complete validated repository-owned configuration."""

    schema_version: int
    project: ProjectConfig
    images: tuple[ImageConfig, ...]
    path: Path
    raw_bytes: bytes

    def image(self, image_id: str | None) -> ImageConfig:
        """Select explicitly, or infer the sole releasable image."""
        if image_id is None:
            releases = self.release_images
            if len(releases) == 1:
                return releases[0]
            choices = ", ".join(image.image_id for image in releases) or "none"
            raise InvalidInvocationError(
                "--image is required unless exactly one release image is configured; "
                f"release images: {choices}"
            )
        matches = [image for image in self.images if image.image_id == image_id]
        if not matches:
            raise InvalidInvocationError(f"Unknown image id: {image_id}")
        return matches[0]

    def release_image(self, image_id: str | None) -> ReleaseImageConfig:
        """Return one releasable image; a test-only image cannot be selected."""
        image = self.image(image_id)
        if not isinstance(image, ReleaseImageConfig):
            raise InvalidInvocationError(
                f"Image {image_id} is test-only and cannot be selected: "
                "it declares no release repository"
            )
        return image

    @property
    def release_images(self) -> tuple[ReleaseImageConfig, ...]:
        """Return every image that names a release destination."""
        return tuple(
            image for image in self.images if isinstance(image, ReleaseImageConfig)
        )

    def test_dependencies(self, image_id: str) -> tuple[ImageConfig, ...]:
        """Return transitive test dependencies in stable dependency-first order."""
        return _dependency_order(
            self.image(image_id), {image.image_id: image for image in self.images}
        )


def parse_duration(value: str, *, maximum: timedelta, field_name: str) -> timedelta:
    """Parse a bounded whole-hour, day or week duration."""
    match = _DURATION_PATTERN.fullmatch(value)
    if match is None:
        raise InvalidInvocationError(
            f"{field_name} must be a positive duration such as 24h, 7d or 1w"
        )
    amount = int(match.group("amount"))
    unit = match.group("unit").lower()
    duration = {
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
        "w": timedelta(weeks=amount),
    }[unit]
    if duration > maximum:
        raise InvalidInvocationError(
            f"{field_name} exceeds the built-in maximum of {maximum}"
        )
    return duration


def load_repository_config(path: Path) -> RepositoryConfig:
    """Load, schema-validate and narrow a repository configuration."""
    try:
        raw_bytes = _read_repository_file(path)
        decoded = raw_bytes.decode("utf-8")
        value: Any = tomllib.loads(decoded)
    except (UnicodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise InvalidInvocationError(
            f"Unable to read repository configuration {path}"
        ) from exc
    if isinstance(value, dict):
        decisions = unresolved_decisions(value)
        if decisions:
            raise InvalidInvocationError(
                "Unresolved configuration decisions:\n"
                + "\n".join(f"  {item.field}: {item.reason}" for item in decisions)
            )
        _reject_release_keys_without_repository(value)
    validate_external(
        value,
        "config.schema.json",
        label="conclear.toml",
        all_errors=True,
        code="CC0001",
    )
    if not isinstance(value, dict):
        raise InvalidInvocationError("conclear.toml must contain a table")
    source_root = path.parent.resolve(strict=True)
    project_value = toml_table(value["project"])
    images_value = value["images"]
    if not isinstance(images_value, list):
        raise InvalidInvocationError("images must be an array of tables")
    images = tuple(_parse_image(toml_table(item), source_root) for item in images_value)
    identifiers = [image.image_id for image in images]
    if len(identifiers) != len(set(identifiers)):
        raise InvalidInvocationError("Image identifiers must be unique")
    _validate_test_graph(images)
    return RepositoryConfig(
        schema_version=toml_integer(value["schema_version"]),
        project=ProjectConfig(
            name=toml_string(project_value["name"]),
            source=validate_public_source_url(toml_string(project_value["source"])),
        ),
        images=images,
        path=path.resolve(strict=True),
        raw_bytes=raw_bytes,
    )


def validate_public_source_url(value: str) -> str:
    """Validate the declared public source URL and return it byte for byte.

    The public source URL is where users find the source code; it need not be a
    Git repository and is never compared with a Git origin, so nothing is
    normalized away. Fragments such as `#source` are part of the identity.
    """
    if not value or any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in value
    ):
        raise InvalidInvocationError(
            "Project source must not be empty or contain whitespace or control characters"
        )
    try:
        parsed = urlsplit(value)
        parsed.port  # noqa: B018 - validates the authority
    except ValueError as exc:
        raise InvalidInvocationError("Project source URL is malformed") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or HOST_PATTERN.fullmatch(hostname.lower()) is None
    ):
        raise InvalidInvocationError(
            "Project source must be a credential-free absolute HTTPS URL without a query"
        )
    return value


def normalize_git_repository_url(value: str) -> str:
    """Normalize an HTTPS Git repository URL to its canonical identity."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise InvalidInvocationError("Git repository URL is malformed") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or HOST_PATTERN.fullmatch(hostname.lower()) is None
    ):
        raise InvalidInvocationError(
            "Git repository URL must be a credential-free HTTPS URL"
        )
    components = parsed.path.removesuffix("/").removesuffix(".git").split("/")[1:]
    if len(components) < 2 or any(
        URL_PATH_COMPONENT_PATTERN.fullmatch(item) is None or item in {".", ".."}
        for item in components
    ):
        raise InvalidInvocationError("Git repository URL must name a repository")
    authority = hostname.lower() + ("" if port is None else f":{port}")
    return urlunsplit(("https", authority, "/" + "/".join(components), "", ""))


def normalize_observed_source_url(value: str) -> str:
    """Convert a supported observed Git remote to its HTTPS identity.

    The result is compared with the release profile's allowed origins and then
    discarded; it never enters labels, records, attestations or results.
    """
    scp_remote = _SCP_GIT_REMOTE_PATTERN.fullmatch(value)
    if scp_remote is not None:
        return _normalize_ssh_repository(
            scp_remote.group("host"), scp_remote.group("path")
        )

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise InvalidInvocationError("Observed Git remote is malformed") from exc
    if parsed.scheme == "https":
        return normalize_git_repository_url(value)
    if (
        parsed.scheme != "ssh"
        or parsed.hostname is None
        or parsed.username != "git"
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise InvalidInvocationError(
            "Observed Git remote must be canonical HTTPS or an equivalent Git SSH URL"
        )
    return _normalize_ssh_repository(parsed.hostname, parsed.path.removeprefix("/"))


def _normalize_ssh_repository(hostname: str, path: str) -> str:
    """Normalize one unambiguous Git SSH host and repository path."""
    if HOST_PATTERN.fullmatch(hostname.lower()) is None or path.startswith("/"):
        raise InvalidInvocationError("Observed Git SSH remote is malformed")
    components = path.removesuffix("/").removesuffix(".git").split("/")
    if len(components) < 2 or any(
        URL_PATH_COMPONENT_PATTERN.fullmatch(item) is None or item in {".", ".."}
        for item in components
    ):
        raise InvalidInvocationError("Observed Git SSH remote must name a repository")
    return urlunsplit(("https", hostname.lower(), "/" + "/".join(components), "", ""))


def _parse_image(value: dict[str, Any], source_root: Path) -> ImageConfig:
    image_id = toml_string(value["id"])
    platforms = tuple(Platform.parse(item) for item in _string_list(value["platforms"]))
    if any(
        left.semantically_matches(right)
        for index, left in enumerate(platforms)
        for right in platforms[index + 1 :]
    ):
        raise InvalidInvocationError("An image cannot declare duplicate platforms")
    amd64 = Platform.parse("linux/amd64")
    if not any(platform.semantically_matches(amd64) for platform in platforms):
        raise InvalidInvocationError("Every image must include linux/amd64")
    containerfile = contained_path(
        source_root, toml_string(value.get("containerfile", "Containerfile"))
    )
    context = contained_path(source_root, toml_string(value.get("context", ".")))
    runtime = _parse_runtime(toml_table(value["runtime"]))
    pins = _parse_pins(_list(value.get("pins", [])), containerfile)
    limits_value = toml_table(value.get("limits", {}))
    pin_limits = PinLimits(
        pin_freshness=parse_duration(
            toml_string(limits_value.get("pin_freshness", "24h")),
            maximum=MAX_PIN_FRESHNESS,
            field_name="pin_freshness",
        ),
        pin_divergence=parse_duration(
            toml_string(limits_value.get("pin_divergence", "7d")),
            maximum=MAX_PIN_DIVERGENCE,
            field_name="pin_divergence",
        ),
    )
    test_value = toml_table(value.get("test", {}))
    test = _parse_test(test_value, source_root)
    escalation = not runtime.no_new_privileges
    if escalation != (test.sudo is not None) and value.get("repository") is not None:
        raise InvalidInvocationError(
            "Sudo escalation requires test.sudo; other modes must not declare it"
        )
    test_dependencies = tuple(_string_list(test_value.get("dependencies", [])))
    repository_value = value.get("repository")
    if repository_value is None:
        return ImageConfig(
            image_id=image_id,
            containerfile=containerfile,
            context=context,
            platforms=platforms,
            runtime=runtime,
            pins=pins,
            pin_limits=pin_limits,
            test_dependencies=test_dependencies,
        )
    repository = OCIReference.parse(
        toml_string(repository_value),
        allow_localhost=False,
    )
    if repository.tag or repository.digest:
        raise InvalidInvocationError("Release repositories must be untagged names")
    native_platforms = tuple(
        Platform.parse(item)
        for item in _string_list(value.get("native_test_platforms", ["linux/amd64"]))
    )
    if not all(
        any(platform.semantically_matches(candidate) for candidate in platforms)
        for platform in native_platforms
    ):
        raise InvalidInvocationError(
            "native_test_platforms must be a subset of platforms"
        )
    exceptions = tuple(
        _parse_exception(toml_table(item), image_id)
        for item in _list(value.get("vulnerability_exceptions", []))
    )
    exception_keys = [(item.component, item.advisory) for item in exceptions]
    if len(exception_keys) != len(set(exception_keys)):
        raise InvalidInvocationError(
            f"Vulnerability exceptions for {image_id} must be unique"
        )
    assessment_value = value.get("package_assessment_exception")
    package_assessment_exception = (
        None
        if assessment_value is None
        else _parse_package_assessment_exception(toml_table(assessment_value))
    )
    return ReleaseImageConfig(
        image_id=image_id,
        containerfile=containerfile,
        context=context,
        platforms=platforms,
        runtime=runtime,
        pins=pins,
        pin_limits=pin_limits,
        test_dependencies=test_dependencies,
        repository=repository,
        release=_parse_release_tags(toml_table(value["release"])),
        native_test_platforms=native_platforms,
        rescan_scope=toml_string(value.get("rescan_scope", "sbom-vulnerabilities")),
        test=test,
        hooks=tuple(
            _parse_hook(toml_table(item)) for item in _list(value.get("hooks", []))
        ),
        vulnerability_exceptions=exceptions,
        package_assessment_exception=package_assessment_exception,
        release_limits=ReleaseLimits(
            candidate_lifetime=parse_duration(
                toml_string(limits_value.get("candidate_lifetime", "7d")),
                maximum=MAX_CANDIDATE_LIFETIME,
                field_name="candidate_lifetime",
            ),
            remediation=parse_duration(
                toml_string(limits_value.get("remediation", "30d")),
                maximum=MAX_REMEDIATION,
                field_name="remediation",
            ),
        ),
    )


_RELEASE_ONLY_KEYS = (
    "release",
    "native_test_platforms",
    "rescan_scope",
    "hooks",
    "vulnerability_exceptions",
    "package_assessment_exception",
)
_RELEASE_ONLY_TEST_KEYS = ("fixtures", "outputs", "preparations", "launch")
_RELEASE_ONLY_LIMIT_KEYS = ("candidate_lifetime", "remediation")


def _reject_release_keys_without_repository(value: dict[str, Any]) -> None:
    """Name the keys a test-only image cannot declare before the schema does.

    The schema enforces the same closed key set; this check runs first so the
    rejection explains that the keys need a release repository.
    """
    images = value.get("images")
    if not isinstance(images, list):
        return
    for item in images:
        if not isinstance(item, dict) or "repository" in item:
            continue
        offending = [key for key in _RELEASE_ONLY_KEYS if key in item]
        test = item.get("test")
        if isinstance(test, dict):
            offending.extend(
                f"test.{key}" for key in _RELEASE_ONLY_TEST_KEYS if key in test
            )
        limits = item.get("limits")
        if isinstance(limits, dict):
            offending.extend(
                f"limits.{key}" for key in _RELEASE_ONLY_LIMIT_KEYS if key in limits
            )
        if offending:
            image_id = item.get("id")
            raise InvalidInvocationError(
                f"Image {image_id if isinstance(image_id, str) else '?'} declares "
                "no repository and is test-only; it cannot declare "
                + ", ".join(offending)
            )


def _parse_test(value: dict[str, Any], source_root: Path) -> TestConfig:
    fixtures = tuple(
        TestFixtureConfig(
            name=_test_name(toml_string(item_value["name"]), "fixture"),
            path=_test_fixture_path(source_root, toml_string(item_value["path"])),
        )
        for item in _list(value.get("fixtures", []))
        for item_value in (toml_table(item),)
    )
    outputs = tuple(
        TestOutputConfig(
            name=_test_name(toml_string(item_value["name"]), "output"),
            secret=_boolean(item_value.get("secret", False)),
        )
        for item in _list(value.get("outputs", []))
        for item_value in (toml_table(item),)
    )
    _require_unique_names(fixtures, "test fixtures")
    _require_unique_names(outputs, "test outputs")
    if {item.name for item in fixtures} & {item.name for item in outputs}:
        raise InvalidInvocationError("Test fixture and output names must be distinct")
    handles = {
        **{item.name: TestMountSource.FIXTURE for item in fixtures},
        **{item.name: TestMountSource.OUTPUT for item in outputs},
    }
    preparations = tuple(
        _parse_test_preparation(toml_table(item), handles)
        for item in _list(value.get("preparations", []))
    )
    _require_unique_names(preparations, "test preparations")
    launch = _parse_test_launch(toml_table(value.get("launch", {})), handles)
    test = TestConfig(
        fixtures=fixtures,
        outputs=outputs,
        preparations=preparations,
        launch=launch,
        sudo=_parse_sudo_test(toml_table(value["sudo"])) if "sudo" in value else None,
    )
    _validate_mount_handles(test)
    return test


def _parse_sudo_test(value: dict[str, Any]) -> SudoTestConfig:
    user = toml_integer(value["user"])
    denied_user = toml_integer(value["denied_user"])
    target_user = toml_integer(value.get("target_user", 0))
    if len({user, denied_user, target_user}) != 3:
        raise InvalidInvocationError(
            "Sudo test callers and target must be distinct identities"
        )
    command = _command(value["command"], "sudo test command")
    if not command[0].startswith("/"):
        raise InvalidInvocationError(
            "Sudo test command must use an absolute executable path"
        )
    return SudoTestConfig(
        user=user,
        denied_user=denied_user,
        command=command,
        expected_stdout=toml_string(value["expected_stdout"]),
        target_user=target_user,
        timeout_seconds=toml_integer(value.get("timeout_seconds", 30)),
    )


def _parse_test_preparation(
    value: dict[str, Any], handles: dict[str, TestMountSource]
) -> TestPreparationConfig:
    return TestPreparationConfig(
        name=_test_name(toml_string(value["name"]), "preparation"),
        image=_test_name(toml_string(value["image"]), "preparation image"),
        command=_command(value["command"], "preparation command"),
        environment=_test_environment(value.get("environment", {})),
        mounts=tuple(
            _parse_test_mount(toml_table(item), handles)
            for item in _list(value.get("mounts", []))
        ),
        timeout_seconds=toml_integer(value.get("timeout_seconds", 300)),
        expected_exit_status=toml_integer(value.get("expected_exit_status", 0)),
    )


def _parse_test_launch(
    value: dict[str, Any], handles: dict[str, TestMountSource]
) -> TestLaunchConfig:
    return TestLaunchConfig(
        arguments=_command(value.get("arguments", []), "launch arguments", empty=True),
        environment=_test_environment(value.get("environment", {})),
        mounts=tuple(
            _parse_test_mount(toml_table(item), handles)
            for item in _list(value.get("mounts", []))
        ),
        expected_exit_status=toml_integer(value.get("expected_exit_status", 0)),
    )


def _parse_test_mount(
    value: dict[str, Any], handles: dict[str, TestMountSource]
) -> TestMountConfig:
    name = _test_name(toml_string(value["name"]), "mount source")
    source = handles.get(name)
    if source is None:
        raise InvalidInvocationError(
            f"Test mount refers to undeclared fixture or output {name}"
        )
    read_only = _boolean(value.get("read_only", True))
    if source is TestMountSource.FIXTURE and not read_only:
        raise InvalidInvocationError(
            f"Repository test fixture {name} cannot be mounted with read_only = false"
        )
    target = _container_paths(
        [value["target"]], field_name="test mount target", allow_root=False
    )[0]
    if (
        "," in target
        or target in {"/dev", "/proc", "/sys"}
        or target.startswith(("/dev/", "/proc/", "/sys/"))
    ):
        raise InvalidInvocationError(f"Unsafe test mount target: {target}")
    return TestMountConfig(
        source=source,
        name=name,
        target=target,
        read_only=read_only,
    )


def _test_environment(value: object) -> tuple[tuple[str, str], ...]:
    environment = toml_table(value)
    result: list[tuple[str, str]] = []
    for name, item in environment.items():
        if _ENVIRONMENT_NAME_PATTERN.fullmatch(name) is None:
            raise InvalidInvocationError(f"Invalid test environment name: {name}")
        if _SECRET_ENVIRONMENT_PATTERN.search(name):
            raise InvalidInvocationError(
                f"Test secrets must use declared private files, not environment {name}"
            )
        text = toml_string(item)
        if "\x00" in text:
            raise InvalidInvocationError(f"Test environment {name} contains NUL")
        result.append((name, text))
    return tuple(sorted(result))


def _validate_mount_handles(test: TestConfig) -> None:
    outputs = {item.name for item in test.outputs}
    for owner, mounts in (
        *((item.name, item.mounts) for item in test.preparations),
        ("launch", test.launch.mounts),
    ):
        targets = [item.target for item in mounts]
        if len(targets) != len(set(targets)):
            raise InvalidInvocationError(f"{owner} contains duplicate mount targets")
        if any(
            _container_paths_overlap(left, right)
            for index, left in enumerate(targets)
            for right in targets[index + 1 :]
        ):
            raise InvalidInvocationError(f"{owner} contains overlapping mount targets")
    available_outputs: set[str] = set()
    for preparation in test.preparations:
        for mount in preparation.mounts:
            if (
                mount.source is TestMountSource.OUTPUT
                and mount.read_only
                and mount.name not in available_outputs
            ):
                raise InvalidInvocationError(
                    f"Preparation {preparation.name} consumes output {mount.name} before it is produced"
                )
        available_outputs.update(
            mount.name
            for mount in preparation.mounts
            if mount.source is TestMountSource.OUTPUT and not mount.read_only
        )
    launch_written: set[str] = set()
    for mount in test.launch.mounts:
        if mount.source is not TestMountSource.OUTPUT:
            continue
        if mount.read_only and mount.name not in available_outputs:
            raise InvalidInvocationError(
                f"Launch consumes output {mount.name} before it is produced"
            )
        if not mount.read_only:
            launch_written.add(mount.name)
    unwritten = outputs - available_outputs - launch_written
    if unwritten:
        raise InvalidInvocationError(
            "Test outputs have no writable preparation or launch mount: "
            + ", ".join(sorted(unwritten))
        )


def _validate_test_graph(images: tuple[ImageConfig, ...]) -> None:
    by_id = {image.image_id: image for image in images}
    for image in images:
        dependencies = image.test_dependencies
        if len(dependencies) != len(set(dependencies)):
            raise InvalidInvocationError(
                f"Image {image.image_id} contains duplicate test dependencies"
            )
        unknown = sorted(set(dependencies) - by_id.keys())
        if unknown:
            raise InvalidInvocationError(
                f"Image {image.image_id} has unknown test dependencies: {', '.join(unknown)}"
            )
        if image.image_id in dependencies:
            raise InvalidInvocationError(
                f"Image {image.image_id} cannot depend on itself for tests"
            )
        for dependency_id in dependencies:
            if not all(
                any(
                    platform.semantically_matches(candidate)
                    for candidate in by_id[dependency_id].platforms
                )
                for platform in image.platforms
            ):
                raise InvalidInvocationError(
                    f"Test dependency {dependency_id} does not cover all platforms of {image.image_id}"
                )

    depended = {
        dependency_id for image in images for dependency_id in image.test_dependencies
    }
    for image in images:
        if not image.releasable and image.image_id not in depended:
            raise InvalidInvocationError(
                f"Image {image.image_id} declares no repository and no image "
                "depends on it for tests"
            )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(image_id: str) -> None:
        if image_id in visiting:
            raise InvalidInvocationError("Test image dependencies contain a cycle")
        if image_id in visited:
            return
        visiting.add(image_id)
        for dependency_id in by_id[image_id].test_dependencies:
            visit(dependency_id)
        visiting.remove(image_id)
        visited.add(image_id)

    for image in images:
        visit(image.image_id)

    for image in images:
        if not isinstance(image, ReleaseImageConfig):
            continue
        permitted = {item.image_id for item in _dependency_order(image, by_id)} | {
            image.image_id
        }
        for preparation in image.test.preparations:
            if preparation.image not in permitted:
                raise InvalidInvocationError(
                    f"Preparation {preparation.name} uses undeclared test image {preparation.image}"
                )
            selected = by_id[preparation.image]
            _validate_writable_mounts(preparation.name, preparation.mounts, selected)
        _validate_writable_mounts("launch", image.test.launch.mounts, image)


def _dependency_order(
    image: ImageConfig, by_id: dict[str, ImageConfig]
) -> tuple[ImageConfig, ...]:
    ordered: list[ImageConfig] = []
    visited: set[str] = set()

    def visit(current: ImageConfig) -> None:
        for dependency_id in current.test_dependencies:
            if dependency_id in visited:
                continue
            dependency = by_id[dependency_id]
            visit(dependency)
            visited.add(dependency_id)
            ordered.append(dependency)

    visit(image)
    return tuple(ordered)


def _validate_writable_mounts(
    owner: str, mounts: tuple[TestMountConfig, ...], image: ImageConfig
) -> None:
    writable = set(image.runtime.writable_mounts)
    for mount in mounts:
        if not mount.read_only and mount.target not in writable:
            raise InvalidInvocationError(
                f"{owner} writable mount {mount.target} is not declared by image {image.image_id}"
            )


def _test_name(value: str, label: str) -> str:
    if _TEST_NAME_PATTERN.fullmatch(value) is None:
        raise InvalidInvocationError(f"Invalid {label} name: {value}")
    return value


def _test_fixture_path(source_root: Path, value: str) -> Path:
    resolved = contained_path(source_root, value)
    current = source_root.resolve(strict=True)
    try:
        for component in Path(value).parts:
            current /= component
            if current.is_symlink():
                raise InvalidInvocationError(
                    f"Test fixture path contains a symbolic link: {value}",
                    code="CC0002",
                )
    except OSError as exc:
        raise InvalidInvocationError(
            f"Unable to inspect test fixture path: {value}", code="CC0002"
        ) from exc
    return resolved


def _container_paths_overlap(left: str, right: str) -> bool:
    return (
        left == right
        or left == "/"
        or right == "/"
        or left.startswith(right + "/")
        or right.startswith(left + "/")
    )


def _require_unique_names(values: tuple[object, ...], label: str) -> None:
    names = [getattr(item, "name", None) for item in values]
    if len(names) != len(set(names)):
        raise InvalidInvocationError(f"{label} must have unique names")


def _parse_release_tags(value: dict[str, Any]) -> ReleaseTags:
    version_tags = tuple(_string_list(value.get("version_tags", [])))
    moving_tags = tuple(_string_list(value.get("moving_tags", [])))
    if not version_tags and not moving_tags:
        raise InvalidInvocationError(
            "A release must declare at least one version or moving tag"
        )
    reserved = tuple(
        tag for tag in (*version_tags, *moving_tags) if "-candidate." in tag
    )
    if reserved:
        raise InvalidInvocationError(
            "Release tags cannot use the ConClear-owned -candidate. namespace"
        )
    literal_tags = tuple(tag for tag in version_tags if "{version}" not in tag)
    ReleaseTags(literal_tags, moving_tags).render_versions(None)
    return ReleaseTags(
        version_tags=version_tags,
        moving_tags=moving_tags,
    )


def _parse_runtime(value: dict[str, Any]) -> RuntimeConfig:
    profile = toml_string(value["profile"])
    writable_mounts = set(
        _container_paths(
            value.get("writable_mounts", []),
            field_name="writable_mounts",
            allow_root=False,
        )
    )
    if profile == "systemd":
        writable_mounts.update(SYSTEMD_WRITABLE_MOUNTS)
    immutable_paths = _container_paths(
        value.get("immutable_paths", []), field_name="immutable_paths", allow_root=True
    )
    if any(
        _container_paths_overlap(immutable, writable)
        for immutable in immutable_paths
        for writable in writable_mounts
    ):
        raise InvalidInvocationError(
            "Immutable runtime paths cannot overlap writable runtime mounts"
        )
    root_value = value.get("root_requirement")
    root_requirement = (
        None if root_value is None else _parse_requirement(toml_table(root_value))
    )
    sudo_value = value.get("sudo_requirement")
    sudo = (
        None if sudo_value is None else _parse_sudo_requirement(toml_table(sudo_value))
    )
    writable_value = value.get("writable_root_requirement")
    writable = (
        None
        if writable_value is None
        else _parse_requirement(toml_table(writable_value))
    )
    setid = tuple(
        SetIDRequirement(
            path=_container_paths(
                [item["path"]], field_name="set-ID executable", allow_root=False
            )[0],
            review=_parse_requirement(item),
        )
        for raw in _list(value.get("setid_requirements", []))
        for item in (toml_table(raw),)
    )
    paths = [
        *(item.path for item in setid),
        *(() if sudo is None else sudo.setid_paths),
    ]
    if len(paths) != len(set(paths)):
        raise InvalidInvocationError(
            "Set-ID executable requirements must name distinct paths"
        )
    systemd_value = value.get("systemd")
    systemd = (
        None
        if systemd_value is None
        else SystemdConfig(
            required_units=tuple(
                _string_list(toml_table(systemd_value)["required_units"])
            ),
        )
    )
    return RuntimeConfig(
        profile=profile,
        user=toml_integer(value["user"]),
        read_only=writable is None,
        writable_mounts=tuple(sorted(writable_mounts)),
        memory=toml_string(value["memory"]),
        cpus=_number(value["cpus"]),
        pids=toml_integer(value["pids"]),
        nofile=toml_integer(value["nofile"]),
        health_command=_command(
            value.get("health_command", []), "health_command", empty=True
        ),
        immutable_paths=immutable_paths,
        capabilities=tuple(_string_list(value.get("capabilities", []))),
        startup_timeout_seconds=toml_integer(value.get("startup_timeout_seconds", 60)),
        shutdown_timeout_seconds=toml_integer(
            value.get("shutdown_timeout_seconds", 30)
        ),
        root_requirement=root_requirement,
        systemd=systemd,
        sudo_requirement=sudo,
        writable_root_requirement=writable,
        setid_requirements=setid,
    )


def _parse_requirement(value: dict[str, Any]) -> RuntimeRequirement:
    fields = tuple(
        toml_string(value[name]).strip()
        for name in ("rationale", "owner", "review_trigger")
    )
    if not all(fields):
        raise InvalidInvocationError(
            "Runtime requirement rationale, owner and review trigger must not be blank"
        )
    return RuntimeRequirement(*fields)


def _parse_sudo_requirement(value: dict[str, Any]) -> SudoRequirement:
    scope = toml_string(value["scope"]).strip()
    if not scope:
        raise InvalidInvocationError("Sudo authorization scope must not be blank")
    paths = _container_paths(
        value.get("setid_paths", ["/usr/bin/sudo"]),
        field_name="sudo set-ID executables",
        allow_root=False,
    )
    if value["mode"] == "escalation" and not paths:
        raise InvalidInvocationError(
            "Sudo escalation requires a declared set-ID executable"
        )
    return SudoRequirement(
        review=_parse_requirement(value),
        mode=toml_string(value["mode"]),
        scope=scope,
        setid_paths=paths,
    )


def _parse_hook(value: dict[str, Any]) -> HookConfig:
    return HookConfig(
        name=toml_string(value["name"]),
        command=_command(value["command"], "hook command"),
        timeout_seconds=toml_integer(value.get("timeout_seconds", 300)),
        required=_boolean(value.get("required", True)),
    )


def _parse_pins(values: list[Any], containerfile: Path) -> tuple[PinConfig, ...]:
    """Bind explicit tag intent to the digest owned by the Containerfile."""
    if not values:
        return ()
    content = read_regular_file(
        containerfile, maximum_bytes=MAX_CONTAINERFILE_BYTES, label="Containerfile"
    )
    source = parse_containerfile(content, path=containerfile)
    references: dict[str, set[OCIReference]] = {}
    for item in source.external_inputs:
        reference = OCIReference.parse(
            item.reference, require_tag=True, require_digest=True, allow_localhost=False
        )
        tag = str(
            OCIReference(reference.registry, reference.repository, tag=reference.tag)
        )
        references.setdefault(tag, set()).add(reference)
    pins: list[PinConfig] = []
    declared: set[str] = set()
    for raw in values:
        value = toml_table(raw)
        tag = toml_string(value["reference"])
        OCIReference.parse(tag, require_tag=True, allow_localhost=False)
        if tag in declared:
            raise InvalidInvocationError(
                f"Duplicate pin intent declaration: {tag}", code="CC0203"
            )
        declared.add(tag)
        matches = references.get(tag, set())
        if len(matches) != 1:
            raise InvalidInvocationError(
                f"Pin {tag} must match exactly one digest in {containerfile.name}; "
                f"found {len(matches)}",
                code="CC0203",
            )
        pins.append(
            PinConfig(next(iter(matches)), PinIntent(toml_string(value["tag_intent"])))
        )
    return tuple(pins)


def _parse_exception(value: dict[str, Any], image_id: str) -> VulnerabilityException:
    expires = toml_string(value["expires"])
    try:
        date.fromisoformat(expires)
    except ValueError as exc:
        raise InvalidInvocationError(
            f"Vulnerability exception expiry is not an ISO date: {expires}"
        ) from exc
    return VulnerabilityException(
        image=image_id,
        component=toml_string(value["component"]),
        advisory=toml_string(value["advisory"]),
        rationale=toml_string(value["rationale"]),
        reachability=toml_string(value["reachability"]),
        exposure=toml_string(value["exposure"]),
        compensating_controls=toml_string(value["compensating_controls"]),
        owner=toml_string(value["owner"]),
        expires=expires,
        review_trigger=toml_string(value["review_trigger"]),
    )


def _parse_package_assessment_exception(
    value: dict[str, Any],
) -> PackageAssessmentException:
    expires = toml_string(value["expires"])
    try:
        date.fromisoformat(expires)
    except ValueError as exc:
        raise InvalidInvocationError(
            f"Package assessment exception expiry is not an ISO date: {expires}"
        ) from exc
    review = _parse_requirement(value)
    return PackageAssessmentException(
        rationale=review.rationale,
        owner=review.owner,
        review_trigger=review.review_trigger,
        expires=expires,
    )


def _container_paths(
    value: object, *, field_name: str, allow_root: bool
) -> tuple[str, ...]:
    paths = tuple(_string_list(value))
    for path in paths:
        components = path.split("/")
        if (
            not path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or (path == "/" and not allow_root)
            or (path != "/" and any(item in {"", ".", ".."} for item in components[1:]))
        ):
            raise InvalidInvocationError(
                f"{field_name} contains an unsafe container path: {path}"
            )
    if len(paths) != len(set(paths)):
        raise InvalidInvocationError(f"{field_name} contains duplicate paths")
    return tuple(sorted(paths))


def _command(value: object, field_name: str, *, empty: bool = False) -> tuple[str, ...]:
    command = tuple(_string_list(value))
    if not empty and not command:
        raise InvalidInvocationError(f"{field_name} cannot be empty")
    if any("\x00" in item for item in command):
        raise InvalidInvocationError(f"{field_name} contains NUL")
    return command


def _read_repository_file(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InvalidInvocationError(
            f"Unable to read repository configuration {path}"
        ) from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise InvalidInvocationError(
                f"Repository configuration is not a regular file: {path}"
            )
        content = bytearray()
        while len(content) <= MAX_CONFIG_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_CONFIG_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > MAX_CONFIG_BYTES:
            raise InvalidInvocationError(
                f"Repository configuration exceeds the size limit: {path}"
            )
        return bytes(content)
    except OSError as exc:
        raise InvalidInvocationError(
            f"Unable to read repository configuration {path}"
        ) from exc
    finally:
        os.close(descriptor)


def _list(value: object) -> list[Any]:
    if not isinstance(value, list):
        raise InvalidInvocationError("Expected an array")
    return value


def _string_list(value: object) -> list[str]:
    items = _list(value)
    if any(not isinstance(item, str) for item in items):
        raise InvalidInvocationError("Expected an array of strings")
    return items


def _number(value: object) -> float:
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise InvalidInvocationError("Expected a number")
    return float(value)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise InvalidInvocationError("Expected a boolean")
    return value
