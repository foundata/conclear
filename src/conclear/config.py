"""Validated repository and maintainer release configuration."""

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

from conclear.errors import InvalidInvocationError
from conclear.jsonutil import sha256_bytes
from conclear.path_safety import contained_path
from conclear.schema import validate_external
from conclear.secrets import MAX_PROFILE_BYTES, read_protected_file
from conclear.values import OCIReference, Platform

MAX_PIN_FRESHNESS = timedelta(hours=24)
MAX_PIN_DIVERGENCE = timedelta(days=7)
MAX_CANDIDATE_LIFETIME = timedelta(days=7)
MAX_REMEDIATION = timedelta(days=30)
MAX_CONFIG_BYTES = 4 * 1024 * 1024
_DURATION_PATTERN = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>[hHdDwW])$")
_HOST_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_URL_PATH_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9._~-]+$")
_TEST_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_ENVIRONMENT_NAME_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_SECRET_ENVIRONMENT_PATTERN = re.compile(
    r"(?:^|_)(?:PASSWORD|PASSPHRASE|SECRET|TOKEN)(?:_|$)"
)


class PinIntent(StrEnum):
    """Declared behavior expected from a readable image tag."""

    IMMUTABLE_VERSION = "immutable-version"
    MOVING_RELEASE_LINE = "moving-release-line"


class CIContextPolicy(StrEnum):
    """Protected policy for optional CI correlation observations."""

    OMIT = "omit"
    OBSERVE = "observe"
    REQUIRE = "require"


class RegistryProvider(StrEnum):
    """Compiled release-registry control backends."""

    QUAY = "quay"


@dataclass(frozen=True, slots=True)
class EffectiveLimits:
    """Effective intervals after repository narrowing."""

    pin_freshness: timedelta = MAX_PIN_FRESHNESS
    pin_divergence: timedelta = MAX_PIN_DIVERGENCE
    candidate_lifetime: timedelta = MAX_CANDIDATE_LIFETIME
    remediation: timedelta = MAX_REMEDIATION


@dataclass(frozen=True, slots=True)
class ProjectConfig:
    """Observed project identity."""

    name: str
    source: str


@dataclass(frozen=True, slots=True)
class PinConfig:
    """One declared tagged and digest-pinned external image."""

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
    """One run-owned generated output handle."""

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
class TestConfig:
    """Typed runtime preparation and exact sibling-image dependencies."""

    dependencies: tuple[str, ...]
    fixtures: tuple[TestFixtureConfig, ...]
    outputs: tuple[TestOutputConfig, ...]
    preparations: tuple[TestPreparationConfig, ...]
    launch: TestLaunchConfig


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


@dataclass(frozen=True, slots=True)
class ReleaseTags:
    """Configured immutable and moving release tags."""

    immutable_tags: tuple[str, ...]
    moving_tags: tuple[str, ...]


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
class ImageConfig:
    """One image definition after schema and semantic validation."""

    image_id: str
    containerfile: Path
    context: Path
    repository: OCIReference
    platforms: tuple[Platform, ...]
    native_test_platforms: tuple[Platform, ...]
    arm64_omission_reason: str | None
    scanner: str
    rescan_scope: str
    release: ReleaseTags
    runtime: RuntimeConfig
    test: TestConfig
    hooks: tuple[HookConfig, ...]
    pins: tuple[PinConfig, ...]
    vulnerability_exceptions: tuple[VulnerabilityException, ...]
    limits: EffectiveLimits


@dataclass(frozen=True, slots=True)
class RepositoryConfig:
    """The complete validated repository-owned configuration."""

    schema_version: int
    project: ProjectConfig
    images: tuple[ImageConfig, ...]
    path: Path
    raw_bytes: bytes

    def image(self, image_id: str) -> ImageConfig:
        """Return one image by stable identifier."""
        matches = [image for image in self.images if image.image_id == image_id]
        if not matches:
            raise InvalidInvocationError(f"Unknown image id: {image_id}")
        return matches[0]

    def test_dependencies(self, image_id: str) -> tuple[ImageConfig, ...]:
        """Return transitive test dependencies in stable dependency-first order."""
        selected = self.image(image_id)
        images = {image.image_id: image for image in self.images}
        ordered: list[ImageConfig] = []
        visited: set[str] = set()

        def visit(current: ImageConfig) -> None:
            for dependency_id in current.test.dependencies:
                if dependency_id in visited:
                    continue
                dependency = images[dependency_id]
                visit(dependency)
                visited.add(dependency_id)
                ordered.append(dependency)

        visit(selected)
        return tuple(ordered)


@dataclass(frozen=True, slots=True)
class BuilderConfig:
    """Protected SLSA build-platform trust-domain identity."""

    id: str


@dataclass(frozen=True, slots=True)
class QuayRegistryConfig:
    """Protected Quay control-plane configuration."""

    provider: RegistryProvider
    host: str
    api_url: str
    token_file: Path | None


type RegistryConfig = QuayRegistryConfig


@dataclass(frozen=True, slots=True)
class ReleaseProfile:
    """Maintainer-controlled trust and credential locations."""

    name: str
    ci_context: CIContextPolicy
    builder: BuilderConfig
    auth_file: Path | None
    registry: RegistryConfig
    cosign_private_key: str | None
    cosign_public_key: Path
    passphrase_file: Path | None
    configuration_digest: str
    public_key_digest: str


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
    validate_external(value, "config.schema.json", label="conclear.toml")
    if not isinstance(value, dict):
        raise InvalidInvocationError("conclear.toml must contain a table")
    source_root = path.parent.resolve(strict=True)
    project_value = _object(value["project"])
    images_value = value["images"]
    if not isinstance(images_value, list):
        raise InvalidInvocationError("images must be an array of tables")
    images = tuple(_parse_image(_object(item), source_root) for item in images_value)
    identifiers = [image.image_id for image in images]
    if len(identifiers) != len(set(identifiers)):
        raise InvalidInvocationError("Image identifiers must be unique")
    _validate_test_graph(images)
    return RepositoryConfig(
        schema_version=_integer(value["schema_version"]),
        project=ProjectConfig(
            name=_string(project_value["name"]),
            source=normalize_source_url(_string(project_value["source"])),
        ),
        images=images,
        path=path.resolve(strict=True),
        raw_bytes=raw_bytes,
    )


def normalize_source_url(value: str) -> str:
    """Normalize an HTTPS Git source URL for observed comparisons."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise InvalidInvocationError("Project source URL is malformed") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or _HOST_PATTERN.fullmatch(hostname.lower()) is None
    ):
        raise InvalidInvocationError(
            "Project source must be a credential-free HTTPS URL"
        )
    components = parsed.path.removesuffix("/").removesuffix(".git").split("/")[1:]
    if len(components) < 2 or any(
        _URL_PATH_COMPONENT_PATTERN.fullmatch(item) is None or item in {".", ".."}
        for item in components
    ):
        raise InvalidInvocationError("Project source must name a repository")
    authority = hostname.lower() + ("" if port is None else f":{port}")
    return urlunsplit(("https", authority, "/" + "/".join(components), "", ""))


def load_release_profile(
    name: str, *, config_home: Path | None = None
) -> ReleaseProfile:
    """Load and validate a named maintainer-controlled release profile."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", name):
        raise InvalidInvocationError(f"Invalid release profile name: {name}")
    base = config_home or Path(
        os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
    )
    path = base / "conclear" / f"{name}.toml"
    try:
        profile_bytes = read_protected_file(path, maximum_bytes=MAX_PROFILE_BYTES)
        value: Any = tomllib.loads(profile_bytes.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise InvalidInvocationError(f"Unable to read release profile {path}") from exc
    validate_external(value, "profile.schema.json", label="release profile")
    profile = _object(value)
    auth_file = _optional_private_path(profile.get("auth_file"))
    builder = BuilderConfig(
        normalize_builder_id(_string(_object(profile["builder"])["id"]))
    )
    registry = _parse_registry_profile(_object(profile["registry"]))
    public_key = _private_path(profile["cosign_public_key"], allow_group_read=True)
    public_key_bytes = read_protected_file(
        public_key,
        maximum_bytes=MAX_PROFILE_BYTES,
        allow_group_read=True,
    )
    passphrase_file = _optional_private_path(profile.get("passphrase_file"))
    private_key_value = profile.get("cosign_private_key")
    private_key = (
        _signing_key(_string(private_key_value))
        if private_key_value is not None
        else None
    )
    return ReleaseProfile(
        name=name,
        ci_context=CIContextPolicy(_string(profile["ci_context"])),
        builder=builder,
        auth_file=auth_file,
        registry=registry,
        cosign_private_key=private_key,
        cosign_public_key=public_key,
        passphrase_file=passphrase_file,
        configuration_digest=sha256_bytes(profile_bytes),
        public_key_digest=sha256_bytes(public_key_bytes),
    )


def _parse_image(value: dict[str, Any], source_root: Path) -> ImageConfig:
    image_id = _string(value["id"])
    platforms = tuple(Platform.parse(item) for item in _string_list(value["platforms"]))
    if len(platforms) != len(set(platforms)):
        raise InvalidInvocationError("An image cannot declare duplicate platforms")
    amd64 = Platform.parse("linux/amd64")
    arm64 = Platform.parse("linux/arm64")
    if amd64 not in platforms:
        raise InvalidInvocationError("Every image must include linux/amd64")
    native_platforms = tuple(
        Platform.parse(item)
        for item in _string_list(value.get("native_test_platforms", ["linux/amd64"]))
    )
    if not set(native_platforms).issubset(platforms):
        raise InvalidInvocationError(
            "native_test_platforms must be a subset of platforms"
        )
    omission_reason_value = value.get("arm64_omission_reason")
    omission_reason = (
        _string(omission_reason_value) if omission_reason_value is not None else None
    )
    if arm64 not in platforms and omission_reason is None:
        raise InvalidInvocationError(
            "An image omitting linux/arm64 must provide arm64_omission_reason"
        )

    release_value = _object(value["release"])
    release = _parse_release_tags(release_value)
    runtime_value = _object(value["runtime"])
    limits_value = _object(value.get("limits", {}))
    limits = EffectiveLimits(
        pin_freshness=parse_duration(
            _string(limits_value.get("pin_freshness", "24h")),
            maximum=MAX_PIN_FRESHNESS,
            field_name="pin_freshness",
        ),
        pin_divergence=parse_duration(
            _string(limits_value.get("pin_divergence", "7d")),
            maximum=MAX_PIN_DIVERGENCE,
            field_name="pin_divergence",
        ),
        candidate_lifetime=parse_duration(
            _string(limits_value.get("candidate_lifetime", "7d")),
            maximum=MAX_CANDIDATE_LIFETIME,
            field_name="candidate_lifetime",
        ),
        remediation=parse_duration(
            _string(limits_value.get("remediation", "30d")),
            maximum=MAX_REMEDIATION,
            field_name="remediation",
        ),
    )
    repository = OCIReference.parse(
        _string(value["repository"]),
        allow_localhost=False,
    )
    if repository.tag or repository.digest:
        raise InvalidInvocationError("Release repositories must be untagged names")
    exceptions = tuple(
        _parse_exception(_object(item), image_id)
        for item in _list(value.get("vulnerability_exceptions", []))
    )
    exception_keys = [(item.component, item.advisory) for item in exceptions]
    if len(exception_keys) != len(set(exception_keys)):
        raise InvalidInvocationError(
            f"Vulnerability exceptions for {image_id} must be unique"
        )
    return ImageConfig(
        image_id=image_id,
        containerfile=contained_path(
            source_root, _string(value.get("containerfile", "Containerfile"))
        ),
        context=contained_path(source_root, _string(value.get("context", "."))),
        repository=repository,
        platforms=platforms,
        native_test_platforms=native_platforms,
        arm64_omission_reason=omission_reason,
        scanner=_string(value.get("scanner", "trivy")),
        rescan_scope=_string(value.get("rescan_scope", "sbom-vulnerabilities")),
        release=release,
        runtime=_parse_runtime(runtime_value),
        test=_parse_test(_object(value.get("test", {})), source_root),
        hooks=tuple(
            _parse_hook(_object(item)) for item in _list(value.get("hooks", []))
        ),
        pins=tuple(_parse_pin(_object(item)) for item in _list(value.get("pins", []))),
        vulnerability_exceptions=exceptions,
        limits=limits,
    )


def _parse_test(value: dict[str, Any], source_root: Path) -> TestConfig:
    fixtures = tuple(
        TestFixtureConfig(
            name=_test_name(_string(item_value["name"]), "fixture"),
            path=_test_fixture_path(source_root, _string(item_value["path"])),
        )
        for item in _list(value.get("fixtures", []))
        for item_value in (_object(item),)
    )
    outputs = tuple(
        TestOutputConfig(
            name=_test_name(_string(item_value["name"]), "output"),
            secret=_boolean(item_value.get("secret", False)),
        )
        for item in _list(value.get("outputs", []))
        for item_value in (_object(item),)
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
        _parse_test_preparation(_object(item), handles)
        for item in _list(value.get("preparations", []))
    )
    _require_unique_names(preparations, "test preparations")
    launch = _parse_test_launch(_object(value.get("launch", {})), handles)
    test = TestConfig(
        dependencies=tuple(_string_list(value.get("dependencies", []))),
        fixtures=fixtures,
        outputs=outputs,
        preparations=preparations,
        launch=launch,
    )
    _validate_mount_handles(test)
    return test


def _parse_test_preparation(
    value: dict[str, Any], handles: dict[str, TestMountSource]
) -> TestPreparationConfig:
    return TestPreparationConfig(
        name=_test_name(_string(value["name"]), "preparation"),
        image=_test_name(_string(value["image"]), "preparation image"),
        command=_command(value["command"], "preparation command"),
        environment=_test_environment(value.get("environment", {})),
        mounts=tuple(
            _parse_test_mount(_object(item), handles)
            for item in _list(value.get("mounts", []))
        ),
        timeout_seconds=_integer(value.get("timeout_seconds", 300)),
        expected_exit_status=_integer(value.get("expected_exit_status", 0)),
    )


def _parse_test_launch(
    value: dict[str, Any], handles: dict[str, TestMountSource]
) -> TestLaunchConfig:
    return TestLaunchConfig(
        arguments=_command(value.get("arguments", []), "launch arguments", empty=True),
        environment=_test_environment(value.get("environment", {})),
        mounts=tuple(
            _parse_test_mount(_object(item), handles)
            for item in _list(value.get("mounts", []))
        ),
        expected_exit_status=_integer(value.get("expected_exit_status", 0)),
    )


def _parse_test_mount(
    value: dict[str, Any], handles: dict[str, TestMountSource]
) -> TestMountConfig:
    name = _test_name(_string(value["name"]), "mount source")
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
    environment = _object(value)
    result: list[tuple[str, str]] = []
    for name, item in environment.items():
        if _ENVIRONMENT_NAME_PATTERN.fullmatch(name) is None:
            raise InvalidInvocationError(f"Invalid test environment name: {name}")
        if _SECRET_ENVIRONMENT_PATTERN.search(name):
            raise InvalidInvocationError(
                f"Test secrets must use declared private files, not environment {name}"
            )
        text = _string(item)
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
    missing_producers = outputs - available_outputs
    if missing_producers:
        raise InvalidInvocationError(
            "Test outputs have no preparation producer: "
            + ", ".join(sorted(missing_producers))
        )
    for mount in test.launch.mounts:
        if (
            mount.source is TestMountSource.OUTPUT
            and mount.name not in available_outputs
        ):
            raise InvalidInvocationError(
                f"Launch consumes output {mount.name} before it is produced"
            )


def _validate_test_graph(images: tuple[ImageConfig, ...]) -> None:
    by_id = {image.image_id: image for image in images}
    for image in images:
        dependencies = image.test.dependencies
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
            if not set(image.platforms).issubset(by_id[dependency_id].platforms):
                raise InvalidInvocationError(
                    f"Test dependency {dependency_id} does not cover all platforms of {image.image_id}"
                )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(image_id: str) -> None:
        if image_id in visiting:
            raise InvalidInvocationError("Test image dependencies contain a cycle")
        if image_id in visited:
            return
        visiting.add(image_id)
        for dependency_id in by_id[image_id].test.dependencies:
            visit(dependency_id)
        visiting.remove(image_id)
        visited.add(image_id)

    for image in images:
        visit(image.image_id)

    for image in images:
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
        for dependency_id in current.test.dependencies:
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
    return left.startswith(right + "/") or right.startswith(left + "/")


def _require_unique_names(values: tuple[object, ...], label: str) -> None:
    names = [getattr(item, "name", None) for item in values]
    if len(names) != len(set(names)):
        raise InvalidInvocationError(f"{label} must have unique names")


def _parse_release_tags(value: dict[str, Any]) -> ReleaseTags:
    immutable_tags = tuple(_string_list(value["immutable_tags"]))
    moving_tags = tuple(_string_list(value["moving_tags"]))
    reserved = tuple(
        tag for tag in (*immutable_tags, *moving_tags) if "-candidate." in tag
    )
    if reserved:
        raise InvalidInvocationError(
            "Release tags cannot use the ConClear-owned -candidate. namespace"
        )
    return ReleaseTags(
        immutable_tags=immutable_tags,
        moving_tags=moving_tags,
    )


def _parse_runtime(value: dict[str, Any]) -> RuntimeConfig:
    writable_mounts = _container_paths(
        value.get("writable_mounts", []), field_name="writable_mounts", allow_root=False
    )
    immutable_paths = _container_paths(
        value.get("immutable_paths", []), field_name="immutable_paths", allow_root=True
    )
    return RuntimeConfig(
        profile=_string(value["profile"]),
        user=_integer(value["user"]),
        read_only=True,
        writable_mounts=writable_mounts,
        memory=_string(value["memory"]),
        cpus=_number(value["cpus"]),
        pids=_integer(value["pids"]),
        nofile=_integer(value["nofile"]),
        health_command=_command(
            value.get("health_command", []), "health_command", empty=True
        ),
        immutable_paths=immutable_paths,
        capabilities=tuple(_string_list(value.get("capabilities", []))),
        startup_timeout_seconds=_integer(value.get("startup_timeout_seconds", 60)),
        shutdown_timeout_seconds=_integer(value.get("shutdown_timeout_seconds", 30)),
    )


def _parse_hook(value: dict[str, Any]) -> HookConfig:
    return HookConfig(
        name=_string(value["name"]),
        command=_command(value["command"], "hook command"),
        timeout_seconds=_integer(value.get("timeout_seconds", 300)),
        required=_boolean(value.get("required", True)),
    )


def _parse_pin(value: dict[str, Any]) -> PinConfig:
    return PinConfig(
        reference=OCIReference.parse(
            _string(value["reference"]),
            require_tag=True,
            require_digest=True,
            allow_localhost=False,
        ),
        tag_intent=PinIntent(_string(value["tag_intent"])),
    )


def _parse_exception(value: dict[str, Any], image_id: str) -> VulnerabilityException:
    expires = _string(value["expires"])
    try:
        date.fromisoformat(expires)
    except ValueError as exc:
        raise InvalidInvocationError(
            f"Vulnerability exception expiry is not an ISO date: {expires}"
        ) from exc
    return VulnerabilityException(
        image=image_id,
        component=_string(value["component"]),
        advisory=_string(value["advisory"]),
        rationale=_string(value["rationale"]),
        reachability=_string(value["reachability"]),
        exposure=_string(value["exposure"]),
        compensating_controls=_string(value["compensating_controls"]),
        owner=_string(value["owner"]),
        expires=expires,
        review_trigger=_string(value["review_trigger"]),
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


def _parse_registry_profile(value: dict[str, Any]) -> RegistryConfig:
    provider = RegistryProvider(_string(value["provider"]))
    if provider is RegistryProvider.QUAY:
        return QuayRegistryConfig(
            provider=provider,
            host=_string(value["host"]),
            api_url=_registry_api_url(
                _string(value.get("api_url", "https://quay.io/api/v1"))
            ),
            token_file=_optional_private_path(value.get("token_file")),
        )
    raise InvalidInvocationError(f"Unsupported registry provider: {provider.value}")


def normalize_builder_id(value: str) -> str:
    """Validate and normalize a public SLSA builder documentation URI."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise InvalidInvocationError("Builder identity URI is malformed") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or _HOST_PATTERN.fullmatch(hostname.lower()) is None
    ):
        raise InvalidInvocationError(
            "Builder identity must be a credential-free HTTPS URI without a query or fragment"
        )
    components = parsed.path.rstrip("/").split("/")[1:]
    if not components or any(
        _URL_PATH_COMPONENT_PATTERN.fullmatch(item) is None or item in {".", ".."}
        for item in components
    ):
        raise InvalidInvocationError(
            "Builder identity must name a public documentation path"
        )
    authority = hostname.lower() + ("" if port is None else f":{port}")
    return urlunsplit(("https", authority, parsed.path, "", ""))


def _registry_api_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise InvalidInvocationError("Registry API URL is malformed") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or _HOST_PATTERN.fullmatch(parsed.hostname.lower()) is None
    ):
        raise InvalidInvocationError(
            "Registry API URL must be credential-free HTTPS without a query or fragment"
        )
    authority = parsed.hostname.lower() + ("" if port is None else f":{port}")
    components = parsed.path.rstrip("/").split("/")[1:]
    if not components or any(
        _URL_PATH_COMPONENT_PATTERN.fullmatch(item) is None or item in {".", ".."}
        for item in components
    ):
        raise InvalidInvocationError("Registry API URL must contain a canonical path")
    path = "/" + "/".join(components)
    return urlunsplit(("https", authority, path, "", ""))


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


def _require_private_file(path: Path, *, allow_group_read: bool = False) -> None:
    try:
        file_stat = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise InvalidInvocationError(
            f"Credential or profile file is unavailable: {path}"
        ) from exc
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise InvalidInvocationError(
            f"Credential or profile path is not a regular file: {path}"
        )
    if file_stat.st_uid != os.getuid():
        raise InvalidInvocationError(
            f"Credential or profile file is not owned by this user: {path}"
        )
    allowed = 0o640 if allow_group_read else 0o600
    if stat.S_IMODE(file_stat.st_mode) & ~allowed:
        raise InvalidInvocationError(
            f"Credential or profile file permissions are unsafe: {path}"
        )


def _private_path(value: object, *, allow_group_read: bool = False) -> Path:
    path = Path(_string(value)).expanduser()
    _require_private_file(path, allow_group_read=allow_group_read)
    return path.resolve(strict=True)


def _optional_private_path(value: object) -> Path | None:
    return None if value is None else _private_path(value)


def _signing_key(value: str) -> str:
    """Validate a protected file path or credential-free KMS/HSM handle."""
    if value.startswith("pkcs11:") or "://" in value:
        lowered = value.lower()
        parsed = urlsplit(value)
        if (
            not value
            or any(character.isspace() or ord(character) < 0x20 for character in value)
            or any(
                marker in lowered
                for marker in (
                    "pin-value=",
                    "pin-source=",
                    "password=",
                    "passphrase=",
                    "secret=",
                    "token=",
                )
            )
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise InvalidInvocationError(
                "Cosign KMS or HSM handle must not contain credentials"
            )
        return value
    path = Path(value).expanduser()
    _require_private_file(path)
    return str(path.resolve(strict=True))


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise InvalidInvocationError("Expected a table with string keys")
    return value


def _list(value: object) -> list[Any]:
    if not isinstance(value, list):
        raise InvalidInvocationError("Expected an array")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise InvalidInvocationError("Expected a string")
    return value


def _string_list(value: object) -> list[str]:
    items = _list(value)
    if any(not isinstance(item, str) for item in items):
        raise InvalidInvocationError("Expected an array of strings")
    return items


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidInvocationError("Expected an integer")
    return value


def _number(value: object) -> float:
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise InvalidInvocationError("Expected a number")
    return float(value)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise InvalidInvocationError("Expected a boolean")
    return value
