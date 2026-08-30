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

from conclear.errors import InvalidInvocationError
from conclear.path_safety import contained_path
from conclear.schema import validate_external
from conclear.values import OCIReference, Platform

MAX_PIN_FRESHNESS = timedelta(hours=24)
MAX_PIN_DIVERGENCE = timedelta(days=7)
MAX_CANDIDATE_LIFETIME = timedelta(days=7)
MAX_REMEDIATION = timedelta(days=30)
_DURATION_PATTERN = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>[hHdDwW])$")


class PinIntent(StrEnum):
    """Declared behavior expected from a readable image tag."""

    IMMUTABLE_VERSION = "immutable-version"
    MOVING_RELEASE_LINE = "moving-release-line"


class ReleaseMode(StrEnum):
    """Observed release environment class."""

    LOCAL = "local"
    CI = "ci"


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
    release: ReleaseTags
    runtime: RuntimeConfig
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


@dataclass(frozen=True, slots=True)
class ReleaseProfile:
    """Maintainer-controlled trust and credential locations."""

    name: str
    mode: ReleaseMode
    auth_file: Path | None
    quay_token_file: Path | None
    cosign_private_key: str | None
    cosign_public_key: Path
    passphrase_file: Path | None
    quay_api_url: str


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
        raw_bytes = path.read_bytes()
        decoded = raw_bytes.decode("utf-8")
        value: Any = tomllib.loads(decoded)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
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
    if not value.startswith("https://") or "@" in value.split("/", maxsplit=3)[2]:
        raise InvalidInvocationError(
            "Project source must be a credential-free HTTPS URL"
        )
    normalized = value.removesuffix("/").removesuffix(".git")
    if len(normalized.split("/")) < 5:
        raise InvalidInvocationError("Project source must name a repository")
    return normalized


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
    _require_private_file(path)
    try:
        value: Any = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise InvalidInvocationError(f"Unable to read release profile {path}") from exc
    validate_external(value, "profile.schema.json", label="release profile")
    profile = _object(value)
    auth_file = _optional_private_path(profile.get("auth_file"))
    token_file = _optional_private_path(profile.get("quay_token_file"))
    public_key = _private_path(profile["cosign_public_key"], allow_group_read=True)
    passphrase_file = _optional_private_path(profile.get("passphrase_file"))
    private_key_value = profile.get("cosign_private_key")
    private_key = _string(private_key_value) if private_key_value is not None else None
    if private_key is not None and "://" not in private_key:
        _require_private_file(Path(private_key))
    return ReleaseProfile(
        name=name,
        mode=ReleaseMode(_string(profile["mode"])),
        auth_file=auth_file,
        quay_token_file=token_file,
        cosign_private_key=private_key,
        cosign_public_key=public_key,
        passphrase_file=passphrase_file,
        quay_api_url=_string(profile.get("quay_api_url", "https://quay.io/api/v1")),
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
        Platform.parse(item) for item in _string_list(value["native_test_platforms"])
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
    runtime_value = _object(value["runtime"])
    limits_value = _object(value.get("limits", {}))
    candidate_value = value.get(
        "candidate_lifetime",
        limits_value.get("candidate_lifetime", "7d"),
    )
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
            _string(candidate_value),
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
    if repository.registry != "quay.io" or repository.tag or repository.digest:
        raise InvalidInvocationError(
            "Release repositories must be untagged quay.io repository names"
        )
    exceptions = tuple(
        _parse_exception(_object(item))
        for item in _list(value.get("vulnerability_exceptions", []))
    )
    if any(item.image != image_id for item in exceptions):
        raise InvalidInvocationError(
            f"Vulnerability exceptions for {image_id} must name that image exactly"
        )
    exception_keys = [(item.component, item.advisory) for item in exceptions]
    if len(exception_keys) != len(set(exception_keys)):
        raise InvalidInvocationError(
            f"Vulnerability exceptions for {image_id} must be unique"
        )
    return ImageConfig(
        image_id=image_id,
        containerfile=contained_path(source_root, _string(value["containerfile"])),
        context=contained_path(source_root, _string(value["context"])),
        repository=repository,
        platforms=platforms,
        native_test_platforms=native_platforms,
        arm64_omission_reason=omission_reason,
        scanner=_string(value.get("scanner", "trivy")),
        release=ReleaseTags(
            immutable_tags=tuple(_string_list(release_value["immutable_tags"])),
            moving_tags=tuple(_string_list(release_value["moving_tags"])),
        ),
        runtime=_parse_runtime(runtime_value),
        hooks=tuple(
            _parse_hook(_object(item)) for item in _list(value.get("hooks", []))
        ),
        pins=tuple(_parse_pin(_object(item)) for item in _list(value.get("pins", []))),
        vulnerability_exceptions=exceptions,
        limits=limits,
    )


def _parse_runtime(value: dict[str, Any]) -> RuntimeConfig:
    return RuntimeConfig(
        profile=_string(value["profile"]),
        user=_integer(value["user"]),
        read_only=_boolean(value["read_only"]),
        writable_mounts=tuple(_string_list(value.get("writable_mounts", []))),
        memory=_string(value["memory"]),
        cpus=_number(value["cpus"]),
        pids=_integer(value["pids"]),
        nofile=_integer(value["nofile"]),
        health_command=tuple(_string_list(value.get("health_command", []))),
        immutable_paths=tuple(_string_list(value.get("immutable_paths", []))),
        capabilities=tuple(_string_list(value.get("capabilities", []))),
        startup_timeout_seconds=_integer(value.get("startup_timeout_seconds", 60)),
        shutdown_timeout_seconds=_integer(value.get("shutdown_timeout_seconds", 30)),
    )


def _parse_hook(value: dict[str, Any]) -> HookConfig:
    return HookConfig(
        name=_string(value["name"]),
        command=tuple(_string_list(value["command"])),
        timeout_seconds=_integer(value.get("timeout_seconds", 300)),
        required=_boolean(value.get("required", True)),
    )


def _parse_pin(value: dict[str, Any]) -> PinConfig:
    return PinConfig(
        reference=OCIReference.parse(
            _string(value["reference"]),
            require_tag=True,
            require_digest=True,
        ),
        tag_intent=PinIntent(_string(value["tag_intent"])),
    )


def _parse_exception(value: dict[str, Any]) -> VulnerabilityException:
    expires = _string(value["expires"])
    try:
        date.fromisoformat(expires)
    except ValueError as exc:
        raise InvalidInvocationError(
            f"Vulnerability exception expiry is not an ISO date: {expires}"
        ) from exc
    return VulnerabilityException(
        image=_string(value["image"]),
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
