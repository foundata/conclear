"""Maintainer-controlled release profiles and their trust inputs.

A release profile is read from the user's protected configuration directory,
never from the repository. It names the SLSA builder identity, the compiled
registry backend, the Cosign key material and the CI-context policy, and it
enforces ownership and permission checks on every credential path it resolves.
"""

import os
import re
import stat
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from conclear.config import (
    HOST_PATTERN,
    URL_PATH_COMPONENT_PATTERN,
    toml_integer,
    toml_string,
    toml_table,
)
from conclear.errors import InvalidInvocationError
from conclear.jsonutil import sha256_bytes
from conclear.schema import validate_external
from conclear.secrets import MAX_PROFILE_BYTES, read_protected_file


class CIContextPolicy(StrEnum):
    """Protected policy for optional CI correlation observations."""

    OMIT = "omit"
    OBSERVE = "observe"
    REQUIRE = "require"


class RegistryProvider(StrEnum):
    """Compiled release-registry control backends."""

    QUAY = "quay"


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
    schema_version: int = 1


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
    profile = toml_table(value)
    auth_file = _optional_private_path(profile.get("auth_file"))
    builder = BuilderConfig(
        normalize_builder_id(toml_string(toml_table(profile["builder"])["id"]))
    )
    registry = _parse_registry_profile(toml_table(profile["registry"]))
    public_key = _private_path(profile["cosign_public_key"], allow_group_read=True)
    public_key_bytes = read_protected_file(
        public_key,
        maximum_bytes=MAX_PROFILE_BYTES,
        allow_group_read=True,
    )
    passphrase_file = _optional_private_path(profile.get("passphrase_file"))
    private_key_value = profile.get("cosign_private_key")
    private_key = (
        _signing_key(toml_string(private_key_value))
        if private_key_value is not None
        else None
    )
    return ReleaseProfile(
        name=name,
        ci_context=CIContextPolicy(toml_string(profile["ci_context"])),
        builder=builder,
        auth_file=auth_file,
        registry=registry,
        cosign_private_key=private_key,
        cosign_public_key=public_key,
        passphrase_file=passphrase_file,
        configuration_digest=sha256_bytes(profile_bytes),
        public_key_digest=sha256_bytes(public_key_bytes),
        schema_version=toml_integer(profile["schema_version"]),
    )


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
        or HOST_PATTERN.fullmatch(hostname.lower()) is None
    ):
        raise InvalidInvocationError(
            "Builder identity must be a credential-free HTTPS URI without a query or fragment"
        )
    components = parsed.path.rstrip("/").split("/")[1:]
    if not components or any(
        URL_PATH_COMPONENT_PATTERN.fullmatch(item) is None or item in {".", ".."}
        for item in components
    ):
        raise InvalidInvocationError(
            "Builder identity must name a public documentation path"
        )
    authority = hostname.lower() + ("" if port is None else f":{port}")
    return urlunsplit(("https", authority, parsed.path, "", ""))


def _parse_registry_profile(value: dict[str, Any]) -> RegistryConfig:
    provider = RegistryProvider(toml_string(value["provider"]))
    if provider is RegistryProvider.QUAY:
        return QuayRegistryConfig(
            provider=provider,
            host=toml_string(value["host"]),
            api_url=_registry_api_url(
                toml_string(value.get("api_url", "https://quay.io/api/v1"))
            ),
            token_file=_optional_private_path(value.get("token_file")),
        )
    raise InvalidInvocationError(f"Unsupported registry provider: {provider.value}")


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
        or HOST_PATTERN.fullmatch(parsed.hostname.lower()) is None
    ):
        raise InvalidInvocationError(
            "Registry API URL must be credential-free HTTPS without a query or fragment"
        )
    authority = parsed.hostname.lower() + ("" if port is None else f":{port}")
    components = parsed.path.rstrip("/").split("/")[1:]
    if not components or any(
        URL_PATH_COMPONENT_PATTERN.fullmatch(item) is None or item in {".", ".."}
        for item in components
    ):
        raise InvalidInvocationError("Registry API URL must contain a canonical path")
    path = "/" + "/".join(components)
    return urlunsplit(("https", authority, path, "", ""))


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
    path = Path(toml_string(value)).expanduser()
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
