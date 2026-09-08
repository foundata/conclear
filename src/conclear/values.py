"""Shared identifier syntax and validated OCI and release value objects."""

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import override

from conclear.errors import InvalidInvocationError

HOST_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
URL_PATH_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9._~-]+$")

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_PLATFORM_PATTERN = re.compile(
    r"^(?P<os>[a-z0-9]+(?:[._-][a-z0-9]+)*)/"
    r"(?P<architecture>[a-z0-9]+(?:[._-][a-z0-9]+)*)"
    r"(?:/(?P<variant>[a-z0-9]+(?:[._-][a-z0-9]+)*))?$"
)
_REGISTRY_PATTERN = re.compile(
    r"^(?:localhost|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)(?::[0-9]{1,5})?$"
)
_REPOSITORY_COMPONENT_PATTERN = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_TAG_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_ULID_PATTERN = re.compile(r"^[0-9a-hjkmnp-tv-z]{26}$")
_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
CANDIDATE_TAG_PATTERN = (
    r"^([A-Za-z0-9_][A-Za-z0-9_.-]{0,80}-candidate\."
    r"[0-9a-hjkmnp-tv-z]{26}\.g[0-9a-f]{8}|"
    r"g[0-9a-f]{8}-candidate\.[0-9a-hjkmnp-tv-z]{26})$"
)


@dataclass(frozen=True, slots=True, order=True)
class Digest:
    """A normalized SHA-256 content digest."""

    value: str

    def __post_init__(self) -> None:
        """Validate normalized digest syntax."""
        if _DIGEST_PATTERN.fullmatch(self.value) is None:
            raise InvalidInvocationError(
                "Digest must use lowercase sha256 followed by 64 hexadecimal characters"
            )

    @property
    def algorithm(self) -> str:
        """Return the digest algorithm."""
        return "sha256"

    @property
    def encoded(self) -> str:
        """Return the hexadecimal digest value without its algorithm."""
        return self.value.removeprefix("sha256:")

    @override
    def __str__(self) -> str:
        """Return normalized digest text."""
        return self.value


@total_ordering
@dataclass(frozen=True, slots=True)
class Platform:
    """A canonical OCI operating-system and architecture tuple."""

    os: str
    architecture: str
    variant: str | None = None

    def __lt__(self, other: "Platform") -> bool:
        """Order platforms by OS, architecture and then variant, absent first."""
        return self._sort_key < other._sort_key

    @property
    def _sort_key(self) -> tuple[str, str, str]:
        return (self.os, self.architecture, self.variant or "")

    def semantically_matches(self, other: "Platform") -> bool:
        """Return whether two OCI platform spellings select the same target."""
        return (
            self.os,
            self.architecture,
            self._effective_variant,
        ) == (
            other.os,
            other.architecture,
            other._effective_variant,
        )

    @property
    def _effective_variant(self) -> str | None:
        if self.architecture == "arm64" and self.variant is None:
            return "v8"
        return self.variant

    @classmethod
    def parse(cls, value: str) -> "Platform":
        """Parse a canonical slash-separated OCI platform."""
        match = _PLATFORM_PATTERN.fullmatch(value)
        if match is None:
            raise InvalidInvocationError(f"Invalid OCI platform: {value}")
        return cls(
            os=match.group("os"),
            architecture=match.group("architecture"),
            variant=match.group("variant"),
        )

    @property
    def key(self) -> str:
        """Return the filesystem-safe workspace key."""
        parts = [self.os, self.architecture]
        if self.variant is not None:
            parts.append(self.variant)
        return "-".join(parts)

    @override
    def __str__(self) -> str:
        """Return the canonical OCI platform string."""
        parts = [self.os, self.architecture]
        if self.variant is not None:
            parts.append(self.variant)
        return "/".join(parts)


@dataclass(frozen=True, slots=True)
class OCIReference:
    """A fully qualified OCI registry reference."""

    registry: str
    repository: str
    tag: str | None = None
    digest: Digest | None = None

    @classmethod
    def parse(
        cls,
        value: str,
        *,
        require_tag: bool = False,
        require_digest: bool = False,
        allow_localhost: bool = True,
    ) -> "OCIReference":
        """Parse and validate a fully qualified registry reference."""
        if "://" in value or any(character.isspace() for character in value):
            raise InvalidInvocationError(f"Invalid OCI reference: {value}")

        name_and_tag, separator, digest_text = value.partition("@")
        if separator and not digest_text:
            raise InvalidInvocationError(f"OCI reference has an empty digest: {value}")
        if "@" in digest_text:
            raise InvalidInvocationError(
                f"OCI reference has more than one digest: {value}"
            )

        slash_index = name_and_tag.rfind("/")
        colon_index = name_and_tag.rfind(":")
        tag: str | None = None
        name = name_and_tag
        if colon_index > slash_index:
            name = name_and_tag[:colon_index]
            tag = name_and_tag[colon_index + 1 :]

        registry, slash, repository = name.partition("/")
        if not slash or not repository or _REGISTRY_PATTERN.fullmatch(registry) is None:
            raise InvalidInvocationError(
                f"OCI reference must contain a fully qualified registry: {value}"
            )
        if registry == "localhost" or registry.startswith("localhost:"):
            if not allow_localhost:
                raise InvalidInvocationError(
                    "Localhost is not an allowed release registry"
                )
        components = repository.split("/")
        if any(
            _REPOSITORY_COMPONENT_PATTERN.fullmatch(component) is None
            for component in components
        ):
            raise InvalidInvocationError(f"Invalid OCI repository name: {value}")
        if tag is not None and _TAG_PATTERN.fullmatch(tag) is None:
            raise InvalidInvocationError(f"Invalid OCI tag: {tag}")

        digest = Digest(digest_text) if digest_text else None
        if require_tag and tag is None:
            raise InvalidInvocationError(
                f"OCI reference requires a readable tag: {value}"
            )
        if require_digest and digest is None:
            raise InvalidInvocationError(
                f"OCI reference requires a digest pin: {value}"
            )
        return cls(
            registry=registry,
            repository=repository,
            tag=tag,
            digest=digest,
        )

    @property
    def repository_name(self) -> str:
        """Return the registry and repository without a tag or digest."""
        return f"{self.registry}/{self.repository}"

    def with_tag(self, tag: str) -> "OCIReference":
        """Return the same repository with a validated tag and no digest."""
        if _TAG_PATTERN.fullmatch(tag) is None:
            raise InvalidInvocationError(f"Invalid OCI tag: {tag}")
        return OCIReference(self.registry, self.repository, tag=tag)

    def with_digest(self, digest: Digest) -> "OCIReference":
        """Return the same repository addressed only by digest."""
        return OCIReference(self.registry, self.repository, digest=digest)

    @override
    def __str__(self) -> str:
        """Return the fully qualified normalized reference."""
        value = self.repository_name
        if self.tag is not None:
            value += f":{self.tag}"
        if self.digest is not None:
            value += f"@{self.digest}"
        return value


def validate_run_id(value: str) -> str:
    """Return a validated lowercase ULID release-run identifier."""
    if _ULID_PATTERN.fullmatch(value) is None:
        raise InvalidInvocationError("Run identifier must be a lowercase ULID")
    return value


def validate_source_revision(value: str) -> str:
    """Return a validated full hexadecimal source revision."""
    if _REVISION_PATTERN.fullmatch(value) is None:
        raise InvalidInvocationError(
            "Source revision must be a full lowercase hexadecimal object ID"
        )
    return value


def validate_release_version(value: str) -> str:
    """Return a release version that is safe within owned OCI tag names."""
    if _TAG_PATTERN.fullmatch(value) is None or "candidate" in value:
        raise InvalidInvocationError(f"Invalid release version for a tag: {value}")
    return value


def candidate_tag(*, version: str | None, run_id: str, source_revision: str) -> str:
    """Generate the required single-use candidate tag."""
    validate_run_id(run_id)
    validate_source_revision(source_revision)
    short_revision = source_revision[:8]
    if version is None:
        value = f"g{short_revision}-candidate.{run_id}"
    else:
        validate_release_version(version)
        value = f"{version}-candidate.{run_id}.g{short_revision}"
    if _TAG_PATTERN.fullmatch(value) is None:
        raise InvalidInvocationError("Generated candidate tag is invalid or too long")
    return value
