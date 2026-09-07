"""Supported external tool discovery, compatibility policy and identity checks.

Compatibility and identity are separate concerns. A `VersionPolicy` decides
which installed versions may start a run; the resolved tool records the exact
version and executable digest the run used, and that identity is rechecked
before later phases and compared across distributed workers.
"""

import os
import re
import shutil
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, override

from conclear.errors import OperationalError, RuleRejectionError
from conclear.jsonutil import sha256_file
from conclear.process import CommandRequest, ProcessResult, ProcessRunner
from conclear.records import ToolIdentity


class ToolName(StrEnum):
    """Core executable names in the supported toolchain."""

    GIT = "git"
    BUILDAH = "buildah"
    PODMAN = "podman"
    SKOPEO = "skopeo"
    HADOLINT = "hadolint"
    TRIVY = "trivy"
    COSIGN = "cosign"


_VERSION_TEXT = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


@dataclass(frozen=True, slots=True, order=True)
class ToolVersion:
    """One canonical `MAJOR.MINOR.PATCH` tool version, ordered numerically."""

    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, text: str) -> "ToolVersion":
        """Parse a canonical version; leading zeros, suffixes and extra parts fail."""
        match = _VERSION_TEXT.fullmatch(text)
        if match is None:
            raise ValueError(f"not a canonical MAJOR.MINOR.PATCH version: {text!r}")
        return cls(int(match.group(1)), int(match.group(2)), int(match.group(3)))

    @override
    def __str__(self) -> str:
        """Return the canonical text form."""
        return f"{self.major}.{self.minor}.{self.patch}"


def _version(text: str) -> ToolVersion:
    return ToolVersion.parse(text)


@dataclass(frozen=True, slots=True)
class VersionPolicy:
    """Which versions of one tool may start a run and which were really exercised.

    Compatibility is an interval: `minimum` is inclusive, `maximum` exclusive,
    and `excluded` names versions inside the interval with known defects or
    vulnerabilities. `tested` names the exact versions ConClear's real-tool
    tiers ran against; it documents evidence, not the accepted set. Acceptance
    never replaces run identity: every run records the exact version and
    executable digest it used, rechecks that digest before later use, and
    distributed workers of one release must report identical versions.
    """

    minimum: ToolVersion
    maximum: ToolVersion
    tested: frozenset[ToolVersion]
    excluded: frozenset[ToolVersion] = frozenset()

    def __post_init__(self) -> None:
        """Reject an inconsistent policy definition."""
        if not self.minimum < self.maximum:
            raise OperationalError("Tool policy minimum must be below its maximum")
        if not self.tested:
            raise OperationalError("Tool policy needs at least one tested version")
        for version in self.excluded:
            if not self.minimum <= version < self.maximum:
                raise OperationalError(
                    f"Excluded tool version {version} is outside the accepted interval"
                )
        for version in self.tested:
            if not self.accepts(version):
                raise OperationalError(f"Tested tool version {version} is not accepted")

    def accepts(self, version: ToolVersion) -> bool:
        """Return whether a version may start a run."""
        return self.minimum <= version < self.maximum and version not in self.excluded

    @property
    def interval(self) -> str:
        """Return the accepted interval in comparison form."""
        return f"{self.minimum} <= version < {self.maximum}"

    def describe(self) -> str:
        """Render the complete policy for a diagnostic."""
        excluded = ", ".join(str(item) for item in sorted(self.excluded)) or "none"
        tested = ", ".join(str(item) for item in sorted(self.tested))
        return (
            f"accepted {self.interval}; excluded: {excluded}; "
            f"real-tool tested (not the only accepted versions): {tested}"
        )


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Version invocation, version parsing and compatibility policy for one tool."""

    version_arguments: tuple[str, ...]
    version_pattern: re.Pattern[str]
    policy: VersionPolicy


def _pattern(prefix: str) -> re.Pattern[str]:
    # A version is complete only when no suffix such as `-beta` or `.1` follows.
    return re.compile(prefix + r"(?P<version>\d+\.\d+\.\d+)(?![\w.+-])")


SUPPORTED_TOOLS: Mapping[ToolName, ToolSpec] = {
    # Git: only stable plumbing (rev-parse, remote get-url, show, worktree,
    # archive, hash-object, diff --check), so the floor is the oldest line current
    # enterprise distributions ship and the whole 2.x series is accepted.
    ToolName.GIT: ToolSpec(
        ("--version",),
        _pattern(r"git version "),
        VersionPolicy(
            _version("2.43.0"), _version("3.0.0"), frozenset({_version("2.55.0")})
        ),
    ),
    # Buildah: `build --source-date-epoch --rewrite-timestamp` exists since the
    # 1.39 line, which also lies above the 1.38.1 build-breakout fix
    # (GHSA-5vpc-35f4-r8w6). Minor lines after the tested 1.43 change storage and
    # build behavior and are admitted only with real-tool evidence.
    ToolName.BUILDAH: ToolSpec(
        ("--version",),
        _pattern(r"buildah version "),
        VersionPolicy(
            _version("1.39.0"), _version("1.44.0"), frozenset({_version("1.43.2")})
        ),
    ),
    # Podman: `podman run` below 5.8.4 can leak host environment variables to a
    # malformed image (GHSA-4hq8-gpf5-8p68), so the 5.x line starts there; the
    # untested 6.x major stays out.
    ToolName.PODMAN: ToolSpec(
        ("--version",),
        _pattern(r"podman version "),
        VersionPolicy(
            _version("5.8.4"), _version("6.0.0"), frozenset({_version("5.8.4")})
        ),
    ),
    # Skopeo: `copy --all --preserve-digests` with auth files and raw inspect
    # output have been stable across the maintained 1.x lines.
    ToolName.SKOPEO: ToolSpec(
        ("--version",),
        _pattern(r"skopeo version "),
        VersionPolicy(
            _version("1.14.0"), _version("2.0.0"), frozenset({_version("1.22.2")})
        ),
    ),
    # Hadolint: `--format json` with the code, level, message, line and column
    # fields has been stable across the 2.x releases since 2.12.
    ToolName.HADOLINT: ToolSpec(
        ("--version",),
        _pattern(r"Haskell Dockerfile Linter "),
        VersionPolicy(
            _version("2.12.0"), _version("3.0.0"), frozenset({_version("2.14.0")})
        ),
    ),
    # Trivy: 0.x minor lines change scanners and report schemas, so only the
    # tested 0.74 line is accepted. Its floor lies above 0.71.1, the release that
    # fixed the path traversal through a crafted vulnerability database
    # (GHSA-mcj4-mphf-j9ff), so ConClear no longer relies on its sanitized
    # invocation to stay clear of that advisory.
    ToolName.TRIVY: ToolSpec(
        ("--version",),
        _pattern(r"Version:\s*"),
        VersionPolicy(
            _version("0.74.0"), _version("0.75.0"), frozenset({_version("0.74.0")})
        ),
    ),
    # Cosign: every 3.x release below 3.1.3 has a verification bypass
    # (GHSA-fx35-mq7g-6g98) or one of the earlier 3.0.x verification advisories,
    # so 3.1.3 is the security floor; an untested 4.x major is rejected.
    ToolName.COSIGN: ToolSpec(
        ("version",),
        _pattern(r"GitVersion:\s*v?"),
        VersionPolicy(
            _version("3.1.3"), _version("4.0.0"), frozenset({_version("3.1.3")})
        ),
    ),
}


class Runner(Protocol):
    """Narrow runner boundary used by tool discovery."""

    def run(self, request: CommandRequest) -> ProcessResult:
        """Execute one version observation."""
        ...


@dataclass(frozen=True, slots=True)
class ResolvedTool:
    """Observed immutable executable identity for one release run."""

    name: ToolName
    path: Path
    version: str
    executable_digest: str
    reported_version: str

    def assert_unchanged(self) -> None:
        """Reject a tool whose executable changed after release start."""
        current = sha256_file(self.path)
        if current != self.executable_digest:
            raise OperationalError(
                f"Resolved {self.name.value} executable changed during the run"
            )

    def record_identity(self) -> ToolIdentity:
        """Return the normalized public tool identity."""
        return ToolIdentity(
            name=self.name.value,
            version=self.version,
            executable_digest=self.executable_digest,
        )


class ToolResolver:
    """Resolve and validate every required host executable."""

    def __init__(
        self,
        *,
        runner: Runner | None = None,
        locator: Callable[[str, str], str | None] | None = None,
    ) -> None:
        """Create a resolver with injectable process and path boundaries."""
        self._runner = runner or ProcessRunner()
        self._locator = locator or _locate_on_path

    def resolve(
        self,
        name: ToolName,
        *,
        environment: Mapping[str, str],
    ) -> ResolvedTool:
        """Resolve one executable and reject an unsupported version."""
        search_path = environment.get("PATH")
        if not search_path:
            raise OperationalError("Tool discovery environment has no PATH")
        located = self._locator(name.value, search_path)
        if located is None:
            raise OperationalError(f"Required tool is unavailable: {name.value}")
        try:
            path = Path(located).resolve(strict=True)
            file_stat = path.stat()
        except OSError as exc:
            raise OperationalError(f"Unable to resolve tool {name.value}") from exc
        if not stat.S_ISREG(file_stat.st_mode) or not os.access(path, os.X_OK):
            raise OperationalError(f"Resolved tool is not executable: {path}")
        digest_before = sha256_file(path)
        spec = SUPPORTED_TOOLS[name]
        observation = self._runner.run(
            CommandRequest(
                argv=(str(path), *spec.version_arguments),
                environment=environment,
                timeout_seconds=15,
            )
        )
        reported = f"{observation.stdout}\n{observation.stderr}".strip()
        match = spec.version_pattern.search(reported)
        if match is None:
            raise OperationalError(f"Unable to parse {name.value} version output")
        try:
            version = ToolVersion.parse(match.group("version"))
        except ValueError as exc:
            raise OperationalError(
                f"{name.value} reported a noncanonical version {match.group('version')!r}"
            ) from exc
        if not spec.policy.accepts(version):
            raise RuleRejectionError(
                f"Unsupported {name.value} version {version}: {spec.policy.describe()}",
                code="CC0301",
            )
        digest_after = sha256_file(path)
        if digest_before != digest_after:
            raise OperationalError(
                f"Resolved {name.value} executable changed during discovery"
            )
        return ResolvedTool(
            name=name,
            path=path,
            version=str(version),
            executable_digest=digest_after,
            reported_version=reported,
        )

    def resolve_all(
        self,
        *,
        environment: Mapping[str, str],
        names: Sequence[ToolName] = tuple(ToolName),
    ) -> tuple[ResolvedTool, ...]:
        """Resolve a deterministic collection of required tools."""
        return tuple(self.resolve(name, environment=environment) for name in names)


def _locate_on_path(name: str, search_path: str) -> str | None:
    return shutil.which(name, path=search_path)
