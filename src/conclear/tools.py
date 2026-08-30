"""Supported external tool discovery and immutable identity checks."""

import os
import re
import shutil
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

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


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Version invocation and supported normalized versions for one tool."""

    version_arguments: tuple[str, ...]
    version_pattern: re.Pattern[str]
    supported_versions: frozenset[str]


SUPPORTED_TOOLS: Mapping[ToolName, ToolSpec] = {
    ToolName.GIT: ToolSpec(
        ("--version",),
        re.compile(r"git version (?P<version>\d+\.\d+\.\d+)"),
        frozenset({"2.55.0"}),
    ),
    ToolName.BUILDAH: ToolSpec(
        ("--version",),
        re.compile(r"buildah version (?P<version>\d+\.\d+\.\d+)"),
        frozenset({"1.43.2"}),
    ),
    ToolName.PODMAN: ToolSpec(
        ("--version",),
        re.compile(r"podman version (?P<version>\d+\.\d+\.\d+)"),
        frozenset({"5.8.4"}),
    ),
    ToolName.SKOPEO: ToolSpec(
        ("--version",),
        re.compile(r"skopeo version (?P<version>\d+\.\d+\.\d+)"),
        frozenset({"1.22.2"}),
    ),
    ToolName.HADOLINT: ToolSpec(
        ("--version",),
        re.compile(r"Haskell Dockerfile Linter (?P<version>\d+\.\d+\.\d+)"),
        frozenset({"2.14.0"}),
    ),
    ToolName.TRIVY: ToolSpec(
        ("--version",),
        re.compile(r"Version:\s*(?P<version>\d+\.\d+\.\d+)"),
        frozenset({"0.69.3"}),
    ),
    ToolName.COSIGN: ToolSpec(
        ("version",),
        re.compile(r"GitVersion:\s*v?(?P<version>\d+\.\d+\.\d+)"),
        frozenset({"3.1.3"}),
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
        locator: Callable[[str], str | None] = shutil.which,
    ) -> None:
        """Create a resolver with injectable process and path boundaries."""
        self._runner = runner or ProcessRunner()
        self._locator = locator

    def resolve(
        self,
        name: ToolName,
        *,
        environment: Mapping[str, str],
    ) -> ResolvedTool:
        """Resolve one executable and reject an unsupported version."""
        located = self._locator(name.value)
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
        version = match.group("version")
        if version not in spec.supported_versions:
            supported = ", ".join(sorted(spec.supported_versions))
            raise RuleRejectionError(
                f"Unsupported {name.value} version {version}; supported: {supported}",
                code="CC0701",
            )
        digest_after = sha256_file(path)
        if digest_before != digest_after:
            raise OperationalError(
                f"Resolved {name.value} executable changed during discovery"
            )
        return ResolvedTool(
            name=name,
            path=path,
            version=version,
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
