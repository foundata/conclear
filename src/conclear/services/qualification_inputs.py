"""Immutable inputs and evidence handed between qualification phases.

`QualificationInputs` fixes every adapter-independent fact for one platform of
one image before any tool runs. `BuildEvidence` and `TestDependencyBuild` carry
the verified build results from the build phase into runtime testing, evidence
generation and the final record. The execution-mode gate lives here because
both building and testing refuse a foreign platform without an enabled binfmt
handler.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from conclear.adapters.buildah import BuildObservation
from conclear.config import (
    ImageConfig,
    RepositoryConfig,
)
from conclear.context import ContextObservation
from conclear.emulation import BINFMT_ROOT, detect_execution_mode
from conclear.presentation import Finding
from conclear.records import (
    SourceIdentity,
    ToolIdentity,
)
from conclear.values import Platform
from conclear.workspace import RunWorkspace


@dataclass(frozen=True, slots=True)
class QualificationInputs:
    """Immutable inputs and adapter-independent facts for one platform."""

    repository: RepositoryConfig
    image: ImageConfig
    workspace: RunWorkspace
    source: SourceIdentity
    source_time: datetime
    version: str | None
    platform: Platform
    tools: tuple[ToolIdentity, ...]
    auth_file: Path | None
    host_architecture: str
    binfmt_root: Path = BINFMT_ROOT


@dataclass(frozen=True, slots=True)
class BuildEvidence:
    """Verified build output and source-content digests."""

    observation: BuildObservation
    context: ContextObservation
    containerfile_digest: str
    build_arguments: dict[str, str]
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class TestDependencyBuild:
    """One exact sibling layout built only for the primary image's tests."""

    image: ImageConfig
    build: BuildEvidence
    source_revision: str
    platform: Platform


def require_execution_mode(inputs: QualificationInputs) -> None:
    """Refuse to build or test a foreign platform without an enabled handler."""
    detect_execution_mode(
        inputs.host_architecture, inputs.platform, binfmt_root=inputs.binfmt_root
    )


def execution_observation(inputs: QualificationInputs) -> dict[str, object]:
    """Describe the verified execution mode selected for this platform workflow."""
    return detect_execution_mode(
        inputs.host_architecture, inputs.platform, binfmt_root=inputs.binfmt_root
    ).to_dict()
