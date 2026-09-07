"""Immutable inputs and evidence handed between qualification phases.

`BuildInputs` fixes every adapter-independent fact for building one image on
one platform, whether that image is the qualified one or a test dependency.
`QualificationInputs` narrows the image to a `ReleaseImageConfig`, so scanning,
runtime testing and evidence generation receive the release-only declarations
by type rather than by assumption. `BuildEvidence` and `TestDependencyBuild`
carry the verified build results from the build phase into runtime testing,
evidence generation and the final record. The execution-mode gate lives here
because both building and testing refuse a foreign platform without an enabled
binfmt handler.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from conclear.adapters.buildah import BuildObservation
from conclear.config import (
    ImageConfig,
    ReleaseImageConfig,
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
class BuildInputs:
    """Immutable run facts for building one image on one platform."""

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

    def dependency_inputs(self, image: ImageConfig) -> "BuildInputs":
        """Return the same run facts bound to one test dependency."""
        return BuildInputs(
            repository=self.repository,
            image=image,
            workspace=self.workspace,
            source=self.source,
            source_time=self.source_time,
            version=self.version,
            platform=self.platform,
            tools=self.tools,
            auth_file=self.auth_file,
            host_architecture=self.host_architecture,
            binfmt_root=self.binfmt_root,
        )


@dataclass(frozen=True, slots=True)
class QualificationInputs(BuildInputs):
    """Build inputs of the qualified image, whose release-only state drives evidence."""

    image: ReleaseImageConfig


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


def require_execution_mode(inputs: BuildInputs) -> None:
    """Refuse to build or test a foreign platform without an enabled handler."""
    detect_execution_mode(
        inputs.host_architecture, inputs.platform, binfmt_root=inputs.binfmt_root
    )


def execution_observation(inputs: BuildInputs) -> dict[str, object]:
    """Describe the verified execution mode selected for this platform workflow."""
    return detect_execution_mode(
        inputs.host_architecture, inputs.platform, binfmt_root=inputs.binfmt_root
    ).to_dict()
