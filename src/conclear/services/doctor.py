"""Read-only release environment diagnostics."""

import platform as host_platform
from dataclasses import dataclass
from typing import Protocol

from conclear.config import RepositoryConfig
from conclear.emulation import binfmt_handler, normalize_architecture
from conclear.errors import OperationalError
from conclear.registry_control import TagObservation
from conclear.release_profile import ReleaseProfile
from conclear.runtime import ApplicationRuntime
from conclear.values import OCIReference


class RegistryDiagnostic(Protocol):
    """Read-only registry controls exercised by doctor."""

    @property
    def provider(self) -> str:
        """Return the compiled registry backend identifier."""
        ...

    def observe_tag(self, repository: OCIReference, tag: str) -> TagObservation | None:
        """Observe one exact probe tag."""
        ...


@dataclass(frozen=True, slots=True)
class DoctorObservation:
    """Validated tool, storage, execution, trust and service observations."""

    tools: tuple[dict[str, object], ...]
    native_architecture: str
    emulated_architectures: tuple[str, ...]
    registry_provider: str
    registry_access: bool
    sigstore_access: bool


def diagnose_environment(
    repository: RepositoryConfig,
    profile: ReleaseProfile,
    runtime: ApplicationRuntime,
    *,
    registry_control: RegistryDiagnostic,
) -> DoctorObservation:
    """Exercise read-only prerequisites without publishing or signing content."""
    runtime.buildah().info(
        root=runtime.root / "doctor" / "buildah" / "root",
        runroot=runtime.root / "doctor" / "buildah" / "runroot",
    )
    runtime.podman().info(
        root=runtime.root / "doctor" / "podman" / "root",
        runroot=runtime.root / "doctor" / "podman" / "runroot",
    )
    native = normalize_architecture(host_platform.machine())
    requested = {
        item.architecture for image in repository.images for item in image.platforms
    }
    emulated = tuple(sorted(item for item in requested if item != native))
    unavailable = [item for item in emulated if binfmt_handler(item) is None]
    if unavailable:
        raise OperationalError(
            "No enabled binfmt handler was observed for: " + ", ".join(unavailable)
        )
    for image in repository.images:
        registry_control.observe_tag(image.repository, "conclear-doctor-read-probe")
    runtime.cosign().initialize()
    runtime.assert_unchanged()
    return DoctorObservation(
        tools=tuple(item.to_dict() for item in runtime.identities),
        native_architecture=native,
        emulated_architectures=emulated,
        registry_provider=registry_control.provider,
        registry_access=True,
        sigstore_access=True,
    )
