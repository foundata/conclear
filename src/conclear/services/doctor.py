"""Read-only environment diagnostics for one command scope."""

import platform as host_platform
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from conclear.config import RepositoryConfig
from conclear.dependencies import (
    DOCTOR_SCOPES,
    require_profile_capabilities,
    scope_dependencies,
)
from conclear.emulation import binfmt_handler, normalize_architecture
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.registry_control import TagObservation
from conclear.release_profile import ReleaseProfile
from conclear.runtime import ApplicationRuntime
from conclear.values import OCIReference


class DoctorScope(StrEnum):
    """Commands a diagnosis validates the environment for."""

    CHECK = "check"
    QUALIFY = "qualify"
    RELEASE = "release"


assert tuple(item.value for item in DoctorScope) == tuple(DOCTOR_SCOPES)


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

    scope: DoctorScope
    tools: tuple[dict[str, object], ...]
    native_architecture: str
    emulated_architectures: tuple[str, ...]
    registry_provider: str | None
    registry_access: bool
    sigstore_access: bool


def diagnose_environment(
    repository: RepositoryConfig,
    runtime: ApplicationRuntime,
    *,
    scope: DoctorScope,
    profile: ReleaseProfile | None = None,
    registry_control: RegistryDiagnostic | None = None,
) -> DoctorObservation:
    """Exercise the read-only prerequisites of one scope without mutating anything.

    `check` proves the static toolchain. `qualify` adds run-owned rootless
    storage and an execution mode for every configured platform. `release` adds
    the selected registry backend and the public Sigstore services. A profile is
    first checked for every input the scope's commands will use, so readiness
    is never reported for a profile that cannot write or sign.
    """
    if profile is not None:
        require_profile_capabilities(profile, scope_dependencies(scope.value))
    native = normalize_architecture(host_platform.machine())
    emulated: tuple[str, ...] = ()
    if scope in {DoctorScope.QUALIFY, DoctorScope.RELEASE}:
        runtime.buildah().info(
            root=runtime.root / "doctor" / "buildah" / "root",
            runroot=runtime.root / "doctor" / "buildah" / "runroot",
        )
        runtime.podman().info(
            root=runtime.root / "doctor" / "podman" / "root",
            runroot=runtime.root / "doctor" / "podman" / "runroot",
        )
        requested = {
            item.architecture for image in repository.images for item in image.platforms
        }
        emulated = tuple(sorted(item for item in requested if item != native))
        unavailable = [item for item in emulated if binfmt_handler(item) is None]
        if unavailable:
            raise OperationalError(
                "No enabled binfmt handler was observed for: " + ", ".join(unavailable)
            )
    registry_provider: str | None = None
    if scope is DoctorScope.RELEASE:
        if profile is None or registry_control is None:
            raise InvalidInvocationError(
                "Release scope diagnosis needs a release profile and registry backend"
            )
        for image in repository.images:
            registry_control.observe_tag(image.repository, "conclear-doctor-read-probe")
        registry_provider = registry_control.provider
        runtime.cosign().initialize()
    runtime.assert_unchanged()
    return DoctorObservation(
        scope=scope,
        tools=tuple(item.to_dict() for item in runtime.identities),
        native_architecture=native,
        emulated_architectures=emulated,
        registry_provider=registry_provider,
        registry_access=scope is DoctorScope.RELEASE,
        sigstore_access=scope is DoctorScope.RELEASE,
    )
