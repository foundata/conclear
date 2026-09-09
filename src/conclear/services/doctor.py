"""Read-only environment diagnostics for one command scope."""

import platform as host_platform
from dataclasses import dataclass
from enum import StrEnum

from conclear.config import RepositoryConfig
from conclear.dependencies import (
    DOCTOR_SCOPES,
    require_profile_capabilities,
    scope_dependencies,
)
from conclear.emulation import binfmt_handler, normalize_architecture
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.release_profile import ReleaseProfile
from conclear.runtime import ApplicationRuntime
from conclear.services.registry_diagnostics import (
    DiagnosticStatus,
    RegistryCheck,
    RegistryDiagnostic,
    diagnose_registry,
)
from conclear.values import validate_release_version


class DoctorScope(StrEnum):
    """Commands a diagnosis validates the environment for."""

    CHECK = "check"
    QUALIFY = "qualify"
    RELEASE = "release"


assert tuple(item.value for item in DoctorScope) == tuple(DOCTOR_SCOPES)


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
    registry_checks: tuple[RegistryCheck, ...] = ()


def diagnose_environment(
    repository: RepositoryConfig,
    runtime: ApplicationRuntime,
    *,
    scope: DoctorScope,
    profile: ReleaseProfile | None = None,
    registry_control: RegistryDiagnostic | None = None,
    version: str | None = None,
) -> DoctorObservation:
    """Exercise the read-only prerequisites of one scope without mutating anything.

    `check` proves the static toolchain. `qualify` adds run-owned rootless
    storage and an execution mode for every configured platform. `release` adds
    the selected registry backend and the public Sigstore services. A profile is
    first checked for the credential inputs the scope's commands will use.
    Their presence does not prove write permissions or signing capability.
    """
    if version is not None:
        if scope is not DoctorScope.RELEASE:
            raise InvalidInvocationError("--version applies only to --scope release")
        validate_release_version(version)
        for image in repository.release_images:
            image.release.render_versions(version)
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
    registry_checks: tuple[RegistryCheck, ...] = ()
    if scope is DoctorScope.RELEASE:
        if profile is None or registry_control is None:
            raise InvalidInvocationError(
                "Release scope diagnosis needs a release profile and registry backend"
            )
        registry_checks = tuple(
            check
            for image in repository.release_images
            for check in diagnose_registry(
                image, profile.registry.policy, registry_control, version=version
            )
        )
        registry_provider = registry_control.provider
        runtime.cosign().initialize()
    runtime.assert_unchanged()
    return DoctorObservation(
        scope=scope,
        tools=tuple(item.to_dict() for item in runtime.identities),
        native_architecture=native,
        emulated_architectures=emulated,
        registry_provider=registry_provider,
        registry_access=scope is DoctorScope.RELEASE
        and all(
            item.status is DiagnosticStatus.CHECKED
            for item in registry_checks
            if item.name == "tagRead"
        ),
        sigstore_access=scope is DoctorScope.RELEASE,
        registry_checks=registry_checks,
    )
