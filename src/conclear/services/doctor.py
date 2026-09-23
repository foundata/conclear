"""Read-only environment diagnostics for one command scope."""

import platform as host_platform
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from conclear.config import ReleaseImageConfig, RepositoryConfig
from conclear.database import DatabaseAdapter, database_freshness
from conclear.dependencies import (
    DOCTOR_SCOPES,
    require_profile_capabilities,
    scope_dependencies,
)
from conclear.emulation import binfmt_handler, normalize_architecture
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.presentation import Finding
from conclear.records import format_timestamp, utc_now
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
class DatabaseDiagnostic:
    """Freshness of the installed Trivy snapshot, read without refreshing it.

    A stale vulnerability database needs no warning: qualification refreshes it
    before scanning. A stale Java database does, because nothing refreshes it
    until its publisher does, and an image with Java artifacts then rejects
    with `CC0507` at the end of its build rather than before it starts.
    """

    digest: str | None
    vulnerability_fresh: bool | None
    java_fresh: bool | None
    java_next_update: str | None
    note: str
    finding: Finding | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the public diagnostic object."""
        return {
            "digest": self.digest,
            "vulnerabilityFresh": self.vulnerability_fresh,
            "javaFresh": self.java_fresh,
            "javaNextUpdate": self.java_next_update,
            "note": self.note,
        }


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
    database: DatabaseDiagnostic | None = None


def diagnose_database(
    adapter: DatabaseAdapter, cache_root: Path, *, now: datetime
) -> DatabaseDiagnostic:
    """Report the installed snapshot's freshness; never download or refresh."""
    try:
        selected = adapter.select_database(cache_root)
    except OperationalError as exc:
        return DatabaseDiagnostic(
            digest=None,
            vulnerability_fresh=None,
            java_fresh=None,
            java_next_update=None,
            note=f"No usable Trivy database snapshot is installed ({exc}); "
            "qualification downloads one",
        )
    freshness = database_freshness(selected.metadata, now)
    java_due = format_timestamp(freshness.java_next_update)
    finding: Finding | None = None
    if not freshness.java:
        overdue = now.astimezone(UTC) - freshness.java_next_update.astimezone(UTC)
        hours = int(overdue.total_seconds() // 3600)
        note = (
            f"Trivy Java database next update was due {java_due} ({hours}h ago); "
            "images with Java artifacts reject with CC0507 unless "
            "--accept-stale-java-database is given"
        )
        finding = Finding("CC0507", "warning", note)
    elif not freshness.vulnerability:
        note = (
            "Trivy vulnerability database has reached its next-update time; "
            "qualification refreshes it before scanning"
        )
    else:
        note = f"Trivy database snapshot is fresh; Java database next update {java_due}"
    return DatabaseDiagnostic(
        digest=selected.digest,
        vulnerability_fresh=freshness.vulnerability,
        java_fresh=freshness.java,
        java_next_update=java_due,
        note=note,
        finding=finding,
    )


def _require_credentials_flag_for_escalation(
    images: tuple[ReleaseImageConfig, ...], native: str
) -> None:
    """Refuse early when escalation tests would run under a handler without `C`.

    Without the credentials flag a set-user-ID binary runs with the caller's
    credentials under user-mode emulation, so `sudo` cannot become root and the
    escalation tests of every emulated platform would fail for a host reason.
    """
    for image in images:
        requirement = image.runtime.sudo_requirement
        if requirement is None or requirement.mode != "escalation":
            continue
        for platform in image.platforms:
            if platform.architecture == native:
                continue
            handler = binfmt_handler(platform.architecture)
            if handler is not None and "C" not in handler.flags:
                raise OperationalError(
                    f"Image {image.image_id} tests sudo escalation on {platform}, "
                    f"but the binfmt handler {handler.name} has flags "
                    f"'{handler.flags}' without C (credentials); register it with "
                    f"C or test {platform} natively"
                )


def diagnose_environment(
    repository: RepositoryConfig | None,
    runtime: ApplicationRuntime,
    *,
    scope: DoctorScope,
    profile: ReleaseProfile | None = None,
    registry_control: RegistryDiagnostic | None = None,
    version: str | None = None,
    database_cache: Path | None = None,
    now: datetime | None = None,
) -> DoctorObservation:
    """Exercise the read-only prerequisites of one scope without mutating anything.

    `check` proves the static toolchain. `qualify` adds run-owned rootless
    storage, an execution mode for every configured platform and, when a
    `database_cache` is given, the freshness of the installed scanner snapshot.
    `release` adds the selected registry backend and the public Sigstore
    services. A profile is first checked for the credential inputs the scope's
    commands will use. Their presence does not prove write permissions or
    signing capability.
    """
    if repository is None and scope is not DoctorScope.CHECK:
        raise InvalidInvocationError(
            f"--scope {scope.value} needs the repository configuration; "
            "run it from a repository with conclear.toml"
        )
    images = () if repository is None else repository.images
    release_images = () if repository is None else repository.release_images
    if version is not None:
        if scope is not DoctorScope.RELEASE:
            raise InvalidInvocationError("--version applies only to --scope release")
        validate_release_version(version)
        for image in release_images:
            image.release.render_versions(version)
    if profile is not None:
        require_profile_capabilities(profile, scope_dependencies(scope.value))
    native = normalize_architecture(host_platform.machine())
    emulated: tuple[str, ...] = ()
    database: DatabaseDiagnostic | None = None
    if scope in {DoctorScope.QUALIFY, DoctorScope.RELEASE}:
        if database_cache is not None:
            database = diagnose_database(
                runtime.trivy(), database_cache, now=now or utc_now()
            )
        runtime.buildah().info(
            root=runtime.root / "doctor" / "buildah" / "root",
            runroot=runtime.root / "doctor" / "buildah" / "runroot",
        )
        runtime.podman().info(
            root=runtime.root / "doctor" / "podman" / "root",
            runroot=runtime.root / "doctor" / "podman" / "runroot",
        )
        requested = {item.architecture for image in images for item in image.platforms}
        emulated = tuple(sorted(item for item in requested if item != native))
        unavailable = [item for item in emulated if binfmt_handler(item) is None]
        if unavailable:
            raise OperationalError(
                "No enabled binfmt handler was observed for: " + ", ".join(unavailable)
            )
        _require_credentials_flag_for_escalation(release_images, native)
    registry_provider: str | None = None
    registry_checks: tuple[RegistryCheck, ...] = ()
    if scope is DoctorScope.RELEASE:
        if profile is None or registry_control is None:
            raise InvalidInvocationError(
                "Release scope diagnosis needs a release profile and registry backend"
            )
        registry_checks = tuple(
            check
            for image in release_images
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
        database=database,
    )
