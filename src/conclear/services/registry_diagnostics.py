"""Read-only registry observations, separate from write and enforcement claims."""

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Protocol

from conclear.config import ReleaseImageConfig
from conclear.errors import OperationalError
from conclear.registry_control import CandidateRetentionObservation, TagObservation
from conclear.registry_policy import (
    CandidateCleanupMode,
    RegistryPolicy,
    TagProtectionMode,
)
from conclear.values import OCIReference, candidate_tag


class DiagnosticStatus(StrEnum):
    """Whether a named prerequisite was observed, untested or failed."""

    CHECKED = "checked"
    NOT_CHECKED = "notChecked"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class RegistryCheck:
    """One narrowly scoped diagnostic, including its verification limits."""

    repository: str
    name: str
    status: DiagnosticStatus
    message: str
    code: str | None = None
    policy_creation_required: bool | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the public diagnostic without credentials or response bodies."""
        result: dict[str, object] = {
            "repository": self.repository,
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
        }
        if self.code is not None:
            result["checkId"] = self.code
        if self.policy_creation_required is not None:
            result["policyCreationRequired"] = self.policy_creation_required
        return result


class RegistryDiagnostic(Protocol):
    """Only read operations available to registry diagnostics."""

    @property
    def provider(self) -> str:
        """Return the compiled backend identifier."""
        ...

    def observe_tag(self, repository: OCIReference, tag: str) -> TagObservation | None:
        """Read one exact tag."""
        ...

    def verify_tag_policy(
        self,
        repository: OCIReference,
        *,
        version_tags: tuple[str, ...],
        mutable_tags: tuple[str, ...],
    ) -> None:
        """Check effective policy coverage without changing policies or tags."""
        ...

    def observe_candidate_retention(
        self, repository: OCIReference, maximum_age: timedelta
    ) -> CandidateRetentionObservation | None:
        """Read an adequate candidate policy, or return none if creation is needed."""
        ...


def diagnose_registry(
    image: ReleaseImageConfig,
    policy: RegistryPolicy,
    control: RegistryDiagnostic,
    *,
    version: str | None,
) -> tuple[RegistryCheck, ...]:
    """Inspect selected controls independently; unselected APIs are never required."""
    repository = image.repository
    name = repository.repository_name
    checks: list[RegistryCheck] = []
    try:
        control.observe_tag(repository, "conclear-doctor-read-probe")
    except OperationalError as exc:
        checks.append(RegistryCheck(name, "tagRead", DiagnosticStatus.FAILED, str(exc)))
    else:
        checks.append(
            RegistryCheck(
                name, "tagRead", DiagnosticStatus.CHECKED, "Tag API is readable."
            )
        )
    if policy.tag_protection.mode is TagProtectionMode.NOT_ENFORCED:
        checks.append(
            RegistryCheck(
                name,
                "tagPolicy",
                DiagnosticStatus.NOT_CHECKED,
                "Registry protection is not required by the reviewed profile.",
            )
        )
    else:
        checks.append(_tag_policy(image, control, version))
    if policy.candidate_cleanup.mode is CandidateCleanupMode.AUTO_PRUNE:
        try:
            retention = control.observe_candidate_retention(
                repository, image.release_limits.candidate_lifetime
            )
        except OperationalError as exc:
            checks.append(
                RegistryCheck(
                    name,
                    "candidateRetention",
                    DiagnosticStatus.FAILED,
                    str(exc),
                    exc.code or "CC0603",
                )
            )
        else:
            checks.append(
                RegistryCheck(
                    name,
                    "candidateRetention",
                    DiagnosticStatus.CHECKED,
                    "Retention API is readable; publication must create a candidate policy."
                    if retention is None
                    else "An adequate candidate-only retention policy exists.",
                    policy_creation_required=retention is None,
                )
            )
    else:
        checks.append(
            RegistryCheck(
                name,
                "candidateRetention",
                DiagnosticStatus.NOT_CHECKED,
                f"Cleanup mode is {policy.candidate_cleanup.mode.value}; auto-prune is not selected.",
            )
        )
    checks.extend(
        (
            RegistryCheck(
                name,
                "tagExpiration",
                DiagnosticStatus.NOT_CHECKED,
                "Expiration write and read-back are checked during publication."
                if policy.candidate_cleanup.mode is not CandidateCleanupMode.MANUAL
                else "Cleanup is assigned to the profile's manual procedure.",
            ),
            RegistryCheck(
                name,
                "registryWrites",
                DiagnosticStatus.NOT_CHECKED,
                "No push, tag assignment or policy creation was attempted.",
            ),
            RegistryCheck(
                name,
                "policyEnforcement",
                DiagnosticStatus.NOT_CHECKED,
                "Overwrite protection and eventual cleanup require a disposable release drill.",
            ),
        )
    )
    return tuple(checks)


def _tag_policy(
    image: ReleaseImageConfig, control: RegistryDiagnostic, version: str | None
) -> RegistryCheck:
    missing_version = version is None and any(
        "{version}" in tag for tag in image.release.version_tags
    )
    versions = (
        tuple(tag for tag in image.release.version_tags if "{version}" not in tag)
        if missing_version
        else image.release.render_versions(version)
    )
    sample = candidate_tag(version=version, run_id="0" * 26, source_revision="0" * 40)
    try:
        control.verify_tag_policy(
            image.repository,
            version_tags=versions,
            mutable_tags=(*image.release.moving_tags, sample),
        )
    except OperationalError as exc:
        return RegistryCheck(
            image.repository.repository_name,
            "tagPolicy",
            DiagnosticStatus.FAILED,
            str(exc),
            exc.code or "CC0604",
        )
    return RegistryCheck(
        image.repository.repository_name,
        "tagPolicy",
        DiagnosticStatus.NOT_CHECKED if missing_version else DiagnosticStatus.CHECKED,
        "Policies are readable; supply --version to check all version-tag templates."
        if missing_version
        else "Policies cover the version tags and exclude moving tags and a sample candidate; enforcement is untested.",
    )
