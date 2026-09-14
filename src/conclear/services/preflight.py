"""Static and pin gates for the complete test-image closure of one image.

Nothing is built before every image a qualification builds has passed the
same source checks and the same pin gate. The closure is the transitive test
dependencies in stable dependency-first order followed by the selected image;
each image is checked under its own Containerfile, context, pins and pin
limits at one instant, and every distinct readable tag is resolved once for
the whole closure. Static findings reject the closure before any registry is
contacted or durable pin state is updated. Every finding names the image it
concerns so a rejection is attributable.
"""

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.hadolint import HadolintAdapter
from conclear.config import ImageConfig, ReleaseImageConfig, RepositoryConfig
from conclear.pins import (
    MemoizedPinResolver,
    PinObservation,
    PinResolver,
    PinStore,
    check_image_pins,
)
from conclear.presentation import Finding
from conclear.services.checking import check_image
from conclear.version_sources import (
    VersionSourceObservation,
    observe_version_sources,
    version_source_findings,
)


@dataclass(frozen=True, slots=True)
class ImagePreflight:
    """Static findings and pin observations of one image in the closure."""

    image: ImageConfig
    findings: tuple[Finding, ...]
    pin_observations: tuple[PinObservation, ...]

    @property
    def accepted(self) -> bool:
        """Return whether neither the source checks nor the pin gate rejected."""
        return not any(item.severity == "error" for item in self.findings) and all(
            item.accepted for item in self.pin_observations
        )

    @property
    def static_findings(self) -> tuple[Finding, ...]:
        """Return the source-check findings, each naming this image."""
        return tuple(replace(item, image=self.image.image_id) for item in self.findings)

    @property
    def pin_findings(self) -> tuple[Finding, ...]:
        """Return the pin-gate findings, each naming this image."""
        return tuple(
            replace(item, image=self.image.image_id)
            for observation in self.pin_observations
            for item in observation.findings
        )


@dataclass(frozen=True, slots=True)
class ClosurePreflight:
    """Preflight results for the selected image and its test dependencies."""

    primary: ImagePreflight
    dependencies: tuple[ImagePreflight, ...]
    version_sources: tuple[VersionSourceObservation, ...] = ()
    version_findings: tuple[Finding, ...] = ()

    @property
    def images(self) -> tuple[ImagePreflight, ...]:
        """Return the closure in dependency-first order, the primary image last."""
        return (*self.dependencies, self.primary)

    @property
    def static_findings(self) -> tuple[Finding, ...]:
        """Return every attributed source-check finding across the closure."""
        return (
            *(item for image in self.images for item in image.static_findings),
            *self.version_findings,
        )

    @property
    def pin_findings(self) -> tuple[Finding, ...]:
        """Return every attributed pin-gate finding across the closure."""
        return tuple(item for image in self.images for item in image.pin_findings)

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Return the distinct findings of the closure in gate order."""
        return tuple(dict.fromkeys((*self.static_findings, *self.pin_findings)))

    @property
    def accepted(self) -> bool:
        """Return whether every image and every version source passed."""
        return all(item.accepted for item in self.images) and not any(
            item.severity == "error" for item in self.version_findings
        )


class RevisionTags(Protocol):
    """Tag lookup for the released revision."""

    def tags_at(self, repository: Path, revision: str) -> tuple[str, ...]:
        """Return the tags pointing at a revision."""
        ...


def revision_tags(
    repository: RepositoryConfig,
    git: RevisionTags,
    source_repository: Path,
    revision: str,
) -> tuple[str, ...]:
    """Look up tags only when a declared version source needs them."""
    if any(item.kind == "git-tag" for item in repository.project.version_sources):
        return git.tags_at(source_repository, revision)
    return ()


def preflight_image_closure(
    repository: RepositoryConfig,
    image: ReleaseImageConfig,
    *,
    hadolint: HadolintAdapter,
    store: PinStore,
    resolver: PinResolver,
    now: datetime,
    version: str | None = None,
    revision_tags: Sequence[str] = (),
) -> ClosurePreflight:
    """Run the source checks, the version sources and the pin gate for a closure.

    Version sources are compared only when a release version is known; a
    project without declared sources is unversioned and never rejected for it.
    """
    closure = (*repository.test_dependencies(image.image_id), image)
    outcomes = tuple(check_image(selected, hadolint).findings for selected in closure)
    version_sources: tuple[VersionSourceObservation, ...] = ()
    version_findings: tuple[Finding, ...] = ()
    if version is not None and repository.project.version_sources:
        version_sources = observe_version_sources(
            repository.project.version_sources,
            source_root=repository.path.parent,
            version=version,
            revision_tags=revision_tags,
        )
        version_findings = version_source_findings(version_sources, version)
    if any(
        item.severity == "error" for findings in outcomes for item in findings
    ) or any(item.severity == "error" for item in version_findings):
        observations: tuple[tuple[PinObservation, ...], ...] = tuple(
            () for _selected in closure
        )
    else:
        shared = MemoizedPinResolver(resolver)
        observations = tuple(
            check_image_pins(store, selected, resolver=shared, now=now)
            for selected in closure
        )
    preflights = tuple(
        ImagePreflight(selected, findings, observed)
        for selected, findings, observed in zip(
            closure, outcomes, observations, strict=True
        )
    )
    return ClosurePreflight(
        primary=preflights[-1],
        dependencies=preflights[:-1],
        version_sources=version_sources,
        version_findings=version_findings,
    )
