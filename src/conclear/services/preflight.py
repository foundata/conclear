"""Static and pin gates for the complete test-image closure of one image.

Nothing is built before every image a qualification builds has passed the
same source checks and the same pin gate. The closure is the selected image
plus its transitive test dependencies in dependency-first order; each image is
checked under its own Containerfile, context, pins and pin limits, and every
distinct readable tag is resolved once for the whole closure. Static findings
reject the closure before any registry is contacted or durable pin state is
updated.
"""

from dataclasses import dataclass
from datetime import datetime

from conclear.adapters.hadolint import HadolintAdapter
from conclear.config import ImageConfig, RepositoryConfig
from conclear.pins import (
    MemoizedPinResolver,
    PinObservation,
    PinResolver,
    PinStore,
    check_image_pins,
)
from conclear.presentation import Finding
from conclear.services.checking import check_image


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


@dataclass(frozen=True, slots=True)
class ClosurePreflight:
    """Preflight results for the selected image and its test dependencies."""

    primary: ImagePreflight
    dependencies: tuple[ImagePreflight, ...]

    @property
    def images(self) -> tuple[ImagePreflight, ...]:
        """Return the primary image followed by its dependencies."""
        return (self.primary, *self.dependencies)

    @property
    def static_findings(self) -> tuple[Finding, ...]:
        """Return every source-check finding across the closure."""
        return tuple(item for image in self.images for item in image.findings)

    @property
    def pin_findings(self) -> tuple[Finding, ...]:
        """Return every pin-gate finding across the closure."""
        return tuple(
            item
            for image in self.images
            for observation in image.pin_observations
            for item in observation.findings
        )

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Return the distinct findings of the closure in gate order."""
        return tuple(dict.fromkeys((*self.static_findings, *self.pin_findings)))

    @property
    def accepted(self) -> bool:
        """Return whether every image in the closure passed both gates."""
        return all(item.accepted for item in self.images)


def preflight_image_closure(
    repository: RepositoryConfig,
    image: ImageConfig,
    *,
    hadolint: HadolintAdapter,
    store: PinStore,
    resolver: PinResolver,
    now: datetime,
) -> ClosurePreflight:
    """Run the source checks and the pin gate for an image and its dependencies."""
    closure = (image, *repository.test_dependencies(image.image_id))
    outcomes = tuple(check_image(selected, hadolint).findings for selected in closure)
    if any(item.severity == "error" for findings in outcomes for item in findings):
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
    return ClosurePreflight(primary=preflights[0], dependencies=preflights[1:])
