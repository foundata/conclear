"""Read-only adoption assessment of an existing container repository.

`conclear adopt` observes what a repository already states, suggests
conservative values a maintainer may accept, and lists the decisions only a
maintainer can make. It resolves no registry, writes nothing below the
repository and invents no destination, platform, root justification, writable
path, health behavior, test input, hook, exception or credential. The draft it
renders is deliberately invalid until every decision is resolved, so it cannot
pass `check` or `qualify` by accident.
"""

from dataclasses import dataclass, replace
from pathlib import Path

from conclear.errors import InvalidInvocationError
from conclear.presentation import Finding
from conclear.services.adoption_draft import (
    Note,
    assessment_notes,
    note_scope,
    render_draft,
)
from conclear.services.adoption_observation import (
    ContainerfileObservation,
    PinQuality,
    ProjectObservation,
    SourceObserver,
    derive_image_ids,
    discover_containerfiles,
    explicit_containerfiles,
    observe_containerfile,
    observe_project,
)


@dataclass(frozen=True, slots=True)
class Assessment:
    """Observed facts, suggestions, required decisions and the invalid draft."""

    root: Path
    project: ProjectObservation
    images: tuple[ContainerfileObservation, ...]
    suggestions: tuple[Note, ...]
    decisions: tuple[Note, ...]
    draft: str

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Return every structural finding, each naming its image."""
        return tuple(
            replace(finding, image=image.image_id)
            for image in self.images
            for finding in image.findings
        )

    def to_dict(self) -> dict[str, object]:
        """Return the public assessment for the JSON result."""
        return {
            "root": str(self.root),
            "observations": {
                "project": self.project.to_dict(),
                "images": [image.to_dict() for image in self.images],
            },
            "suggestions": [note.to_dict() for note in self.suggestions],
            "requiredDecisions": [note.to_dict() for note in self.decisions],
            "draftToml": self.draft,
        }

    def details(self) -> tuple[str, ...]:
        """Return the concise human assessment lines."""
        lines = [
            f"Project {self.project.name}: source "
            + (self.project.source or f"not observed ({self.project.status.value})")
        ]
        for image in self.images:
            pinned = sum(
                item.quality is PinQuality.PINNED for item in image.external_references
            )
            lines.append(
                f"Image {image.image_id} ({image.containerfile}): "
                f"{len(image.external_references)} external input(s), {pinned} pinned; "
                f"USER {image.user.kind.value}"
                + (f" {image.user.raw}" if image.user.raw else "")
                + f"; {len(image.volumes)} VOLUME(s); STOPSIGNAL "
                + (image.stop_signal or "none")
                + "; entrypoint "
                + (
                    "systemd"
                    if image.entrypoint.systemd
                    else image.entrypoint.form.value
                )
                + "; context "
                + ("suggested ." if image.conventional else "undecided")
            )
        for note in self.suggestions:
            lines.append(f"Suggested {note_scope(note)}: {note.text}")
        for note in self.decisions:
            lines.append(f"Decide {note_scope(note)}: {note.text}")
        return tuple(lines)


def assess_repository(
    root: Path, *, containerfiles: tuple[str, ...], git: SourceObserver | None
) -> Assessment:
    """Observe one repository read-only and render its deliberately invalid draft."""
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise InvalidInvocationError(f"Source root does not exist: {root}") from exc
    if not resolved_root.is_dir():
        raise InvalidInvocationError(f"Source root is not a directory: {root}")
    paths = (
        discover_containerfiles(resolved_root)
        if not containerfiles
        else explicit_containerfiles(resolved_root, containerfiles)
    )
    project = observe_project(resolved_root, git)
    image_ids = derive_image_ids(resolved_root, paths)
    images = tuple(
        observe_containerfile(resolved_root, path, image_id=image_id)
        for path, image_id in zip(paths, image_ids, strict=True)
    )
    suggestions, decisions = assessment_notes(project, images)
    draft = render_draft(project, images)
    return Assessment(resolved_root, project, images, suggestions, decisions, draft)
