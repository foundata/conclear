"""Suggestions, required decisions and the deliberately invalid draft for `adopt`.

Suggestions only restate observed facts or conservative defaults; everything a
maintainer must choose is a decision, and every unresolved draft value is a
`DECIDE` placeholder next to an `[adopt]` table the configuration schema
rejects.
"""

import json
from dataclasses import dataclass

from conclear.config import SYSTEMD_WRITABLE_MOUNTS
from conclear.services.adoption_observation import (
    ContainerfileObservation,
    PinQuality,
    ProjectObservation,
    SourceStatus,
    UserKind,
)

DECIDE = "DECIDE"


_SUGGESTED_RESOURCES = (
    ("memory", '"512MiB"'),
    ("cpus", "1.0"),
    ("pids", "256"),
    ("nofile", "1024"),
)


@dataclass(frozen=True, slots=True)
class Note:
    """One suggestion or one required decision, bound to a draft field."""

    image: str | None
    field: str
    text: str

    def to_dict(self) -> dict[str, object]:
        """Return the public note."""
        return {"image": self.image, "field": self.field, "text": self.text}


def render_draft(
    project: ProjectObservation,
    images: tuple[ContainerfileObservation, ...],
    decisions: tuple[Note, ...],
) -> str:
    """Render the draft `conclear.toml`; it stays invalid while decisions remain."""
    lines = [
        "# Draft written by `conclear adopt`. Every DECIDE value names a maintainer",
        "# decision; resolve all of them, then delete the [adopt] table at the end.",
        "# Until then the draft is deliberately invalid for `check` and `qualify`.",
        "schema_version = 1",
        "",
        "[project]",
        f"name = {_toml(project.name)}",
        f"source = {_toml(project.source or _decide('canonical HTTPS source URL'))}",
    ]
    for image in images:
        lines.extend(("", "[[images]]", f"id = {_toml(image.image_id)}"))
        if image.containerfile != "Containerfile":
            lines.append(f"containerfile = {_toml(image.containerfile)}")
        if not image.conventional:
            lines.append(
                "context = "
                + _toml(
                    _decide("build context directory relative to the repository root")
                )
            )
        lines.extend(
            (
                "# Releasable image: resolve repository and [images.release]. Test-only",
                "# image: delete both, keep only the build inputs, and add this id to a",
                "# depending image's [images.test] dependencies; a test-only image that",
                "# no image depends on is invalid.",
            )
        )
        lines.append(
            "repository = "
            + _toml(
                _decide(
                    "fully qualified release repository, for example quay.io/<owner>/<name>"
                )
            )
        )
        lines.append(
            "platforms = ["
            + _toml(
                _decide(
                    "linux/amd64 is required; add linux/arm64 only when it is built and tested"
                )
            )
            + "]"
        )
        lines.extend(
            (
                "",
                "[images.release]",
                'immutable_tags = ["{version}"]',
                'moving_tags = ["stable"]',
            )
        )
        lines.extend(("", "[images.runtime]", f'profile = "{image.profile}"'))
        lines.append(f"user = {_user_value(image)}")
        writable = _writable_mounts(image)
        if writable:
            lines.append(
                "writable_mounts = ["
                + ", ".join(_toml(item) for item in writable)
                + "]"
            )
        lines.extend(f"{key} = {value}" for key, value in _SUGGESTED_RESOURCES)
        if image.user.kind is UserKind.ROOT or image.profile == "systemd":
            lines.extend(
                (
                    "",
                    "[images.runtime.root_requirement]",
                    f"rationale = {_toml(_decide('why the image must run as UID 0'))}",
                    f"owner = {_toml(_decide('accountable owner'))}",
                    f"review_trigger = {_toml(_decide('what change triggers another review'))}",
                )
            )
        if image.profile == "systemd":
            lines.extend(
                (
                    "",
                    "[images.runtime.systemd]",
                    "required_units = ["
                    + _toml(
                        _decide(
                            "units that must become active, for example multi-user.target"
                        )
                    )
                    + "]",
                )
            )
        for reference in image.external_references:
            if reference.quality is not PinQuality.PINNED:
                continue
            lines.extend(
                (
                    "",
                    "[[images.pins]]",
                    f"reference = {_toml(reference.reference.split('@')[0])}",
                    f"tag_intent = {_toml(_decide('immutable-version or moving-release-line'))}",
                )
            )
    lines.extend(
        (
            "",
            "[adopt]",
            "# Unknown to the configuration schema on purpose: delete this table only",
            "# after every decision above is resolved.",
            "required_decisions = [",
            *(f"  {_toml(note_scope(note))}," for note in decisions),
            "]",
        )
    )
    return "\n".join(lines) + "\n"


def assessment_notes(
    project: ProjectObservation, images: tuple[ContainerfileObservation, ...]
) -> tuple[tuple[Note, ...], tuple[Note, ...]]:
    """Return the suggestions and the required decisions for one assessment."""
    suggestions: list[Note] = []
    decisions: list[Note] = []
    if project.source is None:
        reason = (
            "the Git origin is not a canonical HTTPS or Git SSH URL"
            if project.status is SourceStatus.UNSUPPORTED
            else "no Git origin could be observed"
        )
        decisions.append(
            Note(
                None,
                "project.source",
                f"Declare the canonical HTTPS source URL; {reason}.",
            )
        )
    decisions.append(
        Note(
            None,
            "release profile",
            "Trust roots, signing keys and registry credentials never enter conclear.toml; "
            "create a release profile outside the repository before releasing.",
        )
    )
    if len(images) > 1:
        decisions.append(
            Note(
                None,
                "test.dependencies",
                "Declare which images are test dependencies of which; the draft infers no dependency graph.",
            )
        )
    for image in images:
        suggestions.append(
            Note(
                image.image_id,
                "id",
                f"Use the image id {image.image_id!r} derived from {image.containerfile}.",
            )
        )
        if image.conventional:
            suggestions.append(
                Note(
                    image.image_id,
                    "context",
                    "Use the repository root as the build context; `context` defaults to `.` and the draft omits it.",
                )
            )
        else:
            decisions.append(
                Note(
                    image.image_id,
                    "context",
                    f"Declare the build context directory for {image.containerfile}; a nested or explicitly selected Containerfile does not establish it.",
                )
            )
        decisions.append(
            Note(
                image.image_id,
                "role",
                "Decide whether the image is released or exists only as a test dependency. "
                "Releasable: resolve repository and [images.release]. Test-only: delete both, "
                "keep only the build inputs and list the id in a depending image's "
                "[images.test] dependencies; a test-only image that no image depends on is invalid.",
            )
        )
        decisions.append(
            Note(
                image.image_id,
                "repository",
                "Choose the fully qualified release repository; none is inferred.",
            )
        )
        decisions.append(
            Note(
                image.image_id,
                "platforms",
                "Declare the platforms you build and test; linux/amd64 is required.",
            )
        )
        suggestions.append(
            Note(
                image.image_id,
                "release",
                'Start with immutable_tags = ["{version}"] and moving_tags = ["stable"]; drop {version} for an unversioned project.',
            )
        )
        suggestions.append(
            Note(
                image.image_id,
                "runtime.profile",
                (
                    "The entrypoint starts systemd, so the systemd profile applies."
                    if image.profile == "systemd"
                    else "Start with the service profile; use one-shot for a command that exits."
                ),
            )
        )
        suggestions.append(
            Note(
                image.image_id,
                "runtime.resources",
                "Start with the conservative limits memory 512MiB, cpus 1.0, pids 256 and nofile 1024.",
            )
        )
        _user_notes(image, suggestions, decisions)
        decisions.append(
            Note(
                image.image_id,
                "runtime.privileges",
                "Review sudo presence, inherited set-ID executables and any need for a writable root; declare each requirement separately and test sudo escalation when required.",
            )
        )
        writable = _writable_mounts(image)
        if writable:
            suggestions.append(
                Note(
                    image.image_id,
                    "runtime.writable_mounts",
                    "Declare the VOLUME destinations as writable mounts: "
                    + ", ".join(writable)
                    + ".",
                )
            )
        decisions.append(
            Note(
                image.image_id,
                "runtime.writable_mounts",
                "Confirm the writable paths the application needs; only VOLUME destinations are observed.",
            )
        )
        if image.profile == "systemd":
            decisions.append(
                Note(
                    image.image_id,
                    "runtime.systemd.required_units",
                    "Name the units that must become active.",
                )
            )
            if not image.stop_signal_accepted:
                decisions.append(
                    Note(
                        image.image_id,
                        "STOPSIGNAL",
                        "A systemd image must set STOPSIGNAL SIGRTMIN+3 in its Containerfile.",
                    )
                )
        else:
            decisions.append(
                Note(
                    image.image_id,
                    "runtime.health_command",
                    "Declare a health command for a service, or confirm the image has no readiness signal.",
                )
            )
        for reference in image.external_references:
            if reference.quality is PinQuality.PINNED:
                suggestions.append(
                    Note(
                        image.image_id,
                        "pins",
                        f"Declare {reference.reference} as a pin.",
                    )
                )
                decisions.append(
                    Note(
                        image.image_id,
                        "pins.tag_intent",
                        f"State whether the tag of {reference.reference} is an immutable version or a moving release line.",
                    )
                )
            else:
                decisions.append(
                    Note(
                        image.image_id,
                        "pins",
                        f"Pin {reference.reference} with a fully qualified name, a readable tag and a digest ({reference.quality.value}); it cannot be declared until then.",
                    )
                )
        decisions.append(
            Note(
                image.image_id,
                "test",
                "Declare test inputs, dependencies, hooks and vulnerability exceptions only after review; the draft declares none.",
            )
        )
    return tuple(suggestions), tuple(decisions)


def _user_notes(
    image: ContainerfileObservation,
    suggestions: list[Note],
    decisions: list[Note],
) -> None:
    user = image.user
    if image.profile == "systemd":
        if user.kind is UserKind.ROOT:
            suggestions.append(
                Note(
                    image.image_id,
                    "runtime.user",
                    "Keep the numeric `USER 0`; the systemd profile requires UID 0.",
                )
            )
        elif user.kind is UserKind.MISSING:
            decisions.append(
                Note(
                    image.image_id,
                    "USER",
                    "Add `USER 0` as the final USER; the systemd profile runs as UID 0 "
                    "and the contract requires it to be stated numerically.",
                )
            )
        elif user.kind is UserKind.NAMED:
            decisions.append(
                Note(
                    image.image_id,
                    "USER",
                    f"Replace the named USER {user.raw!r} with the numeric `USER 0`; "
                    "the systemd profile requires UID 0 as a number.",
                )
            )
        else:
            decisions.append(
                Note(
                    image.image_id,
                    "USER",
                    f"Change USER {user.raw} to `USER 0`; the systemd profile requires UID 0.",
                )
            )
        decisions.append(_root_requirement_decision(image))
        return
    if user.kind is UserKind.NUMERIC:
        suggestions.append(
            Note(
                image.image_id,
                "runtime.user",
                f"Keep the numeric UID {user.uid} from the final USER instruction.",
            )
        )
    elif user.kind is UserKind.ROOT:
        decisions.append(_root_requirement_decision(image))
    elif user.kind is UserKind.NAMED:
        decisions.append(
            Note(
                image.image_id,
                "runtime.user",
                f"Replace the named USER {user.raw!r} with the numeric UID it maps to; the contract requires a numeric user.",
            )
        )
    else:
        decisions.append(
            Note(
                image.image_id,
                "runtime.user",
                "Add a final numeric non-root USER; without one the image runs as root.",
            )
        )


def _root_requirement_decision(image: ContainerfileObservation) -> Note:
    return Note(
        image.image_id,
        "runtime.root_requirement",
        "Justify UID 0 with a rationale, an owner and a review trigger"
        + (
            "; the systemd profile cannot run as another user."
            if image.profile == "systemd"
            else ", or switch to a non-root user."
        ),
    )


def _user_value(image: ContainerfileObservation) -> str:
    if image.profile == "systemd":
        return "0"
    if (
        image.user.kind in {UserKind.NUMERIC, UserKind.ROOT}
        and image.user.uid is not None
    ):
        return str(image.user.uid)
    return _toml(_decide("numeric non-root UID of the final USER"))


def _writable_mounts(image: ContainerfileObservation) -> tuple[str, ...]:
    provided = set(SYSTEMD_WRITABLE_MOUNTS) if image.profile == "systemd" else set()
    return tuple(volume for volume in image.volumes if volume not in provided)


def _decide(text: str) -> str:
    return f"{DECIDE}: {text}"


def _toml(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def note_scope(note: Note) -> str:
    """Return the field a note binds, prefixed by its image id when it has one."""
    return note.field if note.image is None else f"{note.image}.{note.field}"
