"""Read-only adoption assessment of an existing container repository.

`conclear adopt` observes what a repository already states, suggests
conservative values a maintainer may accept, and lists the decisions only a
maintainer can make. It resolves no registry, writes nothing below the
repository and invents no destination, platform, root justification, writable
path, health behavior, test input, hook, exception or credential. The draft it
renders is deliberately invalid until every decision is resolved, so it cannot
pass `check` or `qualify` by accident.
"""

import json
import re
import shlex
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from conclear.adapters.git import SourceObservation
from conclear.checks import (
    Instruction,
    analyze_containerfile,
    normalized_signal,
    parse_containerfile,
    volume_paths,
)
from conclear.config import (
    SYSTEMD_STOP_SIGNAL,
    SYSTEMD_WRITABLE_MOUNTS,
    normalize_observed_source_url,
)
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.path_safety import contained_path
from conclear.presentation import Finding
from conclear.values import OCIReference

CONVENTIONAL_NAMES = ("Containerfile", "Dockerfile")
DECIDE = "DECIDE"
_SUFFIX_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
_IMAGE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SYSTEMD_EXECUTABLES = frozenset(
    {
        "/sbin/init",
        "/usr/sbin/init",
        "/lib/systemd/systemd",
        "/usr/lib/systemd/systemd",
        "/usr/bin/systemd",
        "systemd",
    }
)
_SUGGESTED_RESOURCES = (
    ("memory", '"512MiB"'),
    ("cpus", "1.0"),
    ("pids", "256"),
    ("nofile", "1024"),
)


class SourceObserver(Protocol):
    """The read-only part of the Git adapter the assessment uses."""

    def observe(self, repository: Path, selector: str) -> SourceObservation:
        """Observe the revision, origin URL and commit time of a selector."""
        ...


class PinQuality(StrEnum):
    """How completely one external image input is pinned."""

    PINNED = "pinned"
    TAG_ONLY = "tag-only"
    DIGEST_ONLY = "digest-only"
    UNTAGGED = "untagged"
    UNQUALIFIED = "unqualified"
    BUILD_ARGUMENT = "build-argument"


class UserKind(StrEnum):
    """Classification of the final-stage USER instruction.

    `ROOT` is the numeric UID 0 the systemd contract requires; `USER root` is a
    named user like any other and is classified as `NAMED`.
    """

    NUMERIC = "numeric"
    NAMED = "named"
    ROOT = "root"
    MISSING = "missing"


class EntrypointForm(StrEnum):
    """Form of the final-stage ENTRYPOINT or CMD instruction."""

    EXEC = "exec"
    SHELL = "shell"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class ExternalReference:
    """One external image input and its pin quality."""

    reference: str
    registry: str | None
    repository: str | None
    tag: str | None
    digest: str | None
    quality: PinQuality

    def to_dict(self) -> dict[str, object]:
        """Return the public observation."""
        return {
            "reference": self.reference,
            "registry": self.registry,
            "repository": self.repository,
            "tag": self.tag,
            "digest": self.digest,
            "pinQuality": self.quality.value,
        }


@dataclass(frozen=True, slots=True)
class FinalUser:
    """The final-stage USER instruction as observed."""

    raw: str | None
    uid: int | None
    kind: UserKind

    def to_dict(self) -> dict[str, object]:
        """Return the public observation."""
        return {"raw": self.raw, "uid": self.uid, "kind": self.kind.value}


@dataclass(frozen=True, slots=True)
class Entrypoint:
    """The final-stage process the image starts."""

    instruction: str | None
    command: tuple[str, ...]
    form: EntrypointForm
    systemd: bool

    def to_dict(self) -> dict[str, object]:
        """Return the public observation."""
        return {
            "instruction": self.instruction,
            "command": list(self.command),
            "form": self.form.value,
            "systemd": self.systemd,
        }


@dataclass(frozen=True, slots=True)
class ContainerfileObservation:
    """Facts observed from one Containerfile without building it."""

    image_id: str
    containerfile: str
    context: str
    external_references: tuple[ExternalReference, ...]
    user: FinalUser
    volumes: tuple[str, ...]
    stop_signal: str | None
    labels: tuple[tuple[str, str], ...]
    entrypoint: Entrypoint
    profile: str
    findings: tuple[Finding, ...]

    @property
    def stop_signal_accepted(self) -> bool:
        """Return whether the observed STOPSIGNAL is the fixed systemd signal."""
        return self.stop_signal is not None and normalized_signal(
            self.stop_signal
        ) == normalized_signal(SYSTEMD_STOP_SIGNAL)

    def to_dict(self) -> dict[str, object]:
        """Return the public observation."""
        return {
            "id": self.image_id,
            "containerfile": self.containerfile,
            "context": self.context,
            "externalReferences": [item.to_dict() for item in self.external_references],
            "user": self.user.to_dict(),
            "volumes": list(self.volumes),
            "stopSignal": self.stop_signal,
            "labels": dict(self.labels),
            "entrypoint": self.entrypoint.to_dict(),
        }


class SourceStatus(StrEnum):
    """Whether the canonical source identity could be observed."""

    OBSERVED = "observed"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ProjectObservation:
    """Project identity observed from the directory and Git."""

    name: str
    source: str | None
    revision: str | None
    status: SourceStatus

    def to_dict(self) -> dict[str, object]:
        """Return the public observation."""
        return {
            "name": self.name,
            "source": self.source,
            "revision": self.revision,
            "sourceStatus": self.status.value,
        }


@dataclass(frozen=True, slots=True)
class Note:
    """One suggestion or one required decision, bound to a draft field."""

    image: str | None
    field: str
    text: str

    def to_dict(self) -> dict[str, object]:
        """Return the public note."""
        return {"image": self.image, "field": self.field, "text": self.text}


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
            )
        for note in self.suggestions:
            lines.append(f"Suggested {_scope(note)}: {note.text}")
        for note in self.decisions:
            lines.append(f"Decide {_scope(note)}: {note.text}")
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
    image_ids = _unique_image_ids(
        tuple(_image_id_basis(resolved_root, path) for path in paths)
    )
    images = tuple(
        observe_containerfile(resolved_root, path, image_id=image_id)
        for path, image_id in zip(paths, image_ids, strict=True)
    )
    suggestions, decisions = _notes(project, images)
    draft = render_draft(project, images, decisions)
    return Assessment(resolved_root, project, images, suggestions, decisions, draft)


def discover_containerfiles(root: Path) -> tuple[Path, ...]:
    """Return the conventional Containerfiles at the repository root.

    Only `Containerfile`, `Containerfile.<name>`, `Dockerfile` and
    `Dockerfile.<name>` directly below the root are conventional. Symbolic
    links are ignored. Finding both families, or none, is ambiguous and needs
    explicit paths.
    """
    families: dict[str, list[Path]] = {name: [] for name in CONVENTIONAL_NAMES}
    for entry in sorted(root.iterdir(), key=lambda item: item.name):
        if entry.is_symlink() or not entry.is_file():
            continue
        for family in CONVENTIONAL_NAMES:
            suffix = entry.name.removeprefix(family + ".")
            if entry.name == family or (
                entry.name != suffix and _SUFFIX_PATTERN.fullmatch(suffix)
            ):
                families[family].append(entry)
    present = [candidates for candidates in families.values() if candidates]
    if not present:
        raise InvalidInvocationError(
            f"No conventional Containerfile found in {root}; pass --containerfile"
        )
    if len(present) > 1:
        names = ", ".join(path.name for candidates in present for path in candidates)
        raise InvalidInvocationError(
            f"Containerfile discovery is ambiguous ({names}); pass --containerfile"
        )
    return tuple(present[0])


def explicit_containerfiles(root: Path, values: tuple[str, ...]) -> tuple[Path, ...]:
    """Confine caller-supplied Containerfile paths below the repository root."""
    paths: list[Path] = []
    for value in values:
        path = contained_path(root, value)
        if not path.is_file():
            raise InvalidInvocationError(
                f"Containerfile is not a regular file: {value}"
            )
        if path in paths:
            raise InvalidInvocationError(f"Containerfile is named twice: {value}")
        paths.append(path)
    return tuple(paths)


def observe_project(root: Path, git: SourceObserver | None) -> ProjectObservation:
    """Observe the project name and, when Git can state it, the canonical source."""
    name = root.name or "project"
    if git is None:
        return ProjectObservation(name, None, None, SourceStatus.UNAVAILABLE)
    try:
        observation = git.observe(root, "HEAD")
    except OperationalError:
        return ProjectObservation(name, None, None, SourceStatus.UNAVAILABLE)
    try:
        source = normalize_observed_source_url(observation.remote_url)
    except InvalidInvocationError:
        return ProjectObservation(
            name, None, observation.revision, SourceStatus.UNSUPPORTED
        )
    return ProjectObservation(name, source, observation.revision, SourceStatus.OBSERVED)


def observe_containerfile(
    root: Path, path: Path, *, image_id: str
) -> ContainerfileObservation:
    """Observe one Containerfile through the structural analysis used by `check`.

    Structural facts come first and select the proposed runtime profile; the
    profile-dependent checks then run with the expectations that profile sets,
    so the findings agree with the suggestions, decisions and draft values.
    """
    user: Instruction | None = None
    stop_signal: Instruction | None = None
    entrypoint: Instruction | None = None
    command: Instruction | None = None
    volumes: list[str] = []
    labels: dict[str, str] = {}
    for instruction in parse_containerfile(path):
        keyword = instruction.keyword.upper()
        argument = instruction.argument.strip()
        if keyword == "FROM":
            user = stop_signal = entrypoint = command = None
            volumes = []
            labels = {}
        elif keyword == "USER":
            user = instruction
        elif keyword == "STOPSIGNAL":
            stop_signal = instruction
        elif keyword == "VOLUME":
            volumes.extend(
                volume_paths(argument, f"{path}:{instruction.line_number}", [])
            )
        elif keyword == "LABEL":
            labels.update(_labels(argument))
        elif keyword == "ENTRYPOINT":
            entrypoint = instruction
        elif keyword == "CMD":
            command = instruction
    final_user = _final_user(user)
    final_entrypoint = _entrypoint(entrypoint or command)
    final_volumes = tuple(dict.fromkeys(volumes))
    profile = "systemd" if final_entrypoint.systemd else "service"
    if profile == "systemd":
        expected_user: int | None = 0
        expected_stop_signal: str | None = SYSTEMD_STOP_SIGNAL
        expected_writable = tuple(sorted({*final_volumes, *SYSTEMD_WRITABLE_MOUNTS}))
    else:
        expected_user = (
            final_user.uid
            if final_user.kind in {UserKind.NUMERIC, UserKind.ROOT}
            else None
        )
        expected_stop_signal = None
        expected_writable = final_volumes
    analysis = analyze_containerfile(
        path,
        expected_user=expected_user,
        expected_stop_signal=expected_stop_signal,
        expected_writable_mounts=expected_writable,
    )
    return ContainerfileObservation(
        image_id=image_id,
        containerfile=path.relative_to(root).as_posix(),
        context=".",
        external_references=tuple(
            _external_reference(reference) for reference in analysis.external_references
        ),
        user=final_user,
        volumes=final_volumes,
        stop_signal=None if stop_signal is None else stop_signal.argument.strip(),
        labels=tuple(sorted(labels.items())),
        entrypoint=final_entrypoint,
        profile=profile,
        findings=analysis.findings,
    )


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
                    f"reference = {_toml(reference.reference)}",
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
            *(f"  {_toml(_scope(note))}," for note in decisions),
            "]",
        )
    )
    return "\n".join(lines) + "\n"


def _notes(
    project: ProjectObservation, images: tuple[ContainerfileObservation, ...]
) -> tuple[tuple[Note, ...], tuple[Note, ...]]:
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
    for image in images:
        suggestions.append(
            Note(
                image.image_id,
                "id",
                f"Use the image id {image.image_id!r} derived from {image.containerfile}.",
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


def _external_reference(reference: str) -> ExternalReference:
    if "$" in reference:
        return ExternalReference(
            reference, None, None, None, None, PinQuality.BUILD_ARGUMENT
        )
    try:
        parsed = OCIReference.parse(reference)
    except InvalidInvocationError:
        return ExternalReference(
            reference, None, None, None, None, PinQuality.UNQUALIFIED
        )
    if parsed.tag is not None and parsed.digest is not None:
        quality = PinQuality.PINNED
    elif parsed.digest is not None:
        quality = PinQuality.DIGEST_ONLY
    elif parsed.tag is not None:
        quality = PinQuality.TAG_ONLY
    else:
        quality = PinQuality.UNTAGGED
    return ExternalReference(
        reference,
        parsed.registry,
        parsed.repository,
        parsed.tag,
        None if parsed.digest is None else str(parsed.digest),
        quality,
    )


def _final_user(instruction: Instruction | None) -> FinalUser:
    if instruction is None:
        return FinalUser(None, None, UserKind.MISSING)
    raw = instruction.argument.strip()
    user_part = raw.split(":", 1)[0]
    if user_part.isdecimal():
        uid = int(user_part)
        return FinalUser(raw, uid, UserKind.ROOT if uid == 0 else UserKind.NUMERIC)
    return FinalUser(raw, None, UserKind.NAMED)


def _entrypoint(instruction: Instruction | None) -> Entrypoint:
    if instruction is None:
        return Entrypoint(None, (), EntrypointForm.MISSING, False)
    argument = instruction.argument.strip()
    keyword = instruction.keyword.upper()
    try:
        value = json.loads(argument)
    except (json.JSONDecodeError, RecursionError):
        value = None
    if (
        isinstance(value, list)
        and value
        and all(isinstance(item, str) for item in value)
    ):
        command = tuple(str(item) for item in value)
        form = EntrypointForm.EXEC
    else:
        try:
            command = tuple(shlex.split(argument))
        except ValueError:
            command = (argument,)
        form = EntrypointForm.SHELL
    executable = command[0] if command else ""
    systemd = executable in _SYSTEMD_EXECUTABLES or Path(executable).name == "systemd"
    return Entrypoint(keyword, command, form, systemd)


def _labels(argument: str) -> dict[str, str]:
    try:
        tokens = shlex.split(argument)
    except ValueError:
        return {}
    labels: dict[str, str] = {}
    pending: str | None = None
    for token in tokens:
        if pending is not None:
            labels[pending] = token
            pending = None
            continue
        key, separator, value = token.partition("=")
        if separator:
            labels[key] = value
        else:
            pending = key
    return labels


def _image_id_basis(root: Path, path: Path) -> str:
    name = path.name
    for family in CONVENTIONAL_NAMES:
        if name == family:
            return root.name
        if name.startswith(family + "."):
            return name[len(family) + 1 :]
    return path.stem


def _unique_image_ids(bases: tuple[str, ...]) -> tuple[str, ...]:
    ids: list[str] = []
    for base in bases:
        candidate = re.sub(r"[^a-z0-9_-]+", "-", base.lower()).strip("-_")[:64] or "app"
        if _IMAGE_ID_PATTERN.fullmatch(candidate) is None:
            candidate = "app"
        unique = candidate
        counter = 2
        while unique in ids:
            unique = f"{candidate[:60]}-{counter}"
            counter += 1
        ids.append(unique)
    return tuple(ids)


def _decide(text: str) -> str:
    return f"{DECIDE}: {text}"


def _toml(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _scope(note: Note) -> str:
    return note.field if note.image is None else f"{note.image}.{note.field}"
