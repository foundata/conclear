"""Structural observation of Containerfiles and project identity for `adopt`.

Every fact here comes from the same parsers `check` uses. Structural facts
select the proposed runtime profile before the profile-dependent checks run,
so the findings agree with what the draft will propose.
"""

import json
import re
import shlex
from dataclasses import dataclass
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
    conventional: bool
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
            if entry.name == family or (
                entry.name.startswith(family + ".")
                and _is_conventional_name(entry.name)
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
        conventional=path.parent == root and _is_conventional_name(path.name),
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


def _is_conventional_name(name: str) -> bool:
    for family in CONVENTIONAL_NAMES:
        suffix = name.removeprefix(family + ".")
        if name == family or (name != suffix and _SUFFIX_PATTERN.fullmatch(suffix)):
            return True
    return False


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


def derive_image_ids(root: Path, paths: tuple[Path, ...]) -> tuple[str, ...]:
    """Return one distinct, valid image id per Containerfile in the given order."""
    return _unique_image_ids(tuple(_image_id_basis(root, path) for path in paths))
