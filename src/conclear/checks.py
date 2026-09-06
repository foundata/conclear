"""Static Containerfile, context, pin and repository checks."""

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from conclear.config import ImageConfig
from conclear.context import load_containerignore
from conclear.errors import InvalidInvocationError
from conclear.fileio import read_regular_file
from conclear.jsonutil import structure_depth_is_bounded
from conclear.presentation import Finding
from conclear.values import OCIReference

_INSTRUCTION_PATTERN = re.compile(
    r"^(?P<keyword>[A-Za-z]+)(?:[ \t]+(?P<argument>.*))?$"
)
_COPY_FROM_PATTERN = re.compile(r"(?:^|\s)--from=(?P<value>[^\s]+)")
_MOUNT_FROM_PATTERN = re.compile(r"--mount=(?P<options>[^\s]+)")
_CURL_PIPE_PATTERN = re.compile(
    r"\b(?:curl|wget)\b[^|;&]*(?:\||\|&)[ \t]*(?:sh|bash|dash|zsh|python[0-9.]*)\b",
    re.IGNORECASE,
)
_CHMOD_COMMAND_PATTERN = re.compile(r"\bchmod\b(?P<arguments>[^;&\n]*)")
_BUILDKIT_SYNTAX_DIRECTIVE = re.compile(
    r"^[ \t]*#[ \t]*syntax[ \t]*=", re.IGNORECASE | re.MULTILINE
)
MAX_CONTAINERFILE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Instruction:
    """One logical Containerfile instruction."""

    keyword: str
    argument: str
    line_number: int
    end_line_number: int


@dataclass(frozen=True, slots=True)
class ReferenceOccurrence:
    """One external image input and the logical instruction that names it."""

    reference: str
    line_number: int
    end_line_number: int


@dataclass(frozen=True, slots=True)
class ContainerfileAnalysis:
    """Parsed facts needed by static policy checks."""

    instructions: tuple[Instruction, ...]
    external_references: tuple[str, ...]
    findings: tuple[Finding, ...]


def analyze_containerfile(
    path: Path,
    *,
    expected_user: int | None = None,
    expected_stop_signal: str | None = None,
    expected_writable_mounts: tuple[str, ...] | None = None,
) -> ContainerfileAnalysis:
    """Parse a Containerfile and return facts plus rule findings."""
    content = read_regular_file(
        path,
        maximum_bytes=MAX_CONTAINERFILE_BYTES,
        label="Containerfile",
    )
    findings: list[Finding] = []
    location = str(path)
    if content.startswith(b"\xef\xbb\xbf"):
        findings.append(
            _finding("CC0101", "Containerfile contains a UTF-8 BOM", location)
        )
    if b"\r" in content or not content.endswith(b"\n"):
        findings.append(
            _finding(
                "CC0101",
                "Containerfile must use Unix line endings and one final newline",
                location,
            )
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        findings.append(
            _finding("CC0101", "Containerfile is not valid UTF-8", location)
        )
        return ContainerfileAnalysis((), (), tuple(findings))

    instructions = _logical_instructions(text, path)
    stage_names: set[str] = set()
    external_references: list[str] = []
    final_user: Instruction | None = None
    final_stop_signal: Instruction | None = None
    final_volumes: list[tuple[str, str]] = []
    has_entrypoint = False
    has_cmd = False

    for instruction in instructions:
        line_location = f"{path}:{instruction.line_number}"
        if instruction.keyword != instruction.keyword.upper():
            findings.append(
                _finding(
                    "CC0102", "Instruction keyword must be uppercase", line_location
                )
            )
        keyword = instruction.keyword.upper()
        argument = instruction.argument.strip()
        if keyword == "FROM":
            final_user = None
            final_stop_signal = None
            final_volumes = []
            reference, stage_name = _parse_from(argument, line_location, findings)
            if reference is not None and reference != "scratch":
                if reference not in stage_names:
                    external_references.append(reference)
                    _check_external_reference(reference, line_location, findings)
            if stage_name is not None:
                if not re.fullmatch(r"[a-z][a-z0-9_-]*", stage_name):
                    findings.append(
                        _finding(
                            "CC0104",
                            "Stage names must be short lowercase identifiers",
                            line_location,
                        )
                    )
                stage_names.add(stage_name)
        elif keyword in {"COPY", "ADD"}:
            if keyword == "ADD" and (
                re.search(r"(?:^|\s)(?:https?|git)://", argument)
                or _looks_like_archive_source(argument)
            ):
                findings.append(
                    _finding(
                        "CC0107",
                        "Use COPY and explicit verified extraction instead of remote or archive ADD",
                        line_location,
                    )
                )
            match = _COPY_FROM_PATTERN.search(argument)
            if match is not None:
                reference = match.group("value")
                if reference.isdecimal():
                    findings.append(
                        _finding(
                            "CC0104",
                            "Stage references must use names instead of numeric positions",
                            line_location,
                        )
                    )
                elif reference not in stage_names:
                    external_references.append(reference)
                    _check_external_reference(reference, line_location, findings)
        elif keyword == "RUN":
            if _CURL_PIPE_PATTERN.search(argument):
                findings.append(
                    _finding(
                        "CC0108",
                        "Network downloads must not be piped directly to an interpreter",
                        line_location,
                    )
                )
            if _has_unsafe_chmod(argument):
                findings.append(
                    _finding(
                        "CC0109",
                        "World-writable and set-ID application modes are prohibited",
                        line_location,
                    )
                )
            for mount_match in _MOUNT_FROM_PATTERN.finditer(argument):
                options = mount_match.group("options").split(",")
                for option in options:
                    key, separator, value = option.partition("=")
                    if key == "from" and separator and value not in stage_names:
                        external_references.append(value)
                        _check_external_reference(value, line_location, findings)
        elif keyword == "USER":
            final_user = instruction
        elif keyword == "STOPSIGNAL":
            final_stop_signal = instruction
        elif keyword == "VOLUME":
            final_volumes.extend(
                (volume, line_location)
                for volume in _volume_paths(argument, line_location, findings)
            )
        elif keyword == "ENTRYPOINT":
            has_entrypoint = True
            _check_exec_form(instruction, findings, path)
        elif keyword == "CMD":
            has_cmd = True
            _check_exec_form(instruction, findings, path)
        elif keyword == "HEALTHCHECK":
            findings.append(
                _finding(
                    "CC0112",
                    "OCI images must define health checks in deployment configuration",
                    line_location,
                )
            )

    user_match = (
        None
        if final_user is None
        else re.fullmatch(
            r"(?P<uid>0|[1-9][0-9]*)(?::[0-9]+)?", final_user.argument.strip()
        )
    )
    valid_user = user_match is not None and (
        (expected_user is None and user_match.group("uid") != "0")
        or (expected_user is not None and int(user_match.group("uid")) == expected_user)
    )
    if not valid_user:
        user_location = (
            f"{path}:{final_user.line_number}" if final_user is not None else str(path)
        )
        requirement = (
            "a numeric non-root UID"
            if expected_user is None
            else f"configured numeric UID {expected_user}"
        )
        findings.append(
            _finding("CC0110", f"Final USER must be {requirement}", user_location)
        )
    if expected_stop_signal is not None and (
        final_stop_signal is None
        or _normalized_signal(final_stop_signal.argument.strip())
        != _normalized_signal(expected_stop_signal)
    ):
        stop_location = (
            f"{path}:{final_stop_signal.line_number}"
            if final_stop_signal is not None
            else str(path)
        )
        findings.append(
            _finding(
                "CC0115",
                f"Final STOPSIGNAL must match configured {expected_stop_signal}",
                stop_location,
            )
        )
    if expected_writable_mounts is not None:
        declared = set(expected_writable_mounts)
        for volume, volume_location in final_volumes:
            if volume not in declared:
                findings.append(
                    _finding(
                        "CC0116",
                        "Final-stage VOLUME destination must be declared in "
                        f"runtime writable_mounts: {volume}",
                        volume_location,
                    )
                )
    if not has_entrypoint and not has_cmd:
        findings.append(
            _finding("CC0111", "Final image must define ENTRYPOINT or CMD", str(path))
        )
    if _BUILDKIT_SYNTAX_DIRECTIVE.search(text):
        findings.append(
            _finding(
                "CC0103", "Docker BuildKit parser directives are prohibited", str(path)
            )
        )
    return ContainerfileAnalysis(
        instructions=instructions,
        external_references=tuple(sorted(set(external_references))),
        findings=tuple(findings),
    )


def external_reference_occurrences(path: Path) -> tuple[ReferenceOccurrence, ...]:
    """Return every external image input in instruction order, including repeats.

    The same structural rules as `analyze_containerfile` apply: `scratch` and
    earlier stage names are not external, `COPY --from` and `ADD --from` name
    one input, and each `RUN --mount=from=` option names one input.
    """
    content = read_regular_file(
        path,
        maximum_bytes=MAX_CONTAINERFILE_BYTES,
        label="Containerfile",
    )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidInvocationError(f"Containerfile is not UTF-8: {path}") from exc
    occurrences: list[ReferenceOccurrence] = []
    stage_names: set[str] = set()
    for instruction in _logical_instructions(text, path):
        keyword = instruction.keyword.upper()
        argument = instruction.argument.strip()
        references: list[str] = []
        if keyword == "FROM":
            reference, stage_name = _parse_from(argument, "", [])
            if reference is not None and reference != "scratch":
                if reference not in stage_names:
                    references.append(reference)
            if stage_name is not None:
                stage_names.add(stage_name)
        elif keyword in {"COPY", "ADD"}:
            match = _COPY_FROM_PATTERN.search(argument)
            if match is not None:
                reference = match.group("value")
                if not reference.isdecimal() and reference not in stage_names:
                    references.append(reference)
        elif keyword == "RUN":
            for mount_match in _MOUNT_FROM_PATTERN.finditer(argument):
                for option in mount_match.group("options").split(","):
                    key, separator, value = option.partition("=")
                    if key == "from" and separator and value not in stage_names:
                        references.append(value)
        occurrences.extend(
            ReferenceOccurrence(
                reference=reference,
                line_number=instruction.line_number,
                end_line_number=instruction.end_line_number,
            )
            for reference in references
        )
    return tuple(occurrences)


def check_image_static(image: ImageConfig) -> tuple[Finding, ...]:
    """Run all hermetic source and context checks for one image."""
    analysis = analyze_containerfile(
        image.containerfile,
        expected_user=image.runtime.user,
        expected_stop_signal=(
            None if image.runtime.systemd is None else image.runtime.systemd.stop_signal
        ),
        expected_writable_mounts=image.runtime.writable_mounts,
    )
    findings = list(analysis.findings)
    findings.extend(_check_context(image.context))
    declared = {str(pin.reference) for pin in image.pins}
    observed = set(analysis.external_references)
    for missing in sorted(observed - declared):
        findings.append(
            _finding("CC0203", f"Containerfile image input is not declared: {missing}")
        )
    for orphaned in sorted(declared - observed):
        findings.append(_finding("CC0203", f"Declared pin is not used: {orphaned}"))
    return tuple(
        sorted(
            findings,
            key=lambda item: (item.check_id, item.location or "", item.message),
        )
    )


def validate_image_labels(
    labels: object,
    *,
    source: str,
    revision: str,
    version: str | None,
    created: str,
) -> tuple[Finding, ...]:
    """Validate final OCI image labels against observed release facts."""
    if not isinstance(labels, dict) or any(not isinstance(key, str) for key in labels):
        return (_finding("CC0113", "Image labels are missing or malformed"),)
    expected = {
        "org.opencontainers.image.source": source,
        "org.opencontainers.image.revision": revision,
    }
    if version is not None:
        expected["org.opencontainers.image.version"] = version
    required_presence = {
        "org.opencontainers.image.licenses",
        "org.opencontainers.image.title",
    }
    findings: list[Finding] = []
    for key, expected_value in expected.items():
        if labels.get(key) != expected_value:
            findings.append(
                _finding(
                    "CC0113", f"Image label {key} does not match observed release data"
                )
            )
    created_label = labels.get("org.opencontainers.image.created")
    if created_label is not None and created_label != created:
        findings.append(
            _finding(
                "CC0113",
                "Image label org.opencontainers.image.created does not match observed release data",
            )
        )
    for key in sorted(required_presence):
        value = labels.get(key)
        if not isinstance(value, str) or not value:
            findings.append(_finding("CC0113", f"Image label {key} is required"))
    return tuple(findings)


def _has_unsafe_chmod(argument: str) -> bool:
    for match in _CHMOD_COMMAND_PATTERN.finditer(argument):
        try:
            tokens = shlex.split(match.group("arguments"), comments=False, posix=True)
        except ValueError:
            continue
        mode = next(
            (
                token
                for token in tokens
                if token == "+w" or token == "+s" or not token.startswith("-")
            ),
            None,
        )
        if mode is not None and _unsafe_chmod_mode(mode):
            return True
    return False


def _normalized_signal(value: str) -> str:
    return value if value.startswith("SIG") else f"SIG{value}"


def _volume_paths(
    argument: str, location: str, findings: list[Finding]
) -> tuple[str, ...]:
    try:
        parsed = (
            json.loads(argument) if argument.startswith("[") else shlex.split(argument)
        )
    except (json.JSONDecodeError, RecursionError, ValueError):
        parsed = None
    if (
        not isinstance(parsed, list)
        or not parsed
        or any(not isinstance(item, str) or not item for item in parsed)
    ):
        findings.append(
            _finding(
                "CC0116",
                "VOLUME must contain one or more literal absolute paths",
                location,
            )
        )
        return ()
    paths = tuple(PurePosixPath(item).as_posix() for item in parsed)
    if any(not item.startswith("/") or "$" in item for item in paths):
        findings.append(
            _finding(
                "CC0116",
                "VOLUME must contain one or more literal absolute paths",
                location,
            )
        )
        return ()
    return paths


def _unsafe_chmod_mode(mode: str) -> bool:
    if re.fullmatch(r"[0-7]{3,5}", mode):
        world_writable = int(mode[-1], 8) & 0o2 != 0
        special = mode[-4] if len(mode) >= 4 else "0"
        return world_writable or special in "2467"
    for clause in mode.split(","):
        operation = "+" if "+" in clause else "=" if "=" in clause else None
        if operation is None:
            continue
        who, permissions = clause.split(operation, maxsplit=1)
        affects_world = not who or "a" in who or "o" in who
        if affects_world and "w" in permissions:
            return True
        affects_set_id = not who or "a" in who or "u" in who or "g" in who
        if affects_set_id and "s" in permissions:
            return True
    return False


def _logical_instructions(text: str, path: Path) -> tuple[Instruction, ...]:
    instructions: list[Instruction] = []
    pending = ""
    start_line = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if not pending:
            start_line = line_number
        segment = raw_line.rstrip()
        continued = segment.endswith("\\")
        segment = segment[:-1] if continued else segment
        pending += segment + (" " if continued else "")
        if continued:
            continue
        match = _INSTRUCTION_PATTERN.fullmatch(pending.strip())
        if match is None:
            raise InvalidInvocationError(
                f"Malformed Containerfile instruction at {path}:{start_line}"
            )
        instructions.append(
            Instruction(
                keyword=match.group("keyword"),
                argument=match.group("argument") or "",
                line_number=start_line,
                end_line_number=line_number,
            )
        )
        pending = ""
    if pending:
        raise InvalidInvocationError(
            f"Unterminated continuation in Containerfile {path}"
        )
    return tuple(instructions)


def _parse_from(
    argument: str,
    location: str,
    findings: list[Finding],
) -> tuple[str | None, str | None]:
    parts = argument.split()
    while parts and parts[0].startswith("--"):
        parts.pop(0)
    if not parts:
        findings.append(
            _finding("CC0104", "FROM is missing an image reference", location)
        )
        return None, None
    reference = parts.pop(0)
    stage_name: str | None = None
    if parts:
        if len(parts) == 2 and parts[0].upper() == "AS":
            stage_name = parts[1]
        else:
            findings.append(
                _finding("CC0104", "Malformed FROM stage declaration", location)
            )
    return reference, stage_name


def _check_external_reference(
    reference: str,
    location: str,
    findings: list[Finding],
) -> None:
    if "$" in reference:
        findings.append(
            _finding(
                "CC0106",
                "External image references cannot depend on build arguments",
                location,
            )
        )
        return
    try:
        OCIReference.parse(reference, require_tag=True, require_digest=True)
    except InvalidInvocationError as exc:
        message = str(exc)
        check_id = "CC0105" if "fully qualified" in message else "CC0106"
        findings.append(_finding(check_id, message, location))


def _check_exec_form(
    instruction: Instruction,
    findings: list[Finding],
    path: Path,
) -> None:
    argument = instruction.argument.strip()
    try:
        value = json.loads(argument)
    except (json.JSONDecodeError, RecursionError):
        value = None
    if not structure_depth_is_bounded(value):
        value = None
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) for item in value)
    ):
        findings.append(
            _finding(
                "CC0111",
                f"{instruction.keyword.upper()} must use non-empty JSON exec form",
                f"{path}:{instruction.line_number}",
            )
        )


def _check_context(context: Path) -> tuple[Finding, ...]:
    ignore_path = context / ".containerignore"
    if not ignore_path.is_file():
        return (
            _finding(
                "CC0201",
                "Build context must contain .containerignore",
                str(ignore_path),
            ),
        )
    ignore = load_containerignore(ignore_path)
    categories = {
        "source control": (".git/config", "nested/.git/config"),
        "environment files": (
            ".env",
            ".env.local",
            "nested/.env",
            "nested/.env.production",
        ),
        "private keys": (
            "release.key",
            "certificate.pem",
            "nested/release.key",
            "nested/certificate.pem",
        ),
        "local environments": (
            ".venv/pyvenv.cfg",
            "venv/pyvenv.cfg",
            "nested/.venv/pyvenv.cfg",
            "nested/venv/pyvenv.cfg",
        ),
    }
    findings: list[Finding] = []
    for category, representatives in categories.items():
        if any(
            not ignore.ignored(PurePosixPath(path), is_directory=False)
            for path in representatives
        ):
            findings.append(
                _finding(
                    "CC0202",
                    f".containerignore does not exclude {category}",
                    str(ignore_path),
                )
            )
    return tuple(findings)


def _looks_like_archive_source(argument: str) -> bool:
    tokens = [token for token in argument.split() if not token.startswith("--")]
    if not tokens:
        return False
    return any(
        token.lower().endswith((".tar", ".tar.gz", ".tgz", ".zip"))
        for token in tokens[:-1]
    )


def _finding(check_id: str, message: str, location: str | None = None) -> Finding:
    return Finding(
        check_id=check_id, severity="error", message=message, location=location
    )
