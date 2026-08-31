"""Static Containerfile, context, pin and repository checks."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from conclear.config import ImageConfig
from conclear.context import MAX_CONTAINERIGNORE_BYTES
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.fileio import read_regular_file
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
_WORLD_WRITABLE_PATTERN = re.compile(
    r"\bchmod\b[^;&\n]*(?:777|666|[2367][2367][2367])\b"
)
_SET_ID_PATTERN = re.compile(r"\bchmod\b[^;&\n]*(?:[2467][0-7]{3}|[ug]\+s)\b")
MAX_CONTAINERFILE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Instruction:
    """One logical Containerfile instruction."""

    keyword: str
    argument: str
    line_number: int


@dataclass(frozen=True, slots=True)
class ContainerfileAnalysis:
    """Parsed facts needed by static policy checks."""

    instructions: tuple[Instruction, ...]
    external_references: tuple[str, ...]
    findings: tuple[Finding, ...]


def analyze_containerfile(path: Path) -> ContainerfileAnalysis:
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
            if _WORLD_WRITABLE_PATTERN.search(argument) or _SET_ID_PATTERN.search(
                argument
            ):
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

    if (
        final_user is None
        or re.fullmatch(r"[1-9][0-9]*(?::[1-9][0-9]*)?", final_user.argument.strip())
        is None
    ):
        user_location = (
            f"{path}:{final_user.line_number}" if final_user is not None else str(path)
        )
        findings.append(
            _finding(
                "CC0110", "Final USER must be a numeric non-root UID", user_location
            )
        )
    if not has_entrypoint and not has_cmd:
        findings.append(
            _finding("CC0111", "Final image must define ENTRYPOINT or CMD", str(path))
        )
    if text.startswith("# syntax=") or "\n# syntax=" in text:
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


def check_image_static(image: ImageConfig) -> tuple[Finding, ...]:
    """Run all hermetic source and context checks for one image."""
    analysis = analyze_containerfile(image.containerfile)
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
        "org.opencontainers.image.created": created,
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
    for key in sorted(required_presence):
        value = labels.get(key)
        if not isinstance(value, str) or not value:
            findings.append(_finding("CC0113", f"Image label {key} is required"))
    return tuple(findings)


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
    except json.JSONDecodeError:
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
    try:
        lines = (
            read_regular_file(
                ignore_path,
                maximum_bytes=MAX_CONTAINERIGNORE_BYTES,
                label=".containerignore",
            )
            .decode("utf-8")
            .splitlines()
        )
    except UnicodeError as exc:
        raise OperationalError(f"Unable to read {ignore_path}") from exc
    patterns = {
        line.strip().rstrip("/")
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    }
    categories = {
        "source control": {".git", ".git/**", "**/.git"},
        "environment files": {".env", ".env*", "**/.env*"},
        "private keys": {"*.key", "*.pem", "**/*.key", "**/*.pem"},
        "local environments": {".venv", ".venv/**", "venv", "venv/**"},
    }
    findings: list[Finding] = []
    for category, accepted_patterns in categories.items():
        if patterns.isdisjoint(accepted_patterns) and "**" not in patterns:
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
