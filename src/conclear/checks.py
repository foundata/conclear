"""Static Containerfile, context, pin and repository checks."""

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from conclear.config import SYSTEMD_STOP_SIGNAL, ImageConfig
from conclear.containerfile import Containerfile, Instruction, load_containerfile
from conclear.context import load_containerignore
from conclear.errors import InvalidInvocationError
from conclear.presentation import Finding
from conclear.values import Digest, OCIReference

_CURL_PIPE_PATTERN = re.compile(
    r"\b(?:curl|wget)\b[^|;&]*(?:\||\|&)[ \t]*(?:sh|bash|dash|zsh|python[0-9.]*)\b",
    re.IGNORECASE,
)
_CHMOD_COMMAND_PATTERN = re.compile(r"\bchmod\b(?P<arguments>[^;&\n]*)")


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
    allowed_setid_paths: tuple[str, ...] = (),
) -> ContainerfileAnalysis:
    """Parse a Containerfile and return facts plus rule findings."""
    try:
        source = load_containerfile(path)
    except InvalidInvocationError as exc:
        if exc.code != "CC0101":
            raise
        return ContainerfileAnalysis((), (), (_finding("CC0101", str(exc), str(path)),))
    return analyze_containerfile_source(
        source,
        expected_user=expected_user,
        expected_stop_signal=expected_stop_signal,
        expected_writable_mounts=expected_writable_mounts,
        allowed_setid_paths=allowed_setid_paths,
    )


def analyze_containerfile_source(
    source: Containerfile,
    *,
    expected_user: int | None = None,
    expected_stop_signal: str | None = None,
    expected_writable_mounts: tuple[str, ...] | None = None,
    allowed_setid_paths: tuple[str, ...] = (),
) -> ContainerfileAnalysis:
    """Apply static policy to an already parsed, immutable source snapshot."""
    path = source.path
    content = source.content
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
    instructions = source.instructions
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
        argument = instruction.body
        for image_input in instruction.image_inputs:
            if image_input.numeric_stage:
                findings.append(
                    _finding(
                        "CC0104",
                        "Stage references must use names instead of numeric positions",
                        line_location,
                    )
                )
            elif image_input.external:
                _check_external_reference(
                    image_input.reference, line_location, findings
                )
        if keyword == "FROM":
            final_user = None
            final_stop_signal = None
            final_volumes = []
            has_entrypoint = False
            has_cmd = False
            stage_name = instruction.stage_name
            if stage_name is not None:
                if not re.fullmatch(r"[a-z][a-z0-9_-]*", stage_name):
                    findings.append(
                        _finding(
                            "CC0104",
                            "Stage names must be short lowercase identifiers",
                            line_location,
                        )
                    )
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
        elif keyword == "RUN":
            if _CURL_PIPE_PATTERN.search(argument):
                findings.append(
                    _finding(
                        "CC0108",
                        "Network downloads must not be piped directly to an interpreter",
                        line_location,
                    )
                )
            if _has_unsafe_chmod(argument, allowed_setid_paths):
                findings.append(
                    _finding(
                        "CC0109",
                        "World-writable or undeclared set-ID application modes are prohibited",
                        line_location,
                    )
                )
        elif keyword == "LABEL":
            findings.extend(
                forbidden_label_findings(
                    _label_keys(instruction, source), line_location
                )
            )
        elif keyword == "USER":
            final_user = instruction
        elif keyword == "STOPSIGNAL":
            final_stop_signal = instruction
        elif keyword == "VOLUME":
            final_volumes.extend(
                (volume, line_location)
                for volume in volume_paths(argument, line_location, findings)
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
        else re.fullmatch(r"(?P<uid>0|[1-9][0-9]*)(?::[0-9]+)?", final_user.body)
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
        or normalized_signal(final_stop_signal.body)
        != normalized_signal(expected_stop_signal)
    ):
        stop_location = (
            f"{path}:{final_stop_signal.line_number}"
            if final_stop_signal is not None
            else str(path)
        )
        findings.append(
            _finding(
                "CC0115",
                f"Final STOPSIGNAL must be {expected_stop_signal} for the systemd profile",
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
    if source.syntax_directive:
        findings.append(
            _finding(
                "CC0103", "Docker BuildKit parser directives are prohibited", str(path)
            )
        )
    return ContainerfileAnalysis(
        instructions=instructions,
        external_references=tuple(
            sorted({item.reference for item in source.external_inputs})
        ),
        findings=tuple(findings),
    )


def check_image_static(image: ImageConfig) -> tuple[Finding, ...]:
    """Run all hermetic source and context checks for one image."""
    analysis = analyze_containerfile(
        image.containerfile,
        expected_user=image.runtime.user,
        expected_stop_signal=(
            None if image.runtime.systemd is None else SYSTEMD_STOP_SIGNAL
        ),
        expected_writable_mounts=image.runtime.writable_mounts,
        allowed_setid_paths=image.runtime.setid_paths,
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


# The guide forbids the licenses label (IG0234): its OCI definition covers all
# contained software, which an image on a distribution base cannot state
# truthfully, and the legacy singular key is not a standard annotation at all.
_FORBIDDEN_LABELS = frozenset(
    {
        "org.opencontainers.image.licenses",
        "org.opencontainers.image.license",
        "license",
    }
)
# Buildah stamps its own version unless asked not to; it is not inherited.
_TOOL_LABELS = frozenset({"io.buildah.version"})
BASE_NAME_ANNOTATION = "org.opencontainers.image.base.name"
BASE_DIGEST_ANNOTATION = "org.opencontainers.image.base.digest"
# The base facts are manifest annotations written by the build; the same keys
# as config labels can only have been typed by hand or inherited.
_BASE_LABELS = frozenset({BASE_NAME_ANNOTATION, BASE_DIGEST_ANNOTATION})
# Buildah writes exactly these manifest annotations for a build; anything else
# on a platform manifest was inherited from the base.
_MANIFEST_ANNOTATIONS = frozenset(
    {BASE_NAME_ANNOTATION, BASE_DIGEST_ANNOTATION, "org.opencontainers.image.created"}
)


def _label_keys(
    instruction: Instruction, containerfile: Containerfile
) -> frozenset[str]:
    """Return the label keys one LABEL instruction declares."""
    try:
        words = shlex.split(instruction.body, posix=True)
    except ValueError as exc:
        raise InvalidInvocationError(
            f"Unparseable LABEL instruction at {containerfile.path.name}:"
            f"{instruction.line_number}"
        ) from exc
    if not words:
        return frozenset()
    if all("=" in word for word in words):
        return frozenset(word.split("=", 1)[0] for word in words)
    # Legacy `LABEL key value` form names one key.
    return frozenset({words[0].split("=", 1)[0]})


def declared_label_keys(containerfile: Containerfile) -> frozenset[str]:
    """Return every label key a Containerfile declares in its LABEL instructions."""
    keys: set[str] = set()
    for instruction in containerfile.instructions:
        if instruction.keyword == "LABEL":
            keys.update(_label_keys(instruction, containerfile))
    return frozenset(keys)


def forbidden_label_findings(
    keys: frozenset[str], location: str | None = None
) -> tuple[Finding, ...]:
    """Reject license labels (IG0234) and hand-written base labels (IG0433)."""
    findings: list[Finding] = []
    for key in sorted(keys):
        if key in _FORBIDDEN_LABELS:
            findings.append(
                _finding(
                    "CC0113",
                    f"Image label {key} is forbidden; license information belongs "
                    "in the SBOM and REUSE metadata",
                    location,
                )
            )
        elif key in _BASE_LABELS:
            findings.append(
                _finding(
                    "CC0118",
                    f"Image label {key} must not be written by hand; the build "
                    "derives the base annotations from the pinned FROM reference",
                    location,
                )
            )
    return tuple(findings)


def validate_declared_labels(
    labels: object, containerfile: Containerfile
) -> tuple[Finding, ...]:
    """Reject labels the Containerfile did not declare (IG0431).

    Builds run with label inheritance disabled, so any undeclared key in the
    final image came from somewhere other than the reviewed Containerfile.
    """
    if not isinstance(labels, dict) or any(not isinstance(key, str) for key in labels):
        return (_finding("CC0117", "Image labels are missing or malformed"),)
    declared = declared_label_keys(containerfile)
    return tuple(
        _finding(
            "CC0117",
            f"Image label {key} was not declared by the Containerfile "
            "(inherited from the base image?)",
        )
        for key in sorted(labels)
        if key not in declared and key not in _TOOL_LABELS
    )


def validate_base_annotations(
    annotations: tuple[tuple[str, str], ...],
    *,
    pinned: OCIReference,
    platform_manifest_digest: Digest,
) -> tuple[Finding, ...]:
    """Verify the base annotations of one platform manifest against the pin (IG0432)."""
    values = dict(annotations)
    expected_name = f"{pinned.registry}/{pinned.repository}@{pinned.digest}"
    findings: list[Finding] = []
    if values.get(BASE_NAME_ANNOTATION) != expected_name:
        findings.append(
            _finding(
                "CC0118",
                f"Manifest annotation {BASE_NAME_ANNOTATION} does not name the "
                f"pinned base {expected_name}",
            )
        )
    if values.get(BASE_DIGEST_ANNOTATION) != str(platform_manifest_digest):
        findings.append(
            _finding(
                "CC0118",
                f"Manifest annotation {BASE_DIGEST_ANNOTATION} does not name the "
                f"base platform manifest {platform_manifest_digest}",
            )
        )
    for key in sorted(values):
        if key not in _MANIFEST_ANNOTATIONS:
            findings.append(
                _finding(
                    "CC0118",
                    f"Manifest annotation {key} is not written by the build "
                    "(inherited from the base image?)",
                )
            )
    return tuple(findings)


def validate_scratch_annotations(
    annotations: tuple[tuple[str, str], ...],
) -> tuple[Finding, ...]:
    """Verify the manifest annotations of a build without an external base (IG0432).

    Buildah writes empty `base.name` and `base.digest` annotations for a
    `FROM scratch` build; any value there, or any other annotation besides the
    creation time, was inherited from somewhere the reviewed Containerfile did
    not name.
    """
    findings: list[Finding] = []
    for key, value in annotations:
        if key == "org.opencontainers.image.created":
            continue
        if key in _MANIFEST_ANNOTATIONS and value == "":
            continue
        if key in _MANIFEST_ANNOTATIONS:
            findings.append(
                _finding(
                    "CC0118",
                    f"Manifest annotation {key} names a base for a build without "
                    f"an external base image: {value}",
                )
            )
        else:
            findings.append(
                _finding(
                    "CC0118",
                    f"Manifest annotation {key} is not written by the build "
                    "(inherited from the base image?)",
                )
            )
    return tuple(findings)


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
    required_presence = {"org.opencontainers.image.title"}
    findings: list[Finding] = []
    findings.extend(forbidden_label_findings(frozenset(labels)))
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


def _has_unsafe_chmod(argument: str, allowed_setid_paths: tuple[str, ...] = ()) -> bool:
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
            paths = tokens[tokens.index(mode) + 1 :]
            declared = bool(paths) and all(
                path in allowed_setid_paths for path in paths
            )
            if (
                not declared
                or "-R" in tokens
                or "--recursive" in tokens
                or _unsafe_chmod_mode(mode, allow_setid=True)
            ):
                return True
    return False


def normalized_signal(value: str) -> str:
    """Return a signal name with its `SIG` prefix, the form every check compares."""
    return value if value.startswith("SIG") else f"SIG{value}"


def volume_paths(
    argument: str, location: str, findings: list[Finding]
) -> tuple[str, ...]:
    """Return the destinations one VOLUME instruction declares, in either form."""
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


def _unsafe_chmod_mode(mode: str, *, allow_setid: bool = False) -> bool:
    if re.fullmatch(r"[0-7]{3,5}", mode):
        world_writable = int(mode[-1], 8) & 0o2 != 0
        special = mode[-4] if len(mode) >= 4 else "0"
        return world_writable or (not allow_setid and special in "2467")
    for clause in mode.split(","):
        operation = "+" if "+" in clause else "=" if "=" in clause else None
        if operation is None:
            continue
        who, permissions = clause.split(operation, maxsplit=1)
        affects_world = not who or "a" in who or "o" in who
        if affects_world and "w" in permissions:
            return True
        affects_set_id = not who or "a" in who or "u" in who or "g" in who
        if not allow_setid and affects_set_id and "s" in permissions:
            return True
    return False


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
    if instruction.exec_command is None:
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
