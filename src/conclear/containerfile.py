"""Byte-aware lexical representation of ConClear's supported Containerfile subset.

This module owns instruction boundaries, builder flags and image-input identity.
It does not evaluate shell commands, build arguments or inherited image metadata.
Policy belongs in `checks`; the supported syntax is documented in ARCHITECTURE.md.
"""

import json
import re
from array import array
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from conclear.errors import InvalidInvocationError
from conclear.fileio import read_regular_file

MAX_CONTAINERFILE_BYTES = 4 * 1024 * 1024
_SPACE = b" \t\v\f\r"
_INSTRUCTION = re.compile(rb"([A-Za-z]+)(?:[ \t\v\f\r]+(.*))?", re.DOTALL)
_DIRECTIVE = re.compile(rb"#[ \t]*(syntax|escape|platform)[ \t]*=(.*)", re.I)
_MOUNT_OPTION = re.compile(rb"[^,]+")
_KEYWORDS = frozenset(
    "ADD ARG CMD COPY ENTRYPOINT ENV EXPOSE FROM HEALTHCHECK LABEL MAINTAINER "
    "RUN SHELL STOPSIGNAL USER VOLUME WORKDIR".split()
)


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """Half-open byte offsets in the original file, not the logical line."""

    start: int
    end: int


@dataclass(frozen=True, slots=True)
class ImageInput:
    """One image operand, classified against previously declared stages.

    A span can include quotes or continuations inside an operand. Pin editing
    must verify that its raw bytes equal `reference` before proposing an edit.
    """

    reference: str
    span: SourceSpan
    external: bool
    numeric_stage: bool


@dataclass(frozen=True, slots=True)
class Instruction:
    """One logical instruction with builder flags separated from its body."""

    keyword: str
    flags: tuple[str, ...]
    body: str
    line_number: int
    end_line_number: int
    stage_name: str | None
    image_inputs: tuple[ImageInput, ...]

    @property
    def exec_command(self) -> tuple[str, ...] | None:
        """Decode a non-empty JSON string array, or return None for shell form."""
        try:
            value = json.loads(self.body)
        except (ValueError, RecursionError):
            return None
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) for item in value)
        ):
            return None
        return tuple(value)


@dataclass(frozen=True, slots=True)
class Containerfile:
    """Immutable interpretation of one bounded source snapshot."""

    path: Path
    content: bytes
    instructions: tuple[Instruction, ...]
    syntax_directive: bool

    @property
    def external_inputs(self) -> tuple[ImageInput, ...]:
        """Return external inputs in source order, including repeats."""
        return tuple(
            item
            for instruction in self.instructions
            for item in instruction.image_inputs
            if item.external
        )

    @property
    def final_stage(self) -> tuple[Instruction, ...]:
        """Return explicitly written instructions in the last stage."""
        start = 0
        for index, instruction in enumerate(self.instructions):
            if instruction.keyword.upper() == "FROM":
                start = index
        return self.instructions[start:]


@dataclass(frozen=True, slots=True)
class _Word:
    value: bytes
    positions: tuple[int, ...]

    def slice(self, start: int, end: int | None = None) -> Self:
        return type(self)(self.value[start:end], self.positions[start:end])


def load_containerfile(path: Path) -> Containerfile:
    """Read one bounded regular file without following a symbolic link."""
    return parse_containerfile(
        read_regular_file(
            path, maximum_bytes=MAX_CONTAINERFILE_BYTES, label="Containerfile"
        ),
        path=path,
    )


def parse_containerfile(content: bytes, *, path: Path) -> Containerfile:
    """Lex exact source bytes once, rejecting ambiguous or unsupported syntax.

    Image-reference expansion is deliberately not performed. Literal references
    and `$` expressions are retained for policy checks and adoption observation.
    """
    if len(content) > MAX_CONTAINERFILE_BYTES:
        raise InvalidInvocationError(f"Containerfile exceeds byte limit: {path}")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidInvocationError(
            f"Containerfile is not valid UTF-8: {path}", code="CC0101"
        ) from exc
    instructions: list[Instruction] = []
    stages: set[str] = set()
    pending = bytearray()
    positions = array("I")
    offset = 0
    start_line = 0
    syntax_directive = False
    continuing = False
    for line_number, physical in enumerate(content.split(b"\n"), start=1):
        line = physical.removesuffix(b"\r")
        if offset == 0 and line.startswith(b"\xef\xbb\xbf"):
            line = line[3:]
        stripped = line.lstrip(_SPACE)
        if stripped.startswith(b"#"):
            directive = _DIRECTIVE.fullmatch(stripped)
            if directive is not None:
                name = directive[1].lower()
                syntax_directive |= name == b"syntax"
                if name == b"platform" or (
                    name == b"escape" and directive[2].strip() != b"\\"
                ):
                    raise _syntax_error(
                        path, line_number, "Non-default parser directive"
                    )
            offset += len(physical) + 1
            continue
        if not stripped:
            offset += len(physical) + 1
            continue
        if not continuing:
            start_line = line_number
            line = stripped
        line_start = offset + len(physical.removesuffix(b"\r")) - len(line)
        trimmed = line.rstrip(b" \t")
        continuing = trimmed.endswith(b"\\")
        if continuing:
            line = trimmed[:-1]
        pending.extend(line)
        positions.extend(range(line_start, line_start + len(line)))
        offset += len(physical) + 1
        if continuing:
            continue
        instruction = _instruction(
            bytes(pending), positions, path, start_line, line_number, stages
        )
        instructions.append(instruction)
        if instruction.stage_name is not None:
            stages.add(instruction.stage_name)
        pending.clear()
        positions = array("I")
    if continuing:
        raise _syntax_error(path, start_line, "Unterminated continuation")
    return Containerfile(path, content, tuple(instructions), syntax_directive)


def _instruction(
    line: bytes,
    positions: array[int],
    path: Path,
    start_line: int,
    end_line: int,
    stages: set[str],
) -> Instruction:
    match = _INSTRUCTION.fullmatch(line.rstrip(_SPACE))
    if match is None:
        raise _syntax_error(path, start_line, "Malformed instruction")
    keyword = match[1].decode("ascii")
    kind = keyword.upper()
    if kind not in _KEYWORDS:
        raise _syntax_error(path, start_line, f"Unsupported instruction {keyword}")
    start = match.start(2) if match[2] is not None else len(line)
    flags, body_start = _builder_flags(line, start, positions, path, start_line)
    body = line[body_start:].strip(_SPACE)
    if kind in {"ADD", "COPY", "RUN"} and not body.startswith(b"[") and b"<<" in body:
        raise _syntax_error(path, start_line, "Heredoc syntax is not supported")
    operands: list[_Word] = []
    stage_name = None
    if kind == "FROM":
        # FROM words are whitespace-delimited; unlike builder flags, quotes are literal.
        words = [
            _Word(
                item[0],
                tuple(positions[body_start + item.start() : body_start + item.end()]),
            )
            for item in re.finditer(rb"[^ \t\v\f\r]+", line[body_start:])
        ]
        if not words or not (
            len(words) == 1 or (len(words) == 3 and words[1].value.upper() == b"AS")
        ):
            raise _syntax_error(path, start_line, "Malformed FROM stage declaration")
        operands.append(words[0])
        if len(words) == 3:
            stage_name = words[2].value.decode("utf-8")
    elif kind in {"COPY", "ADD"}:
        operands = [
            word.slice(7) for word in flags if word.value.startswith(b"--from=")
        ]
        if len(operands) > 1:
            raise _syntax_error(path, start_line, "Duplicate --from flags")
    elif kind == "RUN":
        for flag in flags:
            if not flag.value.startswith(b"--mount="):
                continue
            mount_inputs = [
                flag.slice(item.start() + 5, item.end())
                for item in _MOUNT_OPTION.finditer(flag.value, pos=8)
                if item[0].startswith(b"from=")
            ]
            if len(mount_inputs) > 1:
                raise _syntax_error(path, start_line, "Duplicate mount from options")
            operands.extend(mount_inputs)
    inputs: list[ImageInput] = []
    for word in operands:
        if not word.value:
            raise _syntax_error(path, start_line, "Empty image input")
        reference = word.value.decode("utf-8")
        numeric = kind != "FROM" and reference.isdecimal()
        external = (
            not numeric
            and reference not in stages
            and not (kind == "FROM" and reference == "scratch")
        )
        inputs.append(
            ImageInput(
                reference,
                SourceSpan(word.positions[0], word.positions[-1] + 1),
                external,
                numeric,
            )
        )
    return Instruction(
        keyword,
        tuple(flag.value.decode("utf-8") for flag in flags),
        body.decode("utf-8"),
        start_line,
        end_line,
        stage_name,
        tuple(inputs),
    )


def _builder_flags(
    line: bytes, start: int, positions: array[int], path: Path, line_number: int
) -> tuple[tuple[_Word, ...], int]:
    flags: list[_Word] = []
    index = start
    while index < len(line):
        while index < len(line) and line[index] in _SPACE:
            index += 1
        if not line[index:].startswith(b"--"):
            break
        value = bytearray()
        source: list[int] = []
        quote: int | None = None
        while index < len(line):
            char = line[index]
            if quote is None and char in _SPACE:
                break
            if char == quote:
                quote = None
            elif quote is None and char in b"\"'":
                quote = char
            else:
                if char == ord("\\"):
                    index += 1
                    if index == len(line):
                        raise _syntax_error(
                            path, line_number, "Unterminated flag escape"
                        )
                value.append(line[index])
                source.append(positions[index])
            index += 1
        if quote is not None:
            raise _syntax_error(path, line_number, "Unterminated builder flag quote")
        if value == b"--":
            break
        flags.append(_Word(bytes(value), tuple(source)))
    return tuple(flags), index


def _syntax_error(path: Path, line: int, message: str) -> InvalidInvocationError:
    return InvalidInvocationError(
        f"{message} in Containerfile {path}:{line}; "
        "see the supported Containerfile syntax in ARCHITECTURE.md"
    )
