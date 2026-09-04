"""Structural byte-span location of string values in TOML documents.

The locator walks a TOML document with the same table, array-of-tables,
dotted-key, inline-table and array structure that `tomllib` interprets and
reports the exact byte span of every single-line string value together with
its structural path. It does not reserialize anything, so a caller can replace
one value while preserving every unrelated byte. Multi-line strings and
non-string scalars are skipped; a caller that needs one of them must treat the
document as unsupported. Callers cross-check every located value against the
`tomllib` parse so a document that both parsers do not agree on is rejected.
"""

import re
from dataclasses import dataclass

from conclear.errors import InvalidInvocationError

MAX_TOML_NESTING = 64
_BARE_KEY = re.compile(rb"[A-Za-z0-9_-]+")
_SCALAR_END = frozenset(b",]}#\n\r")
_SIMPLE_ESCAPES = {
    ord("b"): "\b",
    ord("t"): "\t",
    ord("n"): "\n",
    ord("f"): "\f",
    ord("r"): "\r",
    ord('"'): '"',
    ord("\\"): "\\",
}


@dataclass(frozen=True, slots=True)
class TomlStringValue:
    """One single-line string value with its structural path and content span."""

    path: tuple[str | int, ...]
    start: int
    end: int
    value: str


def locate_string_values(data: bytes) -> tuple[TomlStringValue, ...]:
    """Return every single-line string value in structural document order."""
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidInvocationError("TOML document is not valid UTF-8") from exc
    if b"\x00" in data:
        raise InvalidInvocationError("TOML document contains NUL")
    return tuple(_Locator(data).run())


class _Locator:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._index = 0
        self._values: list[TomlStringValue] = []
        self._table: tuple[str | int, ...] = ()
        self._array_counts: dict[tuple[str | int, ...], int] = {}

    def run(self) -> list[TomlStringValue]:
        while self._index < len(self._data):
            self._skip_inline_whitespace()
            if self._at_end():
                break
            current = self._data[self._index]
            if current in b"\r\n":
                self._consume_newline()
            elif current == ord("#"):
                self._skip_comment()
            elif current == ord("["):
                self._parse_header()
                self._end_statement()
            else:
                key = self._parse_key()
                self._skip_inline_whitespace()
                self._expect(b"=")
                self._skip_inline_whitespace()
                self._parse_value((*self._table, *key), depth=0)
                self._end_statement()
        return self._values

    def _at_end(self) -> bool:
        return self._index >= len(self._data)

    def _peek(self, count: int = 1) -> bytes:
        return self._data[self._index : self._index + count]

    def _fail(self, message: str) -> InvalidInvocationError:
        line = self._data.count(b"\n", 0, self._index) + 1
        return InvalidInvocationError(
            f"Unsupported or malformed TOML at line {line}: {message}"
        )

    def _expect(self, literal: bytes) -> None:
        if self._peek(len(literal)) != literal:
            raise self._fail(f"expected {literal.decode('ascii')!r}")
        self._index += len(literal)

    def _skip_inline_whitespace(self) -> None:
        while not self._at_end() and self._data[self._index] in b" \t":
            self._index += 1

    def _skip_comment(self) -> None:
        while not self._at_end() and self._data[self._index] not in b"\r\n":
            self._index += 1

    def _consume_newline(self) -> None:
        if self._peek(2) == b"\r\n":
            self._index += 2
        elif self._peek() == b"\n":
            self._index += 1
        else:
            raise self._fail("expected a line break")

    def _skip_layout(self) -> None:
        """Skip whitespace, comments and line breaks permitted inside arrays."""
        while not self._at_end():
            current = self._data[self._index]
            if current in b" \t":
                self._index += 1
            elif current == ord("#"):
                self._skip_comment()
            elif current in b"\r\n":
                self._consume_newline()
            else:
                return

    def _end_statement(self) -> None:
        self._skip_inline_whitespace()
        if self._at_end():
            return
        if self._data[self._index] == ord("#"):
            self._skip_comment()
        if self._at_end():
            return
        self._consume_newline()

    def _parse_header(self) -> None:
        array = self._peek(2) == b"[["
        self._index += 2 if array else 1
        self._skip_inline_whitespace()
        key = self._parse_key()
        self._skip_inline_whitespace()
        self._expect(b"]]" if array else b"]")
        resolved = self._resolve_prefix(key[:-1])
        full = (*resolved, key[-1])
        if array:
            count = self._array_counts.get(full, 0)
            self._array_counts[full] = count + 1
            self._table = (*full, count)
        else:
            self._table = full

    def _resolve_prefix(self, key: tuple[str, ...]) -> tuple[str | int, ...]:
        resolved: tuple[str | int, ...] = ()
        for part in key:
            resolved = (*resolved, part)
            count = self._array_counts.get(resolved)
            if count is not None:
                resolved = (*resolved, count - 1)
        return resolved

    def _parse_key(self) -> tuple[str, ...]:
        parts: list[str] = []
        while True:
            if self._peek() == b'"':
                _, _, value = self._parse_basic_string()
                parts.append(value)
            elif self._peek() == b"'":
                _, _, value = self._parse_literal_string()
                parts.append(value)
            else:
                match = _BARE_KEY.match(self._data, self._index)
                if match is None:
                    raise self._fail("expected a key")
                parts.append(match.group().decode("ascii"))
                self._index = match.end()
            self._skip_inline_whitespace()
            if self._peek() != b".":
                return tuple(parts)
            self._index += 1
            self._skip_inline_whitespace()

    def _parse_value(self, path: tuple[str | int, ...], *, depth: int) -> None:
        if depth > MAX_TOML_NESTING:
            raise self._fail("nesting limit exceeded")
        if self._peek(3) == b'"""':
            self._skip_multiline(b'"""', escapes=True)
        elif self._peek(3) == b"'''":
            self._skip_multiline(b"'''", escapes=False)
        elif self._peek() == b'"':
            start, end, value = self._parse_basic_string()
            self._values.append(TomlStringValue(path, start, end, value))
        elif self._peek() == b"'":
            start, end, value = self._parse_literal_string()
            self._values.append(TomlStringValue(path, start, end, value))
        elif self._peek() == b"[":
            self._parse_array(path, depth=depth)
        elif self._peek() == b"{":
            self._parse_inline_table(path, depth=depth)
        else:
            self._skip_scalar()

    def _parse_array(self, path: tuple[str | int, ...], *, depth: int) -> None:
        self._expect(b"[")
        index = 0
        while True:
            self._skip_layout()
            if self._peek() == b"]":
                self._index += 1
                return
            self._parse_value((*path, index), depth=depth + 1)
            index += 1
            self._skip_layout()
            if self._peek() == b",":
                self._index += 1
            elif self._peek() != b"]":
                raise self._fail("expected ',' or ']' in array")

    def _parse_inline_table(self, path: tuple[str | int, ...], *, depth: int) -> None:
        self._expect(b"{")
        self._skip_inline_whitespace()
        if self._peek() == b"}":
            self._index += 1
            return
        while True:
            self._skip_inline_whitespace()
            key = self._parse_key()
            self._skip_inline_whitespace()
            self._expect(b"=")
            self._skip_inline_whitespace()
            self._parse_value((*path, *key), depth=depth + 1)
            self._skip_inline_whitespace()
            if self._peek() == b",":
                self._index += 1
            elif self._peek() == b"}":
                self._index += 1
                return
            else:
                raise self._fail("expected ',' or '}' in inline table")

    def _skip_scalar(self) -> None:
        start = self._index
        while not self._at_end() and self._data[self._index] not in _SCALAR_END:
            self._index += 1
        if self._data[start : self._index].strip() == b"":
            raise self._fail("expected a value")

    def _skip_multiline(self, delimiter: bytes, *, escapes: bool) -> None:
        self._index += 3
        while True:
            if self._at_end():
                raise self._fail("unterminated multi-line string")
            if escapes and self._peek() == b"\\":
                self._index += 2
                continue
            if self._peek(3) == delimiter:
                self._index += 3
                while self._peek(1) == delimiter[:1] and self._peek(2) != b"\r\n":
                    self._index += 1
                return
            self._index += 1

    def _parse_basic_string(self) -> tuple[int, int, str]:
        self._expect(b'"')
        start = self._index
        characters: list[str] = []
        while True:
            if self._at_end() or self._data[self._index] in b"\r\n":
                raise self._fail("unterminated string")
            current = self._data[self._index]
            if current == ord('"'):
                end = self._index
                self._index += 1
                return start, end, "".join(characters)
            if current == ord("\\"):
                self._index += 1
                characters.append(self._parse_escape())
                continue
            run_end = self._index
            while run_end < len(self._data) and self._data[run_end] not in b'"\\\r\n':
                run_end += 1
            characters.append(self._data[self._index : run_end].decode("utf-8"))
            self._index = run_end

    def _parse_escape(self) -> str:
        if self._at_end():
            raise self._fail("unterminated escape sequence")
        code = self._data[self._index]
        self._index += 1
        simple = _SIMPLE_ESCAPES.get(code)
        if simple is not None:
            return simple
        if code in (ord("u"), ord("U")):
            width = 4 if code == ord("u") else 8
            digits = self._data[self._index : self._index + width]
            if len(digits) != width or not re.fullmatch(rb"[0-9A-Fa-f]+", digits):
                raise self._fail("invalid unicode escape")
            self._index += width
            try:
                return chr(int(digits, 16))
            except (ValueError, OverflowError) as exc:
                raise self._fail("invalid unicode escape") from exc
        raise self._fail("invalid escape sequence")

    def _parse_literal_string(self) -> tuple[int, int, str]:
        self._expect(b"'")
        start = self._index
        while True:
            if self._at_end() or self._data[self._index] in b"\r\n":
                raise self._fail("unterminated string")
            if self._data[self._index] == ord("'"):
                end = self._index
                self._index += 1
                return start, end, self._data[start:end].decode("utf-8")
            self._index += 1
