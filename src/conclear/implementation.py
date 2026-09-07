"""Load, render and verify the versioned implementation promise matrix."""

import argparse
import json
import re
import stat
import sys
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any, cast

from conclear.errors import ConClearError, OperationalError
from conclear.identity import VERSION
from conclear.jsonutil import atomic_write_bytes, structure_depth_is_bounded

MATRIX_SCHEMA_VERSION = 1
MATRIX_PATH = Path(f"docs/implementation-{VERSION}.md")
ARCHITECTURE_PATH = Path("ARCHITECTURE.md")
MATRIX_REFERENCE_PATHS = (
    ARCHITECTURE_PATH,
    Path("README.md"),
    Path("DEVELOPMENT.md"),
    Path("docs/quickstart.md"),
)
_PROMISE_ID = re.compile(r"IP[0-9]{4}")
_PROMISE_ANCHOR = re.compile(r'<a id="promise-(ip[0-9]{4})"></a>')
_TIERS = frozenset({"unit", "local_integration", "emulation", "network"})


@dataclass(frozen=True, slots=True)
class TestReference:
    """One test module and the tier in which it runs."""

    path: str
    tier: str


@dataclass(frozen=True, slots=True)
class ImplementationPromise:
    """One current architectural promise and its implementation evidence."""

    promise_id: str
    summary: str
    implementation: tuple[str, ...]
    tests: tuple[TestReference, ...]

    @property
    def anchor(self) -> str:
        """Return the matching architecture anchor."""
        return f"promise-{self.promise_id.lower()}"


@dataclass(frozen=True, slots=True)
class ImplementationMatrix:
    """The complete implementation inventory for one product contract."""

    product_version: str
    promises: tuple[ImplementationPromise, ...]


def load_implementation_matrix() -> ImplementationMatrix:
    """Load and structurally validate the shipped implementation inventory."""
    resource = files("conclear.data").joinpath("implementation.json")
    try:
        untrusted: Any = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OperationalError("Unable to load the implementation matrix") from exc
    if not isinstance(untrusted, dict) or not structure_depth_is_bounded(untrusted):
        raise OperationalError("Implementation matrix must be a JSON object")
    if untrusted.get("schemaVersion") != MATRIX_SCHEMA_VERSION:
        raise OperationalError("Unsupported implementation matrix schema")
    if untrusted.get("productVersion") != VERSION:
        raise OperationalError(
            "Implementation matrix product version does not match the build"
        )
    values = untrusted.get("promises")
    if not isinstance(values, list) or not values:
        raise OperationalError("Implementation matrix promises are malformed")

    promises = tuple(_promise(value) for value in values)
    identifiers = tuple(item.promise_id for item in promises)
    if len(identifiers) != len(set(identifiers)):
        raise OperationalError("Implementation promise identifiers must be unique")
    if identifiers != tuple(sorted(identifiers)):
        raise OperationalError("Implementation promises must be ordered by identifier")
    return ImplementationMatrix(VERSION, promises)


def validate_implementation_links(
    repository: Path, matrix: ImplementationMatrix | None = None
) -> None:
    """Require every promise anchor, implementation and test reference to exist."""
    try:
        root = repository.resolve(strict=True)
    except OSError as exc:
        raise OperationalError(
            f"Implementation matrix repository is unavailable: {repository}"
        ) from exc
    selected = matrix or load_implementation_matrix()
    architecture = _regular_repository_file(root, str(ARCHITECTURE_PATH))
    try:
        text = architecture.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise OperationalError("Unable to read the architecture contract") from exc
    observed = tuple(match.upper() for match in _PROMISE_ANCHOR.findall(text))
    expected = tuple(item.promise_id for item in selected.promises)
    if observed != expected:
        raise OperationalError(
            "Architecture promise anchors do not match the implementation matrix"
        )
    if f"./{MATRIX_PATH.as_posix()}" not in text:
        raise OperationalError(
            "Architecture does not link the current implementation matrix"
        )
    for reference_path in MATRIX_REFERENCE_PATHS[1:]:
        documentation = _regular_repository_file(root, str(reference_path))
        try:
            reference_text = documentation.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise OperationalError(
                f"Unable to read implementation matrix reference: {reference_path}"
            ) from exc
        if MATRIX_PATH.name not in reference_text:
            raise OperationalError(
                f"{reference_path} does not link the current implementation matrix"
            )
    for promise in selected.promises:
        for implementation_path in promise.implementation:
            _regular_repository_file(root, implementation_path, prefix="src/conclear/")
        for test_reference in promise.tests:
            prefix = {
                "unit": "tests/unit/",
                "local_integration": "tests/local_integration/",
                "emulation": "tests/local_integration/",
                "network": "tests/network/",
            }[test_reference.tier]
            _regular_repository_file(root, test_reference.path, prefix=prefix)


def render_implementation_matrix(
    matrix: ImplementationMatrix | None = None,
) -> str:
    """Render the deterministic, reviewable implementation matrix."""
    selected = matrix or load_implementation_matrix()
    lines = [
        f"# ConClear {selected.product_version} implementation matrix",
        "",
        "<!-- Generated by python -m conclear.implementation. Do not edit by hand. -->",
        "",
        *textwrap.wrap(
            "This matrix enumerates the current behavioral promises marked in "
            "[`ARCHITECTURE.md`](../ARCHITECTURE.md). Each implementation promise "
            "(IP) links to its production implementation and the test tiers that "
            "verify it. The release gate checks the inventory, its links and the "
            "generated document before building a distribution; the embedded "
            "source revision identifies the exact released implementation.",
            width=80,
            break_long_words=False,
            break_on_hyphens=False,
        ),
        "",
    ]
    rows = [
        (
            f"`{promise.promise_id}`",
            _escape(promise.summary),
            f"[contract](../ARCHITECTURE.md#{promise.anchor})",
            "<br>".join(
                _markdown_link(reference) for reference in promise.implementation
            ),
            "<br>".join(
                f"`{reference.tier}`: {_markdown_link(reference.path)}"
                for reference in promise.tests
            ),
        )
        for promise in selected.promises
    ]
    lines.extend(
        aligned_table(
            (
                "Promise",
                "Current behavior",
                "Architecture",
                "Implementation",
                "Verification",
            ),
            rows,
        )
    )
    return "\n".join(lines) + "\n"


def aligned_table(
    headers: tuple[str, ...], rows: Sequence[tuple[str, ...]]
) -> list[str]:
    """Render a table in the Markdown guide's aligned style.

    Every column but the last is padded to its widest cell, header text is
    centered with any odd space on the right, body cells are left-aligned and
    the last column is padded only up to its header width.
    """
    last = len(headers) - 1
    widths = [
        len(header)
        if index == last
        else max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]

    def centered(cell: str, width: int) -> str:
        padding = max(width - len(cell), 0)
        left = padding // 2
        return " " * left + cell + " " * (padding - left)

    def render(cells: tuple[str, ...]) -> str:
        return (
            "| "
            + " | ".join(
                cell.ljust(width) for cell, width in zip(cells, widths, strict=True)
            )
            + " |"
        )

    return [
        "| "
        + " | ".join(
            centered(header, width)
            for header, width in zip(headers, widths, strict=True)
        )
        + " |",
        "| " + " | ".join("-" * width for width in widths) + " |",
        *(render(row) for row in rows),
    ]


def write_implementation_matrix(path: Path) -> None:
    """Write the generated implementation matrix atomically."""
    atomic_write_bytes(path, render_implementation_matrix().encode("utf-8"), mode=0o644)


def main() -> int:
    """Generate the implementation matrix or verify the committed copy."""
    parser = argparse.ArgumentParser(
        prog="python -m conclear.implementation",
        description="Render or verify the versioned implementation promise matrix.",
    )
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=MATRIX_PATH)
    parser.add_argument("--repository", type=Path, default=Path())
    arguments = parser.parse_args()
    try:
        selected = load_implementation_matrix()
        validate_implementation_links(arguments.repository, selected)
        expected = render_implementation_matrix(selected)
    except ConClearError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if arguments.check:
        try:
            observed = arguments.output.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            print(
                f"Implementation matrix is missing: {arguments.output}", file=sys.stderr
            )
            return 1
        if observed != expected:
            print(
                "Implementation matrix is stale; review the change and regenerate it "
                "with `uv run python -m conclear.implementation`",
                file=sys.stderr,
            )
            return 1
        return 0
    atomic_write_bytes(arguments.output, expected.encode("utf-8"), mode=0o644)
    return 0


def _promise(value: object) -> ImplementationPromise:
    if not isinstance(value, dict) or set(value) != {
        "id",
        "summary",
        "implementation",
        "tests",
    }:
        raise OperationalError("Implementation matrix contains a malformed promise")
    item_value = cast(dict[str, object], value)
    promise_id = _string(item_value, "id")
    if _PROMISE_ID.fullmatch(promise_id) is None:
        raise OperationalError("Implementation promise identifiers must match IPnnnn")
    implementation = _string_array(item_value.get("implementation"), "implementation")
    tests_value = item_value.get("tests")
    if not isinstance(tests_value, list) or not tests_value:
        raise OperationalError("Implementation promise tests are malformed")
    tests: list[TestReference] = []
    for item in tests_value:
        if not isinstance(item, dict) or set(item) != {"path", "tier"}:
            raise OperationalError("Implementation promise test is malformed")
        test_value = cast(dict[str, object], item)
        tier = _string(test_value, "tier")
        if tier not in _TIERS:
            raise OperationalError("Implementation promise test tier is unsupported")
        tests.append(TestReference(_string(test_value, "path"), tier))
    if len(tests) != len(set(tests)):
        raise OperationalError("Implementation promise tests contain duplicates")
    return ImplementationPromise(
        promise_id,
        _string(item_value, "summary"),
        implementation,
        tuple(tests),
    )


def _string(value: dict[str, object], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected or "\n" in selected:
        raise OperationalError(f"Implementation matrix field {key} is malformed")
    return selected


def _string_array(value: object, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise OperationalError(f"Implementation promise {label} is malformed")
    result = tuple(cast(str, item) for item in value)
    if len(result) != len(set(result)):
        raise OperationalError(f"Implementation promise {label} contains duplicates")
    return result


def _regular_repository_file(root: Path, value: str, *, prefix: str = "") -> Path:
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or value != pure.as_posix()
        or ".." in pure.parts
        or (prefix and not value.startswith(prefix))
    ):
        raise OperationalError(f"Unsafe implementation matrix path: {value}")
    path = root.joinpath(*pure.parts)
    try:
        observed = path.lstat()
    except OSError as exc:
        raise OperationalError(
            f"Implementation matrix path is unavailable: {value}"
        ) from exc
    if not stat.S_ISREG(observed.st_mode):
        raise OperationalError(
            f"Implementation matrix path is not a regular file: {value}"
        )
    return path


def _markdown_link(value: str) -> str:
    return f"[`{PurePosixPath(value).name}`](../{value})"


def _escape(value: str) -> str:
    return value.replace("|", "\\|")


if __name__ == "__main__":
    raise SystemExit(main())
