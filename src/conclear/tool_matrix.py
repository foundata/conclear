"""Render the README supported-tools table from the production tool policy."""

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from conclear import narration
from conclear.errors import ConClearError, OperationalError
from conclear.implementation import aligned_table
from conclear.jsonutil import atomic_write_bytes
from conclear.tools import SUPPORTED_TOOLS, ToolName

LOGGER = logging.getLogger(__name__)

README_PATH = Path("README.md")
BEGIN_MARKER = "<!-- supported-tools:begin -->"
END_MARKER = "<!-- supported-tools:end -->"


def render_tool_matrix() -> str:
    """Render the aligned table of accepted, excluded and tested versions."""
    rows = []
    for name in ToolName:
        policy = SUPPORTED_TOOLS[name].policy
        rows.append(
            (
                name.value.capitalize(),
                policy.interval,
                ", ".join(str(item) for item in sorted(policy.excluded)) or "none",
                ", ".join(str(item) for item in sorted(policy.tested)),
            )
        )
    headers = (
        "Tool",
        "Accepted versions",
        "Excluded versions",
        "Real-tool tested versions",
    )
    return "\n".join(aligned_table(headers, rows)) + "\n"


def render_readme(text: str) -> str:
    """Return the README text with the marked block replaced by the current table."""
    begin = text.find(BEGIN_MARKER)
    end = text.find(END_MARKER)
    if begin < 0 or end < 0 or end < begin:
        raise OperationalError("README.md lacks the supported-tools markers")
    head = text[: begin + len(BEGIN_MARKER)]
    return f"{head}\n\n{render_tool_matrix()}\n{text[end:]}"


def write_tool_matrix(path: Path = README_PATH) -> None:
    """Rewrite the marked README block from the production policy."""
    atomic_write_bytes(path, render_readme(_read(path)).encode("utf-8"), mode=0o644)


def tool_matrix_is_current(path: Path = README_PATH) -> bool:
    """Return whether the committed README block equals the rendered table."""
    text = _read(path)
    return render_readme(text) == text


def main(argv: Sequence[str] | None = None) -> int:
    """Regenerate the README table or verify that it is current."""
    parser = argparse.ArgumentParser(prog="python -m conclear.tool_matrix")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--readme", type=Path, default=README_PATH)
    options = parser.parse_args(argv)
    with narration.to(sys.stderr):
        try:
            if options.check:
                if tool_matrix_is_current(options.readme):
                    LOGGER.info("Checked the tool matrix in %s", options.readme)
                    return 0
                LOGGER.error(
                    "%s is stale; run python -m conclear.tool_matrix", options.readme
                )
                return 1
            write_tool_matrix(options.readme)
        except ConClearError as exc:
            LOGGER.error("%s", exc)
            return int(exc.exit_status)
        LOGGER.info("Wrote the tool matrix into %s", options.readme)
    return 0


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise OperationalError(f"Unable to read {path}") from exc


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
