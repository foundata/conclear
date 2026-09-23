"""The README supported-tools table is generated from the production policy."""

from pathlib import Path

import pytest

from conclear.errors import OperationalError
from conclear.tool_matrix import (
    BEGIN_MARKER,
    END_MARKER,
    main,
    render_readme,
    render_tool_matrix,
    tool_matrix_is_current,
)
from conclear.tools import SUPPORTED_TOOLS, ToolName


def test_committed_readme_table_matches_the_production_policy() -> None:
    assert tool_matrix_is_current(Path("README.md"))
    assert main(["--check"]) == 0


def test_rendered_table_lists_every_tool_with_interval_exclusions_and_tests() -> None:
    table = render_tool_matrix()
    lines = table.splitlines()

    assert [cell.strip() for cell in lines[0].strip("|").split("|")] == [
        "Tool",
        "Accepted versions",
        "Excluded versions",
        "Real-tool tested versions",
        "Pinned image",
    ]
    assert len(lines) == 2 + len(ToolName)
    for name in ToolName:
        spec = SUPPORTED_TOOLS[name]
        policy = spec.policy
        [row] = [
            line for line in lines if line.startswith(f"| {name.value.capitalize()} ")
        ]
        assert policy.interval in row
        assert all(str(item) in row for item in policy.tested)
        # The pinned repository, never its digest: a reader compares the
        # publisher, and the digest would make the row unreadable.
        image = [cell.strip() for cell in row.strip("|").split("|")][-1]
        assert image == ("none" if spec.image is None else spec.image.reference)
        if spec.image is not None:
            assert spec.image.digest not in row


def test_render_replaces_only_the_marked_block(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        f"before\n\n{BEGIN_MARKER}\n| stale |\n{END_MARKER}\n\nafter\n",
        encoding="utf-8",
    )

    assert not tool_matrix_is_current(readme)
    assert main(["--check", "--readme", str(readme)]) == 1
    assert main(["--readme", str(readme)]) == 0
    text = readme.read_text(encoding="utf-8")
    assert text.startswith("before\n\n" + BEGIN_MARKER + "\n\n|")
    assert "Tool" in text.splitlines()[4]
    assert text.endswith("|\n\n" + END_MARKER + "\n\nafter\n")
    assert "| stale |" not in text
    assert tool_matrix_is_current(readme)


def test_missing_markers_are_an_operational_failure() -> None:
    with pytest.raises(OperationalError, match="markers"):
        render_readme("no markers here\n")
