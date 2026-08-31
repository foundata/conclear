"""Generate or verify the check-catalog conformance document."""

import argparse
import re
import sys
from pathlib import Path

from conclear.catalog import (
    CheckCatalog,
    load_catalog,
    render_conformance,
    write_conformance,
)
from conclear.errors import ConClearError, OperationalError
from conclear.fileio import read_regular_file

MAX_GUIDE_BYTES = 1024 * 1024
_EXPLICIT_ANCHOR = re.compile(r'<a id="([a-z0-9-]+)"></a>')


def validate_guide_anchors(path: Path, catalog: CheckCatalog | None = None) -> None:
    """Require every catalog anchor in one selected OCI guide file."""
    try:
        guide = read_regular_file(
            path,
            maximum_bytes=MAX_GUIDE_BYTES,
            label="OCI guide",
        ).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OperationalError("OCI guide is not UTF-8") from exc
    anchors = frozenset(_EXPLICIT_ANCHOR.findall(guide))
    selected = catalog or load_catalog()
    missing = sorted(
        {check.anchor for check in selected.checks if check.anchor not in anchors}
    )
    if missing:
        raise OperationalError(
            "Check catalog references missing OCI guide anchors: " + ", ".join(missing)
        )


def main() -> int:
    """Generate docs/conformance.md or verify that it is current."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("docs/conformance.md"))
    parser.add_argument("--guide", type=Path)
    arguments = parser.parse_args()
    if arguments.guide is not None:
        try:
            validate_guide_anchors(arguments.guide)
        except ConClearError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    expected = render_conformance()
    if arguments.check:
        try:
            observed = arguments.output.read_text(encoding="utf-8")
        except OSError:
            return 1
        return 0 if observed == expected else 1
    write_conformance(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
