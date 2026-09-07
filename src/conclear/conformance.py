"""Generate or verify the check-catalog conformance document."""

import argparse
import sys
from pathlib import Path

from conclear.catalog import render_conformance, write_conformance
from conclear.errors import ConClearError
from conclear.guide_requirements import validate_guide_anchors


def main() -> int:
    """Generate docs/conformance.md or verify that it is current."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("docs/conformance.md"))
    parser.add_argument("--guide", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.guide is not None:
            validate_guide_anchors(arguments.guide)
        expected = render_conformance()
    except ConClearError as exc:
        print(str(exc), file=sys.stderr)
        return 1
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
