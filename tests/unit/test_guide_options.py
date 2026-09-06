import json
from pathlib import Path

import pytest

import conclear.guide_options as guide_options_module
from conclear.errors import OperationalError
from conclear.guide_options import (
    GuideOption,
    GuideOptionInventory,
    load_guide_options,
    render_guide_options,
    validate_guide_option_anchors,
)
from conclear.identity import GUIDE_REVISION, VERSION

REPOSITORY = Path(__file__).parents[2]


def test_committed_guide_option_document_is_current() -> None:
    assert (REPOSITORY / guide_options_module.INVENTORY_PATH).read_text(
        encoding="utf-8"
    ) == render_guide_options()


def test_guide_options_are_versioned_and_reference_active_checks() -> None:
    raw = json.loads(
        (REPOSITORY / "src/conclear/data/guide-options.json").read_text(
            encoding="utf-8"
        )
    )
    inventory = load_guide_options()

    assert raw["productVersion"] == VERSION
    assert raw["guideRevision"] == GUIDE_REVISION
    assert {item.status for item in inventory.options} == {
        "supported",
        "manual",
        "unsupported",
        "out-of-scope",
    }
    assert {item.option_id for item in inventory.options} == {
        f"GO{index:04d}" for index in range(1, 12)
    }


def test_guide_option_anchors_are_checked_against_selected_guide(
    tmp_path: Path,
) -> None:
    guide = tmp_path / "guide.md"
    guide.write_text(
        '## Users<a id="users-and-runtime-filesystem"></a>\n', encoding="utf-8"
    )
    inventory = GuideOptionInventory(
        (
            GuideOption(
                "GO0001",
                "Root",
                "users-and-runtime-filesystem",
                "supported",
                "Reviewed.",
                "Guide change.",
                ("CC0110",),
            ),
        )
    )

    validate_guide_option_anchors(guide, inventory)

    guide.write_text("# Missing\n", encoding="utf-8")
    with pytest.raises(OperationalError, match="missing OCI guide anchors"):
        validate_guide_option_anchors(guide, inventory)
