import re
from pathlib import Path

from conclear.catalog import load_catalog, render_conformance, write_conformance
from conclear.conformance import validate_guide_anchors


def test_catalog_identifiers_are_unique_and_stable() -> None:
    catalog = load_catalog()
    identifiers = [check.check_id for check in catalog.checks]
    assert len(identifiers) == len(set(identifiers))
    assert all(re.fullmatch(r"CC[0-9]{4}", identifier) for identifier in identifiers)


def test_catalog_anchors_exist_in_selected_guide_snapshot() -> None:
    guide = (
        Path(__file__).parents[1] / "fixtures" / "oci-container-image-guide-headings.md"
    )
    validate_guide_anchors(guide)


def test_conformance_generation_is_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "conformance.md"
    write_conformance(path)
    assert path.read_text(encoding="utf-8") == render_conformance()
    assert "909794089dbabbf6c8d8e50fcf47bb2b6fd315b9" in render_conformance()


def test_committed_conformance_document_is_current() -> None:
    path = Path(__file__).parents[2] / "docs" / "conformance.md"
    assert path.read_text(encoding="utf-8") == render_conformance()
