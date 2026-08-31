import re
from pathlib import Path

from conclear.catalog import (
    CheckCatalog,
    RetiredCheckDefinition,
    load_catalog,
    render_conformance,
    write_conformance,
)
from conclear.conformance import validate_guide_anchors


def test_catalog_identifiers_are_unique_and_stable() -> None:
    catalog = load_catalog()
    identifiers = [
        *(check.check_id for check in catalog.checks),
        *(check.check_id for check in catalog.retired),
    ]
    assert len(identifiers) == len(set(identifiers))
    assert all(re.fullmatch(r"CC[0-9]{4}", identifier) for identifier in identifiers)


def test_every_automated_identifier_is_attached_in_production_code() -> None:
    production_root = Path(__file__).parents[2] / "src" / "conclear"
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in production_root.rglob("*.py")
    )
    missing = sorted(
        check.check_id
        for check in load_catalog().checks
        if check.behavior == "automated" and check.check_id not in source
    )
    assert missing == []


def test_conformance_renders_retired_identifiers_separately() -> None:
    current = load_catalog()
    catalog = CheckCatalog(
        checks=current.checks,
        limits=current.limits,
        retired=(RetiredCheckDefinition("CC0999", "Historical example rule"),),
    )

    rendered = render_conformance(catalog)

    assert "| `CC0999` | Historical example rule |" in rendered
    assert "CC0999" not in rendered.split("## Check catalog", maxsplit=1)[1]


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


def test_catalog_records_unimplemented_optional_scanner_stack() -> None:
    check = next(item for item in load_catalog().checks if item.check_id == "CC0506")
    assert check.behavior == "not implemented"
    assert "Syft and Grype" in check.summary
    assert "| `CC0506` | not implemented | info |" in render_conformance()


def test_committed_conformance_document_is_current() -> None:
    path = Path(__file__).parents[2] / "docs" / "conformance.md"
    assert path.read_text(encoding="utf-8") == render_conformance()
