from pathlib import Path

from conclear.catalog import load_catalog, render_conformance, write_conformance


def test_catalog_identifiers_are_unique_and_stable() -> None:
    catalog = load_catalog()
    identifiers = [check.check_id for check in catalog.checks]
    assert len(identifiers) == len(set(identifiers))
    assert all(
        identifier.startswith("CC") and len(identifier) == 6
        for identifier in identifiers
    )


def test_conformance_generation_is_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "conformance.md"
    write_conformance(path)
    assert path.read_text(encoding="utf-8") == render_conformance()
    assert "909794089dbabbf6c8d8e50fcf47bb2b6fd315b9" in render_conformance()
