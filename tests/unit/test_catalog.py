import re
from pathlib import Path

from conclear.catalog import (
    CheckCatalog,
    RetiredCheckDefinition,
    load_catalog,
    render_conformance,
    requirement_statuses,
    write_conformance,
)
from conclear.guide_requirements import load_requirements


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


def test_every_check_names_known_requirements() -> None:
    known = set(load_requirements().by_id())
    for check in load_catalog().checks:
        assert check.requirements
        assert list(check.requirements) == sorted(set(check.requirements))
        assert set(check.requirements) <= known


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


def test_conformance_lists_every_requirement_with_its_status() -> None:
    rendered = render_conformance()
    coverage = rendered.split("## Requirement coverage", maxsplit=1)[1]

    for status in requirement_statuses():
        identifier = status.requirement.requirement_id
        assert f"[`{identifier}`](" in coverage
        assert f"#{identifier.lower()})" in coverage
    for check in load_catalog().checks:
        assert f"`{check.check_id}`" in coverage
    assert "| automated" in coverage
    assert "| manual" in coverage


def test_conformance_generation_is_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "conformance.md"
    write_conformance(path)
    assert path.read_text(encoding="utf-8") == render_conformance()
    assert "5db54ccf59b67e44f964badb93cfbdc311fa36cb" in render_conformance()


def test_committed_conformance_document_is_current() -> None:
    path = Path(__file__).parents[2] / "docs" / "conformance.md"
    assert path.read_text(encoding="utf-8") == render_conformance()
