import json
from pathlib import Path
from typing import Any

import pytest

import conclear.guide_options as guide_options_module
from conclear.errors import OperationalError
from conclear.guide_options import (
    GuideOption,
    GuideOptionInventory,
    load_guide_options,
    render_guide_options,
)
from conclear.guide_requirements import load_requirements
from conclear.identity import GUIDE_REVISION, VERSION

REPOSITORY = Path(__file__).parents[2]


class _Resource:
    def __init__(self, text: str) -> None:
        self.text = text

    def joinpath(self, name: str) -> "_Resource":
        return self

    def read_text(self, encoding: str) -> str:
        return self.text


def _option(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "id": "GO0001",
        "summary": "Root",
        "requirements": ["IG0207"],
        "status": "supported",
        "rationale": "Reviewed.",
        "reconsiderWhen": "Guide change.",
        "checks": ["CC0110"],
    }
    value.update(changes)
    return value


def _inventory(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "productVersion": VERSION,
        "guideRevision": GUIDE_REVISION,
        "options": [_option()],
    }
    value.update(changes)
    return value


def _install(monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    text = value if isinstance(value, str) else json.dumps(value)
    monkeypatch.setattr(guide_options_module, "files", lambda package: _Resource(text))


def test_committed_conformance_document_contains_the_guide_options() -> None:
    conformance = (REPOSITORY / "docs/conformance.md").read_text(encoding="utf-8")

    assert "\n".join(render_guide_options()) in conformance


def test_guide_options_are_versioned_and_reference_active_checks() -> None:
    raw = json.loads(
        (REPOSITORY / "src/conclear/data/guide-options.json").read_text(
            encoding="utf-8"
        )
    )
    inventory = load_guide_options()
    known = set(load_requirements().by_id())

    assert raw["productVersion"] == VERSION
    assert raw["guideRevision"] == GUIDE_REVISION
    assert {item.status for item in inventory.options} == {
        "supported",
        "manual",
        "unsupported",
        "out-of-scope",
    }
    assert {item.option_id for item in inventory.options} == {
        f"GO{index:04d}" for index in range(1, 15)
    }
    for option in inventory.options:
        assert option.requirements
        assert set(option.requirements) <= known


def test_guide_option_rendering_names_requirements() -> None:
    inventory = GuideOptionInventory(
        (
            GuideOption(
                "GO0001",
                "Root",
                ("IG0207", "IG0219"),
                "supported",
                "Reviewed.",
                "Guide change.",
                ("CC0110",),
            ),
        )
    )

    rendered = "\n".join(render_guide_options(inventory))

    assert "### GO0001: Root" in rendered
    assert "- **Guide requirements:** `IG0207`, `IG0219`" in rendered
    assert "- **Checks:** `CC0110`" in rendered


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (_inventory(options=[_option(requirements=[])]), "must match IGnnnn"),
        (_inventory(options=[_option(requirements=["x"])]), "must match IGnnnn"),
        (
            _inventory(options=[_option(requirements=["IG0219", "IG0207"])]),
            "must be sorted",
        ),
        (
            _inventory(options=[_option(requirements=["IG9999"])]),
            "unknown requirements: IG9999",
        ),
        (_inventory(options=[_option(checks=["CC9999"])]), "unknown checks: CC9999"),
        (_inventory(options=[_option(anchor="x")]), "malformed entry"),
        (_inventory(guideRevision="a" * 40), "does not match the build"),
    ],
)
def test_guide_option_corruption_is_an_operational_failure(
    monkeypatch: pytest.MonkeyPatch, value: object, message: str
) -> None:
    _install(monkeypatch, value)

    with pytest.raises(OperationalError, match=message):
        load_guide_options()


def test_lenient_loading_accepts_another_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        _inventory(
            guideRevision="a" * 40,
            options=[_option(requirements=["IG9999"], checks=["CC9999"])],
        ),
    )

    assert load_guide_options(enforce_revision=False).options[0].requirements == (
        "IG9999",
    )


def test_rendered_options_carry_every_committed_identifier() -> None:
    rendered = "\n".join(render_guide_options())

    for option in load_guide_options().options:
        assert f"### {option.option_id}: {option.summary}" in rendered
