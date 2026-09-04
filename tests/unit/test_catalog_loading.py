"""The shipped check catalog and conformance generator fail closed on corruption."""

import json
import sys
from pathlib import Path
from typing import Any

import pytest

import conclear.catalog as catalog_module
import conclear.conformance as conformance_module
from conclear.catalog import load_catalog, render_conformance
from conclear.conformance import main, validate_guide_anchors
from conclear.errors import OperationalError
from conclear.identity import GUIDE_REVISION


class _Resource:
    def __init__(self, text: str) -> None:
        self.text = text

    def joinpath(self, name: str) -> "_Resource":
        return self

    def read_text(self, encoding: str) -> str:
        return self.text


def _catalog(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "guideRevision": GUIDE_REVISION,
        "limits": [{"name": "Pin divergence", "value": "7 days"}],
        "retired": [],
        "checks": [
            {
                "id": "CC0001",
                "summary": "Validate configuration",
                "severity": "error",
                "behavior": "automated",
                "anchor": "build-context",
            }
        ],
    }
    value.update(changes)
    return value


def _install(monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    text = value if isinstance(value, str) else json.dumps(value)
    monkeypatch.setattr(catalog_module, "files", lambda package: _Resource(text))


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("{not json", "Unable to load"),
        ([], "must be a JSON object"),
        (_catalog(schemaVersion=2), "Unsupported check catalog schema"),
        (_catalog(guideRevision="a" * 40), "does not match the build"),
        (_catalog(checks={}), "arrays are malformed"),
        (_catalog(checks=[1]), "malformed check"),
        (_catalog(checks=[{"id": "CC0001"}]), "incomplete check"),
        (
            _catalog(checks=[{**_catalog()["checks"][0], "summary": ""}]),
            "non-empty string",
        ),
        (_catalog(retired=[1]), "malformed retired check"),
        (_catalog(retired=[{"id": "cc1", "summary": "x"}]), "must match CCnnnn"),
        (
            _catalog(retired=[{"id": "CC0001", "summary": "reused"}]),
            "must be unique",
        ),
        (_catalog(limits=[1]), "malformed limit"),
    ],
)
def test_catalog_corruption_is_an_operational_failure(
    monkeypatch: pytest.MonkeyPatch, value: object, message: str
) -> None:
    _install(monkeypatch, value)

    with pytest.raises(OperationalError, match=message):
        load_catalog()


def test_valid_catalog_renders_retired_and_limit_sections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        _catalog(retired=[{"id": "CC0999", "summary": "Retired rule"}]),
    )

    catalog = load_catalog()
    rendered = render_conformance(catalog)

    assert catalog.retired[0].check_id == "CC0999"
    assert "| `CC0999` | Retired rule |" in rendered
    assert "| Pin divergence | 7 days |" in rendered


def test_guide_anchor_validation_reports_missing_anchors(tmp_path: Path) -> None:
    guide = tmp_path / "guide.md"
    guide.write_text('## Build context<a id="build-context"></a>\n', encoding="utf-8")

    with pytest.raises(OperationalError, match="missing OCI guide anchors"):
        validate_guide_anchors(guide)

    guide.write_bytes(b"\xff\xfe")
    with pytest.raises(OperationalError, match="not UTF-8"):
        validate_guide_anchors(guide)


def test_conformance_entry_point_generates_checks_and_reports_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "conformance.md"
    monkeypatch.setattr(sys, "argv", ["conformance", "--output", str(output)])
    assert main() == 0
    assert output.read_text(encoding="utf-8") == render_conformance()

    monkeypatch.setattr(
        sys, "argv", ["conformance", "--check", "--output", str(output)]
    )
    assert main() == 0

    output.write_text("stale\n", encoding="utf-8")
    assert main() == 1

    monkeypatch.setattr(
        sys, "argv", ["conformance", "--check", "--output", str(tmp_path / "absent")]
    )
    assert main() == 1

    guide = tmp_path / "guide.md"
    guide.write_text("# no anchors\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["conformance", "--guide", str(guide), "--output", str(output)],
    )
    assert main() == 1
    assert conformance_module.MAX_GUIDE_BYTES > 0
