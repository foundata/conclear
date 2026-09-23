"""The shipped requirement inventory and coverage fail closed and stay complete."""

import json
import sys
from pathlib import Path
from typing import Any

import pytest

import conclear.guide_requirements as module
from conclear.catalog import load_catalog, requirement_statuses
from conclear.errors import OperationalError
from conclear.guide_options import load_guide_options
from conclear.guide_requirements import (
    COVERAGE_STATUSES,
    CoverageEntry,
    CoverageSource,
    Requirement,
    RequirementCoverage,
    RequirementInventory,
    RetiredRequirement,
    diff_inventories,
    effective_coverage,
    load_coverage,
    load_requirements,
    main,
    read_listing,
    render_diff,
    render_inventory,
    validate_guide_anchors,
)
from conclear.identity import GUIDE_REVISION


class _Resources:
    def __init__(self, texts: dict[str, str]) -> None:
        self.texts = texts
        self.name = ""

    def joinpath(self, name: str) -> "_Resources":
        selected = _Resources(self.texts)
        selected.name = name
        return selected

    def read_text(self, encoding: str) -> str:
        try:
            return self.texts[self.name]
        except KeyError as exc:
            raise OSError(self.name) from exc


def _requirement(
    identifier: str, text: str = "Do it.", modality: str = "MUST"
) -> Requirement:
    return Requirement(
        identifier, modality, "Release workflow", "release-workflow", text
    )


def _inventory(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "guideRevision": GUIDE_REVISION,
        "requirements": [
            {
                "id": "IG0001",
                "modality": "MUST",
                "section": "Release workflow",
                "anchor": "release-workflow",
                "text": "Automate the release.",
            },
            {
                "id": "IG0002",
                "modality": "SHOULD",
                "section": "Release workflow",
                "anchor": "release-workflow",
                "text": "Prefer a workstation.",
            },
        ],
        "retired": [],
    }
    value.update(changes)
    return value


def _coverage(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": 1,
        "guideRevision": GUIDE_REVISION,
        "entries": [{"id": "IG0002", "status": "manual", "rationale": "Judgment."}],
    }
    value.update(changes)
    return value


def _install(
    monkeypatch: pytest.MonkeyPatch,
    inventory: object = None,
    coverage: object = None,
) -> None:
    texts: dict[str, str] = {}
    for name, value in (
        (module.INVENTORY_RESOURCE, inventory),
        (module.COVERAGE_RESOURCE, coverage),
    ):
        if value is None:
            continue
        texts[name] = value if isinstance(value, str) else json.dumps(value)
    monkeypatch.setattr(module, "files", lambda package: _Resources(texts))


def test_shipped_inventory_matches_the_build() -> None:
    inventory = load_requirements()
    identifiers = [item.requirement_id for item in inventory.requirements]

    assert inventory.guide_revision == GUIDE_REVISION
    assert identifiers == sorted(identifiers)
    assert len(identifiers) == len(set(identifiers))
    assert identifiers
    assert all(item.modality in module.MODALITIES for item in inventory.requirements)


def test_every_requirement_has_exactly_one_status() -> None:
    inventory = load_requirements()
    statuses = requirement_statuses()

    assert len(statuses) == len(inventory.requirements)
    assert {item.status for item in statuses} <= set(COVERAGE_STATUSES)
    by_id = {item.requirement.requirement_id: item for item in statuses}
    for check in load_catalog().checks:
        for requirement_id in check.requirements:
            assert check.check_id in by_id[requirement_id].checks
            if check.behavior == "manual":
                assert by_id[requirement_id].status == "manual"


def test_coverage_entries_never_overlap_checks_or_dangle() -> None:
    covered = {
        requirement_id
        for check in load_catalog().checks
        for requirement_id in check.requirements
    }
    known = set(load_requirements().by_id())

    for entry in load_coverage().entries:
        assert entry.requirement_id not in covered
        assert entry.requirement_id in known
    for option in load_guide_options().options:
        assert set(option.requirements) <= known


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("{not json", "Unable to load"),
        ([], "must be a JSON object"),
        (_inventory(extra=1), "fields are malformed"),
        (_inventory(schemaVersion=2), "Unsupported requirement inventory schema"),
        (_inventory(guideRevision="zz"), "guide revision is malformed"),
        (_inventory(guideRevision="a" * 40), "does not match the build"),
        (_inventory(requirements=[]), "requirements are malformed"),
        (_inventory(retired={}), "retired list is malformed"),
        (_inventory(requirements=[{"id": "IG0001"}]), "malformed entry"),
        (
            _inventory(
                requirements=[{**_inventory()["requirements"][0], "modality": "CAN"}]
            ),
            "modality is unsupported",
        ),
        (
            _inventory(
                requirements=[{**_inventory()["requirements"][0], "anchor": "Bad!"}]
            ),
            "anchor is malformed",
        ),
        (
            _inventory(requirements=[{**_inventory()["requirements"][0], "id": "IG1"}]),
            "must match IGnnnn",
        ),
        (
            _inventory(requirements=list(reversed(_inventory()["requirements"]))),
            "ordered by identifier",
        ),
        (
            _inventory(requirements=_inventory()["requirements"][:1] * 2),
            "must be unique",
        ),
        (_inventory(retired=[{"id": "IG0001"}]), "malformed retired entry"),
        (
            _inventory(retired=[{"id": "IG0001", "note": "reused"}]),
            "must not be active",
        ),
    ],
)
def test_inventory_corruption_is_an_operational_failure(
    monkeypatch: pytest.MonkeyPatch, value: object, message: str
) -> None:
    _install(monkeypatch, inventory=value)

    with pytest.raises(OperationalError, match=message):
        load_requirements()


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("{not json", "Unable to load"),
        (_coverage(extra=1), "fields are malformed"),
        (_coverage(schemaVersion=2), "Unsupported requirement coverage schema"),
        (_coverage(guideRevision=1), "guide revision is malformed"),
        (_coverage(guideRevision="a" * 40), "does not match the build"),
        (_coverage(entries={}), "entries are malformed"),
        (_coverage(entries=[{"id": "IG0002"}]), "malformed entry"),
        (
            _coverage(entries=[{"id": "IG0002", "status": "maybe", "rationale": "x"}]),
            "status is unsupported",
        ),
        (
            _coverage(entries=[{"id": "IG0002", "status": "manual", "rationale": ""}]),
            "field rationale is malformed",
        ),
        (
            _coverage(entries=_coverage()["entries"] * 2),
            "must be unique",
        ),
    ],
)
def test_coverage_corruption_is_an_operational_failure(
    monkeypatch: pytest.MonkeyPatch, value: object, message: str
) -> None:
    _install(monkeypatch, coverage=value)

    with pytest.raises(OperationalError, match=message):
        load_coverage()


def test_lenient_loading_accepts_another_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        inventory=_inventory(guideRevision="b" * 40),
        coverage=_coverage(guideRevision="b" * 40),
    )

    assert load_requirements(enforce_revision=False).guide_revision == "b" * 40
    assert load_coverage(enforce_revision=False).guide_revision == "b" * 40


def _small_inventory() -> RequirementInventory:
    return RequirementInventory(
        guide_revision=GUIDE_REVISION,
        requirements=(_requirement("IG0001"), _requirement("IG0002", modality="MAY")),
        retired=(RetiredRequirement("IG0003", "superseded"),),
    )


def test_effective_coverage_assigns_one_status_per_requirement() -> None:
    inventory = _small_inventory()
    source = CoverageSource(
        checks={"CC0001": ("IG0001",), "CC9001": ("IG0001",)},
        automated=frozenset({"CC0001"}),
    )
    coverage = RequirementCoverage(
        GUIDE_REVISION, (CoverageEntry("IG0002", "external", "Deployment owns it."),)
    )

    statuses = effective_coverage(inventory, source, coverage)

    assert [(item.requirement.requirement_id, item.status) for item in statuses] == [
        ("IG0001", "manual"),
        ("IG0002", "external"),
    ]
    assert statuses[0].checks == ("CC0001", "CC9001")
    assert statuses[1].rationale == "Deployment owns it."

    automated_only = CoverageSource(
        checks={"CC0001": ("IG0001",)}, automated=frozenset({"CC0001"})
    )
    assert (
        effective_coverage(inventory, automated_only, coverage)[0].status == "automated"
    )


@pytest.mark.parametrize(
    ("checks", "entries", "message"),
    [
        ({"CC0001": ("IG0001",)}, (), "without a coverage status: IG0002"),
        (
            {"CC0001": ("IG0001",)},
            (
                CoverageEntry("IG0001", "manual", "x"),
                CoverageEntry("IG0002", "manual", "x"),
            ),
            "both a check and a coverage entry: IG0001",
        ),
        (
            {"CC0001": ("IG0001",)},
            (
                CoverageEntry("IG0002", "manual", "x"),
                CoverageEntry("IG0009", "manual", "x"),
            ),
            "references unknown requirements: IG0009",
        ),
        (
            {"CC0001": ("IG0001", "IG0008")},
            (CoverageEntry("IG0002", "manual", "x"),),
            "Check CC0001 references unknown requirements: IG0008",
        ),
    ],
)
def test_effective_coverage_fails_closed(
    checks: dict[str, tuple[str, ...]],
    entries: tuple[CoverageEntry, ...],
    message: str,
) -> None:
    with pytest.raises(OperationalError, match=message):
        effective_coverage(
            _small_inventory(),
            CoverageSource(checks=checks, automated=frozenset(checks)),
            RequirementCoverage(GUIDE_REVISION, entries),
        )


def test_guide_anchor_validation_requires_requirement_and_section_anchors(
    tmp_path: Path,
) -> None:
    guide = tmp_path / "guide.md"
    inventory = _small_inventory()
    guide.write_text(
        '## Release workflow<a id="release-workflow"></a>\n\n'
        '- Automate. `IG0001`<a id="ig0001"></a>\n- Prefer. `IG0002`<a id="ig0002"></a>\n',
        encoding="utf-8",
    )
    validate_guide_anchors(guide, inventory)

    guide.write_text(
        '## Release workflow<a id="release-workflow"></a>\n', encoding="utf-8"
    )
    with pytest.raises(
        OperationalError, match="missing OCI guide anchors: ig0001, ig0002"
    ):
        validate_guide_anchors(guide, inventory)

    guide.write_bytes(b"\xff\xfe")
    with pytest.raises(OperationalError, match="not UTF-8"):
        validate_guide_anchors(guide, inventory)


def test_shipped_inventory_anchors_are_well_formed() -> None:
    for item in load_requirements().requirements:
        assert item.requirement_id.lower() != item.anchor
        assert module._ANCHOR.fullmatch(item.anchor)


@pytest.mark.parametrize("reverse", [False, True])
def test_listing_import_strips_lines_and_diff_reports_changes(
    tmp_path: Path, reverse: bool
) -> None:
    listing = tmp_path / "listing.json"
    listing.write_text(
        json.dumps(
            {
                "guide": "oci-container-image-guide.md",
                "requirements": [
                    {
                        "id": "IG0001",
                        "modality": "MUST",
                        "section": "Release workflow",
                        "anchor": "release-workflow",
                        "line": 12,
                        "text": "Automate the release now.",
                    },
                    {
                        "id": "IG0004",
                        "modality": "MUST",
                        "section": "Release workflow",
                        "anchor": "release-workflow",
                        "line": 20,
                        "text": "Build from a worktree.",
                    },
                ],
                "retired": [{"id": "IG0002", "note": "`IG0002`: split into IG0004."}],
            }
        ),
        encoding="utf-8",
    )

    if reverse:
        value = json.loads(listing.read_text(encoding="utf-8"))
        value["requirements"].reverse()
        listing.write_text(json.dumps(value), encoding="utf-8")
    new = read_listing(listing, guide_revision="c" * 40)
    rendered = json.loads(render_inventory(new))

    assert rendered["guideRevision"] == "c" * 40
    assert [item["id"] for item in rendered["requirements"]] == ["IG0001", "IG0004"]
    assert "line" not in rendered["requirements"][0]
    assert rendered["retired"] == [
        {"id": "IG0002", "note": "`IG0002`: split into IG0004."}
    ]

    diff = diff_inventories(_small_inventory(), new)
    assert [item.requirement_id for item in diff.added] == ["IG0004"]
    assert [item.requirement_id for item in diff.removed] == ["IG0002"]
    assert [after.requirement_id for _, after in diff.reworded] == ["IG0001"]

    text = render_diff(diff, {"IG0002": {"CC0001"}, "IG0001": {"coverage"}})
    assert "+ IG0004 [MUST] Build from a worktree." in text
    assert "- IG0002 [MAY] Do it. (referenced by CC0001)" in text
    assert "~ IG0001 [MUST -> MUST] (referenced by coverage)" in text
    assert "was: Do it." in text
    assert "now: Automate the release now." in text


@pytest.mark.parametrize(
    "value",
    [
        "{not json",
        [],
        {"requirements": {}},
        {"requirements": [{"id": "IG0001"}]},
    ],
)
def test_listing_corruption_is_an_operational_failure(
    tmp_path: Path, value: object
) -> None:
    listing = tmp_path / "listing.json"
    listing.write_text(
        value if isinstance(value, str) else json.dumps(value), encoding="utf-8"
    )

    with pytest.raises(OperationalError):
        read_listing(listing, guide_revision="c" * 40)


def test_entry_point_checks_diffs_and_imports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["guide_requirements", "--check"])
    assert main() == 0
    assert "requirements at guide revision" in capsys.readouterr().err

    guide = tmp_path / "guide.md"
    guide.write_text("# no anchors\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["guide_requirements", "--guide", str(guide)])
    assert main() == 1
    assert "missing OCI guide anchors" in capsys.readouterr().err

    listing = tmp_path / "listing.json"
    listing.write_text(
        json.dumps(
            {
                "requirements": [
                    {
                        "id": "IG0001",
                        "modality": "MUST",
                        "section": "Release workflow",
                        "anchor": "release-workflow",
                        "line": 1,
                        "text": "Automate the release.",
                    }
                ],
                "retired": [],
            }
        ),
        encoding="utf-8",
    )
    _install(monkeypatch, inventory=_inventory(), coverage=_coverage())
    monkeypatch.setattr(sys, "argv", ["guide_requirements", "--diff", str(listing)])
    assert main() == 0
    captured = capsys.readouterr()
    assert "Removed: 1" in captured.out
    assert (
        "- IG0002 [SHOULD] Prefer a workstation. (referenced by coverage)"
        in captured.out
    )

    target = tmp_path / "guide-requirements.json"
    monkeypatch.setattr(module, "inventory_path", lambda: target)
    monkeypatch.setattr(sys, "argv", ["guide_requirements", "--import", str(listing)])
    assert main() == 0
    assert (
        json.loads(target.read_text(encoding="utf-8"))["guideRevision"]
        == GUIDE_REVISION
    )
    assert "Imported 1 requirements" in capsys.readouterr().err

    _install(monkeypatch, inventory="{broken", coverage=_coverage())
    monkeypatch.setattr(sys, "argv", ["guide_requirements", "--diff", str(listing)])
    assert main() == 0
    captured = capsys.readouterr()
    assert "No usable shipped inventory" in captured.err
    assert "Added: 1" in captured.out

    monkeypatch.setattr(sys, "argv", ["guide_requirements", "--check"])
    assert main() == 1
    assert "Unable to load" in capsys.readouterr().err
