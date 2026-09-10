"""The release-specific implementation matrix is complete and fail closed."""

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

import conclear.implementation as implementation_module
from conclear.errors import OperationalError
from conclear.identity import VERSION
from conclear.implementation import (
    MATRIX_PATH,
    MATRIX_SCHEMA_VERSION,
    ImplementationMatrix,
    ImplementationPromise,
    load_implementation_matrix,
    main,
    render_implementation_matrix,
    validate_implementation_links,
    write_implementation_matrix,
)
from conclear.implementation import TestReference as _TestReference

REPOSITORY = Path(__file__).parents[2]


class _Resource:
    def __init__(self, text: str) -> None:
        self.text = text

    def joinpath(self, name: str) -> "_Resource":
        return self

    def read_text(self, encoding: str) -> str:
        return self.text


def _matrix(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": MATRIX_SCHEMA_VERSION,
        "productVersion": VERSION,
        "promises": [
            {
                "id": "IP0001",
                "summary": "Current behavior",
                "implementation": ["src/conclear/implementation.py"],
                "tests": [
                    {"path": "tests/unit/test_implementation.py", "tier": "unit"}
                ],
            }
        ],
    }
    value.update(changes)
    return value


def _install(monkeypatch: pytest.MonkeyPatch, value: object) -> None:
    content = value if isinstance(value, str) else json.dumps(value)
    monkeypatch.setattr(
        implementation_module, "files", lambda package: _Resource(content)
    )


def test_committed_matrix_matches_current_architecture_code_and_tests() -> None:
    matrix = load_implementation_matrix()
    identifiers = [promise.promise_id for promise in matrix.promises]
    project = tomllib.loads((REPOSITORY / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["version"] == matrix.product_version == VERSION
    assert identifiers == sorted(identifiers)
    assert len(identifiers) == len(set(identifiers))
    assert all(re.fullmatch(r"IP[0-9]{4}", identifier) for identifier in identifiers)
    validate_implementation_links(REPOSITORY, matrix)
    assert (REPOSITORY / MATRIX_PATH).read_text(
        encoding="utf-8"
    ) == render_implementation_matrix(matrix)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("{not json", "Unable to load"),
        ([], "must be a JSON object"),
        (_matrix(schemaVersion=2), "Unsupported implementation matrix schema"),
        (_matrix(productVersion="9.9.9"), "does not match the build"),
        (_matrix(promises={}), "promises are malformed"),
        (_matrix(promises=[1]), "malformed promise"),
        (
            _matrix(promises=[{**_matrix()["promises"][0], "id": "ip1"}]),
            "must match IPnnnn",
        ),
        (
            _matrix(
                promises=[
                    _matrix()["promises"][0],
                    _matrix()["promises"][0],
                ]
            ),
            "must be unique",
        ),
        (
            _matrix(
                promises=[
                    {**_matrix()["promises"][0], "id": "IP0002"},
                    _matrix()["promises"][0],
                ]
            ),
            "ordered by identifier",
        ),
        (
            _matrix(
                promises=[
                    {
                        **_matrix()["promises"][0],
                        "implementation": [
                            "src/conclear/implementation.py",
                            "src/conclear/implementation.py",
                        ],
                    }
                ]
            ),
            "contains duplicates",
        ),
        (
            _matrix(
                promises=[
                    {
                        **_matrix()["promises"][0],
                        "tests": [
                            {
                                "path": "tests/unit/test_implementation.py",
                                "tier": "future",
                            }
                        ],
                    }
                ]
            ),
            "tier is unsupported",
        ),
    ],
)
def test_matrix_corruption_is_an_operational_failure(
    monkeypatch: pytest.MonkeyPatch, value: object, message: str
) -> None:
    _install(monkeypatch, value)

    with pytest.raises(OperationalError, match=message):
        load_implementation_matrix()


def test_link_validation_rejects_drift_and_unsafe_paths(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    architecture = tmp_path / "ARCHITECTURE.md"
    architecture.write_text(
        f'<a id="promise-ip0001"></a>\n[matrix](./{MATRIX_PATH.as_posix()})\n',
        encoding="utf-8",
    )
    for path in (
        tmp_path / "README.md",
        tmp_path / "DEVELOPMENT.md",
    ):
        path.write_text(MATRIX_PATH.name, encoding="utf-8")
    matrix = ImplementationMatrix(
        VERSION,
        (
            ImplementationPromise(
                "IP0001",
                "Current behavior",
                ("src/conclear/../secrets.py",),
                (_TestReference("tests/unit/test_implementation.py", "unit"),),
            ),
        ),
    )

    with pytest.raises(OperationalError, match="Unsafe implementation matrix path"):
        validate_implementation_links(tmp_path, matrix)

    architecture.write_text(f"[matrix](./{MATRIX_PATH.as_posix()})\n", encoding="utf-8")
    with pytest.raises(OperationalError, match="anchors do not match"):
        validate_implementation_links(tmp_path, matrix)


def test_entry_point_generates_checks_and_reports_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / MATRIX_PATH.name
    arguments = [
        "implementation",
        "--repository",
        str(REPOSITORY),
        "--output",
        str(output),
    ]

    monkeypatch.setattr(sys, "argv", [*arguments, "--check"])
    assert main() == 1
    assert "missing" in capsys.readouterr().err

    monkeypatch.setattr(sys, "argv", arguments)
    assert main() == 0
    assert output.read_text(encoding="utf-8") == render_implementation_matrix()

    monkeypatch.setattr(sys, "argv", [*arguments, "--check"])
    assert main() == 0

    output.write_text("stale\n", encoding="utf-8")
    assert main() == 1
    assert "stale" in capsys.readouterr().err

    write_implementation_matrix(output)
    assert main() == 0

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "implementation",
            "--repository",
            str(tmp_path / "missing"),
            "--output",
            str(output),
        ],
    )
    assert main() == 1
    assert "repository is unavailable" in capsys.readouterr().err
