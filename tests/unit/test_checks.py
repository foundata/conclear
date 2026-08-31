from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from conclear.adapters.hadolint import HadolintFinding
from conclear.checks import analyze_containerfile, check_image_static
from conclear.config import load_repository_config
from conclear.services.checking import check_image


class DiagnosticHadolint:
    def check(self, _containerfile: Path) -> tuple[HadolintFinding, ...]:
        return (
            HadolintFinding(
                code="DL3008",
                level="error",
                message="Pin versions in apt get install",
                line=7,
                column=5,
            ),
        )


def test_static_checks_accept_minimal_compliant_source(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    config = load_repository_config(root / "conclear.toml")
    assert check_image_static(config.image("app")) == ()


def test_static_checks_report_security_boundaries(tmp_path: Path) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        "# syntax=docker/dockerfile:1\n"
        "from fedora:latest AS BUILD\n"
        "RUN curl https://example.invalid/install | sh && chmod 777 /app\n"
        "ADD archive.tar /\n"
        "USER root\n"
        "ENTRYPOINT /app\n"
        "HEALTHCHECK CMD /app health\n",
        encoding="utf-8",
    )
    identifiers = {finding.check_id for finding in analyze_containerfile(path).findings}
    assert {
        "CC0102",
        "CC0103",
        "CC0104",
        "CC0105",
        "CC0107",
        "CC0108",
        "CC0109",
        "CC0110",
        "CC0111",
        "CC0112",
    }.issubset(identifiers)


def test_non_root_user_must_be_set_in_the_final_stage(tmp_path: Path) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        'FROM scratch AS build\nUSER 1000\nFROM scratch\nENTRYPOINT ["/app"]\n',
        encoding="utf-8",
    )

    identifiers = {finding.check_id for finding in analyze_containerfile(path).findings}

    assert "CC0110" in identifiers


def test_non_root_uid_may_use_root_gid_in_the_final_stage(tmp_path: Path) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        'FROM scratch\nUSER 1000:0\nENTRYPOINT ["/app"]\n',
        encoding="utf-8",
    )

    identifiers = {finding.check_id for finding in analyze_containerfile(path).findings}

    assert "CC0110" not in identifiers


def test_world_writable_numeric_and_symbolic_modes_are_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        "FROM scratch\n"
        "RUN chmod 646 /one && chmod 707 /two && chmod 757 /three; "
        "chmod o+w /four; chmod a+w /five; chmod +w /six\n"
        "USER 1000\n"
        'ENTRYPOINT ["/app"]\n',
        encoding="utf-8",
    )

    findings = [
        finding
        for finding in analyze_containerfile(path).findings
        if finding.check_id == "CC0109"
    ]

    assert len(findings) == 1


def test_safe_chmod_modes_are_not_rejected(tmp_path: Path) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        "FROM scratch\n"
        "RUN chmod 755 /one && chmod 640 /two && chmod u+w,o-w /three\n"
        "USER 1000\n"
        'ENTRYPOINT ["/app"]\n',
        encoding="utf-8",
    )

    identifiers = {finding.check_id for finding in analyze_containerfile(path).findings}

    assert "CC0109" not in identifiers


def test_hadolint_diagnostics_use_the_adapter_check_identifier(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    config = load_repository_config(root / "conclear.toml")

    outcome = check_image(config.image("app"), cast(Any, DiagnosticHadolint()))

    assert len(outcome.findings) == 1
    finding = outcome.findings[0]
    assert finding.check_id == "CC0114"
    assert finding.severity == "error"
    assert finding.message == "Hadolint DL3008: Pin versions in apt get install"
    assert finding.location == f"{root / 'Containerfile'}:7:5"
