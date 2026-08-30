from collections.abc import Callable
from pathlib import Path

from conclear.checks import analyze_containerfile, check_image_static
from conclear.config import load_repository_config


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
