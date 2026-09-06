from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from conclear.adapters.hadolint import HadolintFinding
from conclear.checks import (
    analyze_containerfile,
    check_image_static,
    validate_image_labels,
)
from conclear.config import load_repository_config
from conclear.services.checking import check_image


class DiagnosticHadolint:
    def check(
        self, _containerfile: Path, *, config_directory: Path
    ) -> tuple[HadolintFinding, ...]:
        del config_directory
        return (
            HadolintFinding(
                code="DL3008",
                level="error",
                message="Pin versions in apt get install",
                line=7,
                column=5,
            ),
        )


class RootWarningHadolint:
    def check(
        self, _containerfile: Path, *, config_directory: Path
    ) -> tuple[HadolintFinding, ...]:
        del config_directory
        return (
            HadolintFinding(
                code="DL3002",
                level="warning",
                message="Last USER should not be root",
                line=3,
                column=1,
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


def test_buildkit_syntax_directive_spelling_variants_are_rejected(
    tmp_path: Path,
) -> None:
    for index, directive in enumerate(
        (
            "#syntax=docker/dockerfile:1",
            "# syntax = docker/dockerfile:1",
            "  # SYNTAX=docker/dockerfile:1",
        )
    ):
        path = tmp_path / f"Containerfile.{index}"
        path.write_text(
            f'{directive}\nFROM scratch\nUSER 1000\nENTRYPOINT ["/app"]\n',
            encoding="utf-8",
        )

        identifiers = {
            finding.check_id for finding in analyze_containerfile(path).findings
        }

        assert "CC0103" in identifiers


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


def test_static_checks_accept_configured_reviewed_root_user(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory(containerfile='USER 0\nENTRYPOINT ["/app"]\n')
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace("user = 10001", "user = 0")
        .replace(
            'health_command = ["/app", "health"]',
            """health_command = ["/app", "health"]

[images.runtime.root_requirement]
rationale = "The application must manage system identities."
owner = "platform@example.com"
review_trigger = "Remove when upstream supports an unprivileged mode."
""",
        ),
        encoding="utf-8",
    )

    identifiers = {
        finding.check_id
        for finding in check_image_static(load_repository_config(path).image("app"))
    }

    assert "CC0110" not in identifiers


def test_static_checks_reject_user_that_differs_from_runtime_contract(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory(containerfile='USER 10002\nENTRYPOINT ["/app"]\n')
    image = load_repository_config(root / "conclear.toml").image("app")

    findings = [
        finding for finding in check_image_static(image) if finding.check_id == "CC0110"
    ]

    assert len(findings) == 1
    assert "configured numeric UID 10001" in findings[0].message


def test_reviewed_root_contract_suppresses_only_hadolint_root_warning(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    containerfile = root / "Containerfile"
    containerfile.write_text(
        containerfile.read_text(encoding="utf-8").replace("USER 10001:10001", "USER 0"),
        encoding="utf-8",
    )
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace("user = 10001", "user = 0")
        .replace(
            'health_command = ["/app", "health"]',
            """health_command = ["/app", "health"]

[images.runtime.root_requirement]
rationale = "The application must manage system identities."
owner = "platform@example.com"
review_trigger = "Remove when upstream supports an unprivileged mode."
""",
        ),
        encoding="utf-8",
    )

    outcome = check_image(
        load_repository_config(path).image("app"), cast(Any, RootWarningHadolint())
    )

    assert outcome.accepted
    assert outcome.findings == ()


def test_systemd_static_check_requires_matching_baked_stop_signal(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    containerfile = root / "Containerfile"
    containerfile.write_text(
        containerfile.read_text(encoding="utf-8")
        .replace("USER 10001:10001", "USER 0")
        .replace('ENTRYPOINT ["/app"]', 'STOPSIGNAL TERM\nENTRYPOINT ["/sbin/init"]'),
        encoding="utf-8",
    )
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace('profile = "service"\nuser = 10001', 'profile = "systemd"\nuser = 0')
        .replace(
            'health_command = ["/app", "health"]',
            """health_command = ["/app", "health"]

[images.runtime.root_requirement]
rationale = "Systemd is the image lifecycle manager."
owner = "platform@example.com"
review_trigger = "Review when the image lifecycle changes."

[images.runtime.systemd]
required_units = ["multi-user.target"]
stop_signal = "RTMIN+3"
""",
        ),
        encoding="utf-8",
    )

    findings = [
        finding
        for finding in check_image_static(load_repository_config(path).image("app"))
        if finding.check_id == "CC0115"
    ]

    assert len(findings) == 1
    assert "RTMIN+3" in findings[0].message

    containerfile.write_text(
        containerfile.read_text(encoding="utf-8").replace(
            "STOPSIGNAL TERM", "STOPSIGNAL SIGRTMIN+3"
        ),
        encoding="utf-8",
    )
    accepted = check_image_static(load_repository_config(path).image("app"))
    assert all(finding.check_id != "CC0115" for finding in accepted)


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


def test_created_label_is_optional_but_verified_when_present() -> None:
    labels = {
        "org.opencontainers.image.source": "https://github.com/example/app",
        "org.opencontainers.image.revision": "a" * 40,
        "org.opencontainers.image.licenses": "MIT",
        "org.opencontainers.image.title": "Example",
    }

    assert (
        validate_image_labels(
            labels,
            source="https://github.com/example/app",
            revision="a" * 40,
            version=None,
            created="2026-01-01T00:00:00Z",
        )
        == ()
    )

    findings = validate_image_labels(
        {**labels, "org.opencontainers.image.created": "2025-01-01T00:00:00Z"},
        source="https://github.com/example/app",
        revision="a" * 40,
        version=None,
        created="2026-01-01T00:00:00Z",
    )
    assert [finding.check_id for finding in findings] == ["CC0113"]


def test_default_deny_allowlist_satisfies_required_context_exclusions(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    (root / ".containerignore").write_text(
        "*\n!Containerfile\n!conclear.toml\n", encoding="utf-8"
    )
    image = load_repository_config(root / "conclear.toml").image("app")

    findings = [
        finding for finding in check_image_static(image) if finding.check_id == "CC0202"
    ]

    assert findings == []


def test_default_deny_allowlist_rejects_later_private_key_reinclusion(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    (root / ".containerignore").write_text(
        "*\n!Containerfile\n!conclear.toml\n!nested/\n!nested/release.key\n",
        encoding="utf-8",
    )
    image = load_repository_config(root / "conclear.toml").image("app")

    findings = [
        finding for finding in check_image_static(image) if finding.check_id == "CC0202"
    ]

    assert any("private keys" in finding.message for finding in findings)


def test_context_exclusion_check_rejects_misleading_near_matches(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory()
    (root / ".containerignore").write_text(
        ".git-safe/\n.env.example.txt\n*.key.txt\n.venv-cache/\n",
        encoding="utf-8",
    )
    image = load_repository_config(root / "conclear.toml").image("app")

    findings = [
        finding for finding in check_image_static(image) if finding.check_id == "CC0202"
    ]

    assert {finding.message for finding in findings} == {
        ".containerignore does not exclude source control",
        ".containerignore does not exclude environment files",
        ".containerignore does not exclude private keys",
        ".containerignore does not exclude local environments",
    }


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
