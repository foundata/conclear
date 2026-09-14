from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from conclear.adapters.hadolint import HadolintFinding
from conclear.checks import (
    analyze_containerfile,
    check_image_static,
    declared_label_keys,
    forbidden_label_findings,
    validate_base_annotations,
    validate_declared_labels,
    validate_image_labels,
)
from conclear.config import load_repository_config
from conclear.containerfile import load_containerfile
from conclear.services.checking import check_image
from conclear.values import Digest, OCIReference


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
            HadolintFinding(
                code="DL3041",
                level="warning",
                message="Specify version with `dnf install -y <package>-<version>`",
                line=9,
                column=1,
            ),
            HadolintFinding(
                code="DL3003",
                level="error",
                message="Use WORKDIR to switch to a directory",
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
    assert check_image_static(config.release_image("app")) == ()


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
        .split("[[images.pins]]")[0]
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
        for finding in check_image_static(
            load_repository_config(path).release_image("app")
        )
    }

    assert "CC0110" not in identifiers


def test_static_checks_reject_user_that_differs_from_runtime_contract(
    repository_factory: Callable[..., Path],
) -> None:
    root = repository_factory(containerfile='USER 10002\nENTRYPOINT ["/app"]\n')
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").split("[[images.pins]]")[0], encoding="utf-8"
    )
    image = load_repository_config(root / "conclear.toml").release_image("app")

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

    image = load_repository_config(path).release_image("app")
    outcome = check_image(image, cast(Any, RootWarningHadolint()))

    assert outcome.accepted
    assert outcome.findings == ()

    invalid_non_root_exception = replace(
        image, runtime=replace(image.runtime, user=10001)
    )
    invalid_outcome = check_image(
        invalid_non_root_exception, cast(Any, RootWarningHadolint())
    )
    assert any(finding.check_id == "CC0114" for finding in invalid_outcome.findings)


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
""",
        ),
        encoding="utf-8",
    )

    findings = [
        finding
        for finding in check_image_static(
            load_repository_config(path).release_image("app")
        )
        if finding.check_id == "CC0115"
    ]

    assert len(findings) == 1
    assert "must be SIGRTMIN+3" in findings[0].message

    containerfile.write_text(
        containerfile.read_text(encoding="utf-8").replace(
            "STOPSIGNAL TERM", "STOPSIGNAL SIGRTMIN+3"
        ),
        encoding="utf-8",
    )
    accepted = check_image_static(load_repository_config(path).release_image("app"))
    assert all(finding.check_id != "CC0115" for finding in accepted)


@pytest.mark.parametrize("volume", ('VOLUME ["/var/lib/app"]', "VOLUME /var/lib/app"))
def test_static_checks_require_final_stage_volumes_in_writable_contract(
    repository_factory: Callable[..., Path], volume: str
) -> None:
    root = repository_factory(
        containerfile=(
            "FROM quay.io/example/base:1@sha256:" + "a" * 64 + " AS runtime\n"
            f"{volume}\n"
            "USER 10001:10001\n"
            'ENTRYPOINT ["/app"]\n'
        )
    )
    path = root / "conclear.toml"

    findings = check_image_static(load_repository_config(path).release_image("app"))

    assert [item.check_id for item in findings].count("CC0116") == 1
    assert "/var/lib/app" in next(
        item.message for item in findings if item.check_id == "CC0116"
    )

    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "user = 10001", 'user = 10001\nwritable_mounts = ["/var/lib/app"]'
        ),
        encoding="utf-8",
    )
    accepted = check_image_static(load_repository_config(path).release_image("app"))
    assert all(item.check_id != "CC0116" for item in accepted)


@pytest.mark.parametrize("volume", ("VOLUME []", "VOLUME relative", "VOLUME $DATA"))
def test_static_checks_reject_malformed_or_dynamic_volumes(
    repository_factory: Callable[..., Path], volume: str
) -> None:
    root = repository_factory(
        containerfile=(
            "FROM quay.io/example/base:1@sha256:" + "a" * 64 + " AS runtime\n"
            f"{volume}\n"
            "USER 10001:10001\n"
            'ENTRYPOINT ["/app"]\n'
        )
    )

    findings = check_image_static(
        load_repository_config(root / "conclear.toml").release_image("app")
    )

    assert [item.check_id for item in findings].count("CC0116") == 1
    assert "literal absolute paths" in next(
        item.message for item in findings if item.check_id == "CC0116"
    )


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
    image = load_repository_config(root / "conclear.toml").release_image("app")

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
    image = load_repository_config(root / "conclear.toml").release_image("app")

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
    image = load_repository_config(root / "conclear.toml").release_image("app")

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

    outcome = check_image(config.release_image("app"), cast(Any, DiagnosticHadolint()))

    assert len(outcome.findings) == 1
    finding = outcome.findings[0]
    assert finding.check_id == "CC0114"
    assert finding.severity == "error"
    assert finding.message == "Hadolint DL3003: Use WORKDIR to switch to a directory"
    assert finding.location == "Containerfile:7:5"
    # DL3008 and DL3041 demand exact distribution package versions, which the
    # guide forbids by default (IG0181); they never surface as findings.


def test_comment_lines_inside_a_continued_instruction_are_ignored(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        "FROM quay.io/example/base:1@sha256:" + "a" * 64 + "\n"
        "RUN apt-get update \\\n"
        "    # comments may interleave a continued instruction\n"
        "    && apt-get install -y curl \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
        "USER 10001\n"
        'ENTRYPOINT ["/app"]\n',
        encoding="utf-8",
    )

    analysis = analyze_containerfile(path)

    run = next(item for item in analysis.instructions if item.keyword == "RUN")
    assert (run.line_number, run.end_line_number) == (2, 5)
    assert "apt-get install -y curl" in run.body
    assert "#" not in run.body
    assert [item.keyword for item in analysis.instructions] == [
        "FROM",
        "RUN",
        "USER",
        "ENTRYPOINT",
    ]


def test_source_label_must_equal_the_public_source_url_byte_for_byte() -> None:
    source = "https://foundata.com/en/projects/example/#source"
    labels = {
        "org.opencontainers.image.source": source,
        "org.opencontainers.image.revision": "a" * 40,
        "org.opencontainers.image.title": "Example",
    }

    assert (
        validate_image_labels(
            labels,
            source=source,
            revision="a" * 40,
            version=None,
            created="2026-01-01T00:00:00Z",
        )
        == ()
    )

    # Dropping the fragment or naming the Git repository instead is a mismatch.
    for wrong in (
        "https://foundata.com/en/projects/example/",
        "https://github.com/foundata/example",
    ):
        findings = validate_image_labels(
            {**labels, "org.opencontainers.image.source": wrong},
            source=source,
            revision="a" * 40,
            version=None,
            created="2026-01-01T00:00:00Z",
        )
        assert [finding.check_id for finding in findings] == ["CC0113"]


def test_license_labels_are_rejected_in_every_form() -> None:
    labels = {
        "org.opencontainers.image.source": "https://github.com/example/app",
        "org.opencontainers.image.revision": "a" * 40,
        "org.opencontainers.image.title": "Example",
        "org.opencontainers.image.licenses": "MIT",
        "org.opencontainers.image.license": "MIT",
        "license": "MIT",
    }

    findings = validate_image_labels(
        labels,
        source="https://github.com/example/app",
        revision="a" * 40,
        version=None,
        created="2026-01-01T00:00:00Z",
    )

    assert [finding.check_id for finding in findings] == ["CC0113"] * 3
    assert {finding.message.split(" ")[2] for finding in findings} == {
        "license",
        "org.opencontainers.image.license",
        "org.opencontainers.image.licenses",
    }


def test_declared_label_keys_cover_multi_key_and_legacy_forms(tmp_path: Path) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        "FROM quay.io/example/base:1@sha256:" + "a" * 64 + "\n"
        "ARG IMAGE_VERSION\n"
        'LABEL org.opencontainers.image.title="Example" \\\n'
        '      org.opencontainers.image.version="${IMAGE_VERSION}"\n'
        "LABEL maintainer someone@example.com\n"
        "LABEL vendor=foundata\n",
        encoding="utf-8",
    )

    assert declared_label_keys(load_containerfile(path)) == frozenset(
        {
            "org.opencontainers.image.title",
            "org.opencontainers.image.version",
            "maintainer",
            "vendor",
        }
    )


def test_undeclared_labels_are_rejected_except_the_buildah_stamp(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        "FROM quay.io/example/base:1@sha256:" + "a" * 64 + "\n"
        'LABEL org.opencontainers.image.title="Example"\n',
        encoding="utf-8",
    )
    containerfile = load_containerfile(path)

    assert (
        validate_declared_labels(
            {
                "org.opencontainers.image.title": "Example",
                "io.buildah.version": "1.43.2",
            },
            containerfile,
        )
        == ()
    )
    findings = validate_declared_labels(
        {
            "org.opencontainers.image.title": "Example",
            "org.opencontainers.image.vendor": "Fedora Project",
            "version": "43",
        },
        containerfile,
    )
    assert [(item.check_id, item.message.split(" ")[2]) for item in findings] == [
        ("CC0117", "org.opencontainers.image.vendor"),
        ("CC0117", "version"),
    ]


def test_base_annotations_must_match_the_pin_and_nothing_else() -> None:
    pinned = OCIReference.parse(
        "quay.io/example/base:1@sha256:" + "a" * 64,
        require_tag=True,
        require_digest=True,
    )
    platform_digest = Digest("sha256:" + "d" * 64)
    good = (
        ("org.opencontainers.image.base.digest", str(platform_digest)),
        (
            "org.opencontainers.image.base.name",
            "quay.io/example/base@sha256:" + "a" * 64,
        ),
        ("org.opencontainers.image.created", "2026-01-01T00:00:00Z"),
    )

    assert (
        validate_base_annotations(
            good, pinned=pinned, platform_manifest_digest=platform_digest
        )
        == ()
    )

    findings = validate_base_annotations(
        (
            ("org.opencontainers.image.base.digest", "sha256:" + "e" * 64),
            ("org.opencontainers.image.base.name", "quay.io/example/base:1"),
            ("org.opencontainers.image.vendor", "Fedora Project"),
        ),
        pinned=pinned,
        platform_manifest_digest=platform_digest,
    )
    assert [item.check_id for item in findings] == ["CC0118"] * 3
    assert "base.name" in findings[0].message
    assert "base.digest" in findings[1].message
    assert "inherited from the base image" in findings[2].message


def test_static_analysis_rejects_license_and_hand_written_base_labels(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        "FROM quay.io/example/base:1@sha256:" + "a" * 64 + "\n"
        'LABEL org.opencontainers.image.title="Example"\n'
        'LABEL org.opencontainers.image.licenses="MIT" \\\n'
        '      org.opencontainers.image.base.name="quay.io/example/base:1"\n'
        "LABEL license MIT\n"
        "LABEL org.opencontainers.image.base.digest=sha256:" + "b" * 64 + "\n"
        "USER 65532\n"
        'ENTRYPOINT ["/bin/true"]\n',
        encoding="utf-8",
    )

    findings = analyze_containerfile(path).findings

    assert [
        (item.check_id, item.message.split(" ")[2], item.location) for item in findings
    ] == [
        ("CC0118", "org.opencontainers.image.base.name", f"{path}:3"),
        ("CC0113", "org.opencontainers.image.licenses", f"{path}:3"),
        ("CC0113", "license", f"{path}:5"),
        ("CC0118", "org.opencontainers.image.base.digest", f"{path}:6"),
    ]
    assert forbidden_label_findings(frozenset({"org.opencontainers.image.title"})) == ()


def test_built_image_labels_reject_hand_written_base_labels() -> None:
    findings = validate_image_labels(
        {
            "org.opencontainers.image.source": "https://github.com/example/app",
            "org.opencontainers.image.revision": "a" * 40,
            "org.opencontainers.image.title": "Example",
            "org.opencontainers.image.base.name": "quay.io/example/base:1",
        },
        source="https://github.com/example/app",
        revision="a" * 40,
        version=None,
        created="2026-01-01T00:00:00Z",
    )

    assert [(item.check_id, item.message.split(" ")[2]) for item in findings] == [
        ("CC0118", "org.opencontainers.image.base.name")
    ]
