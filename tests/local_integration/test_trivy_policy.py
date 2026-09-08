"""Real scanner policy isolation and inherited OCI metadata coverage."""

from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from conclear.config import RuntimeRequirement
from conclear.jsonutil import atomic_write_json, canonical_json_bytes
from conclear.oci import OCI_CONFIG, OCI_MANIFEST
from conclear.runtime import ApplicationRuntime
from conclear.scan_policy import evaluate_trivy_report
from conclear.tools import ToolName
from tests.local_integration.fixtures import (
    manifest_run_id,
    runtime_config,
    tool_resolver,
)
from tests.unit.test_oci import _write_blob

pytestmark = pytest.mark.local_integration


def _layout(root: Path, *, history: str) -> Path:
    layout = root / "layout"
    layout.mkdir(parents=True)
    atomic_write_json(layout / "oci-layout", {"imageLayoutVersion": "1.0.0"})
    config_digest, config_size = _write_blob(
        layout,
        canonical_json_bytes(
            {
                "architecture": "amd64",
                "os": "linux",
                "config": {"User": "0", "Cmd": ["/sbin/init"]},
                "rootfs": {"type": "layers", "diff_ids": []},
                "history": [{"created_by": history, "empty_layer": True}],
            }
        ),
    )
    digest, size = _write_blob(
        layout,
        canonical_json_bytes(
            {
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST,
                "config": {
                    "mediaType": OCI_CONFIG,
                    "digest": config_digest,
                    "size": config_size,
                },
                "layers": [],
            }
        ),
    )
    atomic_write_json(
        layout / "index.json",
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": OCI_MANIFEST,
                    "digest": digest,
                    "size": size,
                    "platform": {"os": "linux", "architecture": "amd64"},
                }
            ],
        },
    )
    return layout


def _hostile_configuration(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / ".trivyignore").write_text("DS-0002\nDS002\ngithub-pat\n")
    (directory / "trivy.yaml").write_text(
        "severity: [UNKNOWN]\nscan:\n  skip-dirs: ['**']\n"
    )
    (directory / "trivy-secret.yaml").write_text("disable-rules: [github-pat]\n")


def test_real_trivy_ignores_ambient_and_repository_suppressions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_run_id()
    runtime = ApplicationRuntime.create(
        tmp_path / "environment", names=(ToolName.TRIVY,), resolver=tool_resolver()
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "Containerfile").write_text("FROM scratch\nUSER 0\n")
    # Deliberately invalid fixture token, not a credential.
    (source / "token.txt").write_text(
        "github_token=ghp_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5" + "\n"
    )
    trivy = runtime.trivy()
    baseline = trivy.scan_filesystem(
        path=source,
        report_path=tmp_path / "baseline.json",
        cache_root=tmp_path / "cache",
        scanners=("misconfig", "secret"),
    )
    ambient = tmp_path / "ambient"
    _hostile_configuration(ambient)
    _hostile_configuration(source)
    monkeypatch.chdir(ambient)
    monkeypatch.setenv("TRIVY_SEVERITY", "UNKNOWN")
    hostile = trivy.scan_filesystem(
        path=source,
        report_path=tmp_path / "hostile.json",
        cache_root=tmp_path / "cache",
        scanners=("misconfig", "secret"),
    )
    before = evaluate_trivy_report(
        baseline.value, image_id="fixture", exceptions=(), today=date(2026, 9, 8)
    )
    after = evaluate_trivy_report(
        hostile.value, image_id="fixture", exceptions=(), today=date(2026, 9, 8)
    )
    assert before.findings == after.findings
    assert any("DS-0002" in finding.message for finding in after.findings)
    assert any("Secret finding" in finding.message for finding in after.findings)


@pytest.mark.parametrize("history_secret", [False, True])
def test_real_trivy_scans_inherited_root_and_history_without_a_containerfile(
    tmp_path: Path, trivy_cache: Path, history_secret: bool
) -> None:
    manifest_run_id()
    runtime = ApplicationRuntime.create(
        tmp_path / "environment", names=(ToolName.TRIVY,), resolver=tool_resolver()
    )
    history = "USER 0"
    if history_secret:
        history = "ENV GITHUB_TOKEN=ghp_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"
    layout = _layout(tmp_path, history=history)
    trivy = runtime.trivy()
    report = trivy.scan_layout(
        layout_path=layout,
        report_path=tmp_path / "image.json",
        cache_root=trivy.select_database(trivy_cache).path,
    )
    reviewed = replace(
        runtime_config(profile="systemd"),
        user=0,
        root_requirement=RuntimeRequirement(
            "systemd manages test services", "maintainer", "runtime changes"
        ),
    )
    ordinary = evaluate_trivy_report(
        report.value, image_id="fixture", exceptions=(), today=date(2026, 9, 8)
    )
    allowed = evaluate_trivy_report(
        report.value,
        image_id="fixture",
        exceptions=(),
        today=date(2026, 9, 8),
        runtime=reviewed,
    )
    assert any("DS-0002" in finding.message for finding in ordinary.findings)
    assert reviewed.root_requirement is not None
    assert allowed.applied_runtime_requirements == (
        {
            "checkId": "DS-0002",
            "requirement": "root_requirement",
            **reviewed.root_requirement.to_dict(),
        },
    )
    assert allowed.accepted is (not history_secret)
    if history_secret:
        assert any("Secret finding" in finding.message for finding in allowed.findings)
