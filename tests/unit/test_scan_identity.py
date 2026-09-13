"""Scanner evidence names the subject, never the release host."""

from pathlib import Path
from typing import Any, cast

from conclear.scan_identity import (
    ScanIdentity,
    evidence_path,
    neutralize_scan_report,
    neutralize_spdx_document,
)

SUBJECT = "quay.io/example/app@sha256:" + "a" * 64


def identity(tmp_path: Path) -> ScanIdentity:
    return ScanIdentity(
        workspace_root=tmp_path / "runs" / "01run",
        subject=SUBJECT,
        artifact_path=tmp_path / "runs" / "01run" / "layouts" / "app" / "linux-amd64",
    )


def test_trivy_report_targets_and_artifact_name_name_the_subject(
    tmp_path: Path,
) -> None:
    layout = str(tmp_path / "runs" / "01run" / "layouts" / "app" / "linux-amd64")
    report = {
        "ArtifactName": layout,
        "ArtifactType": "oci",
        "Metadata": {"OS": {"Family": "fedora", "Name": "43"}},
        "Results": [
            {"Target": f"{layout} (fedora 43)", "Class": "os-pkgs", "Type": "fedora"},
            {"Target": layout, "Class": "config", "Type": "dockerfile"},
            {
                "Target": f"{tmp_path / 'runs' / '01run' / 'source' / 'Containerfile'}",
                "Misconfigurations": [
                    {
                        "CauseMetadata": {
                            "Resource": f"{layout}/x",
                            "Code": {"Lines": [1]},
                        }
                    }
                ],
            },
        ],
    }

    rewritten = cast(dict[str, Any], neutralize_scan_report(report, identity(tmp_path)))

    assert rewritten["ArtifactName"] == SUBJECT
    results = rewritten["Results"]
    assert results[0]["Target"] == f"{SUBJECT} (fedora 43)"
    assert results[1]["Target"] == SUBJECT
    assert results[2]["Target"] == "source/Containerfile"
    assert results[2]["Misconfigurations"][0]["CauseMetadata"]["Resource"] == (
        f"{SUBJECT}/x"
    )
    assert results[2]["Misconfigurations"][0]["CauseMetadata"]["Code"] == {"Lines": [1]}
    assert str(tmp_path) not in repr(rewritten)
    assert report["ArtifactName"] == layout, "input is not mutated"


def test_spdx_document_name_namespace_and_root_package_name_the_subject(
    tmp_path: Path,
) -> None:
    layout = str(tmp_path / "runs" / "01run" / "layouts" / "app" / "linux-amd64")
    document: dict[str, object] = {
        "spdxVersion": "SPDX-2.3",
        "name": layout,
        "documentNamespace": f"http://trivy.dev/container_image/{layout}-1234",
        "packages": [
            {"name": layout, "SPDXID": "SPDXRef-ContainerImage-1"},
            {"name": "bash", "SPDXID": "SPDXRef-Package-2", "versionInfo": "5.2"},
        ],
    }

    rewritten = cast(
        dict[str, Any], neutralize_spdx_document(document, identity(tmp_path))
    )

    assert rewritten["name"] == SUBJECT
    assert rewritten["documentNamespace"] == (
        f"http://trivy.dev/container_image/{SUBJECT}-1234"
    )
    packages = rewritten["packages"]
    assert packages[0]["name"] == SUBJECT
    assert packages[1] == {
        "name": "bash",
        "SPDXID": "SPDXRef-Package-2",
        "versionInfo": "5.2",
    }
    assert str(tmp_path) not in repr(rewritten)


def test_workspace_paths_become_relative_and_foreign_paths_stay(tmp_path: Path) -> None:
    value = identity(tmp_path)
    root = str(tmp_path / "runs" / "01run")
    assert value.rewrite_text(root) == "."
    assert value.rewrite_text(f"{root}/reports/x.json") == "reports/x.json"
    assert value.rewrite_text("/usr/lib/os-release") == "/usr/lib/os-release"
    assert value.rewrite_text("bash") == "bash"


def test_evidence_path_is_relative_inside_the_root_and_a_name_outside(
    tmp_path: Path,
) -> None:
    root = tmp_path / "context"
    assert evidence_path(root / "Containerfile", root) == "Containerfile"
    assert evidence_path(root / "sub" / "Containerfile", root) == "sub/Containerfile"
    assert (
        evidence_path(tmp_path / "elsewhere" / "Containerfile", root) == "Containerfile"
    )
