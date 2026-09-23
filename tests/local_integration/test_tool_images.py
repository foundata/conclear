"""Trivy and Hadolint from their pinned images produce what the host binaries do.

The real images are pulled into a run-owned store, the Trivy signature is
verified against Sigstore, and every finding is compared with the host tool of
the same version. Network access is needed for the pulls and the verification.
"""

from pathlib import Path
from typing import Any, cast

import pytest

from conclear.path_safety import contained_path
from conclear.runtime import ApplicationRuntime
from conclear.scan_identity import ScanIdentity
from conclear.tool_images import ImageBackedTool
from conclear.tools import SUPPORTED_TOOLS, ToolName
from tests.local_integration.fixtures import manifest_run_id, tool_resolver

pytestmark = pytest.mark.local_integration

# Unpinned packages and a missing user give both linters something to report.
CONTAINERFILE = (
    "FROM docker.io/library/debian:13-slim\n"
    "RUN apt-get update && apt-get install -y curl\n"
    'ENTRYPOINT ["/usr/bin/curl"]\n'
)
SUBJECT = "example.invalid/fixture@sha256:" + "a" * 64


def test_tools_run_from_their_images_match_the_host_binaries(tmp_path: Path) -> None:
    run_id = manifest_run_id()
    root = contained_path(tmp_path, run_id, must_exist=False)
    names = (ToolName.HADOLINT, ToolName.TRIVY)
    host = ApplicationRuntime.create(
        root / "host", names=names, resolver=tool_resolver(), images=frozenset()
    )
    images = ApplicationRuntime.create(
        root / "images", names=names, resolver=tool_resolver(), images=frozenset(names)
    )
    try:
        assert tuple(images.tools) == (ToolName.PODMAN, ToolName.COSIGN, *names)
        for name in names:
            tool = images.tools[name]
            assert isinstance(tool, ImageBackedTool)
            pinned = SUPPORTED_TOOLS[name].image
            assert pinned is not None
            identity = tool.record_identity().to_dict()
            assert identity["imageDigest"] == pinned.digest
            # Both publishers ship multi-platform indexes, so the manifest that
            # ran is a different object than the pinned index.
            assert identity["imageManifestDigest"] != pinned.digest
            assert tool.version == host.tools[name].version, name
        assert images.tool_image_store is not None
        assert images.tool_image_store.root.is_dir()

        context = root / "source" / "context"
        context.mkdir(parents=True)
        containerfile = context / "Containerfile"
        containerfile.write_text(CONTAINERFILE, encoding="utf-8")
        host_findings = host.hadolint().check(containerfile, config_directory=context)
        image_findings = images.hadolint().check(
            containerfile, config_directory=context
        )
        assert host_findings, "the fixture Containerfile should produce findings"
        assert image_findings == host_findings

        reports: dict[str, dict[str, Any]] = {}
        for label, runtime in (("host", host), ("image", images)):
            report = root / "reports" / label / "containerfile-scan.json"
            report.parent.mkdir(parents=True)
            cache = root / "trivy-cache" / label
            cache.mkdir(parents=True)
            scan = runtime.trivy().scan_filesystem(
                path=context,
                report_path=report,
                cache_root=cache,
                scanners=("secret", "misconfig"),
                identity=ScanIdentity(
                    workspace_root=root, subject=SUBJECT, artifact_path=context
                ),
            )
            reports[label] = cast(dict[str, Any], scan.value)
        assert reports["host"]["ArtifactName"] == SUBJECT
        assert reports["host"]["Results"], "the fixture should yield misconfigurations"
        # Identical evidence is the point: neither the container paths nor the
        # host paths may leak into what the two modes report.
        assert reports["image"]["ArtifactName"] == reports["host"]["ArtifactName"]
        assert reports["image"]["Results"] == reports["host"]["Results"]
        for report_value in reports.values():
            text = str(report_value)
            assert "/conclear/" not in text and str(root) not in text
    finally:
        images.close()
        host.close()
    assert not (root / "images" / "tool-images").exists()
