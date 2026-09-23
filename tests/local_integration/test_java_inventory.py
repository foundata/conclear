"""Real Trivy inventory of a Java artifact and the Java database verdict it drives.

`scan_policy.java_artifacts` decides whether Trivy's Java database is relevant to
an image by counting `pkg:maven` package URLs. That prefix is an assumption
about what a real scanner emits, and a wrong one would make `CC0507` silently
never fire, so this tier builds an image that genuinely contains a jar and reads
the purl back out of the generated SPDX document.
"""

import gzip
import io
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conclear.database import evaluate_java_database
from conclear.jsonutil import atomic_write_json, canonical_json_bytes, sha256_bytes
from conclear.oci import OCI_CONFIG, OCI_MANIFEST
from conclear.runtime import ApplicationRuntime
from conclear.scan_policy import JAVA_PURL_PREFIX, java_artifacts
from conclear.tools import ToolName
from tests.local_integration.fixtures import manifest_run_id, tool_resolver
from tests.unit.test_oci import _write_blob

pytestmark = pytest.mark.local_integration

OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
GROUP = "com.example.drill"
ARTIFACT = "library"
VERSION = "1.2.3"
EXPECTED_PURL = f"{JAVA_PURL_PREFIX}{GROUP}/{ARTIFACT}@{VERSION}"

NOW = datetime(2026, 1, 2, tzinfo=UTC)


def _database_metadata(*, java_next_update: str) -> dict[str, object]:
    return {
        "vulnerability": {
            "schemaVersion": 2,
            "updatedAt": "2026-01-01T00:00:00Z",
            "nextUpdate": "2026-01-03T00:00:00Z",
            "downloadedAt": "2026-01-01T00:01:00Z",
        },
        "java": {
            "schemaVersion": 1,
            "updatedAt": "2026-01-01T00:00:00Z",
            "nextUpdate": java_next_update,
            "downloadedAt": "2026-01-01T00:01:00Z",
        },
    }


def _jar_bytes() -> bytes:
    """Build a jar that carries its own Maven coordinates.

    Trivy needs its Java database only to identify a jar that has no embedded
    coordinates; `generate_spdx` runs `--offline-scan --skip-java-db-update`, so
    the fixture states them the way a published artifact does.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        archive.writestr(
            f"META-INF/maven/{GROUP}/{ARTIFACT}/pom.properties",
            f"groupId={GROUP}\nartifactId={ARTIFACT}\nversion={VERSION}\n",
        )
        archive.writestr(
            f"{GROUP.replace('.', '/')}/Library.class", b"\xca\xfe\xba\xbe"
        )
    return buffer.getvalue()


def _java_layout(root: Path) -> Path:
    """Write one single-platform OCI layout whose only layer holds the jar."""
    layout = root / "layout"
    layout.mkdir(parents=True)
    atomic_write_json(layout / "oci-layout", {"imageLayoutVersion": "1.0.0"})
    jar = _jar_bytes()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        entry = tarfile.TarInfo(f"opt/drill/{ARTIFACT}-{VERSION}.jar")
        entry.size = len(jar)
        entry.mode = 0o644
        archive.addfile(entry, io.BytesIO(jar))
    uncompressed = raw.getvalue()
    compressed = gzip.compress(uncompressed, mtime=0)
    layer_digest, layer_size = _write_blob(layout, compressed)
    config_digest, config_size = _write_blob(
        layout,
        canonical_json_bytes(
            {
                "architecture": "amd64",
                "os": "linux",
                "config": {"User": "10001", "Cmd": ["/opt/drill/run"]},
                "rootfs": {
                    "type": "layers",
                    "diff_ids": [sha256_bytes(uncompressed)],
                },
                "history": [{"created_by": "COPY library.jar", "empty_layer": False}],
            }
        ),
    )
    manifest_digest, manifest_size = _write_blob(
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
                "layers": [
                    {
                        "mediaType": OCI_LAYER,
                        "digest": layer_digest,
                        "size": layer_size,
                    }
                ],
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
                    "digest": manifest_digest,
                    "size": manifest_size,
                    "platform": {"os": "linux", "architecture": "amd64"},
                }
            ],
        },
    )
    return layout


@pytest.fixture(scope="module")
def java_inventory(
    tmp_path_factory: pytest.TempPathFactory, trivy_cache: Path
) -> dict[str, object]:
    """Return the SPDX document real Trivy generates for an image with a jar."""
    manifest_run_id()
    root = tmp_path_factory.mktemp("java-inventory")
    runtime = ApplicationRuntime.create(
        root / "environment", names=(ToolName.TRIVY,), resolver=tool_resolver()
    )
    trivy = runtime.trivy()
    sbom = trivy.generate_spdx(
        layout_path=_java_layout(root),
        output_path=root / "java.spdx.json",
        cache_root=trivy.select_database(trivy_cache).path,
    )
    document = sbom.value
    assert isinstance(document, dict)
    return document


def test_real_trivy_inventories_a_maven_artifact_with_the_expected_purl(
    java_inventory: dict[str, object],
) -> None:
    packages = java_inventory.get("packages")
    assert isinstance(packages, list)
    locators = [
        reference.get("referenceLocator")
        for package in packages
        if isinstance(package, dict)
        for reference in package.get("externalRefs", [])
        if isinstance(reference, dict) and reference.get("referenceType") == "purl"
    ]

    assert EXPECTED_PURL in locators, locators
    assert java_artifacts(java_inventory) == 1


def test_a_real_java_inventory_drives_the_java_database_verdict(
    java_inventory: dict[str, object],
) -> None:
    artifacts = java_artifacts(java_inventory)
    stale = _database_metadata(java_next_update="2026-01-01T12:00:00Z")

    fresh_database = evaluate_java_database(
        _database_metadata(java_next_update="2026-01-03T00:00:00Z"),
        at=NOW,
        artifacts=artifacts,
        accepted_stale=False,
    )
    rejected = evaluate_java_database(
        stale, at=NOW, artifacts=artifacts, accepted_stale=False
    )
    accepted = evaluate_java_database(
        stale, at=NOW, artifacts=artifacts, accepted_stale=True
    )

    assert fresh_database.finding is None
    assert fresh_database.to_dict() == {
        "fresh": True,
        "required": True,
        "acceptedStale": False,
        "artifacts": 1,
    }
    assert rejected.finding is not None
    assert (rejected.finding.check_id, rejected.finding.severity) == (
        "CC0507",
        "error",
    )
    assert accepted.finding is not None
    assert (accepted.finding.check_id, accepted.finding.severity) == (
        "CC0507",
        "warning",
    )
    assert accepted.to_dict()["acceptedStale"] is True
