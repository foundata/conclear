"""Real Trivy database snapshots, layout scans and SPDX generation.

The database cache is manifest-owned and selected with ``CONCLEAR_TEST_TRIVY_CACHE``
through the session-scoped ``trivy_cache`` fixture, which refreshes a missing
snapshot through the production adapter only when ``CONCLEAR_TEST_TRIVY_DOWNLOAD=1``
is also set, because that download is the one local step that needs the network
and fetches roughly a gigabyte. Every later run is offline and reuses the pinned
snapshot.
"""

from pathlib import Path

import pytest

from conclear.errors import OperationalError
from conclear.path_safety import contained_path
from conclear.runtime import ApplicationRuntime
from conclear.tools import ToolName
from conclear.values import Digest, Platform
from tests.local_integration.fixtures import compile_fixture, manifest_run_id

pytestmark = pytest.mark.local_integration

AMD64 = Platform.parse("linux/amd64")


def test_real_trivy_database_snapshot_layout_scan_and_spdx(
    tmp_path: Path, trivy_cache: Path
) -> None:
    run_id = manifest_run_id()
    cache_root = trivy_cache
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(
        root / "environment", names=(ToolName.BUILDAH, ToolName.TRIVY)
    )
    trivy = runtime.trivy()

    # Selection revalidates the exact stored bytes against the pointer and digest.
    database = trivy.select_database(cache_root)
    assert database.path == cache_root / "snapshots" / database.digest.removeprefix(
        "sha256:"
    )
    by_digest = trivy.select_database_by_digest(cache_root, Digest(database.digest))
    assert by_digest.digest == database.digest
    with pytest.raises(OperationalError):
        trivy.select_database_by_digest(cache_root, Digest("sha256:" + "0" * 64))
    vulnerability = database.metadata["vulnerability"]
    java = database.metadata["java"]
    assert isinstance(vulnerability, dict) and isinstance(java, dict)
    assert vulnerability["schemaVersion"] == 2
    assert java["schemaVersion"] == 1
    for component in (vulnerability, java):
        for field in ("updatedAt", "nextUpdate", "downloadedAt"):
            assert str(component[field]).endswith("Z")

    # Scans and the SPDX inventory run offline against the selected snapshot only.
    buildah_root = root / "buildah" / "root"
    buildah_runroot = root / "buildah" / "runroot"
    ready = False
    try:
        assert runtime.buildah().info(root=buildah_root, runroot=buildah_runroot)
        ready = True
        context = compile_fixture(runtime, root=root, architecture="amd64")
        built = runtime.buildah().build(
            root=buildah_root,
            runroot=buildah_runroot,
            containerfile=context / "Containerfile",
            context=context,
            platform=AMD64,
            image_name=f"localhost/conclear-{run_id.lower()}-trivy:fixture",
            layout_path=root / "layouts" / "amd64",
            layout_reference="fixture",
            source_epoch=946684800,
            build_arguments={},
            auth_file=None,
        )
    finally:
        if ready:
            runtime.buildah().remove_storage(root=buildah_root, runroot=buildah_runroot)

    reports = root / "reports"
    reports.mkdir(mode=0o700)
    image_scan = trivy.scan_layout(
        layout_path=built.layout_path,
        report_path=reports / "image-scan.json",
        cache_root=database.path,
    )
    assert isinstance(image_scan.value, dict)
    assert image_scan.value["SchemaVersion"] == 2
    assert isinstance(image_scan.value.get("Results", []), list)

    sbom = trivy.generate_spdx(
        layout_path=built.layout_path,
        output_path=reports / "image.spdx.json",
        cache_root=database.path,
    )
    assert isinstance(sbom.value, dict)
    assert sbom.value["spdxVersion"] == "SPDX-2.3"
    assert any(
        package.get("name") == "conclear-fixture"
        or str(package.get("name", "")).endswith("/conclear-fixture")
        for package in sbom.value["packages"]
    ), [package.get("name") for package in sbom.value["packages"]]

    sbom_scan = trivy.scan_sbom(
        sbom_path=sbom.path,
        report_path=reports / "sbom-scan.json",
        cache_root=database.path,
    )
    assert isinstance(sbom_scan.value, dict)
    assert sbom_scan.value["SchemaVersion"] == 2

    # The snapshot itself is never modified by scanning.
    assert trivy.select_database_by_digest(
        cache_root, Digest(database.digest)
    ).digest == (database.digest)
