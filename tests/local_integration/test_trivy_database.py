"""Real Trivy database snapshots, layout scans and SPDX generation.

The database cache is manifest-owned and selected with ``CONCLEAR_TEST_TRIVY_CACHE``
through the session-scoped ``trivy_cache`` fixture, which refreshes a missing
snapshot through the production adapter only when ``CONCLEAR_TEST_TRIVY_DOWNLOAD=1``
is also set, because that download is the one local step that needs the network
and fetches roughly a gigabyte. Every later run is offline and reuses the pinned
snapshot.
"""

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

import conclear.records as records_module
import conclear.services.assembly as assembly_module
from conclear.artifacts import qualification_transports
from conclear.config import load_repository_config
from conclear.errors import OperationalError
from conclear.hooks import HookRunner
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import load_json, sha256_bytes
from conclear.path_safety import contained_path
from conclear.records import SourceIdentity, Verdict, utc_now, validate_record
from conclear.runtime import ApplicationRuntime
from conclear.services.assembly import assemble_candidate
from conclear.services.preflight import ClosurePreflight, ImagePreflight
from conclear.services.qualification import qualify_platform
from conclear.services.qualification_inputs import QualificationInputs
from conclear.source_integrity import source_tree_digest
from conclear.tools import ToolName
from conclear.values import Digest, Platform
from conclear.workspace import RunState, RunWorkspace
from tests.local_integration.fixtures import (
    FIXTURE_CONTAINERFILE,
    compile_fixture,
    manifest_run_id,
    tool_resolver,
)
from tests.release_fakes import FakeBaseResolver

pytestmark = pytest.mark.local_integration

AMD64 = Platform.parse("linux/amd64")


def test_real_trivy_database_snapshot_layout_scan_and_spdx(
    tmp_path: Path, trivy_cache: Path
) -> None:
    run_id = manifest_run_id()
    cache_root = trivy_cache
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(
        root / "environment",
        names=(ToolName.BUILDAH, ToolName.TRIVY),
        resolver=tool_resolver(),
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
            build_arguments={
                "IMAGE_CREATED": "2000-01-01T00:00:00Z",
                "IMAGE_REVISION": "a" * 40,
                "IMAGE_SOURCE": "https://github.com/foundata/conclear",
                "IMAGE_VERSION": "integration",
            },
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


SOURCE = "https://github.com/example/fixture"
NOW = datetime(2026, 9, 8, tzinfo=UTC)
SOURCE_TIME = datetime(2000, 1, 1, tzinfo=UTC)
QUALIFICATION_CONFIGURATION = f"""\
schema_version = 1

[project]
name = "fixture"
source = "{SOURCE}"

[[images]]
id = "fixture"
repository = "quay.io/example/fixture"
platforms = ["linux/amd64", "linux/amd64/v3"]

[images.release]
version_tags = ["{{version}}"]
moving_tags = ["stable"]

[images.runtime]
profile = "service"
user = 65532
writable_mounts = ["/tmp"]
memory = "128MiB"
cpus = 1.0
pids = 64
nofile = 256
health_command = ["/app/conclear-fixture", "health"]
startup_timeout_seconds = 30
shutdown_timeout_seconds = 30
"""


class _IdFactory:
    def __init__(self, value: str) -> None:
        self._value = value

    def create(self) -> str:
        return self._value


def test_real_trivy_qualifies_two_platforms_from_one_database_snapshot(
    tmp_path: Path, trivy_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Qualification records and assembly with a real Trivy, sharing one snapshot.

    A development checkout cannot emit public records, so the embedded identity
    is replaced as the unit tier does; every tool identity in the records is
    still the real resolved executable.
    """
    identity = ApplicationIdentity(source_revision="c" * 40)
    monkeypatch.setattr(records_module, "IDENTITY", identity)
    monkeypatch.setattr(assembly_module, "IDENTITY", identity)
    run_id = manifest_run_id()
    workspace_id = os.environ.get("CONCLEAR_TEST_QUALIFICATION_ULID")
    if workspace_id is None:
        pytest.skip("this case requires CONCLEAR_TEST_QUALIFICATION_ULID")
    root = contained_path(tmp_path, f"{run_id}-qualification", must_exist=False)
    runtime = ApplicationRuntime.create(
        root / "environment",
        names=(ToolName.BUILDAH, ToolName.PODMAN, ToolName.TRIVY),
        resolver=tool_resolver(),
    )
    context = compile_fixture(runtime, root=root, architecture="amd64")
    (context / "Containerfile").write_text(
        FIXTURE_CONTAINERFILE.replace("ARG IMAGE_SOURCE\n", "")
        .replace(
            "org.opencontainers.image.source=$IMAGE_SOURCE",
            f"org.opencontainers.image.source={SOURCE}",
        )
        .replace(
            "LABEL org.opencontainers.image.version=$IMAGE_VERSION\n",
            "LABEL org.opencontainers.image.version=$IMAGE_VERSION\n"
            'LABEL org.opencontainers.image.title="ConClear fixture"\n',
        ),
        encoding="utf-8",
    )
    (context / ".containerignore").write_text(
        "**/.git/\n**/.env*\n**/*.key\n**/*.pem\n**/.venv/\n**/venv/\n",
        encoding="utf-8",
    )
    (context / "conclear.toml").write_text(
        QUALIFICATION_CONFIGURATION, encoding="utf-8"
    )
    repository = load_repository_config(context / "conclear.toml")
    image = repository.release_image("fixture")
    workspace = RunWorkspace.create(
        state_home=root / "state",
        immutable_inputs={
            "sourceRevision": "a" * 40,
            "configurationDigest": sha256_bytes(repository.raw_bytes),
            "sourceTreeDigest": source_tree_digest(context),
            "image": "fixture",
            "version": "integration",
        },
        id_factory=_IdFactory(workspace_id),
        now=NOW,
    )
    trivy = runtime.trivy()
    database = trivy.select_database(trivy_cache)
    qualification_started_at = utc_now()
    preflight = ClosurePreflight(primary=ImagePreflight(image, (), ()), dependencies=())

    digests = []
    for platform_text in ("linux/amd64", "linux/amd64/v3"):
        inputs = QualificationInputs(
            repository=repository,
            image=image,
            workspace=workspace,
            source=SourceIdentity(repository.project.source, "a" * 40),
            source_time=SOURCE_TIME,
            version="integration",
            platform=Platform.parse(platform_text),
            tools=runtime.identities,
            auth_file=None,
            host_architecture="x86_64",
        )
        # Workers share the original snapshot and qualification start.
        selected = trivy.select_database_by_digest(trivy_cache, Digest(database.digest))
        result = qualify_platform(
            inputs,
            builder=runtime.buildah(),
            base_resolver=FakeBaseResolver(),
            runtime=runtime.podman(),
            hooks=HookRunner(
                runner=runtime.runner,
                environment=runtime.environment,
                source_root=context,
                log_directory=workspace.root / "logs",
            ),
            scanner=trivy,
            database=selected,
            preflight=preflight,
            now=utc_now(),
            record_clock=utc_now,
            qualification_started_at=qualification_started_at,
        )
        record = load_json(result.record_path)
        validate_record(record)
        payload = record["payload"]
        assert result.verdict is Verdict.ACCEPTED, [
            finding.to_dict() for finding in result.findings
        ]
        assert payload["databaseDigest"] == database.digest
        assert [scan["path"] for scan in payload["scans"]] == [
            "source-scan.json",
            "containerfile-scan.json",
            "image-scan.json",
        ]
        assert payload["sbom"]["spdxVersion"] == "SPDX-2.3"
        assert {tool["name"]: tool["version"] for tool in record["tools"]}[
            "trivy"
        ] == runtime.tools[ToolName.TRIVY].version
        digests.append(payload["databaseDigest"])
    assert digests[0] == digests[1]

    workspace.transition(RunState.QUALIFIED)
    candidate = assemble_candidate(
        qualification_transports(workspace, image),
        repository=repository,
        image=image,
        workspace=workspace,
        version="integration",
        source_time=SOURCE_TIME,
        tools=runtime.identities,
        now=utc_now(),
        clock=utc_now,
    )
    assert candidate.record_path.is_file()
    assert len(candidate.observation.platform_manifests) == 2
