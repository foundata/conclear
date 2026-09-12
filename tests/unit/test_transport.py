"""Worker qualification transports assemble only after exact verification.

Two fake-backed worker runs qualify `linux/amd64` and `linux/arm64`, export
their qualifications as archive and directory transports, and a separate
coordinator run imports, verifies and assembles them. Every negative case
tampers with a real transport so the rejection exercises the same code path a
hostile artifact store would hit.
"""

import io
import itertools
import json
import os
import re
import tarfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import conclear.records as records_module
import conclear.services.assembly as assembly_module
import conclear.transport as transport_module
from conclear.adapters.trivy import DatabaseObservation
from conclear.artifacts import load_candidate, load_provenance_materials
from conclear.config import load_repository_config
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import load_json, sha256_bytes, sha256_file
from conclear.oci import validate_layout
from conclear.records import SourceIdentity, ToolIdentity, Verdict
from conclear.services.assembly import assemble_candidate
from conclear.services.cleanup import cleanup_run
from conclear.services.qualification import qualify_platform
from conclear.services.qualification_inputs import QualificationInputs
from conclear.source_integrity import source_tree_digest
from conclear.transport import (
    MANIFEST_NAME,
    TransportKind,
    export_transport,
    import_transport,
)
from conclear.values import Platform
from conclear.workspace import ResourceStatus, RunState, RunWorkspace
from tests.release_fakes import FakePodman
from tests.unit.test_qualification import (
    DATABASE_METADATA,
    Builder,
    Runtime,
    Scanner,
    _register_arm64_handler,
    closure_preflight,
    hook_runner,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
AMD64 = Platform.parse("linux/amd64")
ARM64 = Platform.parse("linux/arm64")
ARM64_V8 = Platform.parse("linux/arm64/v8")
REVISION = "b" * 40
WORKER_IDS = {
    AMD64: "01arz3ndektsv4rrffq69g5fa1",
    ARM64: "01arz3ndektsv4rrffq69g5fa2",
}
COORDINATOR_ID = "01arz3ndektsv4rrffq69g5fc0"


class FixedId:
    def __init__(self, value: str) -> None:
        self.value = value

    def create(self) -> str:
        return self.value


def tool(version: str = "1.43.2") -> ToolIdentity:
    return ToolIdentity("buildah", version, executable_digest="sha256:" + "d" * 64)


@pytest.fixture(autouse=True)
def embedded_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = ApplicationIdentity(source_revision="c" * 40)
    for module in (records_module, assembly_module, transport_module):
        monkeypatch.setattr(module, "IDENTITY", identity)


def two_platform_repository(repository_factory: Callable[..., Path]) -> Path:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'platforms = ["linux/amd64"]', 'platforms = ["linux/amd64", "linux/arm64"]'
        ),
        encoding="utf-8",
    )
    return root


@dataclass
class Worker:
    """One fake-backed worker run holding an accepted qualification."""

    workspace: RunWorkspace
    inputs: QualificationInputs
    record_path: Path

    @property
    def image(self) -> Any:
        return self.inputs.image

    def rewrite_record(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        value = json.loads(self.record_path.read_text(encoding="utf-8"))
        mutate(value)
        self.record_path.write_text(json.dumps(value), encoding="utf-8")


def qualify_worker(
    tmp_path: Path,
    source_root: Path,
    platform: Platform,
    *,
    run_id: str | None = None,
    version: str | None = "1.2.3",
    source_revision: str = REVISION,
    tools: tuple[ToolIdentity, ...] = (tool(),),
    builder: Builder | None = None,
    database_digest: str = "sha256:" + "e" * 64,
) -> Worker:
    repository = load_repository_config(source_root / "conclear.toml")
    state_home = tmp_path / "workers" / (run_id or WORKER_IDS[platform]) / "state"
    workspace = RunWorkspace.create(
        state_home=state_home,
        immutable_inputs={
            "sourceRevision": source_revision,
            "configurationDigest": sha256_bytes(repository.raw_bytes),
            "sourceTreeDigest": source_tree_digest(source_root),
            "image": "app",
            "version": version or "",
        },
        id_factory=FixedId(run_id or WORKER_IDS[platform]),
        now=NOW,
    )
    inputs = QualificationInputs(
        repository=repository,
        image=repository.release_image("app"),
        workspace=workspace,
        source=SourceIdentity(repository.project.source, source_revision),
        source_time=NOW,
        version=version,
        platform=platform,
        tools=tools,
        auth_file=None,
        host_architecture="x86_64",
        binfmt_root=_register_arm64_handler(tmp_path / "binfmt"),
    )
    selected_builder = builder or Builder(
        observed_variant="v8" if platform.architecture == "arm64" else None
    )
    database_path = tmp_path / "database" / platform.key
    database_path.mkdir(parents=True, exist_ok=True)
    result = qualify_platform(
        inputs,
        builder=selected_builder,
        runtime=Runtime(),
        hooks=hook_runner(inputs),
        scanner=Scanner(),
        database=DatabaseObservation(database_path, database_digest, DATABASE_METADATA),
        preflight=closure_preflight(inputs),
        now=NOW,
        record_clock=lambda: NOW,
    )
    workspace.transition(
        {
            Verdict.ACCEPTED: RunState.QUALIFIED,
            Verdict.REJECTED: RunState.REJECTED,
            Verdict.INCOMPLETE: RunState.INCOMPLETE,
        }[result.verdict]
    )
    return Worker(workspace, inputs, result.record_path)


def export(
    worker: Worker,
    destination: Path,
    *,
    kind: TransportKind = TransportKind.ARCHIVE,
) -> Any:
    return export_transport(
        worker.workspace,
        worker.image,
        worker.inputs.platform,
        destination=destination,
        kind=kind,
        now=NOW,
    )


def coordinator_workspace(
    tmp_path: Path,
    source_root: Path,
    *,
    run_id: str = COORDINATOR_ID,
    version: str | None = "1.2.3",
    source_revision: str = REVISION,
) -> RunWorkspace:
    repository = load_repository_config(source_root / "conclear.toml")
    return RunWorkspace.create(
        state_home=tmp_path / "coordinator" / run_id / "state",
        immutable_inputs={
            "sourceRevision": source_revision,
            "configurationDigest": sha256_bytes(repository.raw_bytes),
            "sourceTreeDigest": source_tree_digest(source_root),
            "image": "app",
            "version": version or "",
        },
        id_factory=FixedId(run_id),
        now=NOW,
    )


def assemble(
    workspace: RunWorkspace,
    source_root: Path,
    transports: tuple[tuple[Path, str], ...],
    *,
    version: str | None = "1.2.3",
    image: Any = None,
) -> Any:
    repository = load_repository_config(source_root / "conclear.toml")
    selected = image or repository.release_image("app")
    imported = tuple(
        import_transport(
            path,
            expected_digest=digest,
            workspace=workspace,
            image=selected,
            repository=repository,
            source_time=NOW,
        )
        for path, digest in transports
    )
    workspace.transition(RunState.QUALIFIED)
    return assemble_candidate(
        tuple(item.transport for item in imported),
        repository=repository,
        image=selected,
        workspace=workspace,
        version=version,
        source_time=NOW,
        tools=(tool(),),
        now=NOW,
        clock=lambda: NOW,
    )


@dataclass
class Setup:
    """Two accepted workers and their exported archive transports."""

    source_root: Path
    amd64: Worker
    arm64: Worker
    amd64_transport: Any
    arm64_transport: Any


@pytest.fixture
def setup(tmp_path: Path, repository_factory: Callable[..., Path]) -> Setup:
    source_root = two_platform_repository(repository_factory)
    amd64 = qualify_worker(tmp_path, source_root, AMD64)
    arm64 = qualify_worker(tmp_path, source_root, ARM64)
    exports = tmp_path / "exports"
    return Setup(
        source_root,
        amd64,
        arm64,
        export(amd64, exports / "app-linux-amd64.tar"),
        export(arm64, exports / "app-linux-arm64.tar"),
    )


def test_two_worker_runs_assemble_an_exact_index_in_a_coordinator_run(
    tmp_path: Path, setup: Setup
) -> None:
    workspace = coordinator_workspace(tmp_path, setup.source_root)
    amd64, arm64 = setup.amd64_transport, setup.arm64_transport
    assert amd64.worker_run_id == WORKER_IDS[AMD64]
    assert arm64.worker_run_id == WORKER_IDS[ARM64]
    assert amd64.transport_digest == sha256_file(amd64.path)
    assert amd64.record_digest == sha256_file(setup.amd64.record_path)

    candidate = assemble(
        workspace,
        setup.source_root,
        (
            (amd64.path, amd64.transport_digest),
            (arm64.path, arm64.transport_digest),
        ),
    )

    graph = validate_layout(
        candidate.observation.path, reference=candidate.candidate_tag
    )
    assert graph.platforms == (AMD64, ARM64_V8)
    assert candidate.candidate_tag == (
        f"1.2.3-candidate.{COORDINATOR_ID}.g{REVISION[:8]}"
    )
    record = load_json(candidate.record_path)
    assert record["runId"] == COORDINATOR_ID
    assert [
        (item["platform"], item["runId"], item["transportDigest"])
        for item in record["payload"]["qualifications"]
    ] == [
        ("linux/amd64", WORKER_IDS[AMD64], amd64.transport_digest),
        ("linux/arm64", WORKER_IDS[ARM64], arm64.transport_digest),
    ]
    assert record["payload"]["platformManifests"] == {
        "linux/amd64": amd64.platform_manifest_digest,
        "linux/arm64/v8": arm64.platform_manifest_digest,
    }
    assert set(record["payload"]["qualifications"][0].keys()) >= {
        "recordDigest",
        "payloadDigests",
    }
    assert candidate.qualification_digests == (
        amd64.record_digest,
        arm64.record_digest,
    )
    assert workspace.load().state is RunState.ASSEMBLED

    # Worker records stay byte-identical and keep their worker identities.
    for worker, key in ((setup.amd64, "linux-amd64"), (setup.arm64, "linux-arm64")):
        installed = workspace.root / "records" / f"platform-qualification-{key}.json"
        assert installed.read_bytes() == worker.record_path.read_bytes()
        assert load_json(installed)["runId"] == worker.workspace.run_id

    # Downstream loaders accept the bound worker records without rewriting them.
    loaded = load_candidate(workspace, setup.amd64.image)
    assert dict(loaded.qualification_runs) == {
        AMD64: WORKER_IDS[AMD64],
        ARM64: WORKER_IDS[ARM64],
    }
    materials = load_provenance_materials(workspace, setup.amd64.image)
    assert {item.uri for item in materials} >= {
        "conclear:qualification/linux/amd64",
        "conclear:qualification/linux/arm64",
    }

    # Journal ownership covers imported layouts and the assembled candidate only.
    statuses = {
        entry.resource_id: entry.status for entry in workspace.journal.entries()
    }
    assert statuses["layout-app-linux-amd64"] is ResourceStatus.CREATED
    assert statuses["layout-app-linux-arm64"] is ResourceStatus.CREATED
    assert statuses["candidate-layout-app"] is ResourceStatus.CREATED
    assert all(
        status is ResourceStatus.REMOVED
        for name, status in statuses.items()
        if name.startswith("transport-")
    )
    assert not (workspace.root / "transports").exists() or not list(
        (workspace.root / "transports").iterdir()
    )


def test_directory_transport_assembles_like_an_archive(
    tmp_path: Path, setup: Setup
) -> None:
    directory = export(
        setup.arm64, tmp_path / "exports" / "arm64-dir", kind=TransportKind.DIRECTORY
    )
    assert directory.kind is TransportKind.DIRECTORY
    assert directory.transport_digest == sha256_file(directory.path / MANIFEST_NAME)
    assert directory.transport_digest == directory.manifest_digest
    members = {
        path.relative_to(directory.path).as_posix()
        for path in directory.path.rglob("*")
        if path.is_file()
    }
    assert members == {member.path for member in directory.members} | {MANIFEST_NAME}
    assert not any(path.is_symlink() for path in directory.path.rglob("*"))

    workspace = coordinator_workspace(tmp_path, setup.source_root)
    candidate = assemble(
        workspace,
        setup.source_root,
        (
            (setup.amd64_transport.path, setup.amd64_transport.transport_digest),
            (directory.path, directory.transport_digest),
        ),
    )

    assert candidate.observation.graph.platforms == (AMD64, ARM64_V8)
    record = load_json(candidate.record_path)
    assert record["payload"]["qualifications"][1]["transportDigest"] == (
        directory.transport_digest
    )
    # The caller-owned transports remain untouched after import.
    assert (directory.path / MANIFEST_NAME).is_file()
    assert setup.amd64_transport.path.is_file()


def test_export_reports_digests_and_excludes_run_internals(
    tmp_path: Path, setup: Setup
) -> None:
    amd64 = setup.amd64_transport
    assert amd64.layout_digest == amd64.platform_manifest_digest
    record = load_json(setup.amd64.record_path)
    assert amd64.payload_digests == tuple(sorted(record["payload"]["payloadDigests"]))
    with tarfile.open(amd64.path) as archive:
        names = archive.getnames()
        infos = archive.getmembers()
    assert names[0] == MANIFEST_NAME
    assert all(info.isfile() for info in infos)
    assert all(info.uid == 0 and info.gid == 0 and info.mtime == 0 for info in infos)
    assert not any(
        name.startswith(("logs/", "environment/", "buildah/", "source/", "reports/app"))
        or name.endswith(("build.json", ".key", "auth.json", "run.json"))
        for name in names
    )
    expected = {
        "records/platform-qualification-linux-amd64.json",
        "layouts/linux-amd64/oci-layout",
        "layouts/linux-amd64/index.json",
        "reports/linux-amd64/tests.json",
        "reports/linux-amd64/source-scan.json",
        "reports/linux-amd64/containerfile-scan.json",
        "reports/linux-amd64/image-scan.json",
        "exports/sbom/linux-amd64.spdx.json",
    }
    assert expected <= set(names)
    assert all(
        name in expected or name.startswith("layouts/linux-amd64/blobs/sha256/")
        for name in names[1:]
    )
    manifest = json.loads(_tar_member(amd64.path, MANIFEST_NAME))
    assert manifest["recordType"] == "qualificationTransport"
    assert manifest["runId"] == WORKER_IDS[AMD64]
    assert manifest["payload"]["qualificationRecordDigest"] == amd64.record_digest


def test_declared_output_archive_survives_worker_transport(
    tmp_path: Path, setup: Setup
) -> None:
    worker = setup.amd64
    path = worker.workspace.root / "reports/app/linux-amd64/test-outputs.tar"
    with tarfile.open(path, "w") as archive:
        header = tarfile.TarInfo("result/data.json")
        header.size = 2
        archive.addfile(header, io.BytesIO(b"{}"))
    digest = sha256_file(path)

    def declare(record: dict[str, Any]) -> None:
        record["payload"]["testOutputArchive"] = {"path": path.name, "digest": digest}
        record["payload"]["payloadDigests"].append(digest)

    worker.rewrite_record(declare)
    exported = export(worker, tmp_path / "outputs.tar")
    assert (
        _tar_member(exported.path, "reports/linux-amd64/test-outputs.tar")
        == path.read_bytes()
    )
    imported = _import(tmp_path, setup, exported.path, exported.transport_digest)
    retained = next(
        item for item in imported.transport.payload_paths if item.name == path.name
    )
    assert retained.read_bytes() == path.read_bytes()


def test_export_refuses_existing_destinations_and_unaccepted_qualifications(
    tmp_path: Path, setup: Setup, repository_factory: Callable[..., Path]
) -> None:
    with pytest.raises(InvalidInvocationError, match="already exists"):
        export(setup.amd64, setup.amd64_transport.path)
    occupied = tmp_path / "exports" / "occupied"
    occupied.mkdir()
    with pytest.raises(InvalidInvocationError, match="already exists"):
        export(setup.amd64, occupied, kind=TransportKind.DIRECTORY)

    rejected = qualify_worker(
        tmp_path,
        setup.source_root,
        AMD64,
        run_id="01arz3ndektsv4rrffq69g5fa3",
        builder=Builder(invalid_labels=True),
    )
    assert rejected.workspace.load().state is RunState.REJECTED
    with pytest.raises(InvalidInvocationError, match="not accepted"):
        export(rejected, tmp_path / "exports" / "rejected.tar")

    setup.arm64.rewrite_record(lambda value: value.update(verdict="incomplete"))
    with pytest.raises(InvalidInvocationError, match="not accepted"):
        export(setup.arm64, tmp_path / "exports" / "incomplete.tar")


def test_import_rejects_dependency_evidence_the_configuration_does_not_declare(
    tmp_path: Path, setup: Setup
) -> None:
    def plant_dependency(value: dict[str, Any]) -> None:
        payload = value["payload"]
        payload["testImageDependencies"] = [
            {
                "imageId": "helper",
                "platform": payload["platform"],
                "manifestDigest": payload["manifestDigest"],
                "layoutDescriptor": payload["layoutDescriptor"],
                "sourceRevision": value["source"]["revision"],
                "containerfileDigest": payload["containerfileDigest"],
                "contextDigest": payload["contextDigest"],
                "buildArguments": payload["buildArguments"],
                "externalImages": [],
                "pinObservations": [],
                "effectiveLimits": payload["effectiveLimits"],
                "testResultDigest": payload["payloadDigests"][0],
            }
        ]

    setup.amd64.rewrite_record(plant_dependency)
    planted = export(setup.amd64, tmp_path / "exports" / "amd64-planted.tar")
    workspace = coordinator_workspace(tmp_path, setup.source_root)

    with pytest.raises(RuleRejectionError, match="configured test dependencies"):
        import_transport(
            planted.path,
            expected_digest=planted.transport_digest,
            workspace=workspace,
            image=setup.amd64.image,
            repository=setup.amd64.inputs.repository,
            source_time=NOW,
        )
    assert workspace.load().state is RunState.CREATED
    assert not list((workspace.root / "records").glob("platform-qualification-*"))


def test_import_rejects_build_arguments_that_differ_from_the_selected_commit(
    tmp_path: Path, setup: Setup
) -> None:
    workspace = coordinator_workspace(tmp_path, setup.source_root)

    with pytest.raises(RuleRejectionError, match="differ from the selected commit"):
        import_transport(
            setup.amd64_transport.path,
            expected_digest=setup.amd64_transport.transport_digest,
            workspace=workspace,
            image=setup.amd64.image,
            repository=setup.amd64.inputs.repository,
            source_time=NOW + timedelta(seconds=60),
        )
    assert workspace.load().state is RunState.CREATED


def test_import_requires_the_caller_supplied_transport_digest(
    tmp_path: Path, setup: Setup
) -> None:
    workspace = coordinator_workspace(tmp_path, setup.source_root)
    wrong = "sha256:" + "0" * 64
    with pytest.raises(RuleRejectionError, match="Transport digest mismatch") as caught:
        import_transport(
            setup.amd64_transport.path,
            expected_digest=wrong,
            workspace=workspace,
            image=setup.amd64.image,
            repository=setup.amd64.inputs.repository,
            source_time=NOW,
        )
    assert caught.value.code == "CC0306"
    entries = {entry.resource_id: entry for entry in workspace.journal.entries()}
    staging = entries[f"transport-{wrong.removeprefix('sha256:')[:16]}"]
    assert staging.status is ResourceStatus.FAILED
    assert not Path(staging.identifier).exists()
    assert workspace.load().state is RunState.CREATED

    directory = export(
        setup.amd64, tmp_path / "exports" / "amd64-dir", kind=TransportKind.DIRECTORY
    )
    with pytest.raises(RuleRejectionError, match="Transport digest mismatch"):
        import_transport(
            directory.path,
            expected_digest=setup.amd64_transport.transport_digest,
            workspace=workspace,
            image=setup.amd64.image,
            repository=setup.amd64.inputs.repository,
            source_time=NOW,
        )
    with pytest.raises(InvalidInvocationError, match="lowercase sha256"):
        import_transport(
            directory.path,
            expected_digest="not-a-digest",
            workspace=workspace,
            image=setup.amd64.image,
            repository=setup.amd64.inputs.repository,
            source_time=NOW,
        )


def _tar_member(path: Path, name: str) -> bytes:
    with tarfile.open(path) as archive:
        stream = archive.extractfile(name)
        assert stream is not None
        with stream:
            return stream.read()


def _rewrite_tar(
    source: Path,
    destination: Path,
    mutate: Callable[[list[tuple[tarfile.TarInfo, bytes | None]]], None],
) -> str:
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(source) as archive:
        for info in archive.getmembers():
            content = None
            if info.isfile():
                stream = archive.extractfile(info)
                assert stream is not None
                with stream:
                    content = stream.read()
            members.append((info, content))
    mutate(members)
    with tarfile.open(destination, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for info, content in members:
            if content is None:
                archive.addfile(info)
            else:
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    return sha256_file(destination)


def _replace_member(
    members: list[tuple[tarfile.TarInfo, bytes | None]],
    name: str,
    transform: Callable[[bytes], bytes],
) -> None:
    for index, (info, content) in enumerate(members):
        if info.name == name:
            assert content is not None
            members[index] = (info, transform(content))
            return
    raise AssertionError(f"member missing: {name}")


_COORDINATORS = itertools.count(100)


def _import(tmp_path: Path, setup: Setup, path: Path, digest: str) -> Any:
    workspace = coordinator_workspace(
        tmp_path,
        setup.source_root,
        run_id=f"01arz3ndektsv4rrffq69g5{next(_COORDINATORS):03d}",
    )
    return import_transport(
        path,
        expected_digest=digest,
        workspace=workspace,
        image=setup.amd64.image,
        repository=setup.amd64.inputs.repository,
        source_time=NOW,
    )


@pytest.mark.parametrize(
    ("member", "message"),
    [
        ("records/platform-qualification-linux-amd64.json", "member differs"),
        ("exports/sbom/linux-amd64.spdx.json", "member differs"),
        ("reports/linux-amd64/image-scan.json", "member differs"),
        ("reports/linux-amd64/tests.json", "member differs"),
        ("layouts/linux-amd64/index.json", "member differs"),
    ],
    ids=["record", "sbom", "scan", "tests", "index"],
)
def test_import_rejects_members_that_differ_from_the_manifest(
    tmp_path: Path, setup: Setup, member: str, message: str
) -> None:
    tampered = tmp_path / "tampered.tar"
    digest = _rewrite_tar(
        setup.amd64_transport.path,
        tampered,
        lambda members: _replace_member(
            members, member, lambda content: content + b" "
        ),
    )
    with pytest.raises(RuleRejectionError, match=message) as caught:
        _import(tmp_path, setup, tampered, digest)
    assert caught.value.code == "CC0306"


def test_import_rejects_a_corrupted_layout_blob_even_with_a_consistent_manifest(
    tmp_path: Path, setup: Setup
) -> None:
    with tarfile.open(setup.amd64_transport.path) as archive:
        blob_name = next(
            name for name in archive.getnames() if "/blobs/sha256/" in name
        )
    manifest = json.loads(_tar_member(setup.amd64_transport.path, MANIFEST_NAME))
    corrupted = b"{}"

    def consistent(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
        _replace_member(members, blob_name, lambda _content: corrupted)
        for item in manifest["payload"]["members"]:
            if item["path"] == blob_name:
                item["digest"] = sha256_bytes(corrupted)
                item["size"] = len(corrupted)
        total = sum(item["size"] for item in manifest["payload"]["members"])
        manifest["payload"]["totalBytes"] = total
        _replace_member(
            members, MANIFEST_NAME, lambda _content: json.dumps(manifest).encode()
        )

    tampered = tmp_path / "blob.tar"
    digest = _rewrite_tar(setup.amd64_transport.path, tampered, consistent)
    with pytest.raises((RuleRejectionError, InvalidInvocationError)):
        _import(tmp_path, setup, tampered, digest)


def test_import_rejects_a_record_that_differs_from_the_manifest_digest(
    tmp_path: Path, setup: Setup
) -> None:
    manifest = json.loads(_tar_member(setup.amd64_transport.path, MANIFEST_NAME))
    record_name = "records/platform-qualification-linux-amd64.json"
    original = _tar_member(setup.amd64_transport.path, record_name)
    swapped = json.loads(original)
    swapped["runId"] = "01arz3ndektsv4rrffq69g5fa9"
    swapped_bytes = json.dumps(swapped).encode()

    def consistent(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
        _replace_member(members, record_name, lambda _content: swapped_bytes)
        for item in manifest["payload"]["members"]:
            if item["path"] == record_name:
                item["digest"] = sha256_bytes(swapped_bytes)
                item["size"] = len(swapped_bytes)
        manifest["payload"]["totalBytes"] = sum(
            item["size"] for item in manifest["payload"]["members"]
        )
        _replace_member(
            members, MANIFEST_NAME, lambda _content: json.dumps(manifest).encode()
        )

    tampered = tmp_path / "record.tar"
    digest = _rewrite_tar(setup.amd64_transport.path, tampered, consistent)
    with pytest.raises(RuleRejectionError, match="record digest differs") as caught:
        _import(tmp_path, setup, tampered, digest)
    assert caught.value.code == "CC0306"


@pytest.mark.parametrize(
    ("name", "kind", "message"),
    [
        ("../escape.json", tarfile.REGTYPE, "Unsafe archive member"),
        ("/etc/passwd", tarfile.REGTYPE, "Unsafe archive member"),
        ("layouts/link", tarfile.SYMTYPE, "not a regular file"),
        ("layouts/hard", tarfile.LNKTYPE, "not a regular file"),
        ("logs/buildah-0001.json", tarfile.REGTYPE, "members differ"),
        ("environment/auth.json", tarfile.REGTYPE, "members differ"),
    ],
    ids=["traversal", "absolute", "symlink", "hardlink", "extra-log", "extra-secret"],
)
def test_import_rejects_unsafe_and_undeclared_archive_members(
    tmp_path: Path, setup: Setup, name: str, kind: bytes, message: str
) -> None:
    def add(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
        info = tarfile.TarInfo(name)
        info.type = kind
        if kind == tarfile.REGTYPE:
            members.append((info, b"{}"))
        else:
            info.linkname = "layouts/linux-amd64/index.json"
            members.append((info, None))

    tampered = tmp_path / "unsafe.tar"
    digest = _rewrite_tar(setup.amd64_transport.path, tampered, add)
    with pytest.raises((InvalidInvocationError, RuleRejectionError), match=message):
        _import(tmp_path, setup, tampered, digest)


def test_import_rejects_archives_without_a_transport_manifest(
    tmp_path: Path, setup: Setup
) -> None:
    # A hand-made tarball of a run workspace is not a transport.
    workspace_tar = tmp_path / "workspace.tar"
    with tarfile.open(workspace_tar, mode="w") as archive:
        archive.add(setup.amd64.workspace.root / "run.json", arcname="run.json")
        archive.add(
            setup.amd64.record_path,
            arcname="records/platform-qualification-linux-amd64.json",
        )
    with pytest.raises(InvalidInvocationError, match=r"no transport\.json manifest"):
        _import(tmp_path, setup, workspace_tar, sha256_file(workspace_tar))


def test_import_rejects_duplicate_and_missing_archive_members(
    tmp_path: Path, setup: Setup
) -> None:
    def duplicate(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
        info, content = next(
            item for item in members if item[0].name.endswith("tests.json")
        )
        members.append((info, content))

    duplicated = tmp_path / "duplicate.tar"
    digest = _rewrite_tar(setup.amd64_transport.path, duplicated, duplicate)
    with pytest.raises(InvalidInvocationError, match="duplicate member"):
        _import(tmp_path, setup, duplicated, digest)

    def drop(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
        members[:] = [
            item for item in members if not item[0].name.endswith("tests.json")
        ]

    missing = tmp_path / "missing.tar"
    digest = _rewrite_tar(setup.amd64_transport.path, missing, drop)
    with pytest.raises(RuleRejectionError, match="missing=") as caught:
        _import(tmp_path, setup, missing, digest)
    assert caught.value.code == "CC0306"


def test_import_enforces_member_and_size_limits(
    tmp_path: Path, setup: Setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = export(
        setup.amd64, tmp_path / "exports" / "limits-dir", kind=TransportKind.DIRECTORY
    )
    archive = (setup.amd64_transport.path, setup.amd64_transport.transport_digest)
    monkeypatch.setattr(transport_module, "MAX_TRANSPORT_MEMBERS", 3)
    with pytest.raises(InvalidInvocationError, match="member limit"):
        _import(tmp_path, setup, *archive)
    monkeypatch.setattr(transport_module, "MAX_TRANSPORT_MEMBERS", 4096)
    monkeypatch.setattr(transport_module, "MAX_TRANSPORT_BYTES", 16)
    with pytest.raises(InvalidInvocationError, match="size limit"):
        _import(tmp_path, setup, *archive)
    with pytest.raises(InvalidInvocationError, match="size accounting"):
        _import(tmp_path, setup, directory.path, directory.transport_digest)
    with pytest.raises(InvalidInvocationError, match="transport limits"):
        export(setup.amd64, tmp_path / "exports" / "too-large.tar")


def test_directory_import_rejects_links_extra_and_missing_files(
    tmp_path: Path, setup: Setup
) -> None:
    def fresh(name: str) -> Any:
        return export(
            setup.amd64, tmp_path / "exports" / name, kind=TransportKind.DIRECTORY
        )

    linked = fresh("symlink")
    target = linked.path / "reports" / "linux-amd64" / "tests.json"
    real = tmp_path / "outside-tests.json"
    real.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(real)
    with pytest.raises(InvalidInvocationError, match="symbolic link"):
        _import(tmp_path, setup, linked.path, linked.transport_digest)

    # A hard-linked source member is copied, never linked, into the workspace.
    hard = fresh("hardlink")
    target = hard.path / "reports" / "linux-amd64" / "tests.json"
    os.link(target, tmp_path / "hard-tests.json")
    imported = _import(tmp_path, setup, hard.path, hard.transport_digest)
    copied = next(
        path for path in imported.transport.payload_paths if path.name == "tests.json"
    )
    assert copied.stat().st_nlink == 1
    assert copied.read_bytes() == target.read_bytes()

    extra = fresh("extra")
    (extra.path / "reports" / "linux-amd64" / "secret-output").write_text(
        "private", encoding="utf-8"
    )
    # A directory transport is copied member by member, so undeclared files are
    # never read; the manifest decides what enters the coordinator workspace.
    workspace = coordinator_workspace(tmp_path, setup.source_root)
    import_transport(
        extra.path,
        expected_digest=extra.transport_digest,
        workspace=workspace,
        image=setup.amd64.image,
        repository=setup.amd64.inputs.repository,
        source_time=NOW,
    )
    assert not (
        workspace.root / "reports" / "app" / "linux-amd64" / "secret-output"
    ).exists()

    absent = fresh("absent")
    (absent.path / "reports" / "linux-amd64" / "tests.json").unlink()
    with pytest.raises(InvalidInvocationError, match=r"Unable to copy|unavailable"):
        _import(tmp_path, setup, absent.path, absent.transport_digest)

    traversal = fresh("traversal")
    manifest = json.loads((traversal.path / MANIFEST_NAME).read_text(encoding="utf-8"))
    manifest["payload"]["members"][0]["path"] = "../escape.json"
    text = json.dumps(manifest)
    (traversal.path / MANIFEST_NAME).write_text(text, encoding="utf-8")
    with pytest.raises(
        InvalidInvocationError, match=r"does not match|Unsafe transport"
    ):
        _import(tmp_path, setup, traversal.path, sha256_bytes(text.encode()))


def test_transport_manifest_is_a_closed_schema_validated_record(
    tmp_path: Path, setup: Setup
) -> None:
    def fresh(name: str) -> Any:
        return export(
            setup.amd64, tmp_path / "exports" / name, kind=TransportKind.DIRECTORY
        )

    valid = fresh("valid")
    manifest = json.loads((valid.path / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["schemaVersion"] == 1
    assert manifest["verdict"] == "accepted"
    assert manifest["payload"]["totalBytes"] == valid.total_bytes
    cases: tuple[tuple[Callable[[dict[str, Any]], None], str], ...] = (
        (lambda value: value.update(unexpected=True), "Invalid public record"),
        (lambda value: value["payload"].update(secrets=["x"]), "Invalid public record"),
        (lambda value: value.update(verdict="rejected"), "not accepted"),
        (lambda value: value.update(recordType="releaseCandidate"), "Invalid public"),
        (
            lambda value: value["payload"].update(imageId="other"),
            "belongs to another image",
        ),
        (
            lambda value: value["payload"].update(platform="linux/ppc64le"),
            "not required",
        ),
        (
            lambda value: value["payload"]["members"][0].update(
                path="reports/linux-amd64/../tests.json"
            ),
            r"does not match|Unsafe",
        ),
        (
            lambda value: value["payload"].update(totalBytes=1),
            "size accounting",
        ),
    )
    for mutate, message in cases:
        mutated = json.loads(json.dumps(manifest))
        mutate(mutated)
        text = json.dumps(mutated)
        (valid.path / MANIFEST_NAME).write_text(text, encoding="utf-8")
        with pytest.raises(InvalidInvocationError, match=message):
            _import(tmp_path, setup, valid.path, sha256_bytes(text.encode()))


def test_assembly_requires_exactly_one_transport_per_required_platform(
    tmp_path: Path, setup: Setup
) -> None:
    amd64, arm64 = setup.amd64_transport, setup.arm64_transport
    with pytest.raises(InvalidInvocationError, match=r"missing=\['linux/arm64'\]"):
        assemble(
            coordinator_workspace(tmp_path, setup.source_root, run_id=_ulid(1)),
            setup.source_root,
            ((amd64.path, amd64.transport_digest),),
        )
    with pytest.raises(InvalidInvocationError, match="already imported"):
        assemble(
            coordinator_workspace(tmp_path, setup.source_root, run_id=_ulid(2)),
            setup.source_root,
            (
                (amd64.path, amd64.transport_digest),
                (amd64.path, amd64.transport_digest),
            ),
        )
    again = export(setup.amd64, tmp_path / "exports" / "amd64-again.tar")
    with pytest.raises(InvalidInvocationError, match="already imported"):
        assemble(
            coordinator_workspace(tmp_path, setup.source_root, run_id=_ulid(3)),
            setup.source_root,
            (
                (amd64.path, amd64.transport_digest),
                (again.path, again.transport_digest),
            ),
        )
    amd64_only = replace(setup.amd64.image, platforms=(AMD64,))
    with pytest.raises(InvalidInvocationError, match="not required"):
        assemble(
            coordinator_workspace(tmp_path, setup.source_root, run_id=_ulid(4)),
            setup.source_root,
            ((arm64.path, arm64.transport_digest),),
            image=amd64_only,
        )


def _ulid(index: int) -> str:
    return f"01arz3ndektsv4rrffq69g5fd{index}"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["source"].update(revision="e" * 40),
            "different source commits|source revision",
        ),
        (
            lambda value: value["repositoryConfiguration"].update(
                sha256="sha256:" + "5" * 64
            ),
            "different repository configurations|repository configuration",
        ),
        (
            lambda value: value["ruleset"].update(conclearRevision="f" * 40),
            "not produced by this ConClear",
        ),
        (
            lambda value: value["tools"].__setitem__(
                0, {**value["tools"][0], "version": "1.99.0"}
            ),
            "different normalized tool versions",
        ),
        (
            lambda value: value["payload"]["pinObservations"][0].update(
                observedDigest="sha256:" + "9" * 64,
                divergenceSince="2026-01-01T00:00:00Z",
            ),
            "different external image digests",
        ),
        (
            lambda value: value["payload"]["effectiveLimits"].update(
                pinFreshnessSeconds=3600
            ),
            "effective pin limits",
        ),
        (
            lambda value: value["payload"].update(databaseDigest="sha256:" + "8" * 64),
            "different vulnerability database",
        ),
        (
            lambda value: value["payload"]["buildArguments"].update(
                IMAGE_VERSION="9.9.9"
            ),
            "differ from the selected commit",
        ),
        (
            lambda value: value["ruleset"].update(guideRevision="1" * 40),
            "Invalid|guideRevision",
        ),
    ],
    ids=[
        "source-revision",
        "configuration",
        "conclear-revision",
        "tool-version",
        "pin-resolution",
        "limits",
        "database",
        "version",
        "guide-revision",
    ],
)
def test_assembly_rejects_workers_that_disagree(
    tmp_path: Path,
    setup: Setup,
    mutate: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    setup.arm64.rewrite_record(mutate)
    # Re-export so the transport itself is internally consistent; only the
    # cross-worker comparison at assembly time can catch the disagreement.
    try:
        arm64 = export(setup.arm64, tmp_path / "exports" / "arm64-mutated.tar")
    except (InvalidInvocationError, RuleRejectionError) as exc:
        assert re.search(message, str(exc))
        return
    workspace = coordinator_workspace(tmp_path, setup.source_root)
    with pytest.raises((InvalidInvocationError, RuleRejectionError), match=message):
        assemble(
            workspace,
            setup.source_root,
            (
                (setup.amd64_transport.path, setup.amd64_transport.transport_digest),
                (arm64.path, arm64.transport_digest),
            ),
        )
    assert workspace.load().state in {RunState.CREATED, RunState.QUALIFIED}


def test_assembly_rejects_a_coordinator_on_another_revision_or_version(
    tmp_path: Path, setup: Setup
) -> None:
    transports = (
        (setup.amd64_transport.path, setup.amd64_transport.transport_digest),
        (setup.arm64_transport.path, setup.arm64_transport.transport_digest),
    )
    other_revision = coordinator_workspace(
        tmp_path, setup.source_root, run_id=_ulid(5), source_revision="e" * 40
    )
    with pytest.raises(
        RuleRejectionError, match="differ from the selected commit: IMAGE_REVISION"
    ):
        assemble(other_revision, setup.source_root, transports)

    other_version = coordinator_workspace(
        tmp_path, setup.source_root, run_id=_ulid(6), version="2.0.0"
    )
    with pytest.raises(
        RuleRejectionError, match="differ from the selected commit: IMAGE_VERSION"
    ):
        assemble(other_version, setup.source_root, transports, version="2.0.0")


def test_owned_and_imported_records_are_validated_differently(
    tmp_path: Path, setup: Setup
) -> None:
    # A copied record without a transport is still foreign to the coordinator.
    workspace = coordinator_workspace(tmp_path, setup.source_root)
    workspace.transition(RunState.QUALIFIED)
    from conclear.services.assembly import QualificationTransport

    owned_copy = QualificationTransport(
        record_path=setup.amd64.record_path,
        layout_path=setup.amd64.workspace.root / "layouts" / "app" / "linux-amd64",
        layout_reference="qualified",
        payload_paths=tuple(
            setup.amd64.workspace.root / relative
            for relative in (
                "reports/app/linux-amd64/tests.json",
                "exports/sbom/linux-amd64.spdx.json",
                "reports/app/linux-amd64/source-scan.json",
                "reports/app/linux-amd64/containerfile-scan.json",
                "reports/app/linux-amd64/image-scan.json",
            )
        ),
    )
    repository = load_repository_config(setup.source_root / "conclear.toml")
    with pytest.raises(InvalidInvocationError, match="another release run"):
        assemble_candidate(
            (owned_copy,),
            repository=repository,
            image=replace(repository.release_image("app"), platforms=(AMD64,)),
            workspace=workspace,
            version="1.2.3",
            source_time=NOW,
            tools=(tool(),),
            now=NOW,
            clock=lambda: NOW,
        )


def test_candidate_loader_rejects_foreign_records_without_a_transport_binding(
    tmp_path: Path, setup: Setup
) -> None:
    workspace = coordinator_workspace(tmp_path, setup.source_root)
    candidate = assemble(
        workspace,
        setup.source_root,
        (
            (setup.amd64_transport.path, setup.amd64_transport.transport_digest),
            (setup.arm64_transport.path, setup.arm64_transport.transport_digest),
        ),
    )
    value = json.loads(candidate.record_path.read_text(encoding="utf-8"))
    del value["payload"]["qualifications"][0]["transportDigest"]
    candidate.record_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="without a transport digest"):
        load_candidate(workspace, setup.amd64.image)


def test_cleanup_removes_only_coordinator_owned_copies(
    tmp_path: Path, setup: Setup
) -> None:
    workspace = coordinator_workspace(tmp_path, setup.source_root)
    candidate = assemble(
        workspace,
        setup.source_root,
        (
            (setup.amd64_transport.path, setup.amd64_transport.transport_digest),
            (setup.arm64_transport.path, setup.arm64_transport.transport_digest),
        ),
    )
    result = cleanup_run(
        workspace, buildah=_NoStorage(), podman=FakePodman(), registry_control=None
    )
    assert set(result.removed) == {
        "layout-app-linux-amd64",
        "layout-app-linux-arm64",
        "candidate-layout-app",
    }
    assert not candidate.observation.path.exists()
    assert not (workspace.root / "layouts" / "app" / "linux-arm64").exists()
    # Worker workspaces and caller-owned transports are not coordinator resources.
    assert (setup.arm64.workspace.root / "layouts" / "app" / "linux-arm64").is_dir()
    assert setup.arm64_transport.path.is_file()
    assert (
        workspace.root / "records" / "platform-qualification-linux-arm64.json"
    ).is_file()


def test_failed_import_retains_staging_under_a_failed_entry_for_cleanup(
    tmp_path: Path, setup: Setup
) -> None:
    tampered = tmp_path / "tampered.tar"
    digest = _rewrite_tar(
        setup.amd64_transport.path,
        tampered,
        lambda members: _replace_member(
            members, "reports/linux-amd64/tests.json", lambda content: content + b" "
        ),
    )
    workspace = coordinator_workspace(tmp_path, setup.source_root)
    with pytest.raises(RuleRejectionError):
        import_transport(
            tampered,
            expected_digest=digest,
            workspace=workspace,
            image=setup.amd64.image,
            repository=setup.amd64.inputs.repository,
            source_time=NOW,
        )
    entry = next(
        item
        for item in workspace.journal.entries()
        if item.resource_id.startswith("transport-")
    )
    assert entry.status is ResourceStatus.FAILED
    assert Path(entry.identifier).is_dir()
    assert not (
        workspace.root / "records" / "platform-qualification-linux-amd64.json"
    ).exists()
    result = cleanup_run(
        workspace, buildah=_NoStorage(), podman=FakePodman(), registry_control=None
    )
    assert result.removed == (entry.resource_id,)
    assert not Path(entry.identifier).exists()


class _NoStorage:
    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        raise AssertionError("coordinator runs own no Buildah storage")


def test_transport_source_changes_during_export_are_operational_failures(
    tmp_path: Path, setup: Setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The member digests are computed before streaming; a file that changes in
    # between is detected while the archive is written and nothing is retained.
    def stale_digest(path: Path) -> str:
        if path.name == "tests.json":
            return "sha256:" + "0" * 64
        return sha256_file(path)

    monkeypatch.setattr(transport_module, "_regular_digest", stale_digest)
    with pytest.raises(OperationalError, match="changed while exporting"):
        export(setup.amd64, tmp_path / "exports" / "racing.tar")
    assert not (tmp_path / "exports" / "racing.tar").exists()
    assert not list((tmp_path / "exports").glob(".racing.tar.*"))
    with pytest.raises(RuleRejectionError, match="member differs"):
        export(
            setup.amd64,
            tmp_path / "exports" / "racing-dir",
            kind=TransportKind.DIRECTORY,
        )
