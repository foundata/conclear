import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

import conclear.records as records_module
import conclear.services.assembly as assembly_service_module
from conclear.artifacts import load_candidate
from conclear.assembly import PlatformLayout, assemble_layout
from conclear.config import load_repository_config
from conclear.errors import InvalidInvocationError
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import canonical_json_bytes, sha256_bytes, sha256_file
from conclear.oci import OCI_CONFIG, OCI_INDEX, OCI_MANIFEST, validate_layout
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
)
from conclear.services.assembly import QualificationTransport, assemble_candidate
from conclear.values import Platform
from conclear.workspace import RunState, RunWorkspace


def write_blob(layout: Path, content: bytes) -> tuple[str, int]:
    digest = sha256_bytes(content)
    path = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return digest, len(content)


def platform_layout(root: Path, architecture: str) -> Path:
    root.mkdir()
    (root / "oci-layout").write_text(
        '{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8"
    )
    config, config_size = write_blob(
        root,
        canonical_json_bytes(
            {
                "architecture": architecture,
                "os": "linux",
                "config": {"User": "10001"},
                "rootfs": {"type": "layers", "diff_ids": []},
            }
        ),
    )
    manifest, manifest_size = write_blob(
        root,
        canonical_json_bytes(
            {
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST,
                "config": {
                    "mediaType": OCI_CONFIG,
                    "digest": config,
                    "size": config_size,
                },
                "layers": [],
            }
        ),
    )
    (root / "index.json").write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": OCI_MANIFEST,
                        "digest": manifest,
                        "size": manifest_size,
                        "platform": {"os": "linux", "architecture": architecture},
                        "annotations": {
                            "org.opencontainers.image.ref.name": "qualified"
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return root


def test_assembly_preserves_platform_manifests_and_creates_index(
    tmp_path: Path,
) -> None:
    amd64 = platform_layout(tmp_path / "amd64", "amd64")
    arm64 = platform_layout(tmp_path / "arm64", "arm64")

    observation = assemble_layout(
        (
            PlatformLayout(Platform.parse("linux/amd64"), amd64, "qualified"),
            PlatformLayout(Platform.parse("linux/arm64"), arm64, "qualified"),
        ),
        output_path=tmp_path / "assembled",
        output_reference="candidate",
    )

    assert observation.graph.root.media_type == OCI_INDEX
    assert observation.graph.platforms == (
        Platform.parse("linux/amd64"),
        Platform.parse("linux/arm64"),
    )
    assert len(observation.platform_manifests) == 2


def test_assembly_rejects_duplicate_platform(tmp_path: Path) -> None:
    layout = platform_layout(tmp_path / "amd64", "amd64")
    item = PlatformLayout(Platform.parse("linux/amd64"), layout, "qualified")

    with pytest.raises(InvalidInvocationError, match="duplicate platform"):
        assemble_layout(
            (item, item),
            output_path=tmp_path / "assembled",
            output_reference="candidate",
        )


class IdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def test_candidate_assembly_verifies_record_payload_and_layout_digests(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = ApplicationIdentity(source_revision="c" * 40)
    monkeypatch.setattr(records_module, "IDENTITY", identity)
    monkeypatch.setattr(assembly_service_module, "IDENTITY", identity)
    repository = load_repository_config(repository_factory() / "conclear.toml")
    workspace = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={
            "sourceRevision": "b" * 40,
            "sourceRepository": repository.project.source,
            "configurationDigest": sha256_bytes(repository.raw_bytes),
            "image": "app",
            "version": "1.2.3",
        },
        id_factory=IdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    workspace.transition(RunState.QUALIFIED)
    layout = platform_layout(tmp_path / "qualified", "amd64")
    graph = validate_layout(layout, reference="qualified")
    payload_file = tmp_path / "scan.json"
    payload_file.write_text("{}\n", encoding="utf-8")
    payload_digest = sha256_file(payload_file)
    digest = "sha256:" + "d" * 64
    configuration_digest = sha256_bytes(repository.raw_bytes)
    tool = ToolIdentity("buildah", "1.43.2", executable_digest=digest)
    record = RecordEnvelope(
        record_type="platformQualification",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        run_id=workspace.run_id,
        source=SourceIdentity("https://github.com/example/app", "b" * 40),
        configuration_digest=configuration_digest,
        tools=(tool,),
        verdict=Verdict.ACCEPTED,
        payload={
            "imageId": "app",
            "platform": "linux/amd64",
            "layoutDescriptor": graph.root.to_dict(),
            "manifestDigest": str(graph.manifests[0].descriptor.digest),
            "containerfileDigest": digest,
            "contextDigest": digest,
            "buildArguments": {},
            "externalImages": [],
            "buildExecution": {
                "targetPlatform": "linux/amd64",
                "hostArchitecture": "x86_64",
                "executionArchitecture": "amd64",
                "mechanism": "native",
            },
            "testExecution": {
                "targetPlatform": "linux/amd64",
                "hostArchitecture": "x86_64",
                "executionArchitecture": "amd64",
                "mechanism": "native",
            },
            "runtimeConstraints": {
                "profile": "service",
                "user": 10001,
                "readOnly": True,
                "writableMounts": [],
                "memory": "512MiB",
                "cpus": 1.0,
                "pids": 128,
                "nofile": 1024,
                "capabilities": [],
            },
            "testResults": [],
            "sbom": {"digest": payload_digest, "spdxVersion": "SPDX-2.3"},
            "scans": [],
            "appliedExceptions": [],
            "payloadDigests": [payload_digest],
            "databaseDigest": digest,
            "databaseMetadata": {
                name: {
                    "schemaVersion": version,
                    "updatedAt": "2026-01-01T00:00:00Z",
                    "nextUpdate": "2026-01-02T00:00:00Z",
                    "downloadedAt": "2026-01-01T00:01:00Z",
                }
                for name, version in (("vulnerability", 2), ("java", 1))
            },
        },
    )
    record_path = tmp_path / "qualification.json"
    record.write(record_path)

    candidate = assemble_candidate(
        (
            QualificationTransport(
                record_path,
                layout,
                "qualified",
                (payload_file,),
            ),
        ),
        repository=repository,
        image=repository.image("app"),
        workspace=workspace,
        version="1.2.3",
        tools=(tool,),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    assert candidate.record_digest == sha256_file(candidate.record_path)
    assert candidate.observation.graph.digest == graph.digest
    assert workspace.load().state is RunState.ASSEMBLED
    assert load_candidate(workspace, repository.image("app")).candidate_tag == (
        candidate.candidate_tag
    )

    candidate_record = json.loads(candidate.record_path.read_text(encoding="utf-8"))
    candidate_record["payload"]["candidateNaming"]["version"] = "9.9.9"
    candidate.record_path.write_text(json.dumps(candidate_record), encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="naming inputs"):
        load_candidate(workspace, repository.image("app"))

    payload_file.write_text("changed\n", encoding="utf-8")
    second_workspace = RunWorkspace.create(
        state_home=tmp_path / "other-state",
        immutable_inputs={
            "sourceRevision": "b" * 40,
            "image": "app",
            "version": "1.2.3",
        },
        id_factory=IdFactory(),
    )
    second_workspace.transition(RunState.QUALIFIED)
    with pytest.raises(InvalidInvocationError, match="payload digests"):
        assemble_candidate(
            (
                QualificationTransport(
                    record_path, layout, "qualified", (payload_file,)
                ),
            ),
            repository=repository,
            image=repository.image("app"),
            workspace=second_workspace,
            version="1.2.3",
            tools=(tool,),
            now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        )
