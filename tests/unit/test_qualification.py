import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import conclear.records as records_module
from conclear.adapters.buildah import BuildObservation
from conclear.adapters.podman import (
    ContainerObservation,
    ImportObservation,
    RuntimeControlObservation,
)
from conclear.adapters.trivy import DatabaseObservation, ScanObservation
from conclear.artifacts import qualification_transport
from conclear.config import load_repository_config
from conclear.hooks import HookRunner
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
)
from conclear.oci import OCI_CONFIG, OCI_MANIFEST, validate_layout
from conclear.process import CommandRequest, ProcessResult
from conclear.records import (
    SourceIdentity,
    ToolIdentity,
    Verdict,
    validate_record,
)
from conclear.services.qualification import QualificationInputs, qualify_platform
from conclear.values import Platform
from conclear.workspace import RunWorkspace


class IdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def write_blob(layout: Path, content: bytes) -> tuple[str, int]:
    digest = sha256_bytes(content)
    path = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return digest, len(content)


class Builder:
    def __init__(self, *, invalid_labels: bool = False) -> None:
        self.invalid_labels = invalid_labels

    def build(self, **values: Any) -> BuildObservation:
        layout = values["layout_path"]
        assert isinstance(layout, Path)
        layout.mkdir(parents=True)
        (layout / "oci-layout").write_text(
            '{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8"
        )
        build_arguments = values["build_arguments"]
        assert isinstance(build_arguments, dict)
        labels = {
            "org.opencontainers.image.source": "https://github.com/example/app",
            "org.opencontainers.image.revision": build_arguments["IMAGE_REVISION"],
            "org.opencontainers.image.created": build_arguments["IMAGE_CREATED"],
            "org.opencontainers.image.version": build_arguments["IMAGE_VERSION"],
            "org.opencontainers.image.licenses": "GPL-3.0-or-later",
            "org.opencontainers.image.title": "Example",
        }
        if self.invalid_labels:
            labels["org.opencontainers.image.revision"] = "wrong"
        config, config_size = write_blob(
            layout,
            canonical_json_bytes(
                {
                    "architecture": "amd64",
                    "os": "linux",
                    "config": {"User": "10001", "Labels": labels},
                    "rootfs": {"type": "layers", "diff_ids": []},
                }
            ),
        )
        manifest, manifest_size = write_blob(
            layout,
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
        (layout / "index.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "manifests": [
                        {
                            "mediaType": OCI_MANIFEST,
                            "digest": manifest,
                            "size": manifest_size,
                            "platform": {"os": "linux", "architecture": "amd64"},
                            "annotations": {
                                "org.opencontainers.image.ref.name": "qualified"
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        graph = validate_layout(layout, reference="qualified")
        return BuildObservation(
            image_name=str(values["image_name"]),
            layout_path=layout,
            graph=graph,
            build_arguments=tuple(sorted(build_arguments.items())),
        )


class Runtime:
    def import_layout(self, **values: Any) -> ImportObservation:
        return ImportObservation(str(values["image_name"]), values["expected_digest"])

    def create_container(self, **values: Any) -> ContainerObservation:
        return ContainerObservation(
            str(values["name"]), "container-id", "running", 100, None
        )

    def inspect_controls(self, **values: Any) -> RuntimeControlObservation:
        return RuntimeControlObservation(
            user="10001",
            read_only=True,
            writable_mounts=(),
            memory_bytes=512 * 1024 * 1024,
            nano_cpus=1_000_000_000,
            pids_limit=128,
            nofile_soft=1024,
            nofile_hard=1024,
            cap_add=(),
            cap_drop=("ALL",),
            security_options=("no-new-privileges",),
        )

    def exec(self, **values: Any) -> str:
        return ""

    def signal(self, **values: Any) -> None:
        return None

    def wait(self, **values: Any) -> int:
        return 0

    def remove(self, **values: Any) -> None:
        return None


class Scanner:
    def scan_filesystem(self, **values: Any) -> ScanObservation:
        return self._write(values["report_path"], {"Results": []})

    def scan_layout(self, **values: Any) -> ScanObservation:
        return self._write(values["report_path"], {"Results": []})

    def generate_spdx(self, **values: Any) -> ScanObservation:
        return self._write(
            values["output_path"],
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "app",
                "documentNamespace": "https://example.invalid/spdx/app",
                "creationInfo": {
                    "creators": ["Tool: test"],
                    "created": "2026-01-01T00:00:00Z",
                },
            },
        )

    @staticmethod
    def _write(path_value: object, value: object) -> ScanObservation:
        assert isinstance(path_value, Path)
        atomic_write_json(path_value, value, mode=0o644)
        return ScanObservation(path_value, sha256_file(path_value), value)


class NoopRunner:
    def run(self, request: CommandRequest) -> ProcessResult:
        raise AssertionError(f"Unexpected hook: {request.argv}")


DATABASE_METADATA: dict[str, object] = {
    name: {
        "schemaVersion": version,
        "updatedAt": "2026-01-01T00:00:00Z",
        "nextUpdate": "2026-01-02T00:00:00Z",
        "downloadedAt": "2026-01-01T00:01:00Z",
    }
    for name, version in (("vulnerability", 2), ("java", 1))
}


def inputs(repository: Path, tmp_path: Path) -> QualificationInputs:
    config = load_repository_config(repository / "conclear.toml")
    workspace = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={
            "sourceRevision": "b" * 40,
            "sourceRepository": config.project.source,
            "configurationDigest": sha256_bytes(config.raw_bytes),
            "image": "app",
            "version": "1.2.3",
        },
        id_factory=IdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    digest = "sha256:" + "d" * 64
    return QualificationInputs(
        repository=config,
        image=config.image("app"),
        workspace=workspace,
        source=SourceIdentity("https://github.com/example/app", "b" * 40),
        source_time=datetime(2026, 1, 1, tzinfo=UTC),
        version="1.2.3",
        platform=Platform.parse("linux/amd64"),
        tools=(ToolIdentity("buildah", "1.43.2", executable_digest=digest),),
        auth_file=None,
        host_architecture="x86_64",
    )


def hook_runner(value: QualificationInputs) -> HookRunner:
    return HookRunner(
        runner=NoopRunner(),
        environment={"PATH": "/usr/bin"},
        source_root=value.repository.path.parent,
        log_directory=value.workspace.root / "logs",
    )


@pytest.fixture(autouse=True)
def embedded_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        records_module,
        "IDENTITY",
        ApplicationIdentity(source_revision="c" * 40),
    )


def test_qualification_writes_accepted_digest_bound_record(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    database_path = tmp_path / "database"
    database_path.mkdir()
    result = qualify_platform(
        value,
        builder=Builder(),
        runtime=Runtime(),
        hooks=hook_runner(value),
        scanner=Scanner(),
        database=DatabaseObservation(
            database_path, "sha256:" + "e" * 64, DATABASE_METADATA
        ),
        pin_observations=(),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    assert result.verdict is Verdict.ACCEPTED
    assert result.record_digest == sha256_file(result.record_path)
    validate_record(json.loads(result.record_path.read_text(encoding="utf-8")))
    transport = qualification_transport(value.workspace, value.image, value.platform)
    assert transport.payload_paths[0] == (
        value.workspace.root / "reports" / "app" / "linux-amd64" / "tests.json"
    )
    assert [path.name for path in transport.payload_paths[2:]] == [
        "source-scan.json",
        "containerfile-scan.json",
        "image-scan.json",
    ]


def test_qualification_records_label_rule_rejection(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    database_path = tmp_path / "database"
    database_path.mkdir()
    result = qualify_platform(
        value,
        builder=Builder(invalid_labels=True),
        runtime=Runtime(),
        hooks=hook_runner(value),
        scanner=Scanner(),
        database=DatabaseObservation(
            database_path, "sha256:" + "e" * 64, DATABASE_METADATA
        ),
        pin_observations=(),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    assert result.verdict is Verdict.REJECTED
    assert result.findings[0].check_id == "CC0113"
