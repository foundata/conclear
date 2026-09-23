"""Trivy and Hadolint run from their images see mounts and still name the subject."""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from conclear.adapters.trivy import TrivyAdapter
from conclear.jsonutil import sha256_file
from conclear.process import CommandRequest, ProcessResult
from conclear.scan_identity import ScanIdentity
from conclear.tool_images import ImageBackedTool, ToolImageStore
from conclear.tools import SUPPORTED_TOOLS, ResolvedTool, ToolName

MANIFEST = "sha256:" + "2" * 64
ENVIRONMENT = {"PATH": "/usr/bin", "HOME": "/run/home"}
type Reaction = Callable[[CommandRequest], None]


def _result(stdout: str = "") -> ProcessResult:
    return ProcessResult(("/tool",), 0, stdout, "", 0.0, 1, False, False)


class ImageRunner:
    """Answer the image recheck and let a test react to every tool run."""

    def __init__(self, digest: str, react: Reaction | None = None) -> None:
        self.digest = digest
        self.react = react
        self.runs: list[CommandRequest] = []

    def run(self, request: CommandRequest) -> ProcessResult:
        if "inspect" in request.argv:
            return _result(self.digest + "\n")
        self.runs.append(request)
        if self.react is not None:
            self.react(request)
        return _result()


def host_of(argv: tuple[str, ...], target: str) -> Path:
    """Return the host directory mounted at ``target`` in a Podman invocation."""
    for index, item in enumerate(argv):
        if item != "--mount":
            continue
        fields = dict(
            part.split("=", 1) for part in argv[index + 1].split(",") if "=" in part
        )
        if fields.get("target") == target:
            return Path(fields["src"])
    raise AssertionError(f"no mount at {target} in {argv}")


def _host_tool(tmp_path: Path, name: ToolName) -> ResolvedTool:
    executable = tmp_path / name.value
    executable.write_bytes(name.value.encode())
    executable.chmod(0o700)
    return ResolvedTool(
        name=name,
        path=executable,
        version="5.8.4",
        executable_digest="sha256:" + hashlib.sha256(name.value.encode()).hexdigest(),
        reported_version="test",
    )


def image_tool(tmp_path: Path, name: ToolName, runner: ImageRunner) -> ImageBackedTool:
    image = SUPPORTED_TOOLS[name].image
    assert image is not None
    return ImageBackedTool(
        name=name,
        image=image,
        version=str(image.version),
        reported_version="test",
        manifest_digest=MANIFEST,
        executor=_host_tool(tmp_path, ToolName.PODMAN),
        store=ToolImageStore.below(tmp_path / "tool-images"),
        runner=runner,
        environment=ENVIRONMENT,
    )


def _trivy(tmp_path: Path, react: Reaction) -> tuple[TrivyAdapter, ImageRunner]:
    image = SUPPORTED_TOOLS[ToolName.TRIVY].image
    assert image is not None
    runner = ImageRunner(image.digest, react)
    adapter = TrivyAdapter(
        tool=image_tool(tmp_path, ToolName.TRIVY, runner),
        runner=runner,
        environment=ENVIRONMENT,
        log_directory=tmp_path / "environment" / "logs",
    )
    return adapter, runner


def _mount_targets(argv: tuple[str, ...]) -> dict[str, str]:
    targets: dict[str, str] = {}
    for index, item in enumerate(argv):
        if item == "--mount":
            fields = dict(
                part.split("=", 1) for part in argv[index + 1].split(",") if "=" in part
            )
            targets[fields["target"]] = "rw" if ",rw," in argv[index + 1] else "ro"
    return targets


def test_trivy_scans_a_layout_through_mounts_and_still_names_the_subject(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "runs" / "01run"
    layout = workspace / "layouts" / "app" / "linux-amd64"
    layout.mkdir(parents=True)
    report = workspace / "reports" / "app" / "image-scan.json"
    report.parent.mkdir(parents=True)
    cache = tmp_path / "cache" / "snapshots" / "abc"
    cache.mkdir(parents=True)
    subject = "quay.io/example/app@sha256:" + "b" * 64
    identity = ScanIdentity(
        workspace_root=workspace, subject=subject, artifact_path=layout
    )

    def scan(request: CommandRequest) -> None:
        seen = request.argv[request.argv.index("--input") + 1]
        report.write_text(
            json.dumps(
                {
                    "ArtifactName": seen,
                    "ArtifactType": "container_image",
                    "Results": [
                        {"Target": f"{seen} (debian 13)", "Class": "os-pkgs"},
                        {
                            "Target": seen,
                            "Class": "config",
                            "Type": "dockerfile",
                            "Misconfigurations": [{"ID": "DS-0026", "Status": "FAIL"}],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

    adapter, runner = _trivy(tmp_path, scan)
    observation = adapter.scan_layout(
        layout_path=layout, report_path=report, cache_root=cache, identity=identity
    )

    (request,) = runner.runs
    argv = request.argv
    assert argv[argv.index("--input") + 1] == "/conclear/layout"
    assert argv[argv.index("--output") + 1] == "/conclear/reports/image-scan.json"
    assert argv[argv.index("--cache-dir") + 1] == "/conclear/cache"
    assert argv[argv.index("--config") + 1] == "/conclear/invocation/trivy.json"
    assert argv[argv.index("--workdir") + 1] == "/conclear/invocation"
    assert _mount_targets(argv) == {
        "/conclear/layout": "ro",
        "/conclear/cache": "rw",
        "/conclear/reports": "rw",
        "/conclear/invocation": "ro",
    }
    assert host_of(argv, "/conclear/layout") == layout
    assert host_of(argv, "/conclear/reports") == report.parent
    assert "--network" in argv
    value = cast(dict[str, Any], observation.value)
    assert value["ArtifactName"] == subject
    assert value["Results"][0]["Target"] == f"{subject} (debian 13)"
    assert value["Results"][1]["Target"] == subject
    text = report.read_text(encoding="utf-8")
    assert "/conclear/" not in text and str(tmp_path) not in text
    assert observation.digest == sha256_file(report)


def test_trivy_spdx_generated_from_an_image_names_the_subject(tmp_path: Path) -> None:
    workspace = tmp_path / "runs" / "01run"
    layout = workspace / "layouts" / "app" / "linux-amd64"
    layout.mkdir(parents=True)
    output = workspace / "exports" / "sbom" / "linux-amd64.spdx.json"
    output.parent.mkdir(parents=True)
    cache = tmp_path / "cache" / "snapshots" / "abc"
    cache.mkdir(parents=True)
    subject = "quay.io/example/app@sha256:" + "c" * 64
    identity = ScanIdentity(
        workspace_root=workspace, subject=subject, artifact_path=layout
    )

    def generate(request: CommandRequest) -> None:
        seen = request.argv[request.argv.index("--input") + 1]
        output.write_text(
            json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "dataLicense": "CC0-1.0",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": seen,
                    "documentNamespace": f"http://trivy.dev/container_image/{seen}-1",
                    "creationInfo": {
                        "created": "2026-01-01T00:00:00Z",
                        "creators": ["Tool: trivy-0.74.0"],
                    },
                    "packages": [
                        {
                            "name": seen,
                            "SPDXID": "SPDXRef-ContainerImage",
                            "downloadLocation": "NONE",
                            "filesAnalyzed": False,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    adapter, runner = _trivy(tmp_path, generate)
    observation = adapter.generate_spdx(
        layout_path=layout,
        output_path=output,
        cache_root=cache,
        identity=identity,
    )

    (request,) = runner.runs
    assert request.argv[request.argv.index("--output") + 1] == (
        "/conclear/exports/linux-amd64.spdx.json"
    )
    document = cast(dict[str, Any], observation.value)
    assert document["name"] == subject
    assert document["packages"][0]["name"] == subject
    assert (
        document["documentNamespace"] == f"http://trivy.dev/container_image/{subject}-1"
    )
    assert "/conclear/" not in output.read_text(encoding="utf-8")


def test_trivy_refreshes_its_database_with_the_network_and_a_writable_cache(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache"

    def download(request: CommandRequest) -> None:
        # The tool writes into the mounted cache; the test writes where that
        # mount points on the host, which is the refresh's temporary directory.
        temporary = host_of(request.argv, "/conclear/cache")
        for component, database in (("db", "trivy.db"), ("java-db", "trivy-java.db")):
            (temporary / component).mkdir(exist_ok=True)
            (temporary / component / database).write_bytes(b"database")
            (temporary / component / "metadata.json").write_text(
                json.dumps(
                    {
                        "Version": 2,
                        "UpdatedAt": "2026-01-01T00:00:00Z",
                        "NextUpdate": "2026-01-02T00:00:00Z",
                        "DownloadedAt": "2026-01-01T00:01:00Z",
                    }
                ),
                encoding="utf-8",
            )

    adapter, runner = _trivy(tmp_path, download)
    observation = adapter.refresh_database(cache_root)

    assert [
        request.argv[request.argv.index("--cache-dir") - 1] for request in runner.runs
    ] == [
        "--download-db-only",
        "--download-java-db-only",
    ]
    for request in runner.runs:
        assert "--network" not in request.argv
        assert _mount_targets(request.argv)["/conclear/cache"] == "rw"
    assert observation.path.parent == cache_root / "snapshots"
    assert (cache_root / "current.json").is_file()


def test_trivy_rescans_a_retained_sbom_mounted_read_only(tmp_path: Path) -> None:
    workspace = tmp_path / "runs" / "01run"
    sbom = workspace / "sbom" / "linux-amd64.spdx.json"
    sbom.parent.mkdir(parents=True)
    sbom.write_text("{}", encoding="utf-8")
    report = workspace / "reports" / "rescan.json"
    report.parent.mkdir(parents=True)
    cache = tmp_path / "cache" / "snapshots" / "abc"
    cache.mkdir(parents=True)
    subject = "quay.io/example/app@sha256:" + "d" * 64
    identity = ScanIdentity(
        workspace_root=workspace, subject=subject, artifact_path=sbom
    )

    def rescan(request: CommandRequest) -> None:
        seen = request.argv[-1]
        report.write_text(
            json.dumps({"ArtifactName": seen, "Results": [{"Target": seen}]}),
            encoding="utf-8",
        )

    adapter, runner = _trivy(tmp_path, rescan)
    observation = adapter.scan_sbom(
        sbom_path=sbom,
        report_path=report,
        cache_root=cache,
        identity=identity,
    )

    (request,) = runner.runs
    assert request.argv[-1] == "/conclear/sbom/linux-amd64.spdx.json"
    assert _mount_targets(request.argv)["/conclear/sbom"] == "ro"
    value = cast(dict[str, Any], observation.value)
    assert value["Results"][0]["Target"] == subject
