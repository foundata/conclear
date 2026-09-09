"""Two independent workers and one coordinator through the public CLI only.

The scenario needs an identity-bearing ConClear executable because a
development checkout cannot emit public records: set ``CONCLEAR_TEST_CLI`` to
the ``conclear`` entry point of an installed wheel built from the revision
under test. It also needs the manifest-owned Trivy snapshot cache described in
``DEVELOPMENT.md`` (``CONCLEAR_TEST_TRIVY_CACHE``) and a manifest-owned run ID.

Each worker qualifies one platform in its own run, exports a transport and
reports the digests a coordinator must be told independently. The coordinator
run assembles the transports, and the test inspects the resulting OCI index
with plain file reads and hashing. No registry, signature or transparency log
is touched at any point.
"""

import hashlib
import json
import os
import platform as host_platform
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from conclear.emulation import detect_execution_mode
from conclear.errors import OperationalError
from conclear.path_safety import contained_path
from conclear.process import CommandRequest, OperationKind
from conclear.runtime import ApplicationRuntime
from conclear.tools import ToolName
from conclear.values import Platform
from tests.local_integration.fixtures import FIXTURE_SOURCE, manifest_run_id

SOURCE = "https://example.invalid/llmtest/app"
CONTAINERFILE = """\
FROM scratch AS runtime
ARG IMAGE_CREATED
ARG IMAGE_REVISION
ARG IMAGE_VERSION
ARG TARGETARCH
COPY --chmod=0555 conclear-fixture-${TARGETARCH} /app/conclear-fixture
LABEL org.opencontainers.image.created="${IMAGE_CREATED}" \\
      org.opencontainers.image.licenses="GPL-3.0-or-later" \\
      org.opencontainers.image.revision="${IMAGE_REVISION}" \\
      org.opencontainers.image.source="https://example.invalid/llmtest/app" \\
      org.opencontainers.image.title="ConClear transport fixture" \\
      org.opencontainers.image.version="${IMAGE_VERSION}"
USER 65532:65532
ENTRYPOINT ["/app/conclear-fixture"]
CMD ["service"]
"""
CONTAINERIGNORE = "*\n!Containerfile\n!conclear.toml\n!conclear-fixture-*\n"


def _configuration(platforms: Sequence[str]) -> str:
    platform_list = ", ".join(f'"{item}"' for item in platforms)
    return f"""schema_version = 1

[project]
name = "llmtest"
source = "{SOURCE}"

[[images]]
id = "app"
repository = "quay.io/llmtest/app"
platforms = [{platform_list}]

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
"""


def _cli_executable() -> Path:
    value = os.environ.get("CONCLEAR_TEST_CLI")
    if value is None:
        pytest.skip(
            "the CLI transport scenario requires CONCLEAR_TEST_CLI, the conclear "
            "entry point of an installed identity-bearing wheel"
        )
    path = Path(value)
    if not path.is_absolute() or not os.access(path, os.X_OK):
        pytest.skip("CONCLEAR_TEST_CLI must name an absolute executable path")
    return path


class Cli:
    """Invoke one identity-bearing ConClear executable with a run-owned environment."""

    def __init__(self, executable: Path, environment: dict[str, str]) -> None:
        self.executable = executable
        self.environment = environment

    def run(self, *arguments: str, expect: int = 0) -> Any:
        completed = subprocess.run(
            [str(self.executable), *arguments, "--format", "json"],
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        assert completed.stdout.count("\n") == 1, completed.stdout
        value = json.loads(completed.stdout)
        assert completed.returncode == expect, (
            completed.returncode,
            value,
            completed.stderr[-2000:],
        )
        return value


def _prepare_repository(
    runtime: ApplicationRuntime,
    root: Path,
    *,
    platforms: Sequence[str],
) -> Path:
    repository = root / "repository"
    repository.mkdir(mode=0o700, parents=True)
    architectures = sorted({Platform.parse(item).architecture for item in platforms})
    go = _go()
    source = root / "main.go"
    source.write_text(FIXTURE_SOURCE, encoding="utf-8")
    for architecture in architectures:
        runtime.runner.run(
            CommandRequest(
                argv=(
                    go,
                    "build",
                    "-trimpath",
                    "-ldflags=-buildid=",
                    "-o",
                    str(repository / f"conclear-fixture-{architecture}"),
                    str(source),
                ),
                environment={
                    **runtime.environment,
                    "CGO_ENABLED": "0",
                    "GOARCH": architecture,
                    "GOOS": "linux",
                },
                timeout_seconds=300,
                cwd=root,
                operation=OperationKind.WRITE,
            )
        )
    (repository / "Containerfile").write_text(CONTAINERFILE, encoding="utf-8")
    (repository / ".containerignore").write_text(CONTAINERIGNORE, encoding="utf-8")
    (repository / "conclear.toml").write_text(
        _configuration(platforms), encoding="utf-8"
    )
    git = str(runtime.tools[ToolName.GIT].path)

    def run_git(*arguments: str) -> None:
        runtime.runner.run(
            CommandRequest(
                argv=(
                    git,
                    "-C",
                    str(repository),
                    "-c",
                    "user.name=ConClear Integration",
                    "-c",
                    "user.email=integration@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    *arguments,
                ),
                environment=runtime.environment,
                timeout_seconds=60,
                operation=OperationKind.WRITE,
            )
        )

    run_git("init", "--quiet", "--initial-branch=main")
    run_git("add", "--all")
    run_git("commit", "--quiet", "-m", "fixture")
    run_git("remote", "add", "origin", SOURCE)
    return repository


def _go() -> str:
    go = shutil.which("go")
    if go is None:
        pytest.skip("the CLI transport scenario requires Go")
    return str(Path(go).resolve(strict=True))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _platform_text(platform: dict[str, Any]) -> str:
    return "/".join(
        part
        for part in (
            platform["os"],
            platform["architecture"],
            platform.get("variant"),
        )
        if part
    )


def _layout_platform(layout: Path) -> str:
    index = json.loads((layout / "index.json").read_text(encoding="utf-8"))
    assert len(index["manifests"]) == 1
    manifest_descriptor = index["manifests"][0]
    manifest = json.loads(
        (
            layout / "blobs" / "sha256" / manifest_descriptor["digest"].split(":")[1]
        ).read_text(encoding="utf-8")
    )
    config_descriptor = manifest["config"]
    config = json.loads(
        (
            layout / "blobs" / "sha256" / config_descriptor["digest"].split(":")[1]
        ).read_text(encoding="utf-8")
    )
    return _platform_text(config)


def _scenario(
    tmp_path: Path,
    *,
    platforms: Sequence[str],
    trivy_cache: Path,
) -> None:
    run_id = manifest_run_id()
    executable = _cli_executable()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(root / "environment", names=(ToolName.GIT,))
    identity = json.loads(
        subprocess.run(
            [str(executable), "version", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        ).stdout
    )
    assert len(identity["sourceRevision"]) in {40, 64}, identity
    repository = _prepare_repository(runtime, root, platforms=platforms)
    state_home = root / "state"
    cache_home = root / "cache"
    (cache_home / "conclear").mkdir(mode=0o700, parents=True)
    (cache_home / "conclear" / "trivy").symlink_to(
        trivy_cache, target_is_directory=True
    )
    database_digest = json.loads(
        (trivy_cache / "current.json").read_text(encoding="utf-8")
    )["databaseDigest"]
    cli = Cli(
        executable,
        {
            "PATH": os.environ["PATH"],
            "HOME": str(root / "home"),
            "XDG_STATE_HOME": str(state_home),
            "XDG_CACHE_HOME": str(cache_home),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_RUNTIME_DIR": str(root / "runtime"),
        },
    )
    (root / "home").mkdir(mode=0o700)
    (root / "runtime").mkdir(mode=0o700)
    version = "0.0.1"
    run_ids: list[str] = []
    rejected_runs: list[str] = []
    try:
        transports: list[tuple[Path, str, dict[str, Any]]] = []
        worker_descriptor_platforms: list[str] = []
        for platform in platforms:
            qualified = cli.run(
                "qualify",
                "--source",
                str(repository),
                "--revision",
                "HEAD",
                "--image",
                "app",
                "--version",
                version,
                "--platform",
                platform,
                "--database-digest",
                database_digest,
            )
            run_ids.append(qualified["data"]["runId"])
            assert qualified["status"] == "success", qualified
            assert qualified["findings"] == []
            worker_descriptor_platforms.append(
                _layout_platform(Path(qualified["data"]["layout"]))
            )
            destination = (
                root / "transports" / f"app-{Platform.parse(platform).key}.tar"
            )
            exported = cli.run(
                "transport",
                "export",
                qualified["data"]["runId"],
                "--platform",
                platform,
                "--output",
                str(destination),
            )
            data = exported["data"]
            assert data["runId"] == qualified["data"]["runId"]
            assert data["recordDigest"] == qualified["data"]["recordDigest"]
            assert data["transportDigest"] == _sha256(destination)
            transports.append((destination, data["transportDigest"], data))
        assert len({item[1] for item in transports}) == len(transports)
        assert len(set(run_ids)) == len(platforms)

        # A wrong caller-supplied digest is a rule rejection before any assembly.
        wrong = ["--transport", str(transports[0][0]), "sha256:" + "0" * 64]
        rejected = cli.run(
            "assemble",
            "--source",
            str(repository),
            "--revision",
            "HEAD",
            "--image",
            "app",
            "--version",
            version,
            *wrong,
            expect=2,
        )
        assert rejected["status"] == "ruleRejection"
        assert any(item["checkId"] == "CC0306" for item in rejected["findings"])
        # The rejected coordinator run is named so its worktree and staging
        # directory can be removed like every other run of the scenario.
        assert rejected["data"]["runId"] not in run_ids
        rejected_runs.append(rejected["data"]["runId"])

        transport_arguments: list[str] = []
        for destination, digest, _data in transports:
            transport_arguments.extend(("--transport", str(destination), digest))
        assembled = cli.run(
            "assemble",
            "--source",
            str(repository),
            "--revision",
            "HEAD",
            "--image",
            "app",
            "--version",
            version,
            *transport_arguments,
        )
        data = assembled["data"]
        coordinator = data["runId"]
        run_ids.append(coordinator)
        assert coordinator not in run_ids[:-1]
        assert data["candidateTag"].startswith(f"{version}-candidate.{coordinator}.g")
        assert [item["workerRunId"] for item in data["transports"]] == run_ids[:-1]

        # Inspect the assembled index with plain reads: exactly the expected
        # descriptors, every digest recomputed, and the index digest as subject.
        layout = Path(data["layout"])
        index_entry = json.loads((layout / "index.json").read_text(encoding="utf-8"))
        assert len(index_entry["manifests"]) == 1
        root_descriptor = index_entry["manifests"][0]
        assert root_descriptor["digest"] == data["subjectDigest"]
        root_blob = (
            layout / "blobs" / "sha256" / root_descriptor["digest"].split(":")[1]
        )
        assert _sha256(root_blob) == root_descriptor["digest"]
        assert root_blob.stat().st_size == root_descriptor["size"]
        image_index = json.loads(root_blob.read_text(encoding="utf-8"))
        assert image_index["mediaType"] == "application/vnd.oci.image.index.v1+json"
        observed_platforms = sorted(
            _platform_text(descriptor["platform"])
            for descriptor in image_index["manifests"]
        )
        assert observed_platforms == sorted(worker_descriptor_platforms)
        for descriptor in image_index["manifests"]:
            blob = layout / "blobs" / "sha256" / descriptor["digest"].split(":")[1]
            assert _sha256(blob) == descriptor["digest"]
            assert blob.stat().st_size == descriptor["size"]
            assert (
                descriptor["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
            )
        assert sorted(data["platformManifests"].values()) == sorted(
            descriptor["digest"] for descriptor in image_index["manifests"]
        )
        assert {item["platformManifestDigest"] for _p, _d, item in transports} == set(
            data["platformManifests"].values()
        )

        # The candidate record names the coordinator and every worker run.
        record = json.loads(Path(data["record"]).read_text(encoding="utf-8"))
        assert record["runId"] == coordinator
        assert [item["runId"] for item in record["payload"]["qualifications"]] == (
            run_ids[:-1]
        )
        assert [
            item["transportDigest"] for item in record["payload"]["qualifications"]
        ] == [digest for _destination, digest, _data in transports]

        # No registry, signing or attestation resource exists in any run journal.
        for run in run_ids:
            journal = json.loads(
                (state_home / "conclear" / "runs" / run / "resources.json").read_text(
                    encoding="utf-8"
                )
            )
            assert not [
                entry
                for entry in journal["resources"]
                if entry["kind"]
                in {"candidateReference", "tagWrite", "signature", "attestation"}
            ]
    finally:
        for run in (*run_ids, *rejected_runs):
            cleaned = cli.run("cleanup", run)
            assert cleaned["status"] == "success", cleaned
    _assert_every_run_is_settled(state_home, expected={*run_ids, *rejected_runs})


def _assert_every_run_is_settled(state_home: Path, *, expected: set[str]) -> None:
    """Require that the scenario left no unknown run and no unresolved journal."""
    runs_root = state_home / "conclear" / "runs"
    observed = {path.name for path in runs_root.iterdir() if path.is_dir()}
    assert observed == expected, (observed, expected)
    for run in sorted(observed):
        state = json.loads((runs_root / run / "run.json").read_text(encoding="utf-8"))
        assert state["state"] in {"qualified", "assembled", "rejected"}, (run, state)
        journal = json.loads(
            (runs_root / run / "resources.json").read_text(encoding="utf-8")
        )
        unresolved = [
            entry["resourceId"]
            for entry in journal["resources"]
            if entry["status"] in {"planned", "created", "failed"}
        ]
        assert not unresolved, (run, unresolved)


@pytest.mark.local_integration
def test_two_native_workers_assemble_one_index_through_the_cli(
    tmp_path: Path, trivy_cache: Path
) -> None:
    """Two x86-64 variants stand in for two workers on a host without emulation."""
    if host_platform.machine() != "x86_64":
        pytest.skip("the native two-variant scenario requires an x86_64 host")
    _scenario(
        tmp_path,
        platforms=("linux/amd64", "linux/amd64/v3"),
        trivy_cache=trivy_cache,
    )


@pytest.mark.emulation
def test_amd64_and_arm64_workers_assemble_one_index_through_the_cli(
    tmp_path: Path, trivy_cache: Path
) -> None:
    try:
        mode = detect_execution_mode(
            host_platform.machine(), Platform.parse("linux/arm64")
        )
    except OperationalError as exc:
        pytest.skip(f"arm64 emulation is unavailable on this host: {exc}")
    assert mode.mechanism in {"native", "qemu-user"}
    _scenario(
        tmp_path,
        platforms=("linux/amd64", "linux/arm64"),
        trivy_cache=trivy_cache,
    )
