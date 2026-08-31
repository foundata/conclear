import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from conclear.adapters.base import ToolAdapter
from conclear.adapters.buildah import BuildahAdapter
from conclear.adapters.cosign import CosignAdapter
from conclear.adapters.git import GitAdapter
from conclear.adapters.hadolint import HadolintAdapter
from conclear.adapters.podman import PodmanAdapter
from conclear.adapters.quay import QuayAdapter
from conclear.adapters.skopeo import SkopeoAdapter
from conclear.adapters.trivy import TrivyAdapter
from conclear.errors import (
    CommandExecutionError,
    InvalidInvocationError,
    OperationalError,
    UnsupportedOperationError,
)
from conclear.process import CommandRequest, ProcessResult
from conclear.tools import ResolvedTool, ToolName
from conclear.values import Digest, OCIReference, Platform

type ResponseFactory = Callable[[CommandRequest], ProcessResult]
type Response = ProcessResult | Exception | ResponseFactory


def trivy_metadata(version: int) -> str:
    return json.dumps(
        {
            "Version": version,
            "UpdatedAt": "2026-01-01T00:00:00Z",
            "NextUpdate": "2026-01-02T00:00:00Z",
            "DownloadedAt": "2026-01-01T00:01:00Z",
        }
    )


def result(stdout: str = "", stderr: str = "") -> ProcessResult:
    return ProcessResult(
        argv=("/tool",),
        returncode=0,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0,
        attempts=1,
        stdout_truncated=False,
        stderr_truncated=False,
    )


class FakeRunner:
    def __init__(self, *responses: Response) -> None:
        self.responses = list(responses)
        self.requests: list[CommandRequest] = []

    def run(self, request: CommandRequest) -> ProcessResult:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response(request)
        return response


@dataclass(frozen=True)
class AdapterArguments:
    tool: ResolvedTool
    runner: FakeRunner
    environment: Mapping[str, str]
    log_directory: Path

    def create[T: ToolAdapter](self, adapter_type: type[T]) -> T:
        return adapter_type(
            tool=self.tool,
            runner=self.runner,
            environment=self.environment,
            log_directory=self.log_directory,
        )


def adapter_arguments(
    tmp_path: Path, name: ToolName, runner: FakeRunner
) -> AdapterArguments:
    executable = tmp_path / name.value
    executable.write_bytes(name.value.encode())
    executable.chmod(0o700)
    return AdapterArguments(
        tool=ResolvedTool(
            name=name,
            path=executable,
            version="test",
            executable_digest="sha256:"
            + hashlib.sha256(name.value.encode()).hexdigest(),
            reported_version="test",
        ),
        runner=runner,
        environment={"PATH": "/usr/bin", "HOME": str(tmp_path / "home")},
        log_directory=tmp_path / "logs",
    )


def test_buildah_info_uses_supported_go_template_json(tmp_path: Path) -> None:
    runner = FakeRunner(result('{"store": {}}'))
    adapter = adapter_arguments(tmp_path, ToolName.BUILDAH, runner).create(
        BuildahAdapter
    )

    assert adapter.info(root=tmp_path / "root", runroot=tmp_path / "runroot") == {
        "store": {}
    }
    assert "{{json .}}" in runner.requests[0].argv


def test_buildah_build_uses_unambiguous_pull_option(tmp_path: Path) -> None:
    runner = FakeRunner(CommandExecutionError("stop after command observation"))
    adapter = adapter_arguments(tmp_path, ToolName.BUILDAH, runner).create(
        BuildahAdapter
    )

    with pytest.raises(CommandExecutionError):
        adapter.build(
            root=tmp_path / "root",
            runroot=tmp_path / "runroot",
            containerfile=tmp_path / "Containerfile",
            context=tmp_path,
            platform=Platform.parse("linux/amd64"),
            image_name="localhost/example:fixture",
            layout_path=tmp_path / "outputs" / "layout",
            layout_reference="fixture",
            source_epoch=946684800,
            build_arguments={},
            auth_file=None,
        )

    assert "--pull=always" in runner.requests[0].argv
    assert "--pull" not in runner.requests[0].argv
    assert (tmp_path / "outputs").is_dir()


def test_buildah_build_rejects_dangling_output_symlink(tmp_path: Path) -> None:
    runner = FakeRunner()
    adapter = adapter_arguments(tmp_path, ToolName.BUILDAH, runner).create(
        BuildahAdapter
    )
    output = tmp_path / "layout"
    output.symlink_to(tmp_path / "missing")

    with pytest.raises(InvalidInvocationError, match="already exists"):
        adapter.build(
            root=tmp_path / "root",
            runroot=tmp_path / "runroot",
            containerfile=tmp_path / "Containerfile",
            context=tmp_path,
            platform=Platform.parse("linux/amd64"),
            image_name="localhost/example:fixture",
            layout_path=output,
            layout_reference="fixture",
            source_epoch=946684800,
            build_arguments={},
            auth_file=None,
        )

    assert not runner.requests


def test_podman_controls_include_exact_tmpfs_destinations(tmp_path: Path) -> None:
    runner = FakeRunner(
        result(
            json.dumps(
                [
                    {
                        "EffectiveCaps": [],
                        "Config": {"User": "10001:10001"},
                        "HostConfig": {
                            "ReadonlyRootfs": True,
                            "Tmpfs": {
                                "/run": "rw,nosuid,nodev",
                                "/tmp": "rw,nosuid,nodev",
                            },
                            "Memory": 536870912,
                            "NanoCpus": 1000000000,
                            "PidsLimit": 128,
                            "Ulimits": [
                                {
                                    "Name": "RLIMIT_NOFILE",
                                    "Soft": 1024,
                                    "Hard": 1024,
                                }
                            ],
                            "CapAdd": [],
                            "CapDrop": ["ALL"],
                            "SecurityOpt": ["no-new-privileges"],
                        },
                    }
                ]
            )
        )
    )
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)

    observation = adapter.inspect_controls(
        root=tmp_path / "root", runroot=tmp_path / "runroot", name="test"
    )

    assert observation.writable_mounts == ("/run", "/tmp")
    assert not observation.effective_capabilities


def test_podman_controls_require_effective_capability_observation(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(result(json.dumps([{"Config": {}, "HostConfig": {}}])))
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)

    with pytest.raises(OperationalError, match="effective container capabilities"):
        adapter.inspect_controls(
            root=tmp_path / "root",
            runroot=tmp_path / "runroot",
            name="test",
        )


def test_podman_cleanup_is_idempotent_and_resets_only_selected_storage(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(result(), result())
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)
    root = tmp_path / "root"
    runroot = tmp_path / "runroot"

    adapter.remove(root=root, runroot=runroot, name="owned", force=True)
    adapter.remove_storage(root=root, runroot=runroot)

    assert runner.requests[0].argv[-4:] == ("rm", "--ignore", "--force", "owned")
    assert runner.requests[1].argv[-3:] == ("system", "reset", "--force")
    assert str(root) in runner.requests[1].argv
    assert str(runroot) in runner.requests[1].argv


def test_git_adapter_observes_full_source_facts(tmp_path: Path) -> None:
    revision = "a" * 40
    runner = FakeRunner(
        result(revision + "\n"),
        result("https://github.com/foundata/example.git\n"),
        result("1767225600\n"),
    )
    adapter = adapter_arguments(tmp_path, ToolName.GIT, runner).create(GitAdapter)

    observation = adapter.observe(tmp_path, "v1.2.3")

    assert observation.revision == revision
    assert observation.commit_time.tzinfo is UTC
    assert runner.requests[0].argv[-1] == "v1.2.3^{commit}"


def test_hadolint_adapter_retains_findings_from_nonzero_exit(tmp_path: Path) -> None:
    output = json.dumps(
        [{"code": "DL3000", "level": "error", "message": "bad", "line": 2, "column": 1}]
    )
    runner = FakeRunner(CommandExecutionError("findings", returncode=1, stdout=output))
    adapter = adapter_arguments(tmp_path, ToolName.HADOLINT, runner).create(
        HadolintAdapter
    )

    findings = adapter.check(tmp_path / "Containerfile")

    assert findings[0].code == "DL3000"
    assert findings[0].line == 2


def test_skopeo_adapter_uses_explicit_auth_and_fully_qualified_transport(
    tmp_path: Path,
) -> None:
    digest = "sha256:" + "1" * 64
    runner = FakeRunner(result(digest + "\n"))
    adapter = adapter_arguments(tmp_path, ToolName.SKOPEO, runner).create(SkopeoAdapter)
    auth_file = tmp_path / "auth.json"

    observed = adapter.resolve_digest(
        OCIReference.parse("quay.io/foundata/example:candidate"),
        auth_file=auth_file,
    )

    assert str(observed) == digest
    assert "--authfile" in runner.requests[0].argv
    assert runner.requests[0].argv[-1] == "docker://quay.io/foundata/example:candidate"
    assert auth_file in runner.requests[0].secret_paths


def test_trivy_database_refresh_installs_content_addressed_snapshot(
    tmp_path: Path,
) -> None:
    def create_database(request: CommandRequest) -> ProcessResult:
        cache = Path(request.argv[request.argv.index("--cache-dir") + 1])
        if "--download-db-only" in request.argv:
            (cache / "db").mkdir(parents=True)
            (cache / "db" / "trivy.db").write_bytes(b"database")
            (cache / "db" / "metadata.json").write_text(
                trivy_metadata(2), encoding="utf-8"
            )
        else:
            (cache / "java-db").mkdir(parents=True)
            (cache / "java-db" / "trivy-java.db").write_bytes(b"java-database")
            (cache / "java-db" / "metadata.json").write_text(
                trivy_metadata(1), encoding="utf-8"
            )
        return result()

    runner = FakeRunner(create_database, create_database)
    adapter = adapter_arguments(tmp_path, ToolName.TRIVY, runner).create(TrivyAdapter)
    cache_root = tmp_path / "cache"

    refreshed = adapter.refresh_database(cache_root)
    selected = adapter.select_database(cache_root)
    selected_by_digest = adapter.select_database_by_digest(
        cache_root, Digest(refreshed.digest)
    )

    assert refreshed.digest == selected.digest
    assert refreshed.digest == selected_by_digest.digest
    assert selected.path.parent.name == "snapshots"
    assert (cache_root / "current.json").is_file()

    (selected.path / "db" / "trivy.db").write_bytes(b"changed")
    with pytest.raises(OperationalError, match="differs from the expected digest"):
        adapter.select_database_by_digest(cache_root, Digest(refreshed.digest))


def test_trivy_database_selection_rejects_pointer_digest_mismatch(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    adapter = adapter_arguments(tmp_path, ToolName.TRIVY, runner).create(TrivyAdapter)
    snapshot = tmp_path / "cache" / "snapshots" / ("a" * 64)
    (snapshot / "db").mkdir(parents=True)
    (snapshot / "db" / "trivy.db").write_bytes(b"database")
    (snapshot / "db" / "metadata.json").write_text(trivy_metadata(2), encoding="utf-8")
    (snapshot / "java-db").mkdir(parents=True)
    (snapshot / "java-db" / "trivy-java.db").write_bytes(b"java-database")
    (snapshot / "java-db" / "metadata.json").write_text(
        trivy_metadata(1), encoding="utf-8"
    )
    (tmp_path / "cache" / "current.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "databaseDigest": "sha256:" + "a" * 64,
                "snapshot": "a" * 64,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(OperationalError, match="does not match pointer"):
        adapter.select_database(tmp_path / "cache")


def test_trivy_scans_cannot_update_or_query_outside_selected_snapshot(
    tmp_path: Path,
) -> None:
    def write_report(request: CommandRequest) -> ProcessResult:
        report = Path(request.argv[request.argv.index("--output") + 1])
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text('{"Results":[]}', encoding="utf-8")
        return result()

    runner = FakeRunner(write_report)
    adapter = adapter_arguments(tmp_path, ToolName.TRIVY, runner).create(TrivyAdapter)
    adapter.scan_filesystem(
        path=tmp_path,
        report_path=tmp_path / "report.json",
        cache_root=tmp_path / "snapshot",
        scanners=("secret", "misconfig"),
    )

    arguments = runner.requests[0].argv
    for option in (
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--offline-scan",
    ):
        assert option in arguments


def test_cosign_release_signing_keeps_public_log_policy_enabled(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(result("signed"))
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)
    subject = OCIReference.parse("quay.io/foundata/example@sha256:" + "2" * 64)

    adapter.sign(subject=subject, private_key="/secret/cosign.key", passphrase="pw")

    request = runner.requests[0]
    assert "--use-signing-config=true" in request.argv
    assert not any("tlog" in argument for argument in request.argv)
    assert request.environment["COSIGN_PASSWORD"] == "pw"
    assert request.secret_values == ("pw",)


def test_cosign_verification_requires_a_verified_entry(tmp_path: Path) -> None:
    runner = FakeRunner(result("[]"))
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)
    subject = OCIReference.parse("quay.io/foundata/example@sha256:" + "2" * 64)

    with pytest.raises(OperationalError, match="no verified entries"):
        adapter.verify(subject=subject, public_key=tmp_path / "cosign.pub")

    assert "--insecure-ignore-tlog" not in runner.requests[0].argv


def quay_repository() -> OCIReference:
    return OCIReference.parse("quay.io/foundata/example")


def test_quay_adapter_sets_and_verifies_expiration_without_leaking_token() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "PUT":
            return httpx.Response(204)
        return httpx.Response(
            200,
            json={
                "tags": [
                    {
                        "name": "candidate",
                        "manifest_digest": "sha256:" + "3" * 64,
                        "expiration": 1767312000,
                        "immutable": False,
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        token_provider=lambda: "protected-token",
        client=client,
    )
    expiration = datetime.fromtimestamp(1767312000, tz=UTC)

    observed = adapter.set_expiration(quay_repository(), "candidate", expiration)

    assert observed.expiration == expiration
    assert all("protected-token" not in str(request.url) for request in requests)
    assert requests[0].headers["Authorization"] == "Bearer protected-token"
    client.close()


def test_quay_adapter_resolves_ambiguous_tag_write_by_digest() -> None:
    writes = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal writes
        if request.method == "PUT":
            writes += 1
            raise httpx.ReadTimeout("ambiguous", request=request)
        return httpx.Response(
            200,
            json={
                "tags": [
                    {
                        "name": "stable",
                        "manifest_digest": "sha256:" + "4" * 64,
                        "expiration": None,
                        "immutable": False,
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        token_provider=lambda: "token",
        client=client,
    )
    digest = Digest("sha256:" + "4" * 64)

    observed = adapter.write_tag(quay_repository(), "stable", digest)

    assert observed.digest == digest
    assert writes == 1
    client.close()


def test_quay_adapter_classifies_unsupported_immutability() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(403))
    )
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        token_provider=lambda: "token",
        client=client,
    )

    with pytest.raises(UnsupportedOperationError, match="immutability is unavailable"):
        adapter.set_immutable(quay_repository(), "candidate")

    client.close()


def test_quay_adapter_lifts_and_verifies_tag_immutability() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "PUT":
            return httpx.Response(201)
        return httpx.Response(
            200,
            json={
                "tags": [
                    {
                        "name": "candidate",
                        "manifest_digest": "sha256:" + "3" * 64,
                        "expiration": 1767312000,
                        "immutable": False,
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        token_provider=lambda: "token",
        client=client,
    )

    observed = adapter.set_mutable(quay_repository(), "candidate")

    assert not observed.immutable
    assert requests[0].read() == b'{"immutable":false}'
    client.close()


def test_quay_adapter_rejects_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("conclear.adapters.quay.MAX_QUAY_RESPONSE_BYTES", 16)
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, content=b"{" + b"x" * 32 + b"}")
        )
    )
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        token_provider=lambda: "token",
        client=client,
    )

    with pytest.raises(OperationalError, match="response exceeds the size limit"):
        adapter.get_tag(quay_repository(), "candidate")

    client.close()
