import base64
import hashlib
import json
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from conclear import parsing
from conclear.adapters.base import ToolAdapter
from conclear.adapters.buildah import BuildahAdapter
from conclear.adapters.cosign import CosignAdapter
from conclear.adapters.git import GitAdapter
from conclear.adapters.hadolint import HadolintAdapter
from conclear.adapters.podman import BindMount, PodmanAdapter
from conclear.adapters.quay import QuayAdapter
from conclear.adapters.skopeo import SkopeoAdapter
from conclear.adapters.trivy import TrivyAdapter
from conclear.attestations import decode_dsse_statements
from conclear.config import load_repository_config
from conclear.errors import (
    CommandExecutionError,
    InvalidInvocationError,
    OperationalError,
    UnsupportedOperationError,
)
from conclear.jsonutil import canonical_json_bytes, sha256_bytes
from conclear.process import (
    CommandRequest,
    ProcessEnvironment,
    ProcessResult,
    ProcessRunner,
)
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
            response = response(request)
        if request.stdout_artifact is not None:
            request.stdout_artifact.write_text(response.stdout)
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


@pytest.mark.parametrize(
    "entry_count,payload_size", [(1, 2 * 1024 * 1024), (2048, 1024)]
)
def test_cosign_machine_responses_exceed_diagnostic_limit(
    tmp_path: Path, entry_count: int, payload_size: int
) -> None:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": {"data": "x" * payload_size},
    }
    entry = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
    }
    output = "\n".join(json.dumps(entry) for _ in range(entry_count))
    runner = FakeRunner(result(output), result(output))
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)
    subject = OCIReference.parse("quay.io/foundata/example@sha256:" + "a" * 64)

    verified = adapter.verify_attestation(
        subject=subject, public_key=tmp_path / "public.pem", predicate_type="custom"
    )
    downloaded = adapter.download_attestations(subject=subject, predicate_type="custom")

    assert len(decode_dsse_statements(verified.entries)) == entry_count
    assert verified.entries == downloaded
    assert all(request.stdout_artifact is not None for request in runner.requests)
    assert not list((tmp_path / "cosign-responses").iterdir())


def test_buildah_info_uses_supported_go_template_json(tmp_path: Path) -> None:
    runner = FakeRunner(result('{"store": {}}'))
    adapter = adapter_arguments(tmp_path, ToolName.BUILDAH, runner).create(
        BuildahAdapter
    )

    assert adapter.info(root=tmp_path / "root", runroot=tmp_path / "runroot") == {
        "store": {}
    }
    assert "{{json .}}" in runner.requests[0].argv


def test_buildah_build_uses_unambiguous_reproducibility_options(
    tmp_path: Path,
) -> None:
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
    assert "--source-date-epoch" in runner.requests[0].argv
    assert "--rewrite-timestamp" in runner.requests[0].argv
    assert "--timestamp" not in runner.requests[0].argv
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
                        "BoundingCaps": [],
                        "Config": {
                            "User": "10001:10001",
                            "StopSignal": "SIGTERM",
                        },
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
                            "UsernsMode": "private",
                            "CgroupMode": "private",
                            "Privileged": False,
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
    assert observation.user_namespace == "private"
    assert observation.cgroup_namespace == "private"
    assert observation.privileged is False


def test_podman_launch_inputs_remain_argument_arrays_and_redact_secret_mounts(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
) -> None:
    runner = FakeRunner(
        result("{}"),
        result(),
        result(
            json.dumps(
                [
                    {
                        "Id": "container-id",
                        "State": {
                            "Pid": 100,
                            "ExitCode": None,
                            "Status": "running",
                        },
                    }
                ]
            )
        ),
    )
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)
    runtime = (
        load_repository_config(repository_factory() / "conclear.toml")
        .release_image("app")
        .runtime
    )
    secret = tmp_path / "private-input"
    secret.mkdir()

    adapter.create_container(
        root=tmp_path / "root",
        runroot=tmp_path / "runroot",
        name="test",
        image_name="localhost/exact@sha256:fixture",
        runtime=runtime,
        platform=Platform.parse("linux/amd64"),
        arguments=("literal;not-shell", "$(false)"),
        environment=(("SERVICE_MODE", "test"),),
        mounts=(BindMount(secret, "/input", True, secret=True),),
        entrypoint=("/generator", "prepare"),
    )

    request = runner.requests[1]
    assert request.argv[-5:] == (
        "/generator",
        "localhost/exact@sha256:fixture",
        "prepare",
        "literal;not-shell",
        "$(false)",
    )
    assert "SERVICE_MODE=test" in request.argv
    assert "literal;not-shell" in request.argv
    assert "$(false)" in request.argv
    assert any(
        value == f"type=bind,src={secret},target=/input,ro,nosuid,nodev,relabel=private"
        for value in request.argv
    )
    assert request.secret_paths == (secret,)
    assert request.argv[request.argv.index("--systemd") + 1] == "false"
    assert request.argv[request.argv.index("--cgroupns") + 1] == "private"


def test_podman_systemd_launch_uses_explicit_rootless_lifecycle_controls(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
) -> None:
    runner = FakeRunner(
        result(
            json.dumps(
                {
                    "/run": {},
                    "/run/lock": {},
                    "/sys/fs/cgroup/systemd": {},
                    "/tmp": {},
                    "/var/lib/journal": {},
                }
            )
        ),
        result(),
        result(
            json.dumps(
                [
                    {
                        "Id": "container-id",
                        "State": {
                            "Pid": 100,
                            "ExitCode": None,
                            "Status": "running",
                        },
                    }
                ]
            )
        ),
    )
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace('profile = "service"\nuser = 10001', 'profile = "systemd"\nuser = 0')
        .replace(
            'memory = "512MiB"',
            'writable_mounts = ["/sys/fs/cgroup/systemd", "/var/lib/journal"]\n'
            'memory = "512MiB"',
        )
        .replace(
            'health_command = ["/app", "health"]',
            """health_command = ["/app", "health"]

[images.runtime.root_requirement]
rationale = "Systemd is the image lifecycle manager."
owner = "platform@example.com"
review_trigger = "Review when the image lifecycle changes."

[images.runtime.systemd]
required_units = ["multi-user.target"]
""",
        ),
        encoding="utf-8",
    )
    runtime = load_repository_config(path).release_image("app").runtime

    adapter.create_container(
        root=tmp_path / "root",
        runroot=tmp_path / "runroot",
        name="test",
        image_name="localhost/exact@sha256:fixture",
        runtime=runtime,
        platform=Platform.parse("linux/amd64"),
    )

    assert runner.requests[0].argv[-5:] == (
        "image",
        "inspect",
        "--format",
        "{{json .Config.Volumes}}",
        "localhost/exact@sha256:fixture",
    )
    argv = runner.requests[1].argv
    assert argv[argv.index("--user") + 1] == "0"
    assert argv[argv.index("--userns") + 1] == "keep-id:uid=0,gid=0"
    assert argv[argv.index("--systemd") + 1] == "always"
    assert argv[argv.index("--stop-signal") + 1] == "SIGRTMIN+3"
    assert {
        argv[index + 1].split(":", maxsplit=1)[0]
        for index, value in enumerate(argv)
        if value == "--tmpfs"
    } == {"/var/log/journal"}


def test_podman_observes_every_writable_mount_type_as_runtime_write_surface(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(
        result(
            json.dumps(
                [
                    {
                        "EffectiveCaps": [],
                        "BoundingCaps": [],
                        "Mounts": [
                            {
                                "Type": "bind",
                                "RW": True,
                                "Destination": "/output",
                            },
                            {
                                "Type": "volume",
                                "RW": True,
                                "Destination": "/image-data",
                            },
                            {
                                "Type": "bind",
                                "RW": False,
                                "Destination": "/input",
                            },
                        ],
                        "Config": {"User": "10001", "StopSignal": "SIGTERM"},
                        "HostConfig": {
                            "ReadonlyRootfs": True,
                            "Tmpfs": {},
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
                            "UsernsMode": "private",
                            "CgroupMode": "private",
                            "Privileged": False,
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

    assert observation.writable_mounts == ("/image-data", "/output")


def test_podman_observes_systemd_as_pid1(tmp_path: Path) -> None:
    runner = FakeRunner(result("PID COMMAND\n1 systemd\n23 worker\n"))
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)

    assert (
        adapter.inspect_pid1(
            root=tmp_path / "root",
            runroot=tmp_path / "runroot",
            name="test",
            timeout_seconds=5,
        )
        == "systemd"
    )
    assert runner.requests[0].argv[-4:] == ("top", "test", "pid", "comm")


def test_podman_observes_in_container_command_status(tmp_path: Path) -> None:
    runner = FakeRunner(
        CommandExecutionError(
            "not ready", returncode=1, stdout="initializing\n", stderr=""
        )
    )
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)

    observation = adapter.exec_observe(
        root=tmp_path / "root",
        runroot=tmp_path / "runroot",
        name="test",
        command=("/app/health",),
        timeout_seconds=7.5,
    )

    assert observation.exit_status == 1
    assert observation.stdout == "initializing\n"
    assert runner.requests[0].timeout_seconds == 7.5


@pytest.mark.parametrize("returncode", [125, 126, 127])
def test_podman_exec_observation_preserves_operational_failures(
    tmp_path: Path, returncode: int
) -> None:
    runner = FakeRunner(CommandExecutionError("podman failed", returncode=returncode))
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)

    with pytest.raises(CommandExecutionError, match="podman failed"):
        adapter.exec_observe(
            root=tmp_path / "root",
            runroot=tmp_path / "runroot",
            name="test",
            command=("/app/health",),
            timeout_seconds=5,
        )


def test_podman_import_digest_mismatch_uses_stable_check_identifier(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(
        result("imported-id\n"),
        result(),
        result("sha256:" + "b" * 64 + "\n"),
    )
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)

    with pytest.raises(OperationalError, match="differs from layout") as caught:
        adapter.import_layout(
            root=tmp_path / "root",
            runroot=tmp_path / "runroot",
            layout_path=tmp_path / "layout",
            layout_reference="qualified",
            image_name="test-image",
            expected_digest=Digest("sha256:" + "a" * 64),
        )

    assert caught.value.code == "CC0305"


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

    runner = FakeRunner(
        result(json.dumps([{"EffectiveCaps": [], "Config": {}, "HostConfig": {}}]))
    )
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)
    with pytest.raises(OperationalError, match="bounding container capabilities"):
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

    findings = adapter.check(tmp_path / "Containerfile", config_directory=tmp_path)

    assert findings[0].code == "DL3000"
    assert findings[0].line == 2
    assert "--config" not in runner.requests[0].argv
    assert runner.requests[0].cwd == tmp_path


def test_hadolint_adapter_uses_committed_configuration_from_context(
    tmp_path: Path,
) -> None:
    context = tmp_path / "context"
    context.mkdir()
    config = context / ".hadolint.yaml"
    config.write_text("ignored:\n  - DL3008\n", encoding="utf-8")
    runner = FakeRunner(result("[]"))
    adapter = adapter_arguments(tmp_path, ToolName.HADOLINT, runner).create(
        HadolintAdapter
    )

    assert adapter.check(context / "Containerfile", config_directory=context) == ()

    argv = runner.requests[0].argv
    assert argv[1:3] == ("--config", str(config))
    assert argv[-1] == str(context / "Containerfile")
    assert runner.requests[0].cwd == context


def test_hadolint_adapter_rejects_symlinked_configuration(tmp_path: Path) -> None:
    context = tmp_path / "context"
    context.mkdir()
    (tmp_path / "outside.yaml").write_text("ignored: []\n", encoding="utf-8")
    (context / ".hadolint.yml").symlink_to(tmp_path / "outside.yaml")
    runner = FakeRunner(result("[]"))
    adapter = adapter_arguments(tmp_path, ToolName.HADOLINT, runner).create(
        HadolintAdapter
    )

    with pytest.raises(InvalidInvocationError, match="regular file"):
        adapter.check(context / "Containerfile", config_directory=context)
    assert runner.requests == []


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


def test_skopeo_optional_resolution_accepts_only_registry_absence(
    tmp_path: Path,
) -> None:
    reference = OCIReference.parse("quay.io/foundata/example:missing")
    absent = CommandExecutionError(
        "Skopeo inspect failed",
        returncode=1,
        stderr=(
            "FATA[0000] Error parsing image name: reading manifest missing in "
            "quay.io/foundata/example: manifest unknown\n"
        ),
    )
    adapter = adapter_arguments(tmp_path, ToolName.SKOPEO, FakeRunner(absent)).create(
        SkopeoAdapter
    )

    assert adapter.resolve_optional(reference) is None

    ambiguous = CommandExecutionError(
        "Skopeo inspect failed",
        returncode=1,
        stderr="dial tcp: lookup quay.io: host not found\n",
    )
    adapter = adapter_arguments(
        tmp_path, ToolName.SKOPEO, FakeRunner(ambiguous)
    ).create(SkopeoAdapter)
    with pytest.raises(CommandExecutionError, match="Skopeo inspect failed"):
        adapter.resolve_optional(reference)


@pytest.mark.parametrize("indent,ensure_ascii", [(None, True), (2, True), (2, False)])
def test_trivy_spdx_hash_survives_attestation_reserialization(
    tmp_path: Path, indent: int | None, ensure_ascii: bool
) -> None:
    document: dict[str, object] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "app-\u00e4",
        "documentNamespace": "https://example.invalid/spdx/app",
        "creationInfo": {
            "creators": ["Tool: trivy"],
            "created": "2026-01-01T00:00:00Z",
        },
    }
    raw_output = json.dumps(document, indent=indent, ensure_ascii=ensure_ascii)
    output = tmp_path / "sbom.json"

    def generate(request: CommandRequest) -> ProcessResult:
        assert request.argv[request.argv.index("--format") + 1] == "spdx-json"
        output.write_text(raw_output, encoding="utf-8")
        return result()

    adapter = adapter_arguments(tmp_path, ToolName.TRIVY, FakeRunner(generate)).create(
        TrivyAdapter
    )
    observation = adapter.generate_spdx(
        layout_path=tmp_path / "layout",
        output_path=output,
        cache_root=tmp_path / "cache",
    )
    signed_predicate = json.loads(json.dumps(document, sort_keys=True))
    assert observation.digest == sha256_bytes(canonical_json_bytes(signed_predicate))
    assert observation.digest != sha256_bytes(raw_output.encode("utf-8"))
    assert output.read_bytes() == canonical_json_bytes(document)
    assert observation.value == document


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

    metadata_path = selected.path / "db" / "metadata.json"
    original_metadata = metadata_path.read_text(encoding="utf-8")
    metadata = json.loads(original_metadata)
    metadata["DownloadedAt"] = "2026-01-01T12:00:00Z"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    assert (
        adapter.select_database_by_digest(cache_root, Digest(refreshed.digest)).digest
        == refreshed.digest
    )
    metadata["NextUpdate"] = "2026-02-01T00:00:00Z"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(OperationalError, match="differs from the expected digest"):
        adapter.select_database_by_digest(cache_root, Digest(refreshed.digest))
    metadata_path.write_text(original_metadata, encoding="utf-8")

    (selected.path / "db" / "trivy.db").write_bytes(b"changed")
    with pytest.raises(OperationalError, match="differs from the expected digest"):
        adapter.select_database_by_digest(cache_root, Digest(refreshed.digest))


def test_trivy_database_refresh_rejects_symlinked_cache_lock(tmp_path: Path) -> None:
    runner = FakeRunner()
    adapter = adapter_arguments(tmp_path, ToolName.TRIVY, runner).create(TrivyAdapter)
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    target = tmp_path / "outside.lock"
    target.write_text("protected", encoding="utf-8")
    (cache_root / ".db.lock").symlink_to(target)

    with pytest.raises(OperationalError, match="Unable to lock Trivy"):
        adapter.refresh_database(cache_root)

    assert target.read_text(encoding="utf-8") == "protected"
    assert runner.requests == []


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
        assert request.cwd is not None and request.cwd != tmp_path
        for option in ("--config", "--ignorefile", "--secret-config"):
            path = Path(request.argv[request.argv.index(option) + 1])
            assert path.parent == request.cwd
            assert path.read_bytes() == (b"" if option == "--ignorefile" else b"{}\n")
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


@pytest.mark.parametrize("coverage", [False, True])
def test_trivy_requires_positive_image_configuration_coverage(
    tmp_path: Path, coverage: bool
) -> None:
    def write_report(request: CommandRequest) -> ProcessResult:
        assert (
            request.argv[request.argv.index("--image-config-scanners") + 1]
            == "misconfig,secret"
        )
        assert "--include-non-failures" in request.argv
        report = Path(request.argv[request.argv.index("--output") + 1])
        report.write_text(
            json.dumps(
                {
                    "ArtifactType": "container_image",
                    "ArtifactName": str(tmp_path),
                    "Results": [
                        {
                            "Class": "config",
                            "Type": "dockerfile",
                            "Target": str(tmp_path),
                            "Misconfigurations": [{"ID": "DS-0002", "Status": "PASS"}],
                        }
                    ]
                    if coverage
                    else [],
                }
            )
        )
        return result()

    adapter = adapter_arguments(
        tmp_path, ToolName.TRIVY, FakeRunner(write_report)
    ).create(TrivyAdapter)
    if coverage:
        adapter.scan_layout(
            layout_path=tmp_path,
            report_path=tmp_path / "image.json",
            cache_root=tmp_path / "cache",
        )
    else:
        with pytest.raises(
            OperationalError, match="lacks OCI configuration scan coverage"
        ):
            adapter.scan_layout(
                layout_path=tmp_path,
                report_path=tmp_path / "image.json",
                cache_root=tmp_path / "cache",
            )


def test_cosign_release_signing_keeps_public_log_policy_enabled(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(result("signed"), result("attested"), result("attested"))
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)
    subject = OCIReference.parse("quay.io/foundata/example@sha256:" + "2" * 64)

    adapter.sign(
        subject=subject,
        private_key="/secret/cosign.key",
        passphrase="pw",
        passphrase_path=Path("/secret/cosign.password"),
    )

    request = runner.requests[0]
    assert "--use-signing-config=true" in request.argv
    assert not any("tlog" in argument for argument in request.argv)
    assert request.environment["COSIGN_PASSWORD"] == "pw"
    assert request.secret_values == ("pw",)
    assert request.secret_paths == (
        Path("/secret/cosign.key"),
        Path("/secret/cosign.password"),
    )
    predicate = tmp_path / "predicate.json"
    statement = tmp_path / "statement.json"
    predicate.write_text("{}", encoding="utf-8")
    statement.write_text(
        json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": "quay.io/foundata/example",
                        "digest": {"sha256": "2" * 64},
                    },
                    {
                        "name": "quay.io/foundata/example#linux/amd64",
                        "digest": {"sha256": "3" * 64},
                    },
                ],
                "predicateType": "https://example.invalid/predicates/custom/v1",
                "predicate": {"claim": True},
            }
        ),
        encoding="utf-8",
    )
    adapter.attest(
        subject=subject,
        predicate=predicate,
        predicate_type="custom",
        private_key="/secret/cosign.key",
        passphrase="pw",
        passphrase_path=Path("/secret/cosign.password"),
    )
    adapter.attest_statement(
        subject=subject,
        statement=statement,
        private_key="/secret/cosign.key",
        passphrase="pw",
        passphrase_path=Path("/secret/cosign.password"),
    )
    assert runner.requests[1].secret_paths == (
        predicate,
        Path("/secret/cosign.key"),
        Path("/secret/cosign.password"),
    )
    wrapped = runner.requests[2]
    assert "--statement" not in wrapped.argv
    predicate_index = wrapped.argv.index("--predicate")
    predicate_path = Path(wrapped.argv[predicate_index + 1])
    assert predicate_path.parent.name == "cosign-predicates"
    assert predicate_path.read_bytes() == b'{"claim":true}\n'
    assert (predicate_path.stat().st_mode & 0o777) == 0o600
    assert wrapped.argv[wrapped.argv.index("--type") + 1] == (
        "https://example.invalid/predicates/custom/v1"
    )
    assert wrapped.secret_paths == (
        statement,
        predicate_path,
        Path("/secret/cosign.key"),
        Path("/secret/cosign.password"),
    )
    foreign = tmp_path / "foreign.json"
    foreign.write_text(
        json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "other", "digest": {"sha256": "9" * 64}}],
                "predicateType": "https://example.invalid/predicates/custom/v1",
                "predicate": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(OperationalError, match="does not name the attested subject"):
        adapter.attest_statement(
            subject=subject,
            statement=foreign,
            private_key="/secret/cosign.key",
            passphrase="pw",
        )


def test_cosign_receives_registry_credentials_through_a_run_owned_docker_config(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(lambda request: result(), lambda request: result())
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        '{"auths": {"quay.io": {"auth": "c2VjcmV0"}}}', encoding="utf-8"
    )
    auth_file.chmod(0o600)
    subject = OCIReference.parse("quay.io/foundata/example@sha256:" + "2" * 64)

    adapter.sign(subject=subject, private_key="key", passphrase="pw")
    assert "DOCKER_CONFIG" not in runner.requests[-1].environment

    adapter.use_registry_credentials(auth_file)
    adapter.sign(subject=subject, private_key="key", passphrase="pw")

    request = runner.requests[-1]
    config_directory = Path(request.environment["DOCKER_CONFIG"])
    copied = config_directory / "config.json"
    assert copied.is_file()
    assert copied.read_bytes() == auth_file.read_bytes()
    assert (copied.stat().st_mode & 0o777) == 0o600
    assert auth_file in request.secret_paths
    assert copied in request.secret_paths

    bad = tmp_path / "bad.json"
    bad.write_text('{"credsStore": "none"}', encoding="utf-8")
    bad.chmod(0o600)
    with pytest.raises(InvalidInvocationError, match="Docker auths object"):
        adapter.use_registry_credentials(bad)


def test_cosign_signing_failure_redacts_private_key_path(tmp_path: Path) -> None:
    executable = tmp_path / "cosign"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "key = sys.argv[sys.argv.index('--key') + 1]\n"
        "print(f'reading key: open {key}: permission denied', file=sys.stderr)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    content = executable.read_bytes()
    private_key = tmp_path / "protected" / "cosign.key"
    environment_root = tmp_path / "environment"
    environment = ProcessEnvironment(
        home=environment_root / "home",
        config_home=environment_root / "config",
        cache_home=environment_root / "cache",
        state_home=environment_root / "state",
        runtime_dir=environment_root / "runtime",
    ).values()
    adapter = CosignAdapter(
        tool=ResolvedTool(
            name=ToolName.COSIGN,
            path=executable,
            version="3.1.3",
            reported_version="3.1.3",
            executable_digest="sha256:" + hashlib.sha256(content).hexdigest(),
        ),
        runner=ProcessRunner(),
        environment=environment,
        log_directory=tmp_path / "logs",
    )
    subject = OCIReference.parse("quay.io/foundata/example@sha256:" + "2" * 64)

    with pytest.raises(OperationalError) as failure:
        adapter.sign(subject=subject, private_key=str(private_key), passphrase="pw")

    assert failure.value.code == "CC0701"
    assert str(private_key) not in str(failure.value)
    assert "[REDACTED]" in str(failure.value)
    log = json.loads(
        (tmp_path / "logs" / "cosign-0001.json").read_text(encoding="utf-8")
    )
    assert str(private_key) not in json.dumps(log)


def test_cosign_attestation_verification_reads_one_envelope_per_line(
    tmp_path: Path,
) -> None:
    lines = "\n".join(
        json.dumps(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": "e30=",
                "signatures": [{"sig": str(index)}],
            }
        )
        for index in range(2)
    )
    runner = FakeRunner(result(lines + "\n"), result("   \n"))
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)
    subject = OCIReference.parse("quay.io/foundata/example@sha256:" + "2" * 64)

    verification = adapter.verify_attestation(
        subject=subject,
        public_key=tmp_path / "cosign.pub",
        predicate_type="spdxjson",
    )
    assert len(verification.entries) == 2

    with pytest.raises(OperationalError, match="no verified entries"):
        adapter.verify_attestation(
            subject=subject,
            public_key=tmp_path / "cosign.pub",
            predicate_type="spdxjson",
        )


def test_cosign_verification_requires_a_verified_entry(tmp_path: Path) -> None:
    runner = FakeRunner(result("[]"))
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)
    subject = OCIReference.parse("quay.io/foundata/example@sha256:" + "2" * 64)

    with pytest.raises(OperationalError, match="no verified entries") as caught:
        adapter.verify(subject=subject, public_key=tmp_path / "cosign.pub")

    assert caught.value.code == "CC0701"
    assert "--insecure-ignore-tlog" not in runner.requests[0].argv


def test_cosign_optional_attestation_download_accepts_only_exact_absence(
    tmp_path: Path,
) -> None:
    predicate_type = "https://example.com/predicate/v1"
    missing = CommandExecutionError(
        "Cosign found no matching attestation",
        returncode=1,
        stderr=f"Error: no attestations with predicate type '{predicate_type}' found\n",
    )
    runner = FakeRunner(missing)
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)
    subject = OCIReference.parse("quay.io/foundata/example@sha256:" + "2" * 64)

    assert (
        adapter.download_attestations(
            subject=subject,
            predicate_type=predicate_type,
            allow_missing=True,
        )
        == ()
    )

    failure = CommandExecutionError(
        "Registry unavailable",
        returncode=1,
        stderr="Error: registry unavailable\n",
    )
    runner = FakeRunner(failure)
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)
    with pytest.raises(CommandExecutionError, match="Registry unavailable"):
        adapter.download_attestations(
            subject=subject,
            predicate_type=predicate_type,
            allow_missing=True,
        )


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
                        "start_ts": 1767225600,
                        "end_ts": 1767312000,
                        "expiration": "Fri, 02 Jan 2026 00:00:00 -0000",
                        "immutable": False,
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        registry="quay.io",
        token_provider=lambda: "protected-token",
        client=client,
    )
    expiration = datetime.fromtimestamp(1767312000, tz=UTC)

    observed = adapter.enforce_candidate_lifetime(
        quay_repository(), "candidate", expiration
    )

    assert observed.expiration == expiration
    assert all("protected-token" not in str(request.url) for request in requests)
    assert requests[0].headers["Authorization"] == "Bearer protected-token"
    assert requests[0].read() == b'{"expiration":1767312000}'
    client.close()


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        (
            {"end_ts": 1789258408, "expiration": "Sun, 13 Sep 2026 00:13:28 -0000"},
            datetime(2026, 9, 13, 0, 13, 28, tzinfo=UTC),
        ),
        (
            {"expiration": "Sun, 13 Sep 2026 00:13:28 -0000"},
            datetime(2026, 9, 13, 0, 13, 28, tzinfo=UTC),
        ),
        ({"expiration": 1789258408}, datetime(2026, 9, 13, 0, 13, 28, tzinfo=UTC)),
        ({"expiration": None}, None),
        ({}, None),
    ],
    ids=["real-quay", "string-only", "epoch-only", "null", "absent"],
)
def test_quay_adapter_reads_tag_expiration_as_quay_reports_it(
    item: dict[str, object], expected: datetime | None
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "tags": [
                    {
                        "name": "candidate",
                        "manifest_digest": "sha256:" + "3" * 64,
                        "start_ts": 1788653636,
                        "is_manifest_list": False,
                        **item,
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        registry="quay.io",
        token_provider=lambda: "token",
        client=client,
    )

    observed = adapter.observe_tag(quay_repository(), "candidate")

    assert observed is not None
    assert observed.expiration == expected
    assert observed.immutable is False
    client.close()


@pytest.mark.parametrize(
    "item",
    [
        {"end_ts": "soon"},
        {"end_ts": True},
        {"expiration": "not a date"},
        {"expiration": 1.5},
    ],
    ids=["end-ts-string", "end-ts-bool", "expiration-text", "expiration-float"],
)
def test_quay_adapter_rejects_malformed_tag_expiration(
    item: dict[str, object],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "tags": [
                    {
                        "name": "candidate",
                        "manifest_digest": "sha256:" + "3" * 64,
                        **item,
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        registry="quay.io",
        token_provider=lambda: "token",
        client=client,
    )

    with pytest.raises(OperationalError, match="expiration is malformed"):
        adapter.observe_tag(quay_repository(), "candidate")
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
        registry="quay.io",
        token_provider=lambda: "token",
        client=client,
    )
    digest = Digest("sha256:" + "4" * 64)

    observed = adapter.assign_tag(quay_repository(), "stable", digest)

    assert observed.digest == digest
    assert writes == 1
    client.close()


def test_quay_adapter_reports_unenforced_immutability_as_unsupported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            return httpx.Response(201, json="Updated")
        return httpx.Response(
            200,
            json={
                "tags": [
                    {
                        "name": "1.0.0",
                        "manifest_digest": "sha256:" + "3" * 64,
                        "start_ts": 1788653636,
                        "is_manifest_list": False,
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        registry="quay.io",
        token_provider=lambda: "token",
        client=client,
    )

    with pytest.raises(UnsupportedOperationError, match="does not enforce"):
        adapter.ensure_tag_immutable(quay_repository(), "1.0.0")
    client.close()


def test_quay_adapter_classifies_unsupported_immutability() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(403))
    )
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        registry="quay.io",
        token_provider=lambda: "token",
        client=client,
    )

    with pytest.raises(UnsupportedOperationError, match="immutability is unavailable"):
        adapter.ensure_tag_immutable(quay_repository(), "candidate")

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
                        "start_ts": 1767225600,
                        "end_ts": 1767312000,
                        "expiration": "Fri, 02 Jan 2026 00:00:00 -0000",
                        "immutable": False,
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = QuayAdapter(
        api_url="https://quay.io/api/v1",
        registry="quay.io",
        token_provider=lambda: "token",
        client=client,
    )

    observed = adapter.ensure_tag_mutable(quay_repository(), "candidate")

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
        registry="quay.io",
        token_provider=lambda: "token",
        client=client,
    )

    with pytest.raises(OperationalError, match="response exceeds the size limit"):
        adapter.observe_tag(quay_repository(), "candidate")

    client.close()


def test_skopeo_registry_copy_requires_an_absent_layout_destination(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    adapter = adapter_arguments(tmp_path, ToolName.SKOPEO, runner).create(SkopeoAdapter)
    existing = tmp_path / "layouts" / "existing"
    existing.mkdir(parents=True)

    with pytest.raises(InvalidInvocationError, match="already exists"):
        adapter.copy_registry_to_layout(
            source=OCIReference.parse("quay.io/foundata/example@sha256:" + "6" * 64),
            layout_path=existing,
            layout_reference="published",
            auth_file=None,
        )
    assert runner.requests == []


def test_skopeo_deletion_requires_a_tag_reference_before_running(
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    adapter = adapter_arguments(tmp_path, ToolName.SKOPEO, runner).create(SkopeoAdapter)
    auth_file = tmp_path / "auth.json"

    for reference in (
        "quay.io/foundata/example@sha256:" + "3" * 64,
        "quay.io/foundata/example:candidate@sha256:" + "3" * 64,
        "quay.io/foundata/example",
    ):
        with pytest.raises(InvalidInvocationError, match="requires a tag reference"):
            adapter.delete(OCIReference.parse(reference), auth_file=auth_file)
    assert runner.requests == []


def test_cosign_release_subjects_must_be_immutable_digests(tmp_path: Path) -> None:
    runner = FakeRunner()
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)

    for reference in (
        "quay.io/foundata/example:candidate",
        "quay.io/foundata/example:candidate@sha256:" + "4" * 64,
    ):
        subject = OCIReference.parse(reference)
        with pytest.raises(OperationalError, match="immutable digest"):
            adapter.download_signatures(subject=subject)
        with pytest.raises(OperationalError, match="immutable digest"):
            adapter.verify_attestation(
                subject=subject,
                public_key=tmp_path / "cosign.pub",
                predicate_type="https://slsa.dev/provenance/v1",
            )
    assert runner.requests == []


def test_cosign_downloads_and_attestation_verification_parse_tool_output(
    tmp_path: Path,
) -> None:
    subject = OCIReference.parse("quay.io/foundata/example@sha256:" + "5" * 64)
    runner = FakeRunner(
        result('{"payload": "first"}\n\n{"payload": "second"}\n'),
        result('[{"critical": {"type": "cosign container image signature"}}]'),
        result("not json"),
    )
    adapter = adapter_arguments(tmp_path, ToolName.COSIGN, runner).create(CosignAdapter)

    assert adapter.download_signatures(subject=subject) == (
        {"payload": "first"},
        {"payload": "second"},
    )
    assert runner.requests[0].argv[1:] == ("download", "signature", str(subject))
    assert runner.requests[0].retries == 2

    verification = adapter.verify_attestation(
        subject=subject,
        public_key=tmp_path / "cosign.pub",
        predicate_type="https://slsa.dev/provenance/v1",
    )
    assert verification.subject == subject
    assert len(verification.entries) == 1
    argv = runner.requests[1].argv
    assert argv[argv.index("--type") + 1] == "https://slsa.dev/provenance/v1"
    assert tmp_path / "cosign.pub" in runner.requests[1].secret_paths

    with pytest.raises(OperationalError, match="did not return valid JSON"):
        adapter.download_signatures(subject=subject)


@pytest.mark.parametrize(
    ("validate", "value", "message"),
    [
        (
            lambda v: parsing.json_value(v, label="Tool"),
            "{",
            "did not return valid JSON",
        ),
        (
            lambda v: parsing.json_value(v, label="Tool"),
            "[" * 200 + "]" * 200,
            "exceeds the nesting limit",
        ),
        (lambda v: parsing.object_value(v, label="Tool"), [], "must be a JSON object"),
        (lambda v: parsing.array_value(v, label="Tool"), {}, "must be a JSON array"),
        (lambda v: parsing.string_value(v, label="Tool"), "", "non-empty string"),
        (lambda v: parsing.string_value(v, label="Tool"), 1, "non-empty string"),
        (lambda v: parsing.integer_value(v, label="Tool"), True, "must be an integer"),
        (lambda v: parsing.integer_value(v, label="Tool"), "1", "must be an integer"),
    ],
    ids=[
        "invalid-json",
        "nesting",
        "object",
        "array",
        "empty-string",
        "non-string",
        "boolean-integer",
        "string-integer",
    ],
)
def test_untrusted_tool_output_validators_reject_malformed_values(
    validate: Callable[[object], object], value: object, message: str
) -> None:
    with pytest.raises(OperationalError, match=message):
        validate(value)


def _write_snapshot(
    snapshot: Path,
    *,
    vulnerability_metadata: str,
    java_metadata: str,
) -> None:
    (snapshot / "db").mkdir(parents=True)
    (snapshot / "db" / "trivy.db").write_bytes(b"database")
    (snapshot / "db" / "metadata.json").write_text(
        vulnerability_metadata, encoding="utf-8"
    )
    (snapshot / "java-db").mkdir(parents=True)
    (snapshot / "java-db" / "trivy-java.db").write_bytes(b"java-database")
    (snapshot / "java-db" / "metadata.json").write_text(java_metadata, encoding="utf-8")


@pytest.mark.parametrize(
    ("pointer", "message"),
    [
        (
            {
                "schemaVersion": 2,
                "databaseDigest": "sha256:" + "a" * 64,
                "snapshot": "a" * 64,
            },
            "unsupported schema",
        ),
        (
            {
                "schemaVersion": 1,
                "databaseDigest": "sha256:" + "a" * 64,
                "snapshot": "../escape",
            },
            "snapshot name is malformed",
        ),
        (
            {
                "schemaVersion": 1,
                "databaseDigest": "sha256:" + "a" * 64,
                "snapshot": "A" * 64,
            },
            "snapshot name is malformed",
        ),
        (
            {"schemaVersion": 1, "databaseDigest": "", "snapshot": "a" * 64},
            "non-empty string",
        ),
    ],
    ids=["schema", "traversal", "uppercase", "digest"],
)
def test_trivy_database_pointer_validation(
    tmp_path: Path, pointer: dict[str, object], message: str
) -> None:
    adapter = adapter_arguments(tmp_path, ToolName.TRIVY, FakeRunner()).create(
        TrivyAdapter
    )
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    (cache_root / "current.json").write_text(json.dumps(pointer), encoding="utf-8")

    with pytest.raises(OperationalError, match=message):
        adapter.select_database(cache_root)


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        (
            '{"Version": 0, "UpdatedAt": "2026-01-01T00:00:00Z", "NextUpdate": "2026-01-02T00:00:00Z", "DownloadedAt": "2026-01-01T00:01:00Z"}',
            "version is malformed",
        ),
        (
            '{"Version": true, "UpdatedAt": "2026-01-01T00:00:00Z", "NextUpdate": "2026-01-02T00:00:00Z", "DownloadedAt": "2026-01-01T00:01:00Z"}',
            "version is malformed",
        ),
        (
            '{"Version": 2, "UpdatedAt": 1, "NextUpdate": "2026-01-02T00:00:00Z", "DownloadedAt": "2026-01-01T00:01:00Z"}',
            "updated-at time is malformed",
        ),
        (
            '{"Version": 2, "UpdatedAt": "2026-01-01T00:00:00Z", "NextUpdate": "yesterday", "DownloadedAt": "2026-01-01T00:01:00Z"}',
            "next-update time is malformed",
        ),
        (
            '{"Version": 2, "UpdatedAt": "2026-01-01T00:00:00Z", "NextUpdate": "2026-01-02T00:00:00Z", "DownloadedAt": "2026-01-01T00:01:00"}',
            "downloaded-at time lacks a timezone",
        ),
        ("[]", "must be a JSON object"),
    ],
    ids=[
        "version-zero",
        "version-bool",
        "updated-type",
        "next-format",
        "naive",
        "shape",
    ],
)
def test_trivy_database_metadata_validation(
    tmp_path: Path, metadata: str, message: str
) -> None:
    adapter = adapter_arguments(tmp_path, ToolName.TRIVY, FakeRunner()).create(
        TrivyAdapter
    )
    cache_root = tmp_path / "cache"
    _write_snapshot(
        cache_root / "snapshots" / ("b" * 64),
        vulnerability_metadata=metadata,
        java_metadata=trivy_metadata(1),
    )

    with pytest.raises(OperationalError, match=message):
        adapter.select_database_by_digest(cache_root, Digest("sha256:" + "b" * 64))


def test_trivy_database_metadata_is_recorded_at_whole_seconds(tmp_path: Path) -> None:
    fractional = json.dumps(
        {
            "Version": 2,
            "UpdatedAt": "2026-01-01T00:00:00.123456Z",
            "NextUpdate": "2026-01-02T01:00:00+01:00",
            "DownloadedAt": "2026-01-01T00:01:00.999999Z",
        }
    )

    def create_database(request: CommandRequest) -> ProcessResult:
        cache = Path(request.argv[request.argv.index("--cache-dir") + 1])
        if "--download-db-only" in request.argv:
            (cache / "db").mkdir(parents=True)
            (cache / "db" / "trivy.db").write_bytes(b"database")
            (cache / "db" / "metadata.json").write_text(fractional, encoding="utf-8")
        else:
            (cache / "java-db").mkdir(parents=True)
            (cache / "java-db" / "trivy-java.db").write_bytes(b"java-database")
            (cache / "java-db" / "metadata.json").write_text(
                trivy_metadata(1), encoding="utf-8"
            )
        return result()

    runner = FakeRunner(create_database, create_database)
    adapter = adapter_arguments(tmp_path, ToolName.TRIVY, runner).create(TrivyAdapter)

    observation = adapter.refresh_database(tmp_path / "cache")

    vulnerability = observation.metadata["vulnerability"]
    assert isinstance(vulnerability, dict)
    assert vulnerability["updatedAt"] == "2026-01-01T00:00:00Z"
    assert vulnerability["nextUpdate"] == "2026-01-02T00:00:00Z"
    assert vulnerability["downloadedAt"] == "2026-01-01T00:01:00Z"


def test_trivy_database_refresh_reports_installation_failures(tmp_path: Path) -> None:
    def create_database(request: CommandRequest) -> ProcessResult:
        cache = Path(request.argv[request.argv.index("--cache-dir") + 1])
        component = "db" if "--download-db-only" in request.argv else "java-db"
        (cache / component).mkdir(parents=True)
        (
            cache / component / f"trivy{'' if component == 'db' else '-java'}.db"
        ).write_bytes(b"x")
        (cache / component / "metadata.json").write_text(
            trivy_metadata(2 if component == "db" else 1), encoding="utf-8"
        )
        return result()

    runner = FakeRunner(create_database, create_database)
    adapter = adapter_arguments(tmp_path, ToolName.TRIVY, runner).create(TrivyAdapter)
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    (cache_root / "snapshots").write_text("not a directory", encoding="utf-8")

    with pytest.raises(OperationalError, match="Unable to install refreshed"):
        adapter.refresh_database(cache_root)
    assert not list(cache_root.glob(".db.*/"))
    assert not (cache_root / "current.json").exists()


def test_trivy_database_lock_must_be_a_regular_file(tmp_path: Path) -> None:
    adapter = adapter_arguments(tmp_path, ToolName.TRIVY, FakeRunner()).create(
        TrivyAdapter
    )
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    os.mkfifo(cache_root / ".db.lock")

    with pytest.raises(OperationalError, match="lock is not a regular file"):
        adapter.refresh_database(cache_root)
