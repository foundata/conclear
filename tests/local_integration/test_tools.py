import os
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conclear.assembly import PlatformLayout, assemble_layout
from conclear.config import RuntimeConfig, load_repository_config
from conclear.errors import CommandExecutionError
from conclear.hooks import HookRunner
from conclear.jsonutil import sha256_bytes
from conclear.oci import validate_layout
from conclear.path_safety import contained_path
from conclear.process import CommandRequest, OperationKind
from conclear.records import SourceIdentity
from conclear.runtime import ApplicationRuntime
from conclear.services.cleanup import cleanup_run
from conclear.services.qualification import (
    QualificationInputs,
    build_platform,
    build_test_dependencies,
)
from conclear.services.qualification import test_platform as run_platform_tests
from conclear.tools import SUPPORTED_TOOLS, ToolName
from conclear.values import Platform
from conclear.workspace import RunWorkspace

pytestmark = pytest.mark.local_integration

_FIXTURE_SOURCE = r"""
package main

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func waitForSignal() os.Signal {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	return <-signals
}

func main() {
	mode := "service"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "health", "one-shot":
		return
	case "keygen":
		if err := os.WriteFile("/output/key", []byte("private-test-key"), 0600); err != nil {
			os.Exit(1)
		}
		return
	case "prepare":
		input, err := os.ReadFile("/input/value")
		if err != nil || string(input) != "fixture-value" {
			os.Exit(1)
		}
		key, err := os.ReadFile("/key/key")
		if err != nil || string(key) != "private-test-key" {
			os.Exit(1)
		}
		if err := os.WriteFile("/output/result", []byte("compatible"), 0600); err != nil {
			os.Exit(1)
		}
		return
	case "health-input", "one-shot-input":
		result, err := os.ReadFile("/input/result")
		if err != nil || string(result) != "compatible" || os.Getenv("SERVICE_SELECTOR") != "test" {
			os.Exit(1)
		}
		return
	case "service-input":
		result, err := os.ReadFile("/input/result")
		if err != nil || string(result) != "compatible" || os.Getenv("SERVICE_SELECTOR") != "test" {
			os.Exit(1)
		}
		waitForSignal()
		return
	case "supervisor-health":
		if _, err := os.Stat("/tmp/conclear-supervisor-ready"); err != nil {
			os.Exit(1)
		}
		return
	case "write-immutable":
		if err := os.WriteFile("/app/mutation", []byte("unexpected"), 0600); err == nil {
			os.Exit(1)
		}
		return
	case "write-temporary":
		if err := os.WriteFile("/tmp/conclear-fixture", []byte("ok"), 0600); err != nil {
			os.Exit(1)
		}
		if err := os.Remove("/tmp/conclear-fixture"); err != nil {
			os.Exit(1)
		}
		return
	case "child":
		waitForSignal()
		return
	case "supervisor":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(signals)
		child := exec.Command("/app/conclear-fixture", "child")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(1)
		}
		if err := os.WriteFile("/tmp/conclear-supervisor-ready", []byte("ok"), 0600); err != nil {
			_ = child.Process.Kill()
			os.Exit(1)
		}
		received := <-signals
		_ = os.Remove("/tmp/conclear-supervisor-ready")
		if err := child.Process.Signal(received); err != nil {
			os.Exit(1)
		}
		if err := child.Wait(); err != nil {
			if status, ok := err.(*exec.ExitError); ok {
				os.Exit(status.ExitCode())
			}
			os.Exit(1)
		}
		return
	case "service":
		waitForSignal()
		return
	default:
		os.Exit(64)
	}
}
"""

_FIXTURE_CONTAINERFILE = """\
FROM scratch AS runtime
ARG IMAGE_CREATED
ARG IMAGE_REVISION
ARG IMAGE_SOURCE
ARG IMAGE_VERSION
COPY conclear-fixture /app/conclear-fixture
LABEL org.opencontainers.image.created=$IMAGE_CREATED
LABEL org.opencontainers.image.revision=$IMAGE_REVISION
LABEL org.opencontainers.image.source=$IMAGE_SOURCE
LABEL org.opencontainers.image.version=$IMAGE_VERSION
HEALTHCHECK CMD [\"/app/conclear-fixture\", \"health\"]
USER 65532:65532
ENTRYPOINT [\"/app/conclear-fixture\"]
CMD [\"service\"]
"""


def test_supported_real_tool_matrix_and_read_only_interfaces(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(tmp_path / "environment")

    assert {name: runtime.tools[name].version for name in ToolName} == {
        name: next(iter(SUPPORTED_TOOLS[name].supported_versions)) for name in ToolName
    }
    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    (repository / "tracked.txt").write_text("test\n", encoding="utf-8")
    git = runtime.tools[ToolName.GIT].path
    for arguments in (
        ("init",),
        ("add", "tracked.txt"),
        (
            "-c",
            "user.name=ConClear test",
            "-c",
            "user.email=conclear@example.invalid",
            "commit",
            "-m",
            "test: create integration fixture",
        ),
        (
            "remote",
            "add",
            "origin",
            "https://github.com/example/conclear-integration.git",
        ),
    ):
        runtime.runner.run(
            CommandRequest(
                argv=(str(git), *arguments),
                environment={
                    **runtime.environment,
                    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
                    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
                },
                timeout_seconds=30,
                cwd=repository,
                operation=OperationKind.WRITE,
            )
        )
    observation = runtime.git().observe(repository, "HEAD")
    assert len(observation.revision) in {40, 64}
    cosign = runtime.tools[ToolName.COSIGN].path
    help_text: dict[str, str] = {}
    for command in ("sign", "sign-blob", "verify-blob"):
        help_text[command] = runtime.runner.run(
            CommandRequest(
                argv=(str(cosign), command, "--help"),
                environment=runtime.environment,
                timeout_seconds=30,
            )
        ).stdout
    assert "--use-signing-config" in help_text["sign"]
    assert "--bundle" in help_text["sign-blob"]
    assert "--signing-config" in help_text["sign-blob"]
    assert "--bundle" in help_text["verify-blob"]
    assert "--insecure-ignore-tlog" in help_text["verify-blob"]


def test_real_rootless_storage_and_local_analysis_are_run_owned(
    tmp_path: Path,
) -> None:
    run_id = _run_id()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(
        root / "environment",
        names=(
            ToolName.BUILDAH,
            ToolName.PODMAN,
            ToolName.HADOLINT,
            ToolName.TRIVY,
        ),
    )
    buildah_root = root / "buildah" / "root"
    buildah_runroot = root / "buildah" / "runroot"
    podman_root = root / "podman" / "root"
    podman_runroot = root / "podman" / "runroot"

    assert runtime.buildah().info(root=buildah_root, runroot=buildah_runroot)
    podman_info = runtime.podman().info(root=podman_root, runroot=podman_runroot)
    assert podman_info
    assert buildah_root.is_relative_to(root)
    assert podman_root.is_relative_to(root)

    containerfile = root / "Containerfile"
    containerfile.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    containerfile.write_text(
        'FROM scratch\nUSER 65532:65532\nENTRYPOINT ["/app"]\n',
        encoding="utf-8",
    )
    assert runtime.hadolint().check(containerfile) == ()

    source = root / "source"
    source.mkdir(mode=0o700)
    (source / "settings.yaml").write_text("enabled: true\n", encoding="utf-8")
    report = root / "reports" / "filesystem.json"
    report.parent.mkdir(mode=0o700)
    cache = root / "trivy-cache"
    cache.mkdir(mode=0o700)
    scan = runtime.trivy().scan_filesystem(
        path=source,
        report_path=report,
        cache_root=cache,
        scanners=("secret", "misconfig"),
    )
    assert scan.path == report
    assert report.is_file()


def test_real_scratch_runtime_modes_and_multi_platform_assembly(
    tmp_path: Path,
) -> None:
    run_id = _run_id()
    resource_id = run_id.lower()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(
        root / "environment",
        names=(ToolName.BUILDAH, ToolName.PODMAN, ToolName.SKOPEO),
    )
    buildah_root = root / "buildah" / "root"
    buildah_runroot = root / "buildah" / "runroot"
    podman_root = root / "podman" / "root"
    podman_runroot = root / "podman" / "runroot"
    buildah_ready = False
    podman_ready = False
    containers = (
        f"cc-{resource_id}-service",
        f"cc-{resource_id}-one-shot",
        f"cc-{resource_id}-supervisor",
    )
    try:
        assert runtime.buildah().info(root=buildah_root, runroot=buildah_runroot)
        buildah_ready = True
        assert runtime.podman().info(root=podman_root, runroot=podman_runroot)
        podman_ready = True
        observations = {}
        for architecture in ("amd64", "arm64"):
            context = _compile_fixture(
                runtime,
                root=root,
                architecture=architecture,
            )
            platform = Platform.parse(f"linux/{architecture}")
            observations[platform] = runtime.buildah().build(
                root=buildah_root,
                runroot=buildah_runroot,
                containerfile=context / "Containerfile",
                context=context,
                platform=platform,
                image_name=f"localhost/conclear-{resource_id}-{architecture}:fixture",
                layout_path=root / "layouts" / architecture,
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
        native = observations[Platform.parse("linux/amd64")]
        image_config = native.graph.manifests[0].config_data.get("config")
        assert isinstance(image_config, dict)
        assert "Healthcheck" not in image_config

        assembled = assemble_layout(
            tuple(
                PlatformLayout(platform, observation.layout_path, "fixture")
                for platform, observation in observations.items()
            ),
            output_path=root / "layouts" / "assembled",
            output_reference="fixture",
        )
        assert assembled.graph.platforms == (
            Platform.parse("linux/amd64"),
            Platform.parse("linux/arm64"),
        )
        copied_layout = root / "layouts" / "skopeo-copy"
        runtime.runner.run(
            CommandRequest(
                argv=(
                    str(runtime.tools[ToolName.SKOPEO].path),
                    "copy",
                    "--all",
                    "--preserve-digests",
                    f"oci:{assembled.path}:{assembled.reference}",
                    f"oci:{copied_layout}:fixture",
                ),
                environment=runtime.environment,
                timeout_seconds=300,
                operation=OperationKind.WRITE,
            )
        )
        copied = validate_layout(copied_layout, reference="fixture")
        assert copied.digest == assembled.graph.digest
        assert copied.platforms == assembled.graph.platforms

        image_name = f"localhost/conclear-{resource_id}:runtime"
        runtime.podman().import_layout(
            root=podman_root,
            runroot=podman_runroot,
            layout_path=native.layout_path,
            layout_reference="fixture",
            image_name=image_name,
            expected_digest=native.graph.digest,
        )
        service_runtime = _runtime_config(profile="service")
        service = runtime.podman().create_container(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[0],
            image_name=image_name,
            runtime=service_runtime,
            platform=Platform.parse("linux/amd64"),
        )
        assert service.status == "running"
        assert service.pid > 0
        controls = runtime.podman().inspect_controls(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[0],
        )
        assert controls.user.split(":", maxsplit=1)[0] == "65532"
        assert controls.read_only is True
        assert controls.writable_mounts == ("/tmp",)
        assert controls.memory_bytes == 128 * 1024 * 1024
        assert controls.nano_cpus == 1_000_000_000
        assert controls.pids_limit == 64
        assert controls.nofile_soft == controls.nofile_hard == 256
        assert controls.cap_drop
        assert not controls.cap_add
        assert not controls.effective_capabilities
        assert any(
            value.lower().replace("_", "-") == "no-new-privileges"
            for value in controls.security_options
        )
        for command in (
            ("/app/conclear-fixture", "health"),
            ("/app/conclear-fixture", "write-immutable"),
            ("/app/conclear-fixture", "write-temporary"),
        ):
            runtime.podman().exec(
                root=podman_root,
                runroot=podman_runroot,
                name=containers[0],
                command=command,
                timeout_seconds=30,
            )
        runtime.podman().signal(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[0],
            signal_name="TERM",
        )
        assert (
            runtime.podman().wait(
                root=podman_root,
                runroot=podman_runroot,
                name=containers[0],
                timeout_seconds=30,
            )
            == 0
        )

        runtime.podman().create_container(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[1],
            image_name=image_name,
            runtime=_runtime_config(profile="one-shot"),
            platform=Platform.parse("linux/amd64"),
            arguments=("one-shot",),
        )
        assert (
            runtime.podman().wait(
                root=podman_root,
                runroot=podman_runroot,
                name=containers[1],
                timeout_seconds=30,
            )
            == 0
        )

        supervisor = runtime.podman().create_container(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[2],
            image_name=image_name,
            runtime=service_runtime,
            platform=Platform.parse("linux/amd64"),
            arguments=("supervisor",),
        )
        assert supervisor.status == "running"
        _wait_for_supervisor(
            runtime,
            root=podman_root,
            runroot=podman_runroot,
            name=containers[2],
        )
        runtime.podman().signal(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[2],
            signal_name="TERM",
        )
        assert (
            runtime.podman().wait(
                root=podman_root,
                runroot=podman_runroot,
                name=containers[2],
                timeout_seconds=30,
            )
            == 0
        )
    finally:
        if podman_ready:
            for name in containers:
                runtime.podman().remove(
                    root=podman_root,
                    runroot=podman_runroot,
                    name=name,
                    force=True,
                )
            runtime.podman().remove_storage(
                root=podman_root,
                runroot=podman_runroot,
            )
        if buildah_ready:
            runtime.buildah().remove_storage(
                root=buildah_root,
                runroot=buildah_runroot,
            )


@pytest.mark.parametrize(
    ("profile", "launch_argument"),
    (("service", "service-input"), ("one-shot", "one-shot-input")),
)
def test_real_exact_image_preparation_and_launch_inputs(
    tmp_path: Path, profile: str, launch_argument: str
) -> None:
    external_run_id = _run_id()
    root = contained_path(
        tmp_path, f"{external_run_id}-test-inputs-{profile}", must_exist=False
    )
    runtime = ApplicationRuntime.create(
        root / "environment", names=(ToolName.BUILDAH, ToolName.PODMAN)
    )
    context = _compile_fixture(runtime, root=root, architecture="amd64")
    _write_test_input_configuration(
        context, profile=profile, launch_argument=launch_argument
    )
    repository = load_repository_config(context / "conclear.toml")
    workspace = RunWorkspace.create(
        state_home=root / "state",
        immutable_inputs={
            "sourceRevision": "a" * 40,
            "sourceRepository": repository.project.source,
            "configurationDigest": sha256_bytes(repository.raw_bytes),
            "image": "runtime",
            "version": "integration",
        },
        id_factory=_IntegrationIdFactory(_workspace_run_id(profile)),
        now=datetime(2026, 9, 3, tzinfo=UTC),
    )
    inputs = QualificationInputs(
        repository=repository,
        image=repository.image("runtime"),
        workspace=workspace,
        source=SourceIdentity(repository.project.source, "a" * 40),
        source_time=datetime(2000, 1, 1, tzinfo=UTC),
        version="integration",
        platform=Platform.parse("linux/amd64"),
        tools=(runtime.tools[ToolName.BUILDAH].record_identity(),),
        auth_file=None,
        host_architecture="x86_64",
    )
    try:
        build = build_platform(inputs, runtime.buildah())
        dependencies = build_test_dependencies(inputs, runtime.buildah())
        evidence = run_platform_tests(
            inputs,
            build,
            runtime.podman(),
            HookRunner(
                runner=runtime.runner,
                environment=runtime.environment,
                source_root=context,
                log_directory=workspace.root / "logs",
            ),
            dependencies=dependencies,
        )

        assert not evidence.findings
        assert evidence.dependencies[0]["imageId"] == "generator"
        assert evidence.dependencies[0]["sourceRevision"] == "a" * 40
        assert any(
            value["name"]
            == ("signalAndShutdown" if profile == "service" else "oneShotExit")
            and value["status"] == "passed"
            for value in evidence.test_results
        )
        report = (
            workspace.root / "reports" / "runtime" / "linux-amd64" / "tests.json"
        ).read_text(encoding="utf-8")
        assert "private-test-key" not in report
        assert not (
            workspace.root / "reports" / "runtime" / "linux-amd64" / "test-inputs"
        ).exists()
    finally:
        cleanup_run(
            workspace,
            buildah=runtime.buildah(),
            podman=runtime.podman(),
            registry_control=None,
        )
    assert not workspace.journal.cleanup_candidates()


def test_manual_cosign_no_service_blob_signing(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    run_id = _run_id()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(
        root / "environment",
        names=(ToolName.COSIGN,),
    )
    cosign = runtime.tools[ToolName.COSIGN].path
    signing_root = root / "manual-signing"
    signing_root.mkdir(mode=0o700, parents=True)
    artifact = signing_root / "artifact.txt"
    artifact.write_text("disposable integration artifact\n", encoding="utf-8")
    key_prefix = signing_root / "disposable"
    private_key = key_prefix.with_suffix(".key")
    request.addfinalizer(lambda: private_key.unlink(missing_ok=True))
    public_key = key_prefix.with_suffix(".pub")
    signing_config = signing_root / "no-service-signing-config.json"
    bundle = signing_root / "artifact.sigstore.json"
    password = f"conclear-{run_id}-disposable"
    environment = {**runtime.environment, "COSIGN_PASSWORD": password}
    runtime.runner.run(
        CommandRequest(
            argv=(
                str(cosign),
                "generate-key-pair",
                "--output-key-prefix",
                str(key_prefix),
            ),
            environment=environment,
            timeout_seconds=120,
            operation=OperationKind.WRITE,
            secret_values=(password,),
            secret_paths=(private_key,),
        )
    )
    runtime.runner.run(
        CommandRequest(
            argv=(
                str(cosign),
                "signing-config",
                "create",
                "--no-default-fulcio",
                "--no-default-oidc",
                "--no-default-rekor",
                "--no-default-tsa",
                "--out",
                str(signing_config),
            ),
            environment=runtime.environment,
            timeout_seconds=120,
            operation=OperationKind.WRITE,
        )
    )
    assert "http://" not in signing_config.read_text(encoding="utf-8")
    assert "https://" not in signing_config.read_text(encoding="utf-8")
    runtime.runner.run(
        CommandRequest(
            argv=(
                str(cosign),
                "sign-blob",
                "--yes",
                "--key",
                str(private_key),
                "--signing-config",
                str(signing_config),
                "--bundle",
                str(bundle),
                str(artifact),
            ),
            environment=environment,
            timeout_seconds=120,
            operation=OperationKind.WRITE,
            secret_values=(password,),
            secret_paths=(private_key,),
        )
    )
    result = runtime.runner.run(
        CommandRequest(
            argv=(
                str(cosign),
                "verify-blob",
                "--key",
                str(public_key),
                "--bundle",
                str(bundle),
                "--insecure-ignore-tlog=true",
                str(artifact),
            ),
            environment=runtime.environment,
            timeout_seconds=120,
            secret_paths=(public_key,),
        )
    )
    assert bundle.is_file()
    assert "Verified OK" in result.stderr


def _run_id() -> str:
    value = os.environ.get("CONCLEAR_TEST_RUN_ID")
    if value is None:
        pytest.skip("local integration tests require a manifest-owned run ID")
    return value


class _IntegrationIdFactory:
    def __init__(self, value: str) -> None:
        self._value = value

    def create(self) -> str:
        return self._value


def _workspace_run_id(profile: str) -> str:
    name = f"CONCLEAR_TEST_{profile.replace('-', '_').upper()}_ULID"
    value = os.environ.get(name)
    if value is None:
        pytest.skip(f"local integration test requires {name}")
    return value


def _write_test_input_configuration(
    context: Path, *, profile: str, launch_argument: str
) -> None:
    (context / "Containerfile").write_text(
        _FIXTURE_CONTAINERFILE.replace("ARG IMAGE_SOURCE\n", "").replace(
            "org.opencontainers.image.source=$IMAGE_SOURCE",
            "org.opencontainers.image.source=https://github.com/example/runtime-inputs",
        ),
        encoding="utf-8",
    )
    (context / ".containerignore").write_text(
        "**/.git/\n**/.env*\n**/*.key\n**/*.pem\n**/.venv/\n**/venv/\n",
        encoding="utf-8",
    )
    fixture = context / "fixture"
    fixture.mkdir(mode=0o700)
    (fixture / "value").write_text("fixture-value", encoding="utf-8")
    (context / "conclear.toml").write_text(
        f'''schema_version = 1

[project]
name = "runtime-inputs"
source = "https://github.com/example/runtime-inputs"

[[images]]
id = "runtime"
containerfile = "Containerfile"
context = "."
repository = "quay.io/example/runtime-inputs"
platforms = ["linux/amd64"]
native_test_platforms = ["linux/amd64"]
arm64_omission_reason = "This isolated integration fixture exercises the native runtime."

[images.test]
dependencies = ["generator"]

[[images.test.fixtures]]
name = "source"
path = "fixture"

[[images.test.outputs]]
name = "private-key"
secret = true

[[images.test.outputs]]
name = "result"

[[images.test.preparations]]
name = "keygen"
image = "generator"
command = ["/app/conclear-fixture", "keygen"]

[[images.test.preparations.mounts]]
source = "output"
name = "private-key"
target = "/output"
read_only = false

[[images.test.preparations]]
name = "generate"
image = "generator"
command = ["/app/conclear-fixture", "prepare"]

[[images.test.preparations.mounts]]
source = "fixture"
name = "source"
target = "/input"
read_only = true

[[images.test.preparations.mounts]]
source = "output"
name = "private-key"
target = "/key"
read_only = true

[[images.test.preparations.mounts]]
source = "output"
name = "result"
target = "/output"
read_only = false

[images.test.launch]
arguments = ["{launch_argument}"]
environment = {{ SERVICE_SELECTOR = "test" }}

[[images.test.launch.mounts]]
source = "output"
name = "result"
target = "/input"
read_only = true

[images.release]
immutable_tags = ["{{version}}"]
moving_tags = ["stable"]

[images.runtime]
profile = "{profile}"
user = 65532
read_only = true
memory = "128MiB"
cpus = 1.0
pids = 64
nofile = 256
health_command = ["/app/conclear-fixture", "health-input"]

[[images]]
id = "generator"
containerfile = "Containerfile"
context = "."
repository = "quay.io/example/runtime-input-generator"
platforms = ["linux/amd64"]
native_test_platforms = ["linux/amd64"]
arm64_omission_reason = "This isolated integration fixture exercises the native runtime."

[images.release]
immutable_tags = ["{{version}}"]
moving_tags = ["stable"]

[images.runtime]
profile = "one-shot"
user = 65532
read_only = true
writable_mounts = ["/output"]
memory = "128MiB"
cpus = 1.0
pids = 64
nofile = 256
''',
        encoding="utf-8",
    )


def _compile_fixture(
    runtime: ApplicationRuntime,
    *,
    root: Path,
    architecture: str,
) -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("the scratch integration fixture requires Go")
    context = root / "contexts" / architecture
    context.mkdir(mode=0o700, parents=True)
    source = context / "main.go"
    source.write_text(_FIXTURE_SOURCE, encoding="utf-8")
    (context / "Containerfile").write_text(
        _FIXTURE_CONTAINERFILE,
        encoding="utf-8",
    )
    (context / ".containerignore").write_text(
        "main.go\nContainerfile\n.containerignore\n",
        encoding="utf-8",
    )
    runtime.runner.run(
        CommandRequest(
            argv=(
                str(Path(go).resolve(strict=True)),
                "build",
                "-trimpath",
                "-ldflags=-buildid=",
                "-o",
                str(context / "conclear-fixture"),
                str(source),
            ),
            environment={
                **runtime.environment,
                "CGO_ENABLED": "0",
                "GOARCH": architecture,
                "GOOS": "linux",
            },
            timeout_seconds=300,
            cwd=context,
            operation=OperationKind.WRITE,
        )
    )
    return context


def _runtime_config(*, profile: str) -> RuntimeConfig:
    return RuntimeConfig(
        profile=profile,
        user=65532,
        read_only=True,
        writable_mounts=("/tmp",),
        memory="128MiB",
        cpus=1.0,
        pids=64,
        nofile=256,
        health_command=("/app/conclear-fixture", "health"),
        immutable_paths=("/app",),
        capabilities=(),
        startup_timeout_seconds=30,
        shutdown_timeout_seconds=30,
    )


def _wait_for_supervisor(
    runtime: ApplicationRuntime,
    *,
    root: Path,
    runroot: Path,
    name: str,
) -> None:
    command = ("/app/conclear-fixture", "supervisor-health")
    for _attempt in range(20):
        try:
            runtime.podman().exec(
                root=root,
                runroot=runroot,
                name=name,
                command=command,
                timeout_seconds=5,
            )
        except CommandExecutionError:
            time.sleep(0.05)
        else:
            return
    runtime.podman().exec(
        root=root,
        runroot=runroot,
        name=name,
        command=command,
        timeout_seconds=5,
    )
