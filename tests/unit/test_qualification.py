import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import conclear.records as records_module
from conclear.adapters.buildah import BuildObservation
from conclear.adapters.podman import (
    ContainerObservation,
    ExecObservation,
    ImportObservation,
    RuntimeControlObservation,
)
from conclear.adapters.trivy import DatabaseObservation, ScanObservation
from conclear.artifacts import qualification_materials, qualification_transport
from conclear.config import SYSTEMD_STOP_SIGNAL, ImageConfig, load_repository_config
from conclear.errors import CommandTimeoutError, OperationalError, RuleRejectionError
from conclear.hooks import HookRunner
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
)
from conclear.oci import OCI_CONFIG, OCI_MANIFEST, validate_layout
from conclear.pins import PinObservation
from conclear.presentation import Finding
from conclear.process import CommandRequest, ProcessResult
from conclear.records import (
    SourceIdentity,
    ToolIdentity,
    Verdict,
    validate_record,
)
from conclear.services.preflight import ClosurePreflight, ImagePreflight
from conclear.services.qualification import (
    build_platform,
    build_test_dependencies,
    qualify_platform,
)
from conclear.services.qualification_inputs import BuildInputs, QualificationInputs
from conclear.services.runtime_lifecycle import ReadinessTiming
from conclear.services.runtime_tests import test_platform as run_platform_tests
from conclear.source_integrity import source_tree_digest
from conclear.values import Digest, Platform
from conclear.workspace import ResourceStatus, RunWorkspace
from tests.unit.test_config import _image_text


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
    def __init__(
        self, *, invalid_labels: bool = False, observed_variant: str | None = None
    ) -> None:
        self.invalid_labels = invalid_labels
        self.observed_variant = observed_variant

    def build(self, **values: Any) -> BuildObservation:
        layout = values["layout_path"]
        assert isinstance(layout, Path)
        layout.mkdir(parents=True)
        (layout / "oci-layout").write_text(
            '{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8"
        )
        build_arguments = values["build_arguments"]
        assert isinstance(build_arguments, dict)
        platform = values["platform"]
        assert isinstance(platform, Platform)
        labels = {
            "org.opencontainers.image.source": "https://foundata.com/en/projects/example/#source",
            "org.opencontainers.image.revision": build_arguments["IMAGE_REVISION"],
            "org.opencontainers.image.created": build_arguments["IMAGE_CREATED"],
            "org.opencontainers.image.version": build_arguments["IMAGE_VERSION"],
            "org.opencontainers.image.licenses": "GPL-3.0-or-later",
            "org.opencontainers.image.title": "Example",
        }
        if self.invalid_labels:
            labels["org.opencontainers.image.revision"] = "wrong"
        observed_platform: dict[str, object] = {
            "architecture": platform.architecture,
            "os": "linux",
        }
        if self.observed_variant is not None:
            observed_platform["variant"] = self.observed_variant
        config, config_size = write_blob(
            layout,
            canonical_json_bytes(
                {
                    **observed_platform,
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
                            "platform": observed_platform,
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
    def __init__(
        self,
        *,
        fail_health: bool = False,
        fail_remove: bool = False,
        effective_capabilities: tuple[str, ...] = (),
        bounding_capabilities: tuple[str, ...] = (),
        write_preparation_outputs: bool = True,
        main_exit_status: int = 0,
        timeout_preparation: bool = False,
        fail_import_call: int | None = None,
        fail_create_call: int | None = None,
        timeout_health: bool = False,
        health_statuses: tuple[int, ...] = (0,),
        health_outputs: tuple[str, ...] = ("",),
        container_observations: tuple[ContainerObservation, ...] = (),
        immutable_stat_output: str = "",
        pid1: str = "systemd",
        inactive_systemd_units: tuple[str, ...] = (),
        observed_writable_mounts: tuple[str, ...] | None = None,
        unreachable_manager_queries: int = 0,
    ) -> None:
        self.fail_health = fail_health
        self.fail_remove = fail_remove
        self.effective_capabilities = effective_capabilities
        self.bounding_capabilities = bounding_capabilities
        self.write_preparation_outputs = write_preparation_outputs
        self.main_exit_status = main_exit_status
        self.timeout_preparation = timeout_preparation
        self.fail_import_call = fail_import_call
        self.fail_create_call = fail_create_call
        self.timeout_health = timeout_health
        self.health_statuses = health_statuses
        self.health_outputs = health_outputs
        self.container_observations = list(container_observations)
        self.immutable_stat_output = immutable_stat_output
        self.pid1 = pid1
        self.inactive_systemd_units = frozenset(inactive_systemd_units)
        self.unreachable_manager_queries = unreachable_manager_queries
        self.observed_writable_mounts = observed_writable_mounts
        self.removals = 0
        self.removed_names: list[str] = []
        self.import_calls = 0
        self.created: list[dict[str, Any]] = []
        self.runtimes: dict[str, Any] = {}
        self.saw_private_input = False
        self.health_calls = 0
        self.health_timeouts: list[float] = []
        self.inspect_timeouts: list[float] = []
        self.signals = 0
        self.signal_names: list[str] = []
        self.systemd_commands: list[tuple[str, ...]] = []
        self.manager_queries: list[tuple[str, ...]] = []

    def import_layout(self, **values: Any) -> ImportObservation:
        self.import_calls += 1
        if self.import_calls == self.fail_import_call:
            raise OperationalError("injected import boundary failure")
        return ImportObservation(str(values["image_name"]), values["expected_digest"])

    def create_container(self, **values: Any) -> ContainerObservation:
        self.created.append(values)
        name = str(values["name"])
        if len(self.created) == self.fail_create_call:
            raise OperationalError("injected create boundary failure")
        self.runtimes[name] = values["runtime"]
        entrypoint = values.get("entrypoint", ())
        if entrypoint and self.write_preparation_outputs:
            for mount in values.get("mounts", ()):
                if mount.read_only:
                    if mount.source.name == "private-key":
                        self.saw_private_input = (mount.source / "payload").read_text(
                            encoding="utf-8"
                        ) == "private-value"
                    continue
                output = mount.source / "payload"
                output.write_text(
                    "private-value"
                    if mount.source.name == "private-key"
                    else "generated-result",
                    encoding="utf-8",
                )
                output.chmod(0o600)
        return ContainerObservation(name, "container-id", "running", 100, None)

    def inspect_controls(self, **values: Any) -> RuntimeControlObservation:
        runtime = self.runtimes.get(str(values["name"]))
        writable_mounts = (
            self.observed_writable_mounts
            if self.observed_writable_mounts is not None
            else ()
            if runtime is None
            else tuple(runtime.writable_mounts)
        )
        return RuntimeControlObservation(
            user="10001" if runtime is None else str(runtime.user),
            read_only=True,
            writable_mounts=writable_mounts,
            memory_bytes=512 * 1024 * 1024,
            nano_cpus=1_000_000_000,
            pids_limit=128,
            nofile_soft=1024,
            nofile_hard=1024,
            cap_add=(),
            cap_drop=("CHOWN", "SETUID"),
            bounding_capabilities=()
            if str(values["name"]).endswith("-restrictive")
            else self.bounding_capabilities,
            effective_capabilities=()
            if str(values["name"]).endswith("-restrictive")
            else self.effective_capabilities,
            security_options=("no-new-privileges",),
            stop_signal=(
                "SIGTERM"
                if runtime is None or runtime.systemd is None
                else SYSTEMD_STOP_SIGNAL
            ),
        )

    def inspect_container(self, **values: Any) -> ContainerObservation:
        self.inspect_timeouts.append(float(values["timeout_seconds"]))
        if self.container_observations:
            return self.container_observations.pop(0)
        return ContainerObservation(
            str(values["name"]), "container-id", "running", 100, None
        )

    def exec(self, **values: Any) -> str:
        return self.immutable_stat_output

    def inspect_pid1(self, **values: Any) -> str:
        del values
        return self.pid1

    def exec_observe(self, **values: Any) -> ExecObservation:
        command = tuple(values["command"])
        if command[:2] == ("systemctl", "show"):
            self.systemd_commands.append(command)
            if len(self.manager_queries) < self.unreachable_manager_queries:
                self.manager_queries.append(command)
                return ExecObservation(
                    1, "", "Failed to connect to bus: No such file or directory\n"
                )
            self.manager_queries.append(command)
            return ExecObservation(0, "259\n", "")
        if command[:2] == ("systemctl", "is-active"):
            self.systemd_commands.append(command)
            status = 3 if command[-1] in self.inactive_systemd_units else 0
            return ExecObservation(status, "", "")
        if self.fail_health:
            raise OperationalError("injected health failure")
        if self.timeout_health:
            raise CommandTimeoutError(
                "injected health command timeout",
                stdout="initializing\n",
                stderr="",
            )
        index = min(self.health_calls, len(self.health_statuses) - 1)
        output_index = min(self.health_calls, len(self.health_outputs) - 1)
        self.health_calls += 1
        self.health_timeouts.append(float(values["timeout_seconds"]))
        return ExecObservation(
            self.health_statuses[index], self.health_outputs[output_index], ""
        )

    def signal(self, **values: Any) -> None:
        self.signals += 1
        self.signal_names.append(str(values["signal_name"]))
        return None

    def wait(self, **values: Any) -> int:
        if self.timeout_preparation and "-prepare-" in str(values["name"]):
            raise CommandTimeoutError("injected preparation timeout")
        return 0 if "-prepare-" in str(values["name"]) else self.main_exit_status

    def remove(self, **values: Any) -> None:
        self.removals += 1
        self.removed_names.append(str(values["name"]))
        if self.fail_remove:
            raise OperationalError("injected removal failure")
        return None

    def remove_storage(self, **values: Any) -> None:
        return None


class FakeReadinessTiming:
    def __init__(self, *, interval_seconds: float = 0.25) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []
        self.value = ReadinessTiming(
            monotonic=self.monotonic,
            sleep=self.sleep,
            interval_seconds=interval_seconds,
        )

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class Scanner:
    def __init__(self) -> None:
        self.identities: list[Any] = []

    def scan_filesystem(self, **values: Any) -> ScanObservation:
        self.identities.append(values.get("identity"))
        return self._write(values["report_path"], {"Results": []})

    def scan_layout(self, **values: Any) -> ScanObservation:
        self.identities.append(values.get("identity"))
        return self._write(values["report_path"], {"Results": []})

    def generate_spdx(self, **values: Any) -> ScanObservation:
        self.identities.append(values.get("identity"))
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


class CapturingRunner:
    def __init__(self) -> None:
        self.requests: list[CommandRequest] = []
        self.manifests: list[dict[str, object]] = []

    def run(self, request: CommandRequest) -> ProcessResult:
        self.requests.append(request)
        manifest_path = Path(request.environment["CC_TEST_INPUT_MANIFEST"])
        self.manifests.append(json.loads(manifest_path.read_text(encoding="utf-8")))
        return ProcessResult(
            argv=request.argv,
            returncode=0,
            stdout="hook passed",
            stderr="",
            duration_seconds=0.01,
            attempts=1,
            stdout_truncated=False,
            stderr_truncated=False,
        )


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
            "configurationDigest": sha256_bytes(config.raw_bytes),
            "sourceTreeDigest": source_tree_digest(repository),
            "image": "app",
            "version": "1.2.3",
        },
        id_factory=IdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    digest = "sha256:" + "d" * 64
    return QualificationInputs(
        repository=config,
        image=config.release_image("app"),
        workspace=workspace,
        source=SourceIdentity(
            "https://foundata.com/en/projects/example/#source", "b" * 40
        ),
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


def configured_hook_runner(
    value: QualificationInputs, runner: CapturingRunner
) -> HookRunner:
    return HookRunner(
        runner=runner,
        environment={"PATH": "/usr/bin"},
        source_root=value.repository.path.parent,
        log_directory=value.workspace.root / "logs",
    )


def configure_test_inputs(
    root: Path, *, profile: str = "service", expected_exit_status: int = 0
) -> None:
    fixture = root / "fixture"
    fixture.mkdir()
    (fixture / "input.txt").write_text("fixture-value\n", encoding="utf-8")
    scripts = root / "scripts"
    scripts.mkdir()
    hook = scripts / "hook"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hook.chmod(0o755)
    path = root / "conclear.toml"
    content = (
        path.read_text(encoding="utf-8")
        .replace(
            "[images.release]",
            """[images.test]
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
command = ["/generator", "keygen"]
mounts = [{ name = "private-key", target = "/output", read_only = false }]

[[images.test.preparations]]
name = "generate"
image = "generator"
command = ["/generator", "generate"]
environment = { GENERATOR_MODE = "compatibility" }
mounts = [
  { name = "source", target = "/input" },
  { name = "private-key", target = "/key" },
  { name = "result", target = "/output", read_only = false },
]

[images.test.launch]
arguments = ["serve", "--fixture", "/input"]
environment = { SERVICE_SELECTOR = "test" }
expected_exit_status = EXPECTED_EXIT_STATUS
mounts = [{ name = "result", target = "/input" }]

[images.release]""",
        )
        .replace('profile = "service"', f'profile = "{profile}"', 1)
    )
    content = content.replace("EXPECTED_EXIT_STATUS", str(expected_exit_status))
    content = content.replace(
        "[[images.pins]]",
        """[[images.hooks]]
name = "compatibility"
command = ["scripts/hook"]

[[images.pins]]""",
    )
    content += """

[[images]]
id = "generator"
repository = "quay.io/example/generator"
platforms = ["linux/amd64"]

[images.release]
version_tags = ["{version}"]
moving_tags = ["stable"]

[images.runtime]
profile = "one-shot"
user = 10001
writable_mounts = ["/output"]
memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
"""
    path.write_text(content, encoding="utf-8")


def closure_preflight(
    value: QualificationInputs,
    *,
    checked_at: datetime = datetime(2026, 1, 1, tzinfo=UTC),
) -> ClosurePreflight:
    def preflight(image: ImageConfig) -> ImagePreflight:
        observations: list[PinObservation] = []
        for pin in image.pins:
            assert pin.reference.digest is not None
            observations.append(
                PinObservation(
                    reference=pin.reference,
                    pinned_digest=pin.reference.digest,
                    observed_digest=pin.reference.digest,
                    checked_at=checked_at,
                    divergence_since=None,
                    history_initialized=True,
                    findings=(),
                )
            )
        return ImagePreflight(image, (), tuple(observations))

    return ClosurePreflight(
        primary=preflight(value.image),
        dependencies=tuple(
            preflight(item)
            for item in value.repository.test_dependencies(value.image.image_id)
        ),
    )


def configure_systemd_runtime(root: Path) -> None:
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace('profile = "service"\nuser = 10001', 'profile = "systemd"\nuser = 0')
        .replace(
            'health_command = ["/app", "health"]',
            """health_command = ["/app", "health"]

[images.runtime.root_requirement]
rationale = "Systemd is the image lifecycle manager."
owner = "platform@example.com"
review_trigger = "Review when the image lifecycle changes."

[images.runtime.systemd]
required_units = ["multi-user.target", "sshd.service"]
""",
        ),
        encoding="utf-8",
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
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    assert result.verdict is Verdict.ACCEPTED
    assert result.record_digest == sha256_file(result.record_path)
    record = json.loads(result.record_path.read_text(encoding="utf-8"))
    validate_record(record)
    assert record["payload"]["pinObservations"] == [
        closure_preflight(value).primary.pin_observations[0].to_dict()
    ]
    transport = qualification_transport(value.workspace, value.image, value.platform)
    assert transport.payload_paths[0] == (
        value.workspace.root / "reports" / "app" / "linux-amd64" / "tests.json"
    )
    assert [path.name for path in transport.payload_paths[2:]] == [
        "source-scan.json",
        "containerfile-scan.json",
        "image-scan.json",
    ]


def _register_arm64_handler(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "qemu-aarch64").write_text(
        "enabled\ninterpreter /usr/bin/qemu-aarch64-static\nflags: F\n",
        encoding="ascii",
    )
    return root


def test_build_accepts_explicit_v8_for_implicit_arm64(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = replace(
        inputs(repository_factory(), tmp_path),
        platform=Platform.parse("linux/arm64"),
        binfmt_root=_register_arm64_handler(tmp_path / "binfmt"),
    )

    evidence = build_platform(value, Builder(observed_variant="v8"))

    assert evidence.observation.graph.platforms == (Platform.parse("linux/arm64/v8"),)


def test_foreign_platform_without_binfmt_handler_is_not_qualified(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = replace(
        inputs(repository_factory(), tmp_path),
        platform=Platform.parse("linux/arm64"),
        binfmt_root=tmp_path / "binfmt-without-handler",
    )
    database_path = tmp_path / "database"
    database_path.mkdir()

    class UnexpectedBuilder:
        def build(self, **values: Any) -> BuildObservation:
            raise AssertionError("foreign platform was built without a handler")

    with pytest.raises(OperationalError, match="No enabled binfmt handler") as caught:
        qualify_platform(
            value,
            builder=UnexpectedBuilder(),
            runtime=Runtime(),
            hooks=hook_runner(value),
            scanner=Scanner(),
            database=DatabaseObservation(
                database_path, "sha256:" + "e" * 64, DATABASE_METADATA
            ),
            preflight=closure_preflight(value),
            now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
            record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        )

    assert caught.value.exit_status == 1
    assert "not qualified" in str(caught.value)
    assert not list((value.workspace.root / "records").glob("platform-qualification-*"))
    with pytest.raises(OperationalError, match="No enabled binfmt handler"):
        run_platform_tests(
            value,
            build_platform(
                replace(value, platform=Platform.parse("linux/amd64")), Builder()
            ),
            Runtime(),
            hook_runner(value),
        )


def test_foreign_build_and_test_record_the_same_qemu_execution_mode(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = replace(
        inputs(repository_factory(), tmp_path),
        platform=Platform.parse("linux/arm64"),
        binfmt_root=_register_arm64_handler(tmp_path / "binfmt"),
    )
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
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    payload = json.loads(result.record_path.read_text(encoding="utf-8"))["payload"]
    expected = {
        "targetPlatform": "linux/arm64",
        "hostArchitecture": "x86_64",
        "executionArchitecture": "arm64",
        "mechanism": "qemu-user",
    }
    assert payload["buildExecution"] == expected
    assert payload["testExecution"] == expected


def test_emulated_qualification_is_accepted_without_justification(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'platforms = ["linux/amd64"]', 'platforms = ["linux/amd64", "linux/arm64"]'
        ),
        encoding="utf-8",
    )
    value = replace(
        inputs(root, tmp_path),
        platform=Platform.parse("linux/arm64"),
        binfmt_root=_register_arm64_handler(tmp_path / "binfmt"),
    )
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
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    assert result.verdict is Verdict.ACCEPTED
    assert result.findings == ()
    payload = json.loads(result.record_path.read_text(encoding="utf-8"))["payload"]
    assert payload["buildExecution"]["mechanism"] == "qemu-user"
    assert payload["testExecution"]["mechanism"] == "qemu-user"
    assert not any("reason" in key.lower() for key in payload)


def test_configured_native_platform_rejects_emulated_runtime_tests(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'platforms = ["linux/amd64"]',
            'platforms = ["linux/amd64", "linux/arm64"]\n'
            'native_test_platforms = ["linux/amd64", "linux/arm64"]',
        ),
        encoding="utf-8",
    )
    value = replace(
        inputs(root, tmp_path),
        platform=Platform.parse("linux/arm64"),
        binfmt_root=_register_arm64_handler(tmp_path / "binfmt"),
    )
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
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    assert result.verdict is Verdict.REJECTED
    assert [
        (finding.check_id, finding.severity, finding.message)
        for finding in result.findings
    ] == [("CC0403", "error", "Platform linux/arm64 requires native runtime testing")]


def test_qualification_payload_tampering_is_a_catalogued_rule_rejection(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    database_path = tmp_path / "database"
    database_path.mkdir()
    qualify_platform(
        value,
        builder=Builder(),
        runtime=Runtime(),
        hooks=hook_runner(value),
        scanner=Scanner(),
        database=DatabaseObservation(
            database_path, "sha256:" + "e" * 64, DATABASE_METADATA
        ),
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )
    sbom_path = value.workspace.root / "exports" / "sbom" / "linux-amd64.spdx.json"
    sbom_path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(RuleRejectionError) as caught:
        qualification_transport(value.workspace, value.image, value.platform)

    assert caught.value.code == "CC0703"
    assert caught.value.exit_status == 2


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
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    assert result.verdict is Verdict.REJECTED
    assert result.findings[0].check_id == "CC0113"
    record = json.loads(result.record_path.read_text(encoding="utf-8"))
    assert record["payload"]["findings"][0]["checkId"] == "CC0113"


@pytest.mark.parametrize("fail_remove", [False, True])
def test_runtime_failure_attempts_cleanup_without_replacing_original_error(
    repository_factory: Any,
    tmp_path: Path,
    fail_remove: bool,
) -> None:
    value = inputs(repository_factory(), tmp_path)
    build = build_platform(value, Builder())
    runtime = Runtime(fail_health=True, fail_remove=fail_remove)

    with pytest.raises(OperationalError, match="injected health failure"):
        run_platform_tests(value, build, runtime, hook_runner(value))

    assert runtime.removals == 1
    status = next(
        entry.status
        for entry in value.workspace.journal.entries()
        if entry.resource_id == "podman-app-linux-amd64"
    )
    assert status is (ResourceStatus.FAILED if fail_remove else ResourceStatus.REMOVED)


def test_health_command_timeout_remains_operational_and_cleans_runtime(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    runtime = Runtime(timeout_health=True)

    with pytest.raises(CommandTimeoutError, match="injected health command timeout"):
        run_platform_tests(
            value,
            build_platform(value, Builder()),
            runtime,
            hook_runner(value),
        )

    assert runtime.health_calls == 0
    assert runtime.removals == 1
    assert (
        next(
            item.status
            for item in value.workspace.journal.entries()
            if item.resource_id == "podman-app-linux-amd64"
        )
        is ResourceStatus.REMOVED
    )


def test_service_health_succeeds_on_first_attempt(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    runtime = Runtime(health_outputs=("ready\n",))

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        hook_runner(value),
    )

    health = next(item for item in evidence.test_results if item["name"] == "health")
    assert isinstance(health["elapsedSeconds"], float)
    assert health["elapsedSeconds"] >= 0
    assert health == {
        "name": "health",
        "status": "passed",
        "outcome": "ready",
        "attempts": 1,
        "elapsedSeconds": health["elapsedSeconds"],
        "timeoutSeconds": 60,
        "containerStatus": "running",
        "containerExitStatus": None,
        "outputDigest": sha256_bytes(
            canonical_json_bytes({"stdout": "ready\n", "stderr": ""})
        ),
        "exitStatus": 0,
    }
    assert runtime.health_timeouts[0] <= 60
    assert runtime.removals == 1


def test_service_health_retries_with_one_remaining_deadline(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    value = replace(
        value,
        image=replace(
            value.image,
            runtime=replace(value.image.runtime, startup_timeout_seconds=1),
        ),
    )
    runtime = Runtime(
        health_statuses=(1, 1, 0),
        health_outputs=("starting-1\n", "starting-2\n", "ready\n"),
    )
    timing = FakeReadinessTiming()

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        hook_runner(value),
        _readiness_timing=timing.value,
    )

    health = next(item for item in evidence.test_results if item["name"] == "health")
    assert health["status"] == "passed"
    assert health["outcome"] == "ready"
    assert health["attempts"] == 3
    assert health["elapsedSeconds"] == 0.5
    assert health["exitStatus"] == 0
    assert health["outputDigest"] == sha256_bytes(
        canonical_json_bytes({"stdout": "ready\n", "stderr": ""})
    )
    assert runtime.health_timeouts == [1.0, 0.75, 0.5]
    assert runtime.inspect_timeouts == [0.75, 0.5]
    assert timing.sleeps == [0.25, 0.25]
    assert runtime.removals == 1


def test_service_health_timeout_rejects_and_cleans_runtime(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    value = replace(
        value,
        image=replace(
            value.image,
            runtime=replace(value.image.runtime, startup_timeout_seconds=1),
        ),
    )
    runtime = Runtime(health_statuses=(4,), health_outputs=("still starting\n",))
    timing = FakeReadinessTiming()

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        hook_runner(value),
        _readiness_timing=timing.value,
    )

    health = next(item for item in evidence.test_results if item["name"] == "health")
    assert health["status"] == "failed"
    assert health["outcome"] == "timeout"
    assert health["attempts"] == 4
    assert health["elapsedSeconds"] == 1.0
    assert health["timeoutSeconds"] == 1
    assert health["containerStatus"] == "running"
    assert health["exitStatus"] == 4
    assert health["outputDigest"] == sha256_bytes(
        canonical_json_bytes({"stdout": "still starting\n", "stderr": ""})
    )
    assert [finding.check_id for finding in evidence.findings] == ["CC0403"]
    assert evidence.findings[0].message == (
        "Service health did not succeed within 1s after 4 attempts"
    )
    assert runtime.health_timeouts == [1.0, 0.75, 0.5, 0.25]
    assert runtime.inspect_timeouts == [0.75, 0.5, 0.25, 5.0]
    assert runtime.signals == 1
    assert runtime.removals == 1
    assert (
        next(
            item.status
            for item in value.workspace.journal.entries()
            if item.resource_id == "podman-app-linux-amd64"
        )
        is ResourceStatus.REMOVED
    )


def test_service_exit_during_readiness_rejects_without_signal(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    stopped = ContainerObservation("test", "container-id", "exited", 0, 23)
    runtime = Runtime(health_statuses=(1,), container_observations=(stopped,))
    timing = FakeReadinessTiming()

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        hook_runner(value),
        _readiness_timing=timing.value,
    )

    health = next(item for item in evidence.test_results if item["name"] == "health")
    assert health["outcome"] == "exited"
    assert health["attempts"] == 1
    assert health["containerStatus"] == "exited"
    assert health["containerExitStatus"] == 23
    assert evidence.findings[0].message == (
        "Service exited with status 23 before becoming ready"
    )
    assert runtime.signals == 0
    assert runtime.removals == 1


def test_scans_are_named_by_the_platform_subject_not_the_host(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    database_path = tmp_path / "database"
    database_path.mkdir()
    scanner = Scanner()

    result = qualify_platform(
        value,
        builder=Builder(),
        runtime=Runtime(),
        hooks=hook_runner(value),
        scanner=scanner,
        database=DatabaseObservation(
            database_path, "sha256:" + "e" * 64, DATABASE_METADATA
        ),
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    assert len(scanner.identities) == 4
    identity = scanner.identities[0]
    assert all(item == identity for item in scanner.identities)
    record = json.loads(result.record_path.read_text(encoding="utf-8"))
    assert identity.subject == str(
        value.image.repository.with_digest(Digest(record["payload"]["manifestDigest"]))
    )
    assert identity.workspace_root == value.workspace.root
    assert identity.artifact_path == result.layout_path
    assert str(tmp_path) not in identity.subject


def test_service_without_health_command_does_not_poll(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    value = replace(
        value,
        image=replace(
            value.image,
            runtime=replace(value.image.runtime, health_command=()),
        ),
    )
    runtime = Runtime()

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        hook_runner(value),
    )

    assert runtime.health_calls == 0
    assert all(item["name"] != "health" for item in evidence.test_results)
    assert runtime.signals == 1


def test_systemd_profile_verifies_pid1_units_and_configured_shutdown(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_systemd_runtime(root)
    value = inputs(root, tmp_path)
    runtime = Runtime()

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        hook_runner(value),
    )

    results = {str(item["name"]): item for item in evidence.test_results}
    assert results["systemdPid1"]["status"] == "passed"
    assert results["systemdManager"]["status"] == "passed"
    assert results["systemdUnit:multi-user.target"]["status"] == "passed"
    assert results["systemdUnit:sshd.service"]["status"] == "passed"
    assert results["health"]["status"] == "passed"
    assert evidence.findings == ()
    assert runtime.signal_names == ["SIGRTMIN+3"]
    assert runtime.systemd_commands == [
        ("systemctl", "show", "--property=Version", "--value"),
        ("systemctl", "is-active", "--quiet", "multi-user.target"),
        ("systemctl", "is-active", "--quiet", "sshd.service"),
    ]


def test_systemd_manager_query_is_retried_until_systemd_answers(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_systemd_runtime(root)
    value = inputs(root, tmp_path)
    runtime = Runtime(unreachable_manager_queries=2)
    timing = FakeReadinessTiming()

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        hook_runner(value),
        _readiness_timing=timing.value,
    )

    results = {str(item["name"]): item for item in evidence.test_results}
    assert results["systemdManager"]["status"] == "passed"
    assert results["systemdUnit:multi-user.target"]["status"] == "passed"
    assert evidence.findings == ()
    assert len(runtime.manager_queries) == 3
    assert timing.sleeps


def test_systemd_manager_query_that_never_answers_is_rejected(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_systemd_runtime(root)
    value = inputs(root, tmp_path)
    value = replace(
        value,
        image=replace(
            value.image,
            runtime=replace(value.image.runtime, startup_timeout_seconds=1),
        ),
    )
    runtime = Runtime(unreachable_manager_queries=1000)
    timing = FakeReadinessTiming()

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        hook_runner(value),
        _readiness_timing=timing.value,
    )

    results = {str(item["name"]): item for item in evidence.test_results}
    assert results["systemdManager"]["status"] == "failed"
    assert {finding.check_id for finding in evidence.findings} == {"CC0403"}
    assert evidence.findings[0].message == "Systemd manager is not operational"
    assert all(
        str(item["name"]) != "systemdUnit:multi-user.target"
        for item in evidence.test_results
    )


def test_systemd_qualification_records_review_and_lifecycle_contract(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_systemd_runtime(root)
    value = inputs(root, tmp_path)
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
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    record = json.loads(result.record_path.read_text(encoding="utf-8"))
    validate_record(record)
    constraints = record["payload"]["runtimeConstraints"]
    assert constraints["user"] == 0
    assert constraints["rootRequirement"]["owner"] == "platform@example.com"
    assert constraints["systemd"] == {
        "requiredUnits": ["multi-user.target", "sshd.service"],
        "stopSignal": "SIGRTMIN+3",
    }
    assert constraints["writableMounts"] == [
        "/run",
        "/run/lock",
        "/tmp",
        "/var/log/journal",
    ]


def test_systemd_profile_rejects_non_systemd_pid1(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_systemd_runtime(root)
    value = inputs(root, tmp_path)
    runtime = Runtime(pid1="bash")

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        hook_runner(value),
    )

    result = next(
        item for item in evidence.test_results if item["name"] == "systemdPid1"
    )
    assert result["status"] == "failed"
    assert any("PID 1 is not systemd" in item.message for item in evidence.findings)
    assert runtime.systemd_commands == []
    assert runtime.signal_names == ["SIGRTMIN+3"]


def test_systemd_profile_rejects_unit_that_misses_shared_startup_deadline(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_systemd_runtime(root)
    value = inputs(root, tmp_path)
    value = replace(
        value,
        image=replace(
            value.image,
            runtime=replace(value.image.runtime, startup_timeout_seconds=1),
        ),
    )
    runtime = Runtime(inactive_systemd_units=("multi-user.target",))
    timing = FakeReadinessTiming()

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        hook_runner(value),
        _readiness_timing=timing.value,
    )

    unit = next(
        item
        for item in evidence.test_results
        if item["name"] == "systemdUnit:multi-user.target"
    )
    assert unit["status"] == "failed"
    assert unit["outcome"] == "timeout"
    assert unit["elapsedSeconds"] == 1.0
    assert all(
        item["name"] != "systemdUnit:sshd.service" for item in evidence.test_results
    )
    assert any("multi-user.target" in item.message for item in evidence.findings)


def test_runtime_rejects_observed_effective_capabilities(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    build = build_platform(value, Builder())

    evidence = run_platform_tests(
        value,
        build,
        Runtime(effective_capabilities=("CAP_NET_RAW",)),
        hook_runner(value),
    )

    assert any(
        finding.check_id == "CC0401" and "capability" in finding.message
        for finding in evidence.findings
    )


def test_runtime_reports_unexpected_image_volume_destination(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    build = build_platform(value, Builder())

    evidence = run_platform_tests(
        value,
        build,
        Runtime(observed_writable_mounts=("/var/lib/journal",)),
        hook_runner(value),
    )

    writable = [
        finding
        for finding in evidence.findings
        if finding.check_id == "CC0401" and "writable mounts" in finding.message
    ]
    assert len(writable) == 1
    assert writable[0].message.endswith("(unexpected: /var/lib/journal; missing: none)")


def _capability_findings(evidence: Any) -> set[str]:
    return {
        finding.message
        for finding in evidence.findings
        if finding.check_id == "CC0401" and "capabilit" in finding.message
    }


def test_declared_capabilities_are_judged_by_the_bounding_set(
    repository_factory: Any, tmp_path: Path
) -> None:
    repository = repository_factory()
    configuration = repository / "conclear.toml"
    configuration.write_text(
        configuration.read_text(encoding="utf-8").replace(
            "[images.runtime]\n",
            '[images.runtime]\ncapabilities = ["CAP_NET_BIND_SERVICE"]\n',
            1,
        ),
        encoding="utf-8",
    )
    value = inputs(repository, tmp_path)
    build = build_platform(value, Builder())

    # Podman reports an added default-set capability with an empty CapAdd, so a
    # correct grant is recognised from the bounding and effective sets alone.
    granted = run_platform_tests(
        value,
        build,
        Runtime(
            bounding_capabilities=("CAP_NET_BIND_SERVICE",),
            effective_capabilities=("CAP_NET_BIND_SERVICE",),
        ),
        hook_runner(value),
    )
    assert _capability_findings(granted) == set()

    ungranted = run_platform_tests(value, build, Runtime(), hook_runner(value))
    assert _capability_findings(ungranted)

    excessive = run_platform_tests(
        value,
        build,
        Runtime(
            bounding_capabilities=("CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE"),
            effective_capabilities=("CAP_NET_BIND_SERVICE",),
        ),
        hook_runner(value),
    )
    assert _capability_findings(excessive)


@pytest.mark.parametrize("mode", ["755", "644", "555", "444"])
def test_immutable_path_allows_root_owned_modes_without_group_or_other_write(
    repository_factory: Any, tmp_path: Path, mode: str
) -> None:
    value = inputs(repository_factory(), tmp_path)
    value = replace(
        value,
        image=replace(
            value.image,
            runtime=replace(value.image.runtime, immutable_paths=("/app",)),
        ),
    )

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        Runtime(immutable_stat_output=f"0:{mode}\n"),
        hook_runner(value),
    )

    assert not evidence.findings


@pytest.mark.parametrize(
    "stat_output",
    [
        pytest.param("10001:555\n", id="runtime-owned"),
        pytest.param("0:775\n", id="group-writable"),
        pytest.param("0:757\n", id="world-writable"),
    ],
)
def test_immutable_path_rejects_non_root_owner_and_group_or_other_write(
    repository_factory: Any, tmp_path: Path, stat_output: str
) -> None:
    value = inputs(repository_factory(), tmp_path)
    value = replace(
        value,
        image=replace(
            value.image,
            runtime=replace(value.image.runtime, immutable_paths=("/app",)),
        ),
    )

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        Runtime(immutable_stat_output=stat_output),
        hook_runner(value),
    )

    assert [
        (finding.check_id, finding.message, finding.location)
        for finding in evidence.findings
    ] == [
        (
            "CC0404",
            "Immutable runtime path is not root-owned or has a group/other write bit",
            "/app",
        )
    ]


def test_qualification_rejects_stale_pin_resolution(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    database_path = tmp_path / "database"
    database_path.mkdir()
    checked_at = datetime(2026, 1, 1, tzinfo=UTC)

    result = qualify_platform(
        value,
        builder=Builder(),
        runtime=Runtime(),
        hooks=hook_runner(value),
        scanner=Scanner(),
        database=DatabaseObservation(
            database_path, "sha256:" + "e" * 64, DATABASE_METADATA
        ),
        preflight=closure_preflight(value, checked_at=checked_at),
        now=checked_at + timedelta(hours=25),
        record_clock=lambda: checked_at + timedelta(hours=25),
        qualification_started_at=checked_at + timedelta(hours=23),
    )

    assert result.verdict is Verdict.REJECTED
    assert any(item.check_id == "CC0204" for item in result.findings)


def test_service_uses_exact_dependency_preparation_and_cleans_secrets(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    build = build_platform(value, Builder())
    dependencies = build_test_dependencies(value, Builder())
    runtime = Runtime()
    runner = CapturingRunner()

    evidence = run_platform_tests(
        value,
        build,
        runtime,
        configured_hook_runner(value, runner),
        dependencies=dependencies,
    )

    assert not evidence.findings
    assert [call.get("entrypoint", ()) for call in runtime.created] == [
        ("/generator", "keygen"),
        ("/generator", "generate"),
        (),
    ]
    assert runtime.created[-1]["arguments"] == (
        "serve",
        "--fixture",
        "/input",
    )
    assert runtime.created[-1]["environment"] == (("SERVICE_SELECTOR", "test"),)
    assert runtime.saw_private_input
    assert len(runner.requests) == 1
    manifest_text = json.dumps(runner.manifests[0], sort_keys=True)
    assert "private-key" not in manifest_text
    assert "private-value" not in manifest_text
    manifest_dependencies = runner.manifests[0]["dependencies"]
    assert isinstance(manifest_dependencies, list)
    assert manifest_dependencies == [
        {
            "imageId": "generator",
            "layout": str(dependencies[0].build.observation.layout_path),
            "digest": str(dependencies[0].build.observation.graph.digest),
        }
    ]
    assert not (
        value.workspace.root / "reports" / "app" / "linux-amd64" / "test-inputs"
    ).exists()
    output_observations = evidence.test_inputs["outputs"]
    assert isinstance(output_observations, list)
    secret_observation = next(
        item
        for item in output_observations
        if isinstance(item, dict) and item.get("secret") is True
    )
    assert "digest" not in secret_observation
    report = (
        value.workspace.root / "reports" / "app" / "linux-amd64" / "tests.json"
    ).read_text(encoding="utf-8")
    assert "private-value" not in report
    assert str(tmp_path) not in report


def test_qualification_record_binds_test_inputs_and_sibling_result(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    database_path = tmp_path / "database"
    database_path.mkdir()

    result = qualify_platform(
        value,
        builder=Builder(),
        runtime=Runtime(),
        hooks=configured_hook_runner(value, CapturingRunner()),
        scanner=Scanner(),
        database=DatabaseObservation(
            database_path, "sha256:" + "e" * 64, DATABASE_METADATA
        ),
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    record = json.loads(result.record_path.read_text(encoding="utf-8"))
    validate_record(record)
    assert record["schemaVersion"] == 1
    payload = record["payload"]
    dependency = payload["testImageDependencies"][0]
    assert dependency["imageId"] == "generator"
    assert dependency["sourceRevision"] == value.source.revision
    assert dependency["testResultDigest"] in payload["payloadDigests"]
    assert dependency["containerfileDigest"] == payload["containerfileDigest"]
    assert dependency["contextDigest"] == payload["contextDigest"]
    assert dependency["buildArguments"]["IMAGE_REVISION"] == value.source.revision
    assert dependency["externalImages"] == []
    assert dependency["pinObservations"] == []
    assert dependency["effectiveLimits"] == payload["effectiveLimits"]
    secret = next(item for item in payload["testInputs"]["outputs"] if item["secret"])
    assert "digest" not in secret


def test_one_shot_launch_uses_arguments_and_expected_exit_contract(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root, profile="one-shot", expected_exit_status=7)
    value = inputs(root, tmp_path)
    runtime = Runtime(main_exit_status=7)

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        runtime,
        configured_hook_runner(value, CapturingRunner()),
        dependencies=build_test_dependencies(value, Builder()),
    )

    assert not evidence.findings
    assert evidence.test_results[-2] == {
        "name": "oneShotExit",
        "status": "passed",
        "exitStatus": 7,
    }
    assert runtime.created[-1].get("entrypoint", ()) == ()
    assert runtime.created[-1]["arguments"][0] == "serve"


def test_launch_written_output_needs_no_preparation_and_may_stay_empty(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace("user = 10001\n", 'user = 10001\nwritable_mounts = ["/state"]\n')
        .replace(
            "[images.release]",
            """[[images.test.outputs]]
name = "state"

[images.test.launch]
mounts = [{ name = "state", target = "/state", read_only = false }]

[images.release]""",
        ),
        encoding="utf-8",
    )
    value = inputs(root, tmp_path)
    runtime = Runtime()

    evidence = run_platform_tests(
        value, build_platform(value, Builder()), runtime, hook_runner(value)
    )

    assert evidence.findings == ()
    assert [call.get("entrypoint", ()) for call in runtime.created] == [()]
    launch_mounts = runtime.created[0]["mounts"]
    assert [(mount.target, mount.read_only) for mount in launch_mounts] == [
        ("/state", False)
    ]
    outputs = evidence.test_inputs["outputs"]
    assert isinstance(outputs, list)
    assert [(item["name"], item["files"]) for item in outputs] == [("state", 0)]


def test_partial_preparation_rejects_before_repository_hook(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    runner = CapturingRunner()

    evidence = run_platform_tests(
        value,
        build_platform(value, Builder()),
        Runtime(write_preparation_outputs=False),
        configured_hook_runner(value, runner),
        dependencies=build_test_dependencies(value, Builder()),
    )

    assert any(
        finding.check_id == "CC0403" and "produced no files" in finding.message
        for finding in evidence.findings
    )
    assert not runner.requests


def test_preparation_timeout_preserves_failure_and_cleans_private_inputs(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    runner = CapturingRunner()

    with pytest.raises(CommandTimeoutError, match="injected preparation timeout"):
        run_platform_tests(
            value,
            build_platform(value, Builder()),
            Runtime(timeout_preparation=True),
            configured_hook_runner(value, runner),
            dependencies=build_test_dependencies(value, Builder()),
        )

    assert not runner.requests
    assert not (
        value.workspace.root / "reports" / "app" / "linux-amd64" / "test-inputs"
    ).exists()
    statuses = {
        item.resource_id: item.status for item in value.workspace.journal.entries()
    }
    assert statuses["podman-preparation-app-linux-amd64-1"] is ResourceStatus.REMOVED
    assert statuses["podman-app-linux-amd64"] is ResourceStatus.REMOVED
    assert statuses["test-inputs-app-linux-amd64"] is ResourceStatus.REMOVED


class RefusingBuilder:
    def build(self, **values: Any) -> BuildObservation:
        raise AssertionError("a build started without an accepted closure preflight")


def test_dependency_inputs_bind_the_same_run_facts_to_the_dependency(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    [generator] = value.repository.test_dependencies("app")

    bound = value.dependency_inputs(generator)

    assert type(bound) is BuildInputs
    assert bound.image is generator
    assert (bound.repository, bound.workspace, bound.source, bound.platform) == (
        value.repository,
        value.workspace,
        value.source,
        value.platform,
    )
    assert (bound.source_time, bound.version, bound.tools, bound.auth_file) == (
        value.source_time,
        value.version,
        value.tools,
        value.auth_file,
    )
    assert bound.host_architecture == value.host_architecture
    assert bound.binfmt_root == value.binfmt_root


def test_qualification_requires_a_preflight_covering_the_test_dependencies(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    database_path = tmp_path / "database"
    database_path.mkdir()
    complete = closure_preflight(value)

    with pytest.raises(OperationalError, match="test dependencies"):
        qualify_platform(
            value,
            builder=RefusingBuilder(),
            runtime=Runtime(),
            hooks=hook_runner(value),
            scanner=Scanner(),
            database=DatabaseObservation(
                database_path, "sha256:" + "e" * 64, DATABASE_METADATA
            ),
            preflight=ClosurePreflight(primary=complete.primary, dependencies=()),
            now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
            record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        )


def test_rejected_dependency_preflight_starts_no_build(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    database_path = tmp_path / "database"
    database_path.mkdir()
    complete = closure_preflight(value)
    rejected = replace(
        complete.dependencies[0],
        findings=(Finding("CC0203", "error", "Declared pin is not used: x"),),
    )

    with pytest.raises(OperationalError, match="rejected preflight"):
        qualify_platform(
            value,
            builder=RefusingBuilder(),
            runtime=Runtime(),
            hooks=hook_runner(value),
            scanner=Scanner(),
            database=DatabaseObservation(
                database_path, "sha256:" + "e" * 64, DATABASE_METADATA
            ),
            preflight=ClosurePreflight(
                primary=complete.primary, dependencies=(rejected,)
            ),
            now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
            record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        )
    assert not list((value.workspace.root / "records").glob("platform-qualification-*"))


def test_dependency_pins_are_evaluated_under_their_own_freshness_limit(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    reference = "quay.io/example/base:1@sha256:" + "a" * 64
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        + f"""
[[images.pins]]
reference = "{reference.split("@")[0]}"
tag_intent = "immutable-version"

[images.limits]
pin_freshness = "1h"
""",
        encoding="utf-8",
    )
    value = inputs(root, tmp_path)
    database_path = tmp_path / "database"
    database_path.mkdir()
    checked_at = datetime(2026, 1, 1, tzinfo=UTC)

    result = qualify_platform(
        value,
        builder=Builder(),
        runtime=Runtime(),
        hooks=configured_hook_runner(value, CapturingRunner()),
        scanner=Scanner(),
        database=DatabaseObservation(
            database_path, "sha256:" + "e" * 64, DATABASE_METADATA
        ),
        preflight=closure_preflight(value, checked_at=checked_at),
        now=checked_at + timedelta(hours=2),
        record_clock=lambda: checked_at + timedelta(hours=2),
    )

    assert result.verdict is Verdict.REJECTED
    stale = [item for item in result.findings if item.check_id == "CC0204"]
    assert [(item.location, item.image) for item in stale] == [(reference, "generator")]
    payload = json.loads(result.record_path.read_text(encoding="utf-8"))["payload"]
    assert payload["effectiveLimits"]["pinFreshnessSeconds"] == 86400
    dependency = payload["testImageDependencies"][0]
    assert dependency["imageId"] == "generator"
    assert dependency["effectiveLimits"]["pinFreshnessSeconds"] == 3600
    assert dependency["externalImages"] == [reference]
    assert dependency["pinObservations"][0]["reference"] == reference


def test_qualification_records_transitive_dependencies_dependency_first(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        + '\n[images.test]\ndependencies = ["tool"]\n'
        + _image_text("tool", releasable=False),
        encoding="utf-8",
    )
    value = inputs(root, tmp_path)
    database_path = tmp_path / "database"
    database_path.mkdir()

    result = qualify_platform(
        value,
        builder=Builder(),
        runtime=Runtime(),
        hooks=configured_hook_runner(value, CapturingRunner()),
        scanner=Scanner(),
        database=DatabaseObservation(
            database_path, "sha256:" + "e" * 64, DATABASE_METADATA
        ),
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
        record_clock=lambda: datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )

    assert result.verdict is Verdict.ACCEPTED
    record = json.loads(result.record_path.read_text(encoding="utf-8"))
    validate_record(record)
    payload = record["payload"]
    dependencies = payload["testImageDependencies"]
    assert [item["imageId"] for item in dependencies] == ["tool", "generator"]
    for item in dependencies:
        assert item["containerfileDigest"] == payload["containerfileDigest"]
        assert item["effectiveLimits"] == payload["effectiveLimits"]
        assert item["testResultDigest"] in payload["payloadDigests"]
    materials = dict(
        qualification_materials(payload, image_id="app", platform=value.platform)
    )
    assert {
        "conclear:test-image/tool/linux/amd64",
        "conclear:test-image/generator/linux/amd64",
        "conclear:containerfile/tool/linux/amd64",
        "conclear:context/generator/linux/amd64",
    } <= materials.keys()


def test_incomplete_dependency_build_set_fails_before_runtime_mutation(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    runtime = Runtime()

    with pytest.raises(OperationalError, match="do not match configuration"):
        run_platform_tests(
            value,
            build_platform(value, Builder()),
            runtime,
            configured_hook_runner(value, CapturingRunner()),
            dependencies=(),
        )

    assert not runtime.created


def test_dependency_revision_mismatch_fails_before_runtime_mutation(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    dependencies = build_test_dependencies(value, Builder())
    changed = (replace(dependencies[0], source_revision="f" * 40),)
    runtime = Runtime()

    with pytest.raises(OperationalError, match="source revision changed"):
        run_platform_tests(
            value,
            build_platform(value, Builder()),
            runtime,
            configured_hook_runner(value, CapturingRunner()),
            dependencies=changed,
        )

    assert not runtime.created


def test_dependency_platform_mismatch_fails_before_runtime_mutation(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    dependencies = build_test_dependencies(value, Builder())
    changed = (replace(dependencies[0], platform=Platform.parse("linux/arm64")),)
    runtime = Runtime()

    with pytest.raises(OperationalError, match="platform changed"):
        run_platform_tests(
            value,
            build_platform(value, Builder()),
            runtime,
            configured_hook_runner(value, CapturingRunner()),
            dependencies=changed,
        )

    assert not runtime.created


def test_dependency_recorded_digest_mismatch_fails_before_repository_hook(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    dependencies = build_test_dependencies(value, Builder())
    dependency = dependencies[0]
    changed_graph = replace(
        dependency.build.observation.graph,
        root=replace(
            dependency.build.observation.graph.root,
            digest=Digest("sha256:" + "f" * 64),
        ),
    )
    changed_observation = replace(dependency.build.observation, graph=changed_graph)
    changed = (
        replace(
            dependency, build=replace(dependency.build, observation=changed_observation)
        ),
    )
    runtime = Runtime()
    runner = CapturingRunner()

    with pytest.raises(OperationalError, match="layout changed after build"):
        run_platform_tests(
            value,
            build_platform(value, Builder()),
            runtime,
            configured_hook_runner(value, runner),
            dependencies=changed,
        )

    assert not runtime.created
    assert not runner.requests


def test_dependency_layout_tampering_fails_before_repository_hook(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    dependencies = build_test_dependencies(value, Builder())
    layout = dependencies[0].build.observation.layout_path
    manifest_digest = (
        dependencies[0].build.observation.graph.manifests[0].descriptor.digest
    )
    manifest_path = layout / "blobs" / "sha256" / manifest_digest.encoded
    manifest_path.write_bytes(manifest_path.read_bytes() + b"changed")
    runner = CapturingRunner()

    with pytest.raises(OperationalError):
        run_platform_tests(
            value,
            build_platform(value, Builder()),
            Runtime(),
            configured_hook_runner(value, runner),
            dependencies=dependencies,
        )

    assert not runner.requests


def test_preexisting_test_input_path_is_retained_on_failed_materialization(
    repository_factory: Any, tmp_path: Path
) -> None:
    value = inputs(repository_factory(), tmp_path)
    build = build_platform(value, Builder())
    path = value.workspace.root / "reports" / "app" / "linux-amd64" / "test-inputs"
    path.mkdir(parents=True)
    caller_file = path / "caller-owned"
    caller_file.write_text("keep", encoding="utf-8")

    with pytest.raises(OperationalError, match="Unable to create run-owned"):
        run_platform_tests(value, build, Runtime(), hook_runner(value))

    assert caller_file.read_text(encoding="utf-8") == "keep"
    entry = next(
        item
        for item in value.workspace.journal.entries()
        if item.resource_id == "test-inputs-app-linux-amd64"
    )
    assert entry.status is ResourceStatus.FAILED


@pytest.mark.parametrize(
    ("failure", "call"),
    (
        ("import", 1),
        ("import", 2),
        ("create", 1),
        ("create", 2),
        ("create", 3),
    ),
)
def test_runtime_creation_boundary_failure_cleans_only_run_owned_resources(
    repository_factory: Any,
    tmp_path: Path,
    failure: str,
    call: int,
) -> None:
    root = repository_factory()
    configure_test_inputs(root)
    value = inputs(root, tmp_path)
    caller_owned = tmp_path / "caller-owned"
    caller_owned.write_text("keep\n", encoding="utf-8")
    runtime = Runtime(
        fail_import_call=call if failure == "import" else None,
        fail_create_call=call if failure == "create" else None,
    )
    runner = CapturingRunner()

    with pytest.raises(OperationalError, match=f"injected {failure} boundary failure"):
        run_platform_tests(
            value,
            build_platform(value, Builder()),
            runtime,
            configured_hook_runner(value, runner),
            dependencies=build_test_dependencies(value, Builder()),
        )

    prefix = f"cc-{value.workspace.run_id}-{value.platform.key}"
    assert set(runtime.removed_names).issubset(
        {prefix, f"{prefix}-prepare-1", f"{prefix}-prepare-2"}
    )
    assert caller_owned.read_text(encoding="utf-8") == "keep\n"
    assert not runner.requests
    assert not (
        value.workspace.root / "reports" / "app" / "linux-amd64" / "test-inputs"
    ).exists()
