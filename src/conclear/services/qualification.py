"""Build, runtime-test, evidence and platform qualification services."""

from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.buildah import BuildObservation
from conclear.adapters.podman import (
    ContainerObservation,
    ImportObservation,
    RuntimeControlObservation,
)
from conclear.adapters.trivy import DatabaseObservation, ScanObservation
from conclear.checks import validate_image_labels
from conclear.config import ImageConfig, RepositoryConfig, RuntimeConfig
from conclear.context import ContextObservation, hash_build_context
from conclear.errors import OperationalError
from conclear.hooks import HookObservation, HookRunner, HookStatus
from conclear.jsonutil import atomic_write_json, sha256_bytes, sha256_file
from conclear.pins import PinObservation
from conclear.presentation import Finding
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
)
from conclear.scan_policy import AppliedException, evaluate_trivy_report
from conclear.values import Digest, Platform
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
    RunWorkspace,
)


class Builder(Protocol):
    """Buildah adapter boundary used by qualification."""

    def build(
        self,
        *,
        root: Path,
        runroot: Path,
        containerfile: Path,
        context: Path,
        platform: Platform,
        image_name: str,
        layout_path: Path,
        layout_reference: str,
        source_epoch: int,
        build_arguments: dict[str, str],
        auth_file: Path | None,
    ) -> BuildObservation:
        """Build one platform layout."""
        ...


class RuntimeAdapter(Protocol):
    """Podman adapter boundary used by qualification."""

    def import_layout(
        self,
        *,
        root: Path,
        runroot: Path,
        layout_path: Path,
        layout_reference: str,
        image_name: str,
        expected_digest: Digest,
    ) -> ImportObservation:
        """Import and re-resolve one exact layout."""
        ...

    def create_container(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        image_name: str,
        runtime: RuntimeConfig,
        platform: Platform,
        command: tuple[str, ...] = (),
    ) -> ContainerObservation:
        """Create one constrained runtime container."""
        ...

    def inspect_controls(
        self, *, root: Path, runroot: Path, name: str
    ) -> RuntimeControlObservation:
        """Observe effective runtime controls."""
        ...

    def exec(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        command: tuple[str, ...],
        timeout_seconds: float,
    ) -> str:
        """Execute one fixed argument array."""
        ...

    def signal(self, *, root: Path, runroot: Path, name: str, signal_name: str) -> None:
        """Signal the container's PID 1."""
        ...

    def wait(
        self, *, root: Path, runroot: Path, name: str, timeout_seconds: float
    ) -> int:
        """Wait and return the container process status."""
        ...

    def remove(
        self, *, root: Path, runroot: Path, name: str, force: bool = False
    ) -> None:
        """Remove one run-owned container."""
        ...


class Scanner(Protocol):
    """Trivy adapter boundary used by qualification."""

    def scan_filesystem(
        self,
        *,
        path: Path,
        report_path: Path,
        cache_root: Path,
        scanners: tuple[str, ...],
    ) -> ScanObservation:
        """Scan local source content."""
        ...

    def scan_layout(
        self,
        *,
        layout_path: Path,
        report_path: Path,
        cache_root: Path,
    ) -> ScanObservation:
        """Scan one local OCI layout."""
        ...

    def generate_spdx(
        self,
        *,
        layout_path: Path,
        output_path: Path,
        cache_root: Path,
    ) -> ScanObservation:
        """Generate one SPDX JSON document."""
        ...


@dataclass(frozen=True, slots=True)
class QualificationInputs:
    """Immutable inputs and adapter-independent facts for one platform."""

    repository: RepositoryConfig
    image: ImageConfig
    workspace: RunWorkspace
    source: SourceIdentity
    source_time: datetime
    version: str | None
    platform: Platform
    tools: tuple[ToolIdentity, ...]
    auth_file: Path | None
    host_architecture: str


@dataclass(frozen=True, slots=True)
class BuildEvidence:
    """Verified build output and source-content digests."""

    observation: BuildObservation
    context: ContextObservation
    containerfile_digest: str
    build_arguments: dict[str, str]
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class RuntimeEvidence:
    """Digest-reverified runtime observations and repository hooks."""

    test_results: tuple[dict[str, object], ...]
    test_report_digest: str
    execution: dict[str, object]
    findings: tuple[Finding, ...]
    hooks: tuple[HookObservation, ...]
    incomplete: bool


@dataclass(frozen=True, slots=True)
class ScanEvidence:
    """SPDX and scan payload observations evaluated by policy."""

    sbom: ScanObservation
    scans: tuple[ScanObservation, ...]
    applied_exceptions: tuple[AppliedException, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class QualificationResult:
    """One stored platform qualification and its exact digest."""

    record_path: Path
    record_digest: str
    layout_path: Path
    layout_reference: str
    verdict: Verdict
    findings: tuple[Finding, ...]


def build_platform(inputs: QualificationInputs, builder: Builder) -> BuildEvidence:
    """Build one isolated platform layout and verify its labels and platform."""
    workspace = inputs.workspace
    platform_key = inputs.platform.key
    layout_path = workspace.root / "layouts" / inputs.image.image_id / platform_key
    storage_root = workspace.root / "buildah" / platform_key / "root"
    runroot = workspace.root / "buildah" / platform_key / "runroot"
    context = hash_build_context(inputs.image.context)
    containerfile_digest = sha256_file(inputs.image.containerfile)
    created = _timestamp(inputs.source_time)
    build_arguments = {
        "IMAGE_REVISION": inputs.source.revision,
        "IMAGE_CREATED": created,
        "SOURCE_DATE_EPOCH": str(int(inputs.source_time.timestamp())),
    }
    if inputs.version is not None:
        build_arguments["IMAGE_VERSION"] = inputs.version
    storage_id = f"buildah-{platform_key}"
    layout_id = f"layout-{platform_key}"
    workspace.journal.plan(
        resource_id=storage_id,
        kind=ResourceKind.BUILDAH_STORAGE,
        identifier=str(storage_root.parent),
        ephemeral=True,
    )
    workspace.journal.plan(
        resource_id=layout_id,
        kind=ResourceKind.LOCAL_PATH,
        identifier=str(layout_path),
        ephemeral=True,
    )
    try:
        observation = builder.build(
            root=storage_root,
            runroot=runroot,
            containerfile=inputs.image.containerfile,
            context=inputs.image.context,
            platform=inputs.platform,
            image_name=(
                f"localhost/conclear-{workspace.run_id}-"
                f"{inputs.image.image_id}-{platform_key}"
            ),
            layout_path=layout_path,
            layout_reference="qualified",
            source_epoch=int(inputs.source_time.timestamp()),
            build_arguments=build_arguments,
            auth_file=inputs.auth_file,
        )
    except Exception:
        _mark_failed(workspace, storage_id, layout_id)
        raise
    workspace.journal.update(storage_id, ResourceStatus.CREATED)
    workspace.journal.update(layout_id, ResourceStatus.CREATED)
    graph = observation.graph
    if len(graph.manifests) != 1 or graph.manifests[0].platform != inputs.platform:
        raise OperationalError(
            f"Build output does not contain exactly platform {inputs.platform}"
        )
    config = graph.manifests[0].config_data.get("config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    findings = validate_image_labels(
        labels,
        source=inputs.source.repository,
        revision=inputs.source.revision,
        version=inputs.version,
        created=created,
    )
    return BuildEvidence(
        observation, context, containerfile_digest, build_arguments, findings
    )


def test_platform(
    inputs: QualificationInputs,
    build: BuildEvidence,
    runtime: RuntimeAdapter,
    hooks: HookRunner,
) -> RuntimeEvidence:
    """Import the exact layout and apply generic and repository-specific tests."""
    platform_key = inputs.platform.key
    storage_root = inputs.workspace.root / "podman" / platform_key / "root"
    runroot = inputs.workspace.root / "podman" / platform_key / "runroot"
    image_name = (
        f"localhost/conclear-{inputs.workspace.run_id}-"
        f"{inputs.image.image_id}-{platform_key}:qualified"
    )
    container_name = f"cc-{inputs.workspace.run_id}-{platform_key}"
    resource_id = f"podman-{platform_key}"
    inputs.workspace.journal.plan(
        resource_id=resource_id,
        kind=ResourceKind.PODMAN_IMPORT,
        identifier=container_name,
        ephemeral=True,
        metadata={"imageName": image_name, "storageRoot": str(storage_root)},
    )
    try:
        imported = runtime.import_layout(
            root=storage_root,
            runroot=runroot,
            layout_path=build.observation.layout_path,
            layout_reference="qualified",
            image_name=image_name,
            expected_digest=build.observation.graph.digest,
        )
        container = runtime.create_container(
            root=storage_root,
            runroot=runroot,
            name=container_name,
            image_name=image_name,
            runtime=inputs.image.runtime,
            platform=inputs.platform,
        )
        inputs.workspace.journal.update(resource_id, ResourceStatus.CREATED)
    except Exception:
        _mark_failed(inputs.workspace, resource_id)
        raise
    findings: list[Finding] = []
    results: list[dict[str, object]] = [
        {
            "name": "importDigest",
            "status": "passed",
            "digest": str(imported.digest),
        }
    ]
    controls = runtime.inspect_controls(
        root=storage_root, runroot=runroot, name=container_name
    )
    findings.extend(_control_findings(inputs.image, controls))
    results.append(
        {
            "name": "runtimeControls",
            "status": "passed" if not findings else "failed",
            "observed": _controls_dict(controls),
        }
    )
    native = (
        _normalized_architecture(inputs.host_architecture)
        == inputs.platform.architecture
    )
    if inputs.platform in inputs.image.native_test_platforms and not native:
        findings.append(
            Finding(
                "CC0403",
                "error",
                f"Platform {inputs.platform} requires native runtime testing",
            )
        )
    profile = inputs.image.runtime.profile
    if profile == "service":
        if container.status != "running" or container.pid <= 0:
            findings.append(
                Finding("CC0403", "error", "Service did not remain running")
            )
        else:
            results.append({"name": "startup", "status": "passed"})
        if inputs.image.runtime.health_command:
            runtime.exec(
                root=storage_root,
                runroot=runroot,
                name=container_name,
                command=inputs.image.runtime.health_command,
                timeout_seconds=inputs.image.runtime.startup_timeout_seconds,
            )
            results.append({"name": "health", "status": "passed"})
        _check_immutable_paths(
            inputs, runtime, storage_root, runroot, container_name, findings
        )
        runtime.signal(
            root=storage_root,
            runroot=runroot,
            name=container_name,
            signal_name="TERM",
        )
        exit_status = runtime.wait(
            root=storage_root,
            runroot=runroot,
            name=container_name,
            timeout_seconds=inputs.image.runtime.shutdown_timeout_seconds,
        )
        if exit_status != 0:
            findings.append(
                Finding(
                    "CC0403",
                    "error",
                    f"Service returned {exit_status} after graceful termination",
                )
            )
        results.append(
            {
                "name": "signalAndShutdown",
                "status": "passed" if exit_status == 0 else "failed",
                "exitStatus": exit_status,
            }
        )
    else:
        exit_status = runtime.wait(
            root=storage_root,
            runroot=runroot,
            name=container_name,
            timeout_seconds=inputs.image.runtime.startup_timeout_seconds,
        )
        if exit_status != 0:
            findings.append(
                Finding("CC0403", "error", f"One-shot image exited with {exit_status}")
            )
        results.append(
            {
                "name": "oneShotExit",
                "status": "passed" if exit_status == 0 else "failed",
                "exitStatus": exit_status,
            }
        )
    runtime.remove(root=storage_root, runroot=runroot, name=container_name, force=True)
    inputs.workspace.journal.update(resource_id, ResourceStatus.REMOVED)
    hook_results = tuple(
        hooks.run(
            hook,
            supplied_environment={
                "CC_LAYOUT": str(build.observation.layout_path),
                "CC_IMAGE_DIGEST": str(build.observation.graph.digest),
                "CC_PLATFORM": str(inputs.platform),
                "CC_SOURCE_ROOT": str(inputs.repository.path.parent),
            },
        )
        for hook in inputs.image.hooks
    )
    for hook in hook_results:
        if hook.status is HookStatus.FAILED:
            findings.append(
                Finding("CC0403", "error", f"Repository hook failed: {hook.name}")
            )
    incomplete = any(
        hook.required and hook.status is HookStatus.SKIPPED for hook in hook_results
    )
    results.extend(hook.to_dict() for hook in hook_results)
    report_path = (
        inputs.workspace.root
        / "reports"
        / inputs.image.image_id
        / platform_key
        / "tests.json"
    )
    report_digest = atomic_write_json(
        report_path, {"schemaVersion": 1, "results": results}, mode=0o644
    )
    return RuntimeEvidence(
        test_results=tuple(results),
        test_report_digest=report_digest,
        execution={
            "targetPlatform": str(inputs.platform),
            "hostArchitecture": inputs.host_architecture,
            "executionArchitecture": inputs.platform.architecture,
            "mechanism": "native" if native else "qemu-user",
        },
        findings=tuple(findings),
        hooks=hook_results,
        incomplete=incomplete,
    )


def generate_evidence(
    inputs: QualificationInputs,
    build: BuildEvidence,
    scanner: Scanner,
    database: DatabaseObservation,
    *,
    today: date,
) -> ScanEvidence:
    """Generate local scans and SPDX, then apply vulnerability policy."""
    report_root = (
        inputs.workspace.root / "reports" / inputs.image.image_id / inputs.platform.key
    )
    report_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    source_scan = scanner.scan_filesystem(
        path=inputs.image.context,
        report_path=report_root / "source-scan.json",
        cache_root=database.path,
        scanners=("secret", "misconfig"),
    )
    image_scan = scanner.scan_layout(
        layout_path=build.observation.layout_path,
        report_path=report_root / "image-scan.json",
        cache_root=database.path,
    )
    sbom_path = (
        inputs.workspace.root / "exports" / "sbom" / f"{inputs.platform.key}.spdx.json"
    )
    sbom = scanner.generate_spdx(
        layout_path=build.observation.layout_path,
        output_path=sbom_path,
        cache_root=database.path,
    )
    source_evaluation = evaluate_trivy_report(
        source_scan.value,
        image_id=inputs.image.image_id,
        exceptions=(),
        today=today,
    )
    image_evaluation = evaluate_trivy_report(
        image_scan.value,
        image_id=inputs.image.image_id,
        exceptions=inputs.image.vulnerability_exceptions,
        today=today,
    )
    return ScanEvidence(
        sbom=sbom,
        scans=(source_scan, image_scan),
        applied_exceptions=image_evaluation.applied_exceptions,
        findings=source_evaluation.findings + image_evaluation.findings,
    )


def qualify_platform(
    inputs: QualificationInputs,
    *,
    builder: Builder,
    runtime: RuntimeAdapter,
    hooks: HookRunner,
    scanner: Scanner,
    database: DatabaseObservation,
    pin_observations: tuple[PinObservation, ...],
    preflight_findings: tuple[Finding, ...] = (),
    now: datetime,
) -> QualificationResult:
    """Execute the local platform pipeline and store one public qualification."""
    if any(finding.severity == "error" for finding in preflight_findings):
        raise OperationalError("Qualification cannot build after rejected preflight")
    build = build_platform(inputs, builder)
    runtime_evidence = test_platform(inputs, build, runtime, hooks)
    scan_evidence = generate_evidence(
        inputs, build, scanner, database, today=now.date()
    )
    findings = tuple(
        sorted(
            (
                *preflight_findings,
                *(
                    finding
                    for observation in pin_observations
                    for finding in observation.findings
                ),
                *build.findings,
                *runtime_evidence.findings,
                *scan_evidence.findings,
            ),
            key=lambda finding: (
                finding.check_id,
                finding.location or "",
                finding.message,
            ),
        )
    )
    if runtime_evidence.incomplete:
        verdict = Verdict.INCOMPLETE
    elif any(finding.severity == "error" for finding in findings):
        verdict = Verdict.REJECTED
    else:
        verdict = Verdict.ACCEPTED
    manifest = build.observation.graph.manifests[0]
    payload_digests = tuple(
        sorted(
            {
                runtime_evidence.test_report_digest,
                scan_evidence.sbom.digest,
                *(scan.digest for scan in scan_evidence.scans),
            }
        )
    )
    payload: dict[str, object] = {
        "imageId": inputs.image.image_id,
        "platform": str(inputs.platform),
        "layoutDescriptor": build.observation.graph.root.to_dict(),
        "manifestDigest": str(manifest.descriptor.digest),
        "containerfileDigest": build.containerfile_digest,
        "contextDigest": build.context.digest,
        "buildArguments": dict(sorted(build.build_arguments.items())),
        "externalImages": [str(pin.reference) for pin in inputs.image.pins],
        "buildExecution": {
            "targetPlatform": str(inputs.platform),
            "hostArchitecture": inputs.host_architecture,
            "executionArchitecture": inputs.platform.architecture,
            "mechanism": (
                "native"
                if _normalized_architecture(inputs.host_architecture)
                == inputs.platform.architecture
                else "cross-build"
            ),
        },
        "testExecution": runtime_evidence.execution,
        "runtimeConstraints": _runtime_constraints(inputs.image),
        "testResults": list(runtime_evidence.test_results),
        "sbom": {"digest": scan_evidence.sbom.digest, "spdxVersion": "SPDX-2.3"},
        "scans": [
            {"digest": scan.digest, "path": scan.path.name}
            for scan in scan_evidence.scans
        ],
        "appliedExceptions": [
            item.to_dict() for item in scan_evidence.applied_exceptions
        ],
        "payloadDigests": list(payload_digests),
        "databaseDigest": database.digest,
    }
    record = RecordEnvelope(
        record_type="platformQualification",
        created_at=now,
        run_id=inputs.workspace.run_id,
        source=inputs.source,
        configuration_digest=sha256_bytes(inputs.repository.raw_bytes),
        tools=inputs.tools,
        verdict=verdict,
        payload=payload,
    )
    record_path = (
        inputs.workspace.root
        / "records"
        / f"platform-qualification-{inputs.platform.key}.json"
    )
    record_digest = record.write(record_path)
    return QualificationResult(
        record_path=record_path,
        record_digest=record_digest,
        layout_path=build.observation.layout_path,
        layout_reference="qualified",
        verdict=verdict,
        findings=findings,
    )


def _control_findings(
    image: ImageConfig, observed: RuntimeControlObservation
) -> tuple[Finding, ...]:
    expected = image.runtime
    mismatches: list[str] = []
    if observed.user.split(":", maxsplit=1)[0] != str(expected.user):
        mismatches.append("user")
    if observed.read_only is not expected.read_only:
        mismatches.append("read-only root")
    if observed.memory_bytes != _memory_bytes(expected.memory):
        mismatches.append("memory")
    if observed.nano_cpus != round(expected.cpus * 1_000_000_000):
        mismatches.append("CPU")
    if observed.pids_limit != expected.pids:
        mismatches.append("PID")
    if (
        observed.nofile_soft != expected.nofile
        or observed.nofile_hard != expected.nofile
    ):
        mismatches.append("nofile")
    if not any(
        value.lower().replace("_", "-") == "no-new-privileges"
        for value in observed.security_options
    ):
        mismatches.append("no-new-privileges")
    cap_drop = {item.removeprefix("CAP_").upper() for item in observed.cap_drop}
    if "ALL" not in cap_drop:
        mismatches.append("capability drop")
    cap_add = {item.removeprefix("CAP_").upper() for item in observed.cap_add}
    expected_add = {item.removeprefix("CAP_") for item in expected.capabilities}
    if cap_add != expected_add:
        mismatches.append("added capabilities")
    return tuple(
        Finding(
            "CC0401"
            if name
            in {
                "user",
                "read-only root",
                "no-new-privileges",
                "capability drop",
                "added capabilities",
            }
            else "CC0402",
            "error",
            f"Effective runtime {name} control does not match configuration",
        )
        for name in mismatches
    )


def _check_immutable_paths(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    root: Path,
    runroot: Path,
    name: str,
    findings: list[Finding],
) -> None:
    paths = inputs.image.runtime.immutable_paths
    if not paths:
        return
    output = runtime.exec(
        root=root,
        runroot=runroot,
        name=name,
        command=("stat", "--format=%u:%a", "--", *paths),
        timeout_seconds=120,
    )
    lines = output.splitlines()
    if len(lines) != len(paths):
        raise OperationalError(
            "Immutable path ownership probe returned incomplete output"
        )
    for path, line in zip(paths, lines, strict=True):
        owner, separator, mode_text = line.partition(":")
        try:
            mode = int(mode_text, 8)
        except ValueError as exc:
            raise OperationalError("Immutable path mode probe is malformed") from exc
        if separator != ":" or owner != "0" or mode & 0o222:
            findings.append(
                Finding(
                    "CC0404",
                    "error",
                    "Immutable runtime path is not root-owned and non-writable",
                    path,
                )
            )


def _controls_dict(value: RuntimeControlObservation) -> dict[str, object]:
    return {
        "user": value.user,
        "readOnly": value.read_only,
        "memoryBytes": value.memory_bytes,
        "nanoCpus": value.nano_cpus,
        "pidsLimit": value.pids_limit,
        "nofile": [value.nofile_soft, value.nofile_hard],
        "capAdd": list(value.cap_add),
        "capDrop": list(value.cap_drop),
        "securityOptions": list(value.security_options),
    }


def _runtime_constraints(image: ImageConfig) -> dict[str, object]:
    runtime = image.runtime
    return {
        "profile": runtime.profile,
        "user": runtime.user,
        "readOnly": runtime.read_only,
        "writableMounts": list(runtime.writable_mounts),
        "memory": runtime.memory,
        "cpus": runtime.cpus,
        "pids": runtime.pids,
        "nofile": runtime.nofile,
        "capabilities": list(runtime.capabilities),
    }


def _memory_bytes(value: str) -> int:
    units = {"KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
    for suffix, multiplier in units.items():
        if value.endswith(suffix):
            return int(value.removesuffix(suffix)) * multiplier
    raise ValueError(f"Unsupported memory value: {value}")


def _normalized_architecture(value: str) -> str:
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(value, value)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Source timestamp must be timezone-aware")
    return (
        value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _mark_failed(workspace: RunWorkspace, *resource_ids: str) -> None:
    """Best-effort journal failure state without replacing the original exception."""
    for resource_id in resource_ids:
        try:
            workspace.journal.update(resource_id, ResourceStatus.FAILED)
        except Exception:
            continue
