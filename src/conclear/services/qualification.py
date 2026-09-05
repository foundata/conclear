"""Build, evidence and platform qualification pipeline.

`qualify_platform` runs the local gates for one platform in order: build the
layout, build any sibling test dependencies, hand the result to the runtime
test session in `conclear.services.runtime_tests`, generate scans and the
SPDX inventory, then write one public platform qualification record whose
verdict follows from every collected finding.
"""

from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.buildah import BuildObservation
from conclear.adapters.trivy import DatabaseObservation, ScanObservation
from conclear.checks import validate_image_labels
from conclear.config import ImageConfig
from conclear.context import hash_build_context
from conclear.errors import OperationalError
from conclear.hooks import HookRunner
from conclear.jsonutil import (
    sha256_bytes,
    sha256_file,
)
from conclear.pins import PinObservation
from conclear.presentation import Finding
from conclear.records import (
    RecordEnvelope,
    Verdict,
    format_timestamp,
)
from conclear.scan_policy import AppliedException, evaluate_trivy_report
from conclear.services.qualification_inputs import (
    BuildEvidence,
    QualificationInputs,
    TestDependencyBuild,
    execution_observation,
    require_execution_mode,
)
from conclear.services.runtime_tests import RuntimeAdapter, test_platform
from conclear.values import Platform
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
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
    require_execution_mode(inputs)
    workspace = inputs.workspace
    platform_key = inputs.platform.key
    layout_path = workspace.root / "layouts" / inputs.image.image_id / platform_key
    storage_root = (
        workspace.root / "buildah" / inputs.image.image_id / platform_key / "root"
    )
    runroot = (
        workspace.root / "buildah" / inputs.image.image_id / platform_key / "runroot"
    )
    context = hash_build_context(inputs.image.context)
    containerfile_digest = sha256_file(inputs.image.containerfile)
    created = format_timestamp(inputs.source_time)
    build_arguments = {
        "IMAGE_REVISION": inputs.source.revision,
        "IMAGE_CREATED": created,
        "SOURCE_DATE_EPOCH": str(int(inputs.source_time.timestamp())),
    }
    if inputs.version is not None:
        build_arguments["IMAGE_VERSION"] = inputs.version
    storage_id = f"buildah-{inputs.image.image_id}-{platform_key}"
    layout_id = f"layout-{inputs.image.image_id}-{platform_key}"
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
        workspace.journal.mark_failed(storage_id, layout_id)
        raise
    workspace.journal.update(storage_id, ResourceStatus.CREATED)
    workspace.journal.update(layout_id, ResourceStatus.CREATED)
    graph = observation.graph
    if len(graph.manifests) != 1 or not graph.manifests[
        0
    ].platform.semantically_matches(inputs.platform):
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


def build_test_dependencies(
    inputs: QualificationInputs, builder: Builder
) -> tuple[TestDependencyBuild, ...]:
    """Build each transitive test dependency once from the same immutable inputs."""
    return tuple(
        TestDependencyBuild(
            image=dependency,
            build=build_platform(replace(inputs, image=dependency), builder),
            source_revision=inputs.source.revision,
            platform=inputs.platform,
        )
        for dependency in inputs.repository.test_dependencies(inputs.image.image_id)
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
        scanners=("secret",),
    )
    containerfile_scan = scanner.scan_filesystem(
        path=inputs.image.containerfile,
        report_path=report_root / "containerfile-scan.json",
        cache_root=database.path,
        scanners=("misconfig",),
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
    containerfile_evaluation = evaluate_trivy_report(
        containerfile_scan.value,
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
        scans=(source_scan, containerfile_scan, image_scan),
        applied_exceptions=image_evaluation.applied_exceptions,
        findings=(
            source_evaluation.findings
            + containerfile_evaluation.findings
            + image_evaluation.findings
        ),
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
    dependency_builds = build_test_dependencies(inputs, builder)
    runtime_evidence = test_platform(
        inputs, build, runtime, hooks, dependencies=dependency_builds
    )
    scan_evidence = generate_evidence(
        inputs, build, scanner, database, today=now.date()
    )
    pin_findings = _pin_findings(inputs.image, pin_observations, now=now)
    findings = tuple(
        sorted(
            (
                *preflight_findings,
                *(
                    finding
                    for observation in pin_observations
                    for finding in observation.findings
                ),
                *pin_findings,
                *build.findings,
                *(
                    finding
                    for dependency in dependency_builds
                    for finding in dependency.build.findings
                ),
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
        "pinObservations": [
            observation.to_dict()
            for observation in sorted(
                pin_observations, key=lambda item: str(item.reference)
            )
        ],
        "effectiveLimits": {
            "pinFreshnessSeconds": int(
                inputs.image.limits.pin_freshness.total_seconds()
            ),
            "pinDivergenceSeconds": int(
                inputs.image.limits.pin_divergence.total_seconds()
            ),
        },
        "buildExecution": execution_observation(inputs),
        "testExecution": runtime_evidence.execution,
        "runtimeConstraints": _runtime_constraints(inputs.image),
        "testInputs": runtime_evidence.test_inputs,
        "testImageDependencies": list(runtime_evidence.dependencies),
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
        "databaseMetadata": database.metadata,
        "findings": [finding.to_dict() for finding in findings],
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


def _pin_findings(
    image: ImageConfig,
    observations: tuple[PinObservation, ...],
    *,
    now: datetime,
) -> tuple[Finding, ...]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise OperationalError("Qualification time must be timezone-aware")
    configured = {pin.reference for pin in image.pins}
    observed = {item.reference for item in observations}
    if len(observations) != len(observed) or observed != configured:
        raise OperationalError(
            "Pin observations do not exactly cover configured image inputs"
        )
    findings: list[Finding] = []
    for observation in observations:
        age = now.astimezone(UTC) - observation.checked_at.astimezone(UTC)
        if age.total_seconds() < 0:
            raise OperationalError("Pin resolution time is in the future")
        if age > image.limits.pin_freshness:
            findings.append(
                Finding(
                    "CC0204",
                    "error",
                    "Successful pin resolution exceeded the effective freshness limit",
                    str(observation.reference),
                )
            )
    return tuple(findings)


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
