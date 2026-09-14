"""Build, evidence and platform qualification pipeline.

`qualify_platform` runs the local gates for one platform in order: require an
accepted `ClosurePreflight` that covers the image and every test dependency,
build the layout, build any sibling test dependencies, hand the result to the
runtime test session in `conclear.services.runtime_tests`, generate scans and
the SPDX inventory, then write one public platform qualification record whose
verdict follows from every collected finding, including those of the
dependency closure.
"""

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.buildah import BuildObservation
from conclear.adapters.trivy import DatabaseObservation, ScanObservation
from conclear.checks import (
    validate_base_annotations,
    validate_declared_labels,
    validate_image_labels,
    validate_scratch_annotations,
)
from conclear.config import SYSTEMD_STOP_SIGNAL, ImageConfig
from conclear.containerfile import Containerfile, ImageInput, load_containerfile
from conclear.context import hash_build_context
from conclear.database import qualification_database_window
from conclear.errors import OperationalError
from conclear.freshness import QualificationWindow, evidence_window
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
)
from conclear.scan_identity import ScanIdentity
from conclear.scan_policy import (
    AppliedConfigurationException,
    AppliedException,
    PackageAssessment,
    evaluate_trivy_report,
)
from conclear.services.preflight import ClosurePreflight, ImagePreflight
from conclear.services.qualification_inputs import (
    BuildEvidence,
    BuildInputs,
    QualificationInputs,
    TestDependencyBuild,
    canonical_build_arguments,
    execution_observation,
    require_execution_mode,
)
from conclear.services.runtime_lifecycle import RuntimeAdapter
from conclear.services.runtime_tests import test_platform
from conclear.source_integrity import require_source_integrity
from conclear.values import Digest, OCIReference, Platform
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
        identity: ScanIdentity | None = None,
    ) -> ScanObservation:
        """Scan local source content."""
        ...

    def scan_layout(
        self,
        *,
        layout_path: Path,
        report_path: Path,
        cache_root: Path,
        identity: ScanIdentity | None = None,
    ) -> ScanObservation:
        """Scan one local OCI layout."""
        ...

    def generate_spdx(
        self,
        *,
        layout_path: Path,
        output_path: Path,
        cache_root: Path,
        identity: ScanIdentity | None = None,
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
    applied_runtime_requirements: tuple[dict[str, object], ...] = ()
    package_assessment: PackageAssessment | None = None
    applied_configuration_exceptions: tuple[AppliedConfigurationException, ...] = ()


@dataclass(frozen=True, slots=True)
class QualificationResult:
    """One stored platform qualification and its exact digest."""

    record_path: Path
    record_digest: str
    layout_path: Path
    layout_reference: str
    verdict: Verdict
    findings: tuple[Finding, ...]
    qualification_window: QualificationWindow
    test_results: tuple[dict[str, object], ...] = ()


def build_platform(inputs: BuildInputs, builder: Builder) -> BuildEvidence:
    """Build one isolated platform layout and verify its labels and platform."""
    require_execution_mode(inputs)
    require_source_integrity(inputs.workspace, inputs.repository.path.parent)
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
    build_arguments = canonical_build_arguments(
        source_revision=inputs.source.revision,
        source_time=inputs.source_time,
        version=inputs.version,
    )
    created = build_arguments["IMAGE_CREATED"]
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
    require_source_integrity(workspace, inputs.repository.path.parent)
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
    ) + validate_declared_labels(labels, load_containerfile(inputs.image.containerfile))
    return BuildEvidence(
        observation, context, containerfile_digest, build_arguments, findings
    )


class BaseManifestResolver(Protocol):
    """Resolve the platform manifest a pinned base reference points to."""

    def platform_manifest_digest(
        self, reference: OCIReference, platform: Platform
    ) -> Digest:
        """Return the digest of the base manifest for one platform."""
        ...


def final_stage_base(containerfile: Containerfile) -> ImageInput | None:
    """Return the external image the final stage is built on, if any."""
    stage_bases: dict[str, ImageInput | None] = {}
    base: ImageInput | None = None
    for instruction in containerfile.instructions:
        if instruction.keyword != "FROM" or not instruction.image_inputs:
            continue
        image_input = instruction.image_inputs[0]
        if image_input.external:
            base = image_input
        else:
            base = stage_bases.get(image_input.reference)
        if instruction.stage_name is not None:
            stage_bases[instruction.stage_name] = base
    return base


def verify_base_annotations(
    inputs: QualificationInputs, build: BuildEvidence, resolver: BaseManifestResolver
) -> BuildEvidence:
    """Attach base-annotation findings (CC0118) to one platform build."""
    containerfile = load_containerfile(inputs.image.containerfile)
    base = final_stage_base(containerfile)
    manifest = build.observation.graph.manifests[0]
    if base is None:
        findings = validate_scratch_annotations(manifest.annotations)
    else:
        pinned = next(
            (
                pin.reference
                for pin in inputs.image.pins
                if str(pin.reference) == base.reference
            ),
            None,
        )
        if pinned is None:
            raise OperationalError(f"Final stage base {base.reference} has no pin")
        findings = validate_base_annotations(
            manifest.annotations,
            pinned=pinned,
            platform_manifest_digest=resolver.platform_manifest_digest(
                pinned, inputs.platform
            ),
        )
    return replace(build, findings=build.findings + findings)


def build_test_dependencies(
    inputs: QualificationInputs, builder: Builder
) -> tuple[TestDependencyBuild, ...]:
    """Build each transitive test dependency once from the same immutable inputs."""
    return tuple(
        TestDependencyBuild(
            image=dependency,
            build=build_platform(inputs.dependency_inputs(dependency), builder),
            source_revision=inputs.source.revision,
            platform=inputs.platform,
        )
        for dependency in inputs.repository.test_dependencies(inputs.image.image_id)
    )


def scan_identity(inputs: QualificationInputs, build: BuildEvidence) -> ScanIdentity:
    """Name scan evidence by the platform subject, never by the release host."""
    manifest = next(
        (
            item
            for item in build.observation.graph.manifests
            if item.platform.semantically_matches(inputs.platform)
        ),
        None,
    )
    digest = (
        build.observation.graph.digest
        if manifest is None
        else manifest.descriptor.digest
    )
    return ScanIdentity(
        workspace_root=inputs.workspace.root,
        subject=str(inputs.image.repository.with_digest(digest)),
        artifact_path=build.observation.layout_path,
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
    require_source_integrity(inputs.workspace, inputs.repository.path.parent)
    report_root = (
        inputs.workspace.root / "reports" / inputs.image.image_id / inputs.platform.key
    )
    report_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    identity = scan_identity(inputs, build)
    source_scan = scanner.scan_filesystem(
        path=inputs.image.context,
        report_path=report_root / "source-scan.json",
        cache_root=database.path,
        scanners=("secret",),
        identity=identity,
    )
    containerfile_scan = scanner.scan_filesystem(
        path=inputs.image.containerfile,
        report_path=report_root / "containerfile-scan.json",
        cache_root=database.path,
        scanners=("misconfig",),
        identity=identity,
    )
    image_scan = scanner.scan_layout(
        layout_path=build.observation.layout_path,
        report_path=report_root / "image-scan.json",
        cache_root=database.path,
        identity=identity,
    )
    sbom_path = (
        inputs.workspace.root / "exports" / "sbom" / f"{inputs.platform.key}.spdx.json"
    )
    sbom = scanner.generate_spdx(
        layout_path=build.observation.layout_path,
        output_path=sbom_path,
        cache_root=database.path,
        identity=identity,
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
        runtime=inputs.image.runtime,
    )
    image_evaluation = evaluate_trivy_report(
        image_scan.value,
        image_id=inputs.image.image_id,
        exceptions=inputs.image.vulnerability_exceptions,
        today=today,
        runtime=inputs.image.runtime,
        expect_packages=True,
        package_assessment_exception=inputs.image.package_assessment_exception,
        configuration_exceptions=inputs.image.configuration_exceptions,
    )
    return ScanEvidence(
        package_assessment=image_evaluation.package_assessment,
        sbom=sbom,
        scans=(source_scan, containerfile_scan, image_scan),
        applied_exceptions=image_evaluation.applied_exceptions,
        applied_configuration_exceptions=(
            image_evaluation.applied_configuration_exceptions
        ),
        applied_runtime_requirements=(
            containerfile_evaluation.applied_runtime_requirements
            + image_evaluation.applied_runtime_requirements
        ),
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
    base_resolver: BaseManifestResolver,
    runtime: RuntimeAdapter,
    hooks: HookRunner,
    scanner: Scanner,
    database: DatabaseObservation,
    preflight: ClosurePreflight,
    now: datetime,
    record_clock: Callable[[], datetime],
    qualification_started_at: datetime | None = None,
) -> QualificationResult:
    """Execute the local platform pipeline and store one public qualification."""
    _require_closure_preflight(inputs, preflight)
    if not preflight.accepted:
        raise OperationalError("Qualification cannot build after rejected preflight")
    window = qualification_database_window(
        database, started_at=qualification_started_at or now, now=now
    )
    build = verify_base_annotations(
        inputs, build_platform(inputs, builder), base_resolver
    )
    dependency_builds = build_test_dependencies(inputs, builder)
    runtime_evidence = test_platform(
        inputs, build, runtime, hooks, dependencies=dependency_builds
    )
    scan_evidence = generate_evidence(
        inputs, build, scanner, database, today=now.date()
    )
    require_source_integrity(inputs.workspace, inputs.repository.path.parent)
    completed_at = record_clock()
    window.require_current(completed_at, phase="qualification completion")
    pin_findings = tuple(
        replace(finding, image=item.image.image_id)
        for item in preflight.images
        for finding in _pin_findings(item.image, item.pin_observations, now=now)
    )
    findings = tuple(
        sorted(
            dict.fromkeys(
                (
                    *preflight.findings,
                    *pin_findings,
                    *build.findings,
                    *(
                        replace(finding, image=dependency.image.image_id)
                        for dependency in dependency_builds
                        for finding in dependency.build.findings
                    ),
                    *runtime_evidence.findings,
                    *scan_evidence.findings,
                )
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
    output_archive = runtime_evidence.output_archive
    payload_digests = tuple(
        sorted(
            {
                runtime_evidence.test_report_digest,
                scan_evidence.sbom.digest,
                *(scan.digest for scan in scan_evidence.scans),
                *((sha256_file(output_archive),) if output_archive is not None else ()),
            }
        )
    )
    payload: dict[str, object] = {
        "imageId": inputs.image.image_id,
        "sourceTreeDigest": inputs.workspace.load().immutable_inputs[
            "sourceTreeDigest"
        ],
        "platform": str(inputs.platform),
        "layoutDescriptor": build.observation.graph.root.to_dict(),
        "manifestDigest": str(manifest.descriptor.digest),
        "containerfileDigest": build.containerfile_digest,
        "contextDigest": build.context.digest,
        "buildArguments": dict(sorted(build.build_arguments.items())),
        "externalImages": [str(pin.reference) for pin in inputs.image.pins],
        "pinObservations": _pin_observation_values(preflight.primary),
        "effectiveLimits": _effective_limits(inputs.image),
        "buildExecution": execution_observation(inputs),
        "testExecution": runtime_evidence.execution,
        "runtimeConstraints": _runtime_constraints(inputs.image),
        "testInputs": runtime_evidence.test_inputs,
        "testImageDependencies": _dependency_evidence(
            dependency_builds, preflight.dependencies, runtime_evidence.dependencies
        ),
        "testResults": list(runtime_evidence.test_results),
        "sbom": {"digest": scan_evidence.sbom.digest, "spdxVersion": "SPDX-2.3"},
        "scans": [
            {"digest": scan.digest, "path": scan.path.name}
            for scan in scan_evidence.scans
        ],
        "appliedExceptions": [
            item.to_dict() for item in scan_evidence.applied_exceptions
        ],
        "appliedConfigurationExceptions": [
            item.to_dict() for item in scan_evidence.applied_configuration_exceptions
        ],
        "appliedRuntimeRequirements": list(scan_evidence.applied_runtime_requirements),
        "packageAssessment": (
            None
            if scan_evidence.package_assessment is None
            else scan_evidence.package_assessment.to_dict()
        ),
        "payloadDigests": list(payload_digests),
        "databaseDigest": database.digest,
        "databaseMetadata": database.metadata,
        "qualificationWindow": window.to_dict(),
        "findings": [finding.to_dict() for finding in findings],
    }
    if verdict is Verdict.ACCEPTED:
        window = evidence_window(payload)
        window.require_current(completed_at, phase="qualification completion")
        payload["qualificationWindow"] = window.to_dict()
    if output_archive is not None:
        payload["testOutputArchive"] = {
            "path": output_archive.name,
            "digest": sha256_file(output_archive),
        }
    record = RecordEnvelope(
        record_type="platformQualification",
        created_at=completed_at,
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
        qualification_window=window,
        test_results=runtime_evidence.test_results,
    )


def _require_closure_preflight(
    inputs: QualificationInputs, preflight: ClosurePreflight
) -> None:
    expected = (
        *inputs.repository.test_dependencies(inputs.image.image_id),
        inputs.image,
    )
    supplied = tuple(item.image for item in preflight.images)
    if supplied != expected:
        raise OperationalError(
            "Preflight does not cover the qualified image and its test dependencies"
        )


def _pin_observation_values(item: ImagePreflight) -> list[dict[str, object]]:
    return [
        observation.to_dict()
        for observation in sorted(
            item.pin_observations, key=lambda value: str(value.reference)
        )
    ]


def _effective_limits(image: ImageConfig) -> dict[str, object]:
    return {
        "pinFreshnessSeconds": int(image.pin_limits.pin_freshness.total_seconds()),
        "pinDivergenceSeconds": int(image.pin_limits.pin_divergence.total_seconds()),
    }


def _dependency_evidence(
    builds: tuple[TestDependencyBuild, ...],
    preflights: tuple[ImagePreflight, ...],
    observations: tuple[dict[str, object], ...],
) -> list[dict[str, object]]:
    if not len(builds) == len(preflights) == len(observations):
        raise OperationalError("Test dependency evidence is incomplete")
    values: list[dict[str, object]] = []
    for build, preflight, observation in zip(
        builds, preflights, observations, strict=True
    ):
        image = build.image
        if (
            preflight.image.image_id != image.image_id
            or observation.get("imageId") != image.image_id
        ):
            raise OperationalError("Test dependency evidence is out of order")
        values.append(
            {
                **observation,
                "containerfileDigest": build.build.containerfile_digest,
                "contextDigest": build.build.context.digest,
                "buildArguments": dict(sorted(build.build.build_arguments.items())),
                "externalImages": [str(pin.reference) for pin in image.pins],
                "pinObservations": _pin_observation_values(preflight),
                "effectiveLimits": _effective_limits(image),
            }
        )
    return values


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
        if age > image.pin_limits.pin_freshness:
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
    result: dict[str, object] = {
        "profile": runtime.profile,
        "user": runtime.user,
        "readOnly": runtime.read_only,
        "noNewPrivileges": runtime.no_new_privileges,
        "writableMounts": list(runtime.writable_mounts),
        "memory": runtime.memory,
        "cpus": runtime.cpus,
        "pids": runtime.pids,
        "nofile": runtime.nofile,
        "capabilities": list(runtime.capabilities),
    }
    if runtime.root_requirement is not None:
        result["rootRequirement"] = runtime.root_requirement.to_dict()
    if runtime.writable_root_requirement is not None:
        result["writableRootRequirement"] = runtime.writable_root_requirement.to_dict()
    if runtime.sudo_requirement is not None:
        sudo = runtime.sudo_requirement
        result["sudoRequirement"] = {
            **sudo.review.to_dict(),
            "mode": sudo.mode,
            "scope": sudo.scope,
            "setidPaths": list(sudo.setid_paths),
        }
    result["setidRequirements"] = [
        {"path": item.path, **item.review.to_dict()}
        for item in runtime.setid_requirements
    ]
    if runtime.systemd is not None:
        result["systemd"] = {
            "requiredUnits": list(runtime.systemd.required_units),
            "stopSignal": SYSTEMD_STOP_SIGNAL,
        }
    return result
