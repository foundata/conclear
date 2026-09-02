"""Build, runtime-test, evidence and platform qualification services."""

import logging
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Protocol

from conclear.adapters.buildah import BuildObservation
from conclear.adapters.podman import (
    BindMount,
    ContainerObservation,
    ImportObservation,
    RuntimeControlObservation,
)
from conclear.adapters.trivy import DatabaseObservation, ScanObservation
from conclear.checks import validate_image_labels
from conclear.config import (
    ImageConfig,
    RepositoryConfig,
    RuntimeConfig,
    TestMountConfig,
)
from conclear.context import ContextObservation, hash_build_context
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.hooks import HookObservation, HookRunner, HookStatus
from conclear.jsonutil import atomic_write_json, sha256_bytes, sha256_file
from conclear.oci import validate_layout
from conclear.pins import PinObservation
from conclear.presentation import Finding
from conclear.records import (
    RecordEnvelope,
    SourceIdentity,
    ToolIdentity,
    Verdict,
)
from conclear.scan_policy import AppliedException, evaluate_trivy_report
from conclear.test_inputs import (
    MaterializedTestInputs,
    destroy_secret_test_outputs,
    empty_test_input_observation,
    launch_declaration,
    materialize_test_inputs,
    observe_test_tree,
    preparation_declaration,
    remove_materialized_test_inputs,
)
from conclear.values import Digest, Platform
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
    RunWorkspace,
)

LOGGER = logging.getLogger(__name__)


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
        arguments: tuple[str, ...] = (),
        environment: tuple[tuple[str, str], ...] = (),
        mounts: tuple[BindMount, ...] = (),
        entrypoint: tuple[str, ...] = (),
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

    def remove_storage(self, *, root: Path, runroot: Path) -> None:
        """Reset one isolated run-owned Podman storage root."""
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
class TestDependencyBuild:
    """One exact sibling layout built only for the primary image's tests."""

    image: ImageConfig
    build: BuildEvidence
    source_revision: str
    platform: Platform


@dataclass(frozen=True, slots=True)
class RuntimeEvidence:
    """Digest-reverified runtime observations and repository hooks."""

    test_results: tuple[dict[str, object], ...]
    test_report_digest: str
    execution: dict[str, object]
    findings: tuple[Finding, ...]
    hooks: tuple[HookObservation, ...]
    incomplete: bool
    test_inputs: dict[str, object]
    dependencies: tuple[dict[str, object], ...]


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
    storage_root = (
        workspace.root / "buildah" / inputs.image.image_id / platform_key / "root"
    )
    runroot = (
        workspace.root / "buildah" / inputs.image.image_id / platform_key / "runroot"
    )
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


def test_platform(
    inputs: QualificationInputs,
    build: BuildEvidence,
    runtime: RuntimeAdapter,
    hooks: HookRunner,
    dependencies: tuple[TestDependencyBuild, ...] = (),
) -> RuntimeEvidence:
    """Import the exact layout and apply generic and repository-specific tests."""
    try:
        primary_graph = validate_layout(
            build.observation.layout_path, reference="qualified"
        )
    except InvalidInvocationError as exc:
        raise OperationalError(
            "Primary runtime test layout failed integrity validation", code="CC0305"
        ) from exc
    if primary_graph.digest != build.observation.graph.digest:
        raise OperationalError("Primary runtime test layout changed after build")
    _validate_dependency_builds(inputs, dependencies)
    platform_key = inputs.platform.key
    storage_root = inputs.workspace.root / "podman" / platform_key / "root"
    runroot = inputs.workspace.root / "podman" / platform_key / "runroot"
    image_names = {
        image.image_id: (
            f"localhost/conclear-{inputs.workspace.run_id}-"
            f"{image.image_id}-{platform_key}:qualified"
        )
        for image in (inputs.image, *(item.image for item in dependencies))
    }
    container_name = f"cc-{inputs.workspace.run_id}-{platform_key}"
    resource_id = f"podman-{inputs.image.image_id}-{platform_key}"
    test_inputs_id = f"test-inputs-{inputs.image.image_id}-{platform_key}"
    test_inputs_root = (
        inputs.workspace.root
        / "reports"
        / inputs.image.image_id
        / platform_key
        / "test-inputs"
    )
    inputs.workspace.journal.plan(
        resource_id=resource_id,
        kind=ResourceKind.PODMAN_IMPORT,
        identifier=container_name,
        ephemeral=True,
        metadata={
            "imageName": image_names[inputs.image.image_id],
            "storageRoot": str(storage_root),
            "resetStorage": True,
        },
    )
    inputs.workspace.journal.plan(
        resource_id=test_inputs_id,
        kind=ResourceKind.TEST_INPUTS,
        identifier=str(test_inputs_root),
        ephemeral=True,
    )
    materialized: MaterializedTestInputs | None = None
    try:
        materialized = materialize_test_inputs(
            test_inputs_root,
            run_id=inputs.workspace.run_id,
            test=inputs.image.test,
        )
        inputs.workspace.journal.update(test_inputs_id, ResourceStatus.CREATED)
        imported = runtime.import_layout(
            root=storage_root,
            runroot=runroot,
            layout_path=build.observation.layout_path,
            layout_reference="qualified",
            image_name=image_names[inputs.image.image_id],
            expected_digest=build.observation.graph.digest,
        )
        dependency_imports = {
            item.image.image_id: runtime.import_layout(
                root=storage_root,
                runroot=runroot,
                layout_path=item.build.observation.layout_path,
                layout_reference="qualified",
                image_name=image_names[item.image.image_id],
                expected_digest=item.build.observation.graph.digest,
            )
            for item in dependencies
        }
        findings, results, input_observation = _run_preparations(
            inputs,
            runtime,
            build,
            dependencies,
            materialized,
            image_names,
            storage_root,
            runroot,
        )
        if not any(finding.severity == "error" for finding in findings):
            container = runtime.create_container(
                root=storage_root,
                runroot=runroot,
                name=container_name,
                image_name=image_names[inputs.image.image_id],
                runtime=inputs.image.runtime,
                platform=inputs.platform,
                arguments=inputs.image.test.launch.arguments,
                environment=inputs.image.test.launch.environment,
                mounts=_bind_mounts(inputs.image.test.launch.mounts, materialized),
            )
            inputs.workspace.journal.update(resource_id, ResourceStatus.CREATED)
            runtime_findings, runtime_results, execution = _exercise_container(
                inputs,
                runtime,
                imported,
                container,
                storage_root=storage_root,
                runroot=runroot,
                container_name=container_name,
            )
            findings.extend(runtime_findings)
            results.extend(runtime_results)
        else:
            execution = _execution_observation(inputs)
        dependency_values = _dependency_observations(
            inputs, dependencies, dependency_imports
        )
        input_observation = _complete_test_input_observation(
            inputs, materialized, input_observation
        )
        output_values = input_observation.get("outputs")
        if not isinstance(output_values, list):
            raise OperationalError("Test output observations are malformed")
        for value in output_values:
            if isinstance(value, dict) and value.get("files") == 0:
                findings.append(
                    Finding(
                        "CC0403",
                        "error",
                        f"Declared test output is empty: {value.get('name', 'unknown')}",
                    )
                )
        manifest_path = _write_test_input_manifest(
            inputs,
            build,
            materialized,
            dependencies,
            input_observation,
        )
        destroy_secret_test_outputs(materialized)
        hook_results = (
            ()
            if any(finding.severity == "error" for finding in findings)
            else tuple(
                hooks.run(
                    hook,
                    supplied_environment={
                        "CC_LAYOUT": str(build.observation.layout_path),
                        "CC_IMAGE_DIGEST": str(build.observation.graph.digest),
                        "CC_PLATFORM": str(inputs.platform),
                        "CC_SOURCE_ROOT": str(inputs.repository.path.parent),
                        "CC_TEST_INPUT_MANIFEST": str(manifest_path),
                    },
                )
                for hook in inputs.image.hooks
            )
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
            report_path,
            {
                "schemaVersion": 1,
                "testInputs": input_observation,
                "testImageDependencies": dependency_values,
                "results": results,
            },
            mode=0o644,
        )
        dependency_values = tuple(
            {**value, "testResultDigest": report_digest} for value in dependency_values
        )
    except BaseException:
        _mark_failed(inputs.workspace, resource_id)
        _cleanup_test_session(
            inputs,
            runtime,
            storage_root=storage_root,
            runroot=runroot,
            container_name=container_name,
            resource_id=resource_id,
            materialized=materialized,
            test_inputs_id=test_inputs_id,
            preserve_failure=True,
        )
        raise
    _cleanup_test_session(
        inputs,
        runtime,
        storage_root=storage_root,
        runroot=runroot,
        container_name=container_name,
        resource_id=resource_id,
        materialized=materialized,
        test_inputs_id=test_inputs_id,
        preserve_failure=False,
    )
    return RuntimeEvidence(
        test_results=tuple(results),
        test_report_digest=report_digest,
        execution=execution,
        findings=tuple(findings),
        hooks=hook_results,
        incomplete=incomplete,
        test_inputs=input_observation,
        dependencies=dependency_values,
    )


def _validate_dependency_builds(
    inputs: QualificationInputs, dependencies: tuple[TestDependencyBuild, ...]
) -> None:
    expected = inputs.repository.test_dependencies(inputs.image.image_id)
    if tuple(item.image.image_id for item in dependencies) != tuple(
        item.image_id for item in expected
    ):
        raise OperationalError("Test dependency builds do not match configuration")
    for supplied, configured in zip(dependencies, expected, strict=True):
        if supplied.image != configured:
            raise OperationalError("Test dependency configuration changed")
        if supplied.source_revision != inputs.source.revision:
            raise OperationalError("Test dependency source revision changed")
        if supplied.platform != inputs.platform:
            raise OperationalError("Test dependency platform changed")
        graph = supplied.build.observation.graph
        try:
            observed_graph = validate_layout(
                supplied.build.observation.layout_path, reference="qualified"
            )
        except InvalidInvocationError as exc:
            raise OperationalError(
                "Test dependency layout failed integrity validation", code="CC0305"
            ) from exc
        if observed_graph.digest != graph.digest:
            raise OperationalError("Test dependency layout changed after build")
        if len(graph.manifests) != 1 or graph.manifests[0].platform != inputs.platform:
            raise OperationalError("Test dependency layout platform is inconsistent")


def _run_preparations(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    build: BuildEvidence,
    dependencies: tuple[TestDependencyBuild, ...],
    materialized: MaterializedTestInputs,
    image_names: dict[str, str],
    storage_root: Path,
    runroot: Path,
) -> tuple[list[Finding], list[dict[str, object]], dict[str, object]]:
    findings: list[Finding] = []
    results: list[dict[str, object]] = []
    images = {inputs.image.image_id: inputs.image}
    images.update({item.image.image_id: item.image for item in dependencies})
    manifest_digests = {
        inputs.image.image_id: str(
            build.observation.graph.manifests[0].descriptor.digest
        )
    }
    manifest_digests.update(
        {
            item.image.image_id: str(
                item.build.observation.graph.manifests[0].descriptor.digest
            )
            for item in dependencies
        }
    )
    observation = empty_test_input_observation(inputs.image.test)
    fixture_values = [
        materialized.fixture_observations[item.name].to_dict(
            name=item.name, secret=False
        )
        for item in inputs.image.test.fixtures
    ]
    observation["fixtures"] = fixture_values
    preparation_values = observation["preparations"]
    if not isinstance(preparation_values, list):
        raise OperationalError("Preparation evidence initialization failed")
    for preparation, value in zip(
        inputs.image.test.preparations, preparation_values, strict=True
    ):
        if not isinstance(value, dict):
            raise OperationalError("Preparation evidence initialization failed")
        value["imageManifestDigest"] = manifest_digests[preparation.image]

    for index, preparation in enumerate(inputs.image.test.preparations, start=1):
        selected = images[preparation.image]
        resource_id = (
            f"podman-preparation-{inputs.image.image_id}-{inputs.platform.key}-{index}"
        )
        container_name = (
            f"cc-{inputs.workspace.run_id}-{inputs.platform.key}-prepare-{index}"
        )
        inputs.workspace.journal.plan(
            resource_id=resource_id,
            kind=ResourceKind.PODMAN_IMPORT,
            identifier=container_name,
            ephemeral=True,
            metadata={
                "imageName": image_names[preparation.image],
                "storageRoot": str(storage_root),
                "resetStorage": False,
            },
        )
        declaration = preparation_declaration(preparation)
        declaration["imageManifestDigest"] = manifest_digests[preparation.image]
        try:
            runtime.create_container(
                root=storage_root,
                runroot=runroot,
                name=container_name,
                image_name=image_names[preparation.image],
                runtime=selected.runtime,
                platform=inputs.platform,
                environment=preparation.environment,
                mounts=_bind_mounts(preparation.mounts, materialized),
                entrypoint=preparation.command,
            )
            inputs.workspace.journal.update(resource_id, ResourceStatus.CREATED)
            controls = runtime.inspect_controls(
                root=storage_root, runroot=runroot, name=container_name
            )
            control_findings = _control_findings(selected, controls)
            findings.extend(control_findings)
            exit_status = runtime.wait(
                root=storage_root,
                runroot=runroot,
                name=container_name,
                timeout_seconds=preparation.timeout_seconds,
            )
        except BaseException:
            _mark_failed(inputs.workspace, resource_id)
            _remove_preparation(
                inputs,
                runtime,
                storage_root,
                runroot,
                container_name,
                resource_id,
                preserve_failure=True,
            )
            raise
        _remove_preparation(
            inputs,
            runtime,
            storage_root,
            runroot,
            container_name,
            resource_id,
            preserve_failure=False,
        )
        passed = (
            not control_findings and exit_status == preparation.expected_exit_status
        )
        if exit_status != preparation.expected_exit_status:
            findings.append(
                Finding(
                    "CC0403",
                    "error",
                    f"Test preparation {preparation.name} exited with {exit_status}",
                )
            )
        for mount in preparation.mounts:
            if mount.source.value != "output" or mount.read_only:
                continue
            try:
                output = observe_test_tree(
                    materialized.outputs[mount.name],
                    secret=mount.name in materialized.secret_outputs,
                )
            except OperationalError as exc:
                findings.append(
                    Finding(
                        "CC0403",
                        "error",
                        f"Test preparation {preparation.name} produced unsafe output: {exc}",
                    )
                )
                passed = False
                continue
            if output.files == 0:
                findings.append(
                    Finding(
                        "CC0403",
                        "error",
                        f"Test preparation {preparation.name} produced no files in {mount.name}",
                    )
                )
                passed = False
        results.append(
            {
                "name": f"preparation:{preparation.name}",
                "status": "passed" if passed else "failed",
                "digest": declaration["commandDigest"],
                "exitStatus": exit_status,
            }
        )
        if not passed:
            break
    return findings, results, observation


def _bind_mounts(
    mounts: tuple[TestMountConfig, ...], materialized: MaterializedTestInputs
) -> tuple[BindMount, ...]:
    values: list[BindMount] = []
    for mount in mounts:
        source = materialized.path_for(mount)
        if "," in str(source):
            raise OperationalError("Test mount source contains an unsupported comma")
        values.append(
            BindMount(
                source=source,
                target=mount.target,
                read_only=mount.read_only,
                secret=materialized.is_secret(mount),
            )
        )
    return tuple(values)


def _complete_test_input_observation(
    inputs: QualificationInputs,
    materialized: MaterializedTestInputs,
    observation: dict[str, object],
) -> dict[str, object]:
    outputs: list[dict[str, object]] = []
    for output in inputs.image.test.outputs:
        value = observe_test_tree(
            materialized.outputs[output.name], secret=output.secret
        )
        outputs.append(value.to_dict(name=output.name, secret=output.secret))
    observation["outputs"] = outputs
    observation["launch"] = launch_declaration(inputs.image.test.launch)
    return observation


def _dependency_observations(
    inputs: QualificationInputs,
    dependencies: tuple[TestDependencyBuild, ...],
    imports: dict[str, ImportObservation],
) -> tuple[dict[str, object], ...]:
    values: list[dict[str, object]] = []
    for dependency in dependencies:
        imported = imports[dependency.image.image_id]
        graph = dependency.build.observation.graph
        if imported.digest != graph.digest:
            raise OperationalError("Imported test dependency digest changed")
        manifest = graph.manifests[0]
        values.append(
            {
                "imageId": dependency.image.image_id,
                "platform": str(inputs.platform),
                "manifestDigest": str(manifest.descriptor.digest),
                "layoutDescriptor": graph.root.to_dict(),
                "sourceRevision": dependency.source_revision,
            }
        )
    return tuple(values)


def _write_test_input_manifest(
    inputs: QualificationInputs,
    build: BuildEvidence,
    materialized: MaterializedTestInputs,
    dependencies: tuple[TestDependencyBuild, ...],
    observation: dict[str, object],
) -> Path:
    output_observations = observation.get("outputs")
    if not isinstance(output_observations, list):
        raise OperationalError("Test output observations are malformed")
    outputs_by_name = {
        value["name"]: value
        for value in output_observations
        if isinstance(value, dict) and isinstance(value.get("name"), str)
    }
    path = materialized.root / "manifest.json"
    atomic_write_json(
        path,
        {
            "schemaVersion": 1,
            "sourceRevision": inputs.source.revision,
            "platform": str(inputs.platform),
            "primary": {
                "imageId": inputs.image.image_id,
                "layout": str(build.observation.layout_path),
                "digest": str(build.observation.graph.digest),
            },
            "dependencies": [
                {
                    "imageId": item.image.image_id,
                    "layout": str(item.build.observation.layout_path),
                    "digest": str(item.build.observation.graph.digest),
                }
                for item in dependencies
            ],
            "fixtures": [
                {
                    "name": item.name,
                    "path": str(item.path),
                    "digest": materialized.fixture_observations[item.name].digest,
                }
                for item in inputs.image.test.fixtures
            ],
            "outputs": [
                {
                    "name": item.name,
                    "path": str(materialized.outputs[item.name]),
                    "digest": outputs_by_name[item.name]["digest"],
                }
                for item in inputs.image.test.outputs
                if not item.secret
            ],
        },
        mode=0o600,
    )
    return path


def _remove_preparation(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    storage_root: Path,
    runroot: Path,
    container_name: str,
    resource_id: str,
    *,
    preserve_failure: bool,
) -> None:
    try:
        runtime.remove(
            root=storage_root,
            runroot=runroot,
            name=container_name,
            force=True,
        )
    except BaseException:
        _mark_failed(inputs.workspace, resource_id)
        if preserve_failure:
            LOGGER.debug(
                "Failed to remove preparation container %s",
                container_name,
                exc_info=True,
            )
            return
        raise
    inputs.workspace.journal.update(resource_id, ResourceStatus.REMOVED)


def _cleanup_test_session(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    *,
    storage_root: Path,
    runroot: Path,
    container_name: str,
    resource_id: str,
    materialized: MaterializedTestInputs | None,
    test_inputs_id: str,
    preserve_failure: bool,
) -> None:
    errors: list[BaseException] = []
    _mark_planned_resource_failed(inputs.workspace, resource_id)
    try:
        _remove_test_container(
            inputs,
            runtime,
            storage_root=storage_root,
            runroot=runroot,
            container_name=container_name,
            resource_id=resource_id,
            preserve_failure=False,
        )
    except BaseException as exc:
        errors.append(exc)
    try:
        remove_materialized_test_inputs(
            (
                materialized.root
                if materialized is not None
                else inputs.workspace.root
                / "reports"
                / inputs.image.image_id
                / inputs.platform.key
                / "test-inputs"
            ),
            run_id=inputs.workspace.run_id,
        )
    except BaseException as exc:
        _mark_failed(inputs.workspace, test_inputs_id)
        errors.append(exc)
    else:
        _mark_planned_resource_failed(inputs.workspace, test_inputs_id)
        inputs.workspace.journal.update(test_inputs_id, ResourceStatus.REMOVED)
    if errors:
        if preserve_failure:
            LOGGER.debug(
                "Runtime test cleanup retained resources: %s",
                "; ".join(str(error) for error in errors),
                exc_info=errors[0],
            )
            return
        raise OperationalError(
            "Runtime test cleanup was incomplete: "
            + "; ".join(str(error) for error in errors)
        ) from errors[0]


def _mark_planned_resource_failed(workspace: RunWorkspace, resource_id: str) -> None:
    entry = next(
        (
            item
            for item in workspace.journal.entries()
            if item.resource_id == resource_id
        ),
        None,
    )
    if entry is None:
        raise OperationalError(
            f"Runtime cleanup resource is not journaled: {resource_id}"
        )
    if entry.status is ResourceStatus.PLANNED:
        workspace.journal.update(resource_id, ResourceStatus.FAILED)


def _exercise_container(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    imported: ImportObservation,
    container: ContainerObservation,
    *,
    storage_root: Path,
    runroot: Path,
    container_name: str,
) -> tuple[list[Finding], list[dict[str, object]], dict[str, object]]:
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
    if inputs.image.runtime.profile == "service":
        _exercise_service(
            inputs,
            runtime,
            container,
            storage_root=storage_root,
            runroot=runroot,
            container_name=container_name,
            findings=findings,
            results=results,
        )
    else:
        exit_status = runtime.wait(
            root=storage_root,
            runroot=runroot,
            name=container_name,
            timeout_seconds=inputs.image.runtime.startup_timeout_seconds,
        )
        expected_exit_status = inputs.image.test.launch.expected_exit_status
        if exit_status != expected_exit_status:
            findings.append(
                Finding(
                    "CC0403",
                    "error",
                    f"One-shot image exited with {exit_status}, expected {expected_exit_status}",
                )
            )
        results.append(
            {
                "name": "oneShotExit",
                "status": (
                    "passed" if exit_status == expected_exit_status else "failed"
                ),
                "exitStatus": exit_status,
            }
        )
    return findings, results, _execution_observation(inputs)


def _exercise_service(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    container: ContainerObservation,
    *,
    storage_root: Path,
    runroot: Path,
    container_name: str,
    findings: list[Finding],
    results: list[dict[str, object]],
) -> None:
    if container.status != "running" or container.pid <= 0:
        findings.append(Finding("CC0403", "error", "Service did not remain running"))
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
    expected_exit_status = inputs.image.test.launch.expected_exit_status
    if exit_status != expected_exit_status:
        findings.append(
            Finding(
                "CC0403",
                "error",
                f"Service returned {exit_status} after graceful termination, expected {expected_exit_status}",
            )
        )
    results.append(
        {
            "name": "signalAndShutdown",
            "status": "passed" if exit_status == expected_exit_status else "failed",
            "exitStatus": exit_status,
        }
    )


def _remove_test_container(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    *,
    storage_root: Path,
    runroot: Path,
    container_name: str,
    resource_id: str,
    preserve_failure: bool,
) -> None:
    try:
        runtime.remove(
            root=storage_root,
            runroot=runroot,
            name=container_name,
            force=True,
        )
        runtime.remove_storage(root=storage_root, runroot=runroot)
    except BaseException:
        _mark_failed(inputs.workspace, resource_id)
        if not preserve_failure:
            raise
    else:
        inputs.workspace.journal.update(resource_id, ResourceStatus.REMOVED)


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
        "buildExecution": _execution_observation(inputs),
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


def _control_findings(
    image: ImageConfig, observed: RuntimeControlObservation
) -> tuple[Finding, ...]:
    expected = image.runtime
    mismatches: list[str] = []
    if observed.user.split(":", maxsplit=1)[0] != str(expected.user):
        mismatches.append("user")
    if observed.read_only is not expected.read_only:
        mismatches.append("read-only root")
    if observed.writable_mounts != tuple(sorted(expected.writable_mounts)):
        mismatches.append("writable mounts")
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
    cap_add = {item.removeprefix("CAP_").upper() for item in observed.cap_add}
    expected_add = {item.removeprefix("CAP_") for item in expected.capabilities}
    effective = {
        item.removeprefix("CAP_").upper() for item in observed.effective_capabilities
    }
    if not effective.issubset(expected_add):
        mismatches.append("capability drop")
    if cap_add != expected_add:
        mismatches.append("added capabilities")
    return tuple(
        Finding(
            "CC0401"
            if name
            in {
                "user",
                "read-only root",
                "writable mounts",
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
        "writableMounts": list(value.writable_mounts),
        "memoryBytes": value.memory_bytes,
        "nanoCpus": value.nano_cpus,
        "pidsLimit": value.pids_limit,
        "nofile": [value.nofile_soft, value.nofile_hard],
        "capAdd": list(value.cap_add),
        "capDrop": list(value.cap_drop),
        "effectiveCapabilities": list(value.effective_capabilities),
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
    raise OperationalError(f"Unsupported memory value: {value}")


def _normalized_architecture(value: str) -> str:
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(value, value)


def _execution_observation(inputs: QualificationInputs) -> dict[str, object]:
    """Describe the execution mode selected for this platform workflow."""
    native = (
        _normalized_architecture(inputs.host_architecture)
        == inputs.platform.architecture
    )
    return {
        "targetPlatform": str(inputs.platform),
        "hostArchitecture": inputs.host_architecture,
        "executionArchitecture": inputs.platform.architecture,
        "mechanism": "native" if native else "qemu-user",
    }


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OperationalError("Source timestamp must be timezone-aware")
    return (
        value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _mark_failed(workspace: RunWorkspace, *resource_ids: str) -> None:
    """Best-effort journal failure state without replacing the original exception."""
    for resource_id in resource_ids:
        try:
            workspace.journal.update(resource_id, ResourceStatus.FAILED)
        except BaseException:
            LOGGER.debug(
                "Failed to record resource failure for %s",
                resource_id,
                exc_info=True,
            )
