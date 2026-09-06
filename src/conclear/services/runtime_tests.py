"""Runtime-test session for one built platform layout.

`test_platform` imports the exact layout into run-owned Podman storage, runs
declared preparations, exercises the primary container under its configured
runtime controls and repository hooks, and records digest-bound test results.
The session owns every container, storage root and materialized test input it
creates and removes them in a fixed order whether it succeeds or fails.
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from conclear.adapters.podman import (
    BindMount,
    ContainerObservation,
    ExecObservation,
    ImportObservation,
    RuntimeControlObservation,
)
from conclear.config import (
    ImageConfig,
    RuntimeConfig,
    TestMountConfig,
)
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.hooks import HookObservation, HookRunner, HookStatus
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    sha256_bytes,
)
from conclear.oci import validate_layout
from conclear.presentation import Finding
from conclear.services.qualification_inputs import (
    BuildEvidence,
    QualificationInputs,
    TestDependencyBuild,
    execution_observation,
    require_execution_mode,
)
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


_HEALTH_POLL_INTERVAL_SECONDS = 0.25


_HEALTH_DIAGNOSTIC_TIMEOUT_SECONDS = 5.0


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

    def inspect_container(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        timeout_seconds: float = 120,
    ) -> ContainerObservation:
        """Observe the current container process state."""
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

    def inspect_pid1(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        timeout_seconds: float,
    ) -> str:
        """Observe the command name for container PID 1."""
        ...

    def exec_observe(
        self,
        *,
        root: Path,
        runroot: Path,
        name: str,
        command: tuple[str, ...],
        timeout_seconds: float,
    ) -> ExecObservation:
        """Observe one in-container command without rejecting its exit status."""
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
class _ReadinessTiming:
    """Inject monotonic time and bounded sleeping into readiness tests."""

    monotonic: Callable[[], float]
    sleep: Callable[[float], None]
    interval_seconds: float = _HEALTH_POLL_INTERVAL_SECONDS


@dataclass(frozen=True, slots=True)
class _HealthObservation:
    """Final bounded observation from service readiness polling."""

    outcome: Literal["ready", "timeout", "exited"]
    attempts: int
    elapsed_seconds: float
    timeout_seconds: int
    command: ExecObservation | None
    container: ContainerObservation


def test_platform(
    inputs: QualificationInputs,
    build: BuildEvidence,
    runtime: RuntimeAdapter,
    hooks: HookRunner,
    dependencies: tuple[TestDependencyBuild, ...] = (),
    *,
    _readiness_timing: _ReadinessTiming | None = None,
) -> RuntimeEvidence:
    """Import the exact layout and apply generic and repository-specific tests."""
    require_execution_mode(inputs)
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
                readiness_timing=_readiness_timing,
            )
            findings.extend(runtime_findings)
            results.extend(runtime_results)
        else:
            execution = execution_observation(inputs)
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
        inputs.workspace.journal.mark_failed(resource_id)
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
        if len(graph.manifests) != 1 or not graph.manifests[
            0
        ].platform.semantically_matches(inputs.platform):
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
            inputs.workspace.journal.mark_failed(resource_id)
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
        inputs.workspace.journal.mark_failed(resource_id)
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
        inputs.workspace.journal.mark_failed(test_inputs_id)
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
    readiness_timing: _ReadinessTiming | None,
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
    if inputs.image.runtime.profile in {"service", "systemd"}:
        _exercise_service(
            inputs,
            runtime,
            container,
            storage_root=storage_root,
            runroot=runroot,
            container_name=container_name,
            findings=findings,
            results=results,
            readiness_timing=readiness_timing,
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
    return findings, results, execution_observation(inputs)


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
    readiness_timing: _ReadinessTiming | None,
) -> None:
    running = _container_is_running(container)
    if not running:
        findings.append(Finding("CC0403", "error", "Service did not remain running"))
        results.append(
            {
                "name": "startup",
                "status": "failed",
                "containerStatus": container.status,
                "containerExitStatus": container.exit_code,
            }
        )
    else:
        results.append(
            {
                "name": "startup",
                "status": "passed",
                "containerStatus": container.status,
                "containerExitStatus": container.exit_code,
            }
        )
    timing = readiness_timing or _ReadinessTiming(
        monotonic=time.monotonic, sleep=time.sleep
    )
    readiness_start = timing.monotonic()
    readiness_deadline = readiness_start + inputs.image.runtime.startup_timeout_seconds
    if running and inputs.image.runtime.systemd is not None:
        container, running = _exercise_systemd_readiness(
            inputs,
            runtime,
            container,
            storage_root=storage_root,
            runroot=runroot,
            container_name=container_name,
            findings=findings,
            results=results,
            timing=timing,
            readiness_start=readiness_start,
            readiness_deadline=readiness_deadline,
        )
    if running and inputs.image.runtime.health_command:
        health = _wait_for_service_health(
            runtime,
            root=storage_root,
            runroot=runroot,
            name=container_name,
            command=inputs.image.runtime.health_command,
            initial=container,
            timeout_seconds=inputs.image.runtime.startup_timeout_seconds,
            timing=timing,
            start_time=readiness_start,
            deadline=readiness_deadline,
        )
        results.append(_health_test_result(health))
        container = health.container
        running = _container_is_running(container)
        if health.outcome == "timeout":
            findings.append(
                Finding(
                    "CC0403",
                    "error",
                    "Service health did not succeed within "
                    f"{health.timeout_seconds}s after {health.attempts} attempts",
                )
            )
        elif health.outcome == "exited" and not any(
            finding.message == "Service did not remain running" for finding in findings
        ):
            suffix = (
                "unknown" if container.exit_code is None else str(container.exit_code)
            )
            findings.append(
                Finding(
                    "CC0403",
                    "error",
                    f"Service exited with status {suffix} before becoming ready",
                )
            )
    if not running:
        shutdown_result: dict[str, object] = {
            "name": "signalAndShutdown",
            "status": "failed",
            "containerStatus": container.status,
            "containerExitStatus": container.exit_code,
        }
        if container.exit_code is not None:
            shutdown_result["exitStatus"] = container.exit_code
        results.append(shutdown_result)
        return
    _check_immutable_paths(
        inputs, runtime, storage_root, runroot, container_name, findings
    )
    signal_name = (
        "TERM"
        if inputs.image.runtime.systemd is None
        else inputs.image.runtime.systemd.stop_signal
    )
    runtime.signal(
        root=storage_root,
        runroot=runroot,
        name=container_name,
        signal_name=signal_name,
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


def _exercise_systemd_readiness(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    container: ContainerObservation,
    *,
    storage_root: Path,
    runroot: Path,
    container_name: str,
    findings: list[Finding],
    results: list[dict[str, object]],
    timing: _ReadinessTiming,
    readiness_start: float,
    readiness_deadline: float,
) -> tuple[ContainerObservation, bool]:
    systemd = inputs.image.runtime.systemd
    if systemd is None:
        raise OperationalError("Systemd readiness requires systemd configuration")
    remaining = readiness_deadline - timing.monotonic()
    if remaining <= 0:
        findings.append(
            Finding("CC0403", "error", "Systemd readiness deadline expired")
        )
        return container, _container_is_running(container)
    pid1 = runtime.inspect_pid1(
        root=storage_root,
        runroot=runroot,
        name=container_name,
        timeout_seconds=remaining,
    )
    pid1_passed = Path(pid1).name == "systemd"
    results.append(
        {
            "name": "systemdPid1",
            "status": "passed" if pid1_passed else "failed",
            "outputDigest": sha256_bytes(pid1.encode("utf-8")),
        }
    )
    if not pid1_passed:
        findings.append(
            Finding("CC0403", "error", f"Container PID 1 is not systemd: {pid1}")
        )
        return container, _container_is_running(container)

    remaining = readiness_deadline - timing.monotonic()
    if remaining <= 0:
        findings.append(
            Finding("CC0403", "error", "Systemd readiness deadline expired")
        )
        return container, _container_is_running(container)
    manager = runtime.exec_observe(
        root=storage_root,
        runroot=runroot,
        name=container_name,
        command=("systemctl", "show", "--property=Version", "--value"),
        timeout_seconds=remaining,
    )
    manager_passed = manager.exit_status == 0 and bool(manager.stdout.strip())
    results.append(_command_test_result("systemdManager", manager, manager_passed))
    if not manager_passed:
        findings.append(
            Finding("CC0403", "error", "Systemd manager is not operational")
        )
        return container, _container_is_running(container)

    for unit in systemd.required_units:
        observation = _wait_for_service_health(
            runtime,
            root=storage_root,
            runroot=runroot,
            name=container_name,
            command=("systemctl", "is-active", "--quiet", unit),
            initial=container,
            timeout_seconds=inputs.image.runtime.startup_timeout_seconds,
            timing=timing,
            start_time=readiness_start,
            deadline=readiness_deadline,
        )
        result = _health_test_result(observation)
        result["name"] = f"systemdUnit:{unit}"
        results.append(result)
        container = observation.container
        if observation.outcome != "ready":
            findings.append(
                Finding(
                    "CC0403",
                    "error",
                    f"Required systemd unit did not become active: {unit}",
                )
            )
            return container, _container_is_running(container)
    return container, _container_is_running(container)


def _command_test_result(
    name: str, observation: ExecObservation, passed: bool
) -> dict[str, object]:
    return {
        "name": name,
        "status": "passed" if passed else "failed",
        "exitStatus": observation.exit_status,
        "outputDigest": sha256_bytes(
            canonical_json_bytes(
                {"stdout": observation.stdout, "stderr": observation.stderr}
            )
        ),
    }


def _wait_for_service_health(
    runtime: RuntimeAdapter,
    *,
    root: Path,
    runroot: Path,
    name: str,
    command: tuple[str, ...],
    initial: ContainerObservation,
    timeout_seconds: int,
    timing: _ReadinessTiming,
    start_time: float | None = None,
    deadline: float | None = None,
) -> _HealthObservation:
    if timing.interval_seconds <= 0:
        raise OperationalError("Readiness polling interval must be positive")
    start = timing.monotonic() if start_time is None else start_time
    deadline = start + timeout_seconds if deadline is None else deadline
    attempts = 0
    current = initial
    final_command: ExecObservation | None = None
    while True:
        now = timing.monotonic()
        if not _container_is_running(current):
            return _HealthObservation(
                "exited",
                attempts,
                max(0.0, now - start),
                timeout_seconds,
                final_command,
                current,
            )
        remaining = deadline - now
        if remaining <= 0:
            return _HealthObservation(
                "timeout",
                attempts,
                max(0.0, now - start),
                timeout_seconds,
                final_command,
                current,
            )
        attempts += 1
        final_command = runtime.exec_observe(
            root=root,
            runroot=runroot,
            name=name,
            command=command,
            timeout_seconds=remaining,
        )
        now = timing.monotonic()
        if final_command.exit_status == 0:
            return _HealthObservation(
                "ready",
                attempts,
                max(0.0, now - start),
                timeout_seconds,
                final_command,
                current,
            )
        remaining = deadline - now
        if remaining > 0:
            timing.sleep(min(timing.interval_seconds, remaining))
        remaining = deadline - timing.monotonic()
        current = runtime.inspect_container(
            root=root,
            runroot=runroot,
            name=name,
            timeout_seconds=(
                remaining if remaining > 0 else _HEALTH_DIAGNOSTIC_TIMEOUT_SECONDS
            ),
        )


def _health_test_result(observation: _HealthObservation) -> dict[str, object]:
    command = observation.command
    result: dict[str, object] = {
        "name": "health",
        "status": "passed" if observation.outcome == "ready" else "failed",
        "outcome": observation.outcome,
        "attempts": observation.attempts,
        "elapsedSeconds": round(observation.elapsed_seconds, 6),
        "timeoutSeconds": observation.timeout_seconds,
        "containerStatus": observation.container.status,
        "containerExitStatus": observation.container.exit_code,
        "outputDigest": sha256_bytes(
            canonical_json_bytes(
                {
                    "stdout": "" if command is None else command.stdout,
                    "stderr": "" if command is None else command.stderr,
                }
            )
        ),
    }
    if command is not None:
        result["exitStatus"] = command.exit_status
    return result


def _container_is_running(container: ContainerObservation) -> bool:
    return container.status == "running" and container.pid > 0


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
        inputs.workspace.journal.mark_failed(resource_id)
        if not preserve_failure:
            raise
    else:
        inputs.workspace.journal.update(resource_id, ResourceStatus.REMOVED)


def _control_findings(
    image: ImageConfig, observed: RuntimeControlObservation
) -> tuple[Finding, ...]:
    expected = image.runtime
    mismatches: list[str] = []
    messages: dict[str, str] = {}
    if observed.user.split(":", maxsplit=1)[0] != str(expected.user):
        mismatches.append("user")
    if observed.read_only is not expected.read_only:
        mismatches.append("read-only root")
    if observed.writable_mounts != tuple(sorted(expected.writable_mounts)):
        mismatches.append("writable mounts")
        unexpected = sorted(
            set(observed.writable_mounts) - set(expected.writable_mounts)
        )
        missing = sorted(set(expected.writable_mounts) - set(observed.writable_mounts))
        messages["writable mounts"] = (
            "Effective runtime writable mounts do not match configuration "
            f"(unexpected: {', '.join(unexpected) or 'none'}; "
            f"missing: {', '.join(missing) or 'none'})"
        )
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
    if observed.user_namespace != "private":
        mismatches.append("user namespace")
    if observed.cgroup_namespace != "private":
        mismatches.append("cgroup namespace")
    if observed.privileged:
        mismatches.append("privileged mode")
    if expected.systemd is not None and _normalized_signal(
        observed.stop_signal
    ) != _normalized_signal(expected.systemd.stop_signal):
        mismatches.append("stop signal")
    # Podman reports CapAdd and CapDrop relative to its own default set, so an
    # explicitly added default capability is invisible there; the bounding set
    # is the authoritative statement of what the container may ever hold.
    expected_add = {item.removeprefix("CAP_") for item in expected.capabilities}
    bounding = {
        item.removeprefix("CAP_").upper() for item in observed.bounding_capabilities
    }
    effective = {
        item.removeprefix("CAP_").upper() for item in observed.effective_capabilities
    }
    if not effective.issubset(expected_add):
        mismatches.append("capability drop")
    if bounding != expected_add:
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
                "user namespace",
                "cgroup namespace",
                "privileged mode",
                "stop signal",
            }
            else "CC0402",
            "error",
            messages.get(
                name, f"Effective runtime {name} control does not match configuration"
            ),
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
        if separator != ":" or owner != "0" or mode & 0o022:
            findings.append(
                Finding(
                    "CC0404",
                    "error",
                    (
                        "Immutable runtime path is not root-owned or has a "
                        "group/other write bit"
                    ),
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
        "boundingCapabilities": list(value.bounding_capabilities),
        "effectiveCapabilities": list(value.effective_capabilities),
        "securityOptions": list(value.security_options),
        "userNamespace": value.user_namespace,
        "cgroupNamespace": value.cgroup_namespace,
        "privileged": value.privileged,
        "stopSignal": value.stop_signal,
    }


def _memory_bytes(value: str) -> int:
    units = {"KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
    for suffix, multiplier in units.items():
        if value.endswith(suffix):
            return int(value.removesuffix(suffix)) * multiplier
    raise OperationalError(f"Unsupported memory value: {value}")


def _normalized_architecture(value: str) -> str:
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(value, value)


def _normalized_signal(value: str) -> str:
    return value if value.startswith("SIG") else f"SIG{value}"
