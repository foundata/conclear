"""Runtime-test session for one built platform layout.

`test_platform` imports the exact layout into run-owned Podman storage, runs
declared preparations, exercises the primary container under its configured
runtime controls and repository hooks, and records digest-bound test results.
The session owns every container, storage root and materialized test input it
creates and removes them in a fixed order whether it succeeds or fails. The
profile-specific container lifecycle lives in
`conclear.services.runtime_lifecycle` and the control comparison in
`conclear.services.runtime_controls`.
"""

import logging
from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.podman import (
    BindMount,
    ImportObservation,
)
from conclear.config import (
    ImageConfig,
    TestMountConfig,
)
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.hooks import HookObservation, HookRunner, HookStatus
from conclear.jsonutil import (
    atomic_write_json,
)
from conclear.oci import validate_layout
from conclear.presentation import Finding
from conclear.services.privilege_tests import test_privileges
from conclear.services.qualification_inputs import (
    BuildEvidence,
    QualificationInputs,
    TestDependencyBuild,
    execution_observation,
    require_execution_mode,
)
from conclear.services.runtime_controls import control_findings
from conclear.services.runtime_lifecycle import (
    ReadinessTiming,
    RuntimeAdapter,
    exercise_container,
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
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
    RunWorkspace,
)

LOGGER = logging.getLogger(__name__)


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


def test_platform(
    inputs: QualificationInputs,
    build: BuildEvidence,
    runtime: RuntimeAdapter,
    hooks: HookRunner,
    dependencies: tuple[TestDependencyBuild, ...] = (),
    *,
    _readiness_timing: ReadinessTiming | None = None,
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
            privilege_findings, privilege_results = test_privileges(
                inputs,
                runtime,
                storage_root=storage_root,
                runroot=runroot,
                image_name=image_names[inputs.image.image_id],
                mounts=_bind_mounts(inputs.image.test.launch.mounts, materialized),
            )
            findings.extend(privilege_findings)
            results.extend(privilege_results)
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
            runtime_findings, runtime_results, execution = exercise_container(
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
    images: dict[str, ImageConfig] = {inputs.image.image_id: inputs.image}
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
            control_mismatches = control_findings(selected, controls)
            findings.extend(control_mismatches)
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
            not control_mismatches and exit_status == preparation.expected_exit_status
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
