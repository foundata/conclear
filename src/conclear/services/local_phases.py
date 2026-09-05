"""Persisted build evidence for independently invokable local phases."""

from pathlib import Path

from conclear.adapters.buildah import BuildObservation
from conclear.checks import validate_image_labels
from conclear.context import hash_build_context
from conclear.errors import InvalidInvocationError
from conclear.jsonutil import atomic_write_json, load_json, sha256_file
from conclear.oci import validate_layout
from conclear.services.qualification_inputs import BuildEvidence, QualificationInputs


def write_build_evidence(inputs: QualificationInputs, build: BuildEvidence) -> Path:
    """Persist adapter-independent build observations for test and evidence commands."""
    path = (
        inputs.workspace.root
        / "reports"
        / inputs.image.image_id
        / inputs.platform.key
        / "build.json"
    )
    atomic_write_json(
        path,
        {
            "schemaVersion": 1,
            "platform": str(inputs.platform),
            "layoutReference": "qualified",
            "layoutDigest": str(build.observation.graph.digest),
            "containerfileDigest": build.containerfile_digest,
            "contextDigest": build.context.digest,
            "contextEntries": [entry.to_dict() for entry in build.context.entries],
            "buildArguments": dict(sorted(build.build_arguments.items())),
            "findings": [finding.to_dict() for finding in build.findings],
        },
        mode=0o644,
    )
    return path


def load_build_evidence(inputs: QualificationInputs) -> BuildEvidence:
    """Revalidate a persisted build against current source and OCI layout bytes."""
    path = (
        inputs.workspace.root
        / "reports"
        / inputs.image.image_id
        / inputs.platform.key
        / "build.json"
    )
    value = _object(load_json(path), "build evidence")
    if value.get("schemaVersion") != 1 or value.get("platform") != str(inputs.platform):
        raise InvalidInvocationError("Build evidence identity is malformed")
    layout_reference = _string(value.get("layoutReference"), "layout reference")
    layout_path = (
        inputs.workspace.root / "layouts" / inputs.image.image_id / inputs.platform.key
    )
    graph = validate_layout(layout_path, reference=layout_reference)
    if value.get("layoutDigest") != str(graph.digest):
        raise InvalidInvocationError("Built OCI layout changed between phases")
    context = hash_build_context(inputs.image.context)
    if value.get("contextDigest") != context.digest:
        raise InvalidInvocationError("Build context changed between phases")
    containerfile_digest = sha256_file(inputs.image.containerfile)
    if value.get("containerfileDigest") != containerfile_digest:
        raise InvalidInvocationError("Containerfile changed between phases")
    build_arguments_value = _object(value.get("buildArguments"), "build arguments")
    if any(not isinstance(item, str) for item in build_arguments_value.values()):
        raise InvalidInvocationError("Build argument values are malformed")
    build_arguments = {
        key: item
        for key, item in build_arguments_value.items()
        if isinstance(item, str)
    }
    config = graph.manifests[0].config_data.get("config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    findings = validate_image_labels(
        labels,
        source=inputs.source.repository,
        revision=inputs.source.revision,
        version=inputs.version,
        created=build_arguments.get("IMAGE_CREATED", ""),
    )
    return BuildEvidence(
        BuildObservation(
            image_name=(
                f"localhost/conclear-{inputs.workspace.run_id}-"
                f"{inputs.image.image_id}-{inputs.platform.key}"
            ),
            layout_path=layout_path,
            graph=graph,
            build_arguments=tuple(sorted(build_arguments.items())),
        ),
        context,
        containerfile_digest,
        build_arguments,
        findings,
    )


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise InvalidInvocationError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidInvocationError(f"{label} must be a non-empty string")
    return value
