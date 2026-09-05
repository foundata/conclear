import json
from pathlib import Path
from typing import Any

import pytest

from conclear.errors import InvalidInvocationError
from conclear.services.local_phases import load_build_evidence, write_build_evidence
from conclear.services.qualification import build_platform
from tests.unit.test_qualification import Builder, inputs


def test_build_evidence_round_trip_revalidates_layout_context_and_containerfile(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    value = inputs(root, tmp_path)
    build = build_platform(value, Builder())

    path = write_build_evidence(value, build)
    loaded = load_build_evidence(value)

    assert path == (
        value.workspace.root / "reports" / "app" / "linux-amd64" / "build.json"
    )
    assert loaded.observation.graph.digest == build.observation.graph.digest
    assert loaded.observation.layout_path == build.observation.layout_path
    assert loaded.observation.image_name == build.observation.image_name
    assert loaded.context.digest == build.context.digest
    assert loaded.containerfile_digest == build.containerfile_digest
    assert loaded.build_arguments == build.build_arguments
    assert loaded.findings == build.findings

    evidence = json.loads(path.read_text(encoding="utf-8"))
    assert evidence["schemaVersion"] == 1
    assert evidence["platform"] == "linux/amd64"
    assert evidence["layoutDigest"] == str(build.observation.graph.digest)


def test_build_evidence_rejects_changes_between_phases(
    repository_factory: Any, tmp_path: Path
) -> None:
    root = repository_factory()
    value = inputs(root, tmp_path)
    build = build_platform(value, Builder())
    path = write_build_evidence(value, build)
    original = path.read_bytes()

    containerfile = value.image.containerfile
    containerfile_bytes = containerfile.read_bytes()
    containerfile.write_bytes(containerfile_bytes + b"# changed\n")
    with pytest.raises(InvalidInvocationError, match="Build context changed"):
        load_build_evidence(value)
    containerfile.write_bytes(containerfile_bytes)

    evidence = json.loads(original)
    evidence["containerfileDigest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="Containerfile changed"):
        load_build_evidence(value)
    path.write_bytes(original)

    (value.image.context / "extra.txt").write_text("new\n", encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="Build context changed"):
        load_build_evidence(value)
    (value.image.context / "extra.txt").unlink()

    index = build.observation.layout_path / "index.json"
    index_bytes = index.read_bytes()
    tampered = json.loads(index_bytes)
    tampered["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"] = (
        "other"
    )
    index.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(InvalidInvocationError):
        load_build_evidence(value)
    index.write_bytes(index_bytes)

    evidence = json.loads(original)
    evidence["layoutDigest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="layout changed"):
        load_build_evidence(value)

    evidence = json.loads(original)
    evidence["platform"] = "linux/arm64"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="identity is malformed"):
        load_build_evidence(value)

    evidence = json.loads(original)
    evidence["buildArguments"] = {"IMAGE_VERSION": 1}
    path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="values are malformed"):
        load_build_evidence(value)

    evidence = json.loads(original)
    evidence["layoutReference"] = ""
    path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="non-empty string"):
        load_build_evidence(value)

    path.write_text("[]", encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="must be a JSON object"):
        load_build_evidence(value)

    path.write_bytes(original)
    assert load_build_evidence(value).context.digest == build.context.digest
