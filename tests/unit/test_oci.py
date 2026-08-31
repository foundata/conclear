import json
import tempfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import conclear.oci as oci_module
from conclear.errors import InvalidInvocationError
from conclear.jsonutil import canonical_json_bytes, sha256_bytes
from conclear.oci import OCI_CONFIG, OCI_MANIFEST, validate_layout


def _write_blob(layout: Path, content: bytes) -> tuple[str, int]:
    digest = sha256_bytes(content)
    path = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return digest, len(content)


def _create_layout(
    tmp_path: Path, *, architecture: str = "amd64", config_padding: int = 0
) -> Path:
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "oci-layout").write_text(
        '{"imageLayoutVersion":"1.0.0"}\n',
        encoding="utf-8",
    )
    config_content = canonical_json_bytes(
        {
            "architecture": architecture,
            "os": "linux",
            "config": {"User": "10001:10001"},
            "rootfs": {"type": "layers", "diff_ids": []},
            "history": [{"created_by": "x" * config_padding}],
        }
    )
    config_digest, config_size = _write_blob(layout, config_content)
    manifest_content = canonical_json_bytes(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {
                "mediaType": OCI_CONFIG,
                "digest": config_digest,
                "size": config_size,
            },
            "layers": [],
        }
    )
    manifest_digest, manifest_size = _write_blob(layout, manifest_content)
    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": OCI_MANIFEST,
                "digest": manifest_digest,
                "size": manifest_size,
                "platform": {"os": "linux", "architecture": architecture},
                "annotations": {"org.opencontainers.image.ref.name": "candidate"},
            }
        ],
    }
    (layout / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return layout


def test_layout_validator_recursively_verifies_manifest_and_config(
    tmp_path: Path,
) -> None:
    graph = validate_layout(_create_layout(tmp_path), reference="candidate")
    assert str(graph.platforms[0]) == "linux/amd64"
    assert len(graph.descriptors) == 2


def test_layout_validator_rejects_digest_mismatch(tmp_path: Path) -> None:
    layout = _create_layout(tmp_path)
    graph = validate_layout(layout, reference="candidate")
    blob = layout / "blobs" / "sha256" / graph.digest.encoded
    blob.write_bytes(blob.read_bytes() + b"x")
    with pytest.raises(InvalidInvocationError, match="size mismatch"):
        validate_layout(layout, reference="candidate")


def test_layout_validator_bounds_json_blob_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = _create_layout(tmp_path, config_padding=4096)
    monkeypatch.setattr(oci_module, "MAX_OCI_JSON_BYTES", 2048)

    with pytest.raises(InvalidInvocationError, match="JSON blob exceeds"):
        validate_layout(layout, reference="candidate")


def test_layout_validator_bounds_descriptor_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = _create_layout(tmp_path)
    monkeypatch.setattr(oci_module, "MAX_OCI_GRAPH_DESCRIPTORS", 1)

    with pytest.raises(InvalidInvocationError, match="graph exceeds the size limit"):
        validate_layout(layout, reference="candidate")


@given(architecture=st.sampled_from(["arm64", "arm", "ppc64le", "s390x"]))
def test_layout_validator_rejects_descriptor_config_platform_mismatch(
    architecture: str,
) -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        layout = _create_layout(Path(temporary_directory), architecture=architecture)
        index_path = layout / "index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["manifests"][0]["platform"]["architecture"] = "amd64"
        index_path.write_text(json.dumps(index), encoding="utf-8")
        with pytest.raises(InvalidInvocationError, match="does not match"):
            validate_layout(layout, reference="candidate")
