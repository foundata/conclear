import json
from pathlib import Path

import pytest

from conclear.assembly import PlatformLayout, assemble_layout
from conclear.errors import InvalidInvocationError
from conclear.jsonutil import canonical_json_bytes, sha256_bytes
from conclear.oci import OCI_CONFIG, OCI_INDEX, OCI_MANIFEST
from conclear.values import Platform


def write_blob(layout: Path, content: bytes) -> tuple[str, int]:
    digest = sha256_bytes(content)
    path = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return digest, len(content)


def platform_layout(root: Path, architecture: str) -> Path:
    root.mkdir()
    (root / "oci-layout").write_text(
        '{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8"
    )
    config, config_size = write_blob(
        root,
        canonical_json_bytes(
            {
                "architecture": architecture,
                "os": "linux",
                "config": {"User": "10001"},
                "rootfs": {"type": "layers", "diff_ids": []},
            }
        ),
    )
    manifest, manifest_size = write_blob(
        root,
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
    (root / "index.json").write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": OCI_MANIFEST,
                        "digest": manifest,
                        "size": manifest_size,
                        "platform": {"os": "linux", "architecture": architecture},
                        "annotations": {
                            "org.opencontainers.image.ref.name": "qualified"
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return root


def test_assembly_preserves_platform_manifests_and_creates_index(
    tmp_path: Path,
) -> None:
    amd64 = platform_layout(tmp_path / "amd64", "amd64")
    arm64 = platform_layout(tmp_path / "arm64", "arm64")

    observation = assemble_layout(
        (
            PlatformLayout(Platform.parse("linux/amd64"), amd64, "qualified"),
            PlatformLayout(Platform.parse("linux/arm64"), arm64, "qualified"),
        ),
        output_path=tmp_path / "assembled",
        output_reference="candidate",
    )

    assert observation.graph.root.media_type == OCI_INDEX
    assert observation.graph.platforms == (
        Platform.parse("linux/amd64"),
        Platform.parse("linux/arm64"),
    )
    assert len(observation.platform_manifests) == 2


def test_assembly_rejects_duplicate_platform(tmp_path: Path) -> None:
    layout = platform_layout(tmp_path / "amd64", "amd64")
    item = PlatformLayout(Platform.parse("linux/amd64"), layout, "qualified")

    with pytest.raises(InvalidInvocationError, match="duplicate platform"):
        assemble_layout(
            (item, item),
            output_path=tmp_path / "assembled",
            output_reference="candidate",
        )
