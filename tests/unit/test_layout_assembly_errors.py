"""Exact-layout assembly refuses mismatched, duplicated and altered inputs."""

from pathlib import Path

import pytest

import conclear.layout_assembly as assembly_module
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.layout_assembly import PlatformLayout, assemble_layout
from conclear.oci import Descriptor, validate_layout
from conclear.values import Digest, Platform
from tests.unit.test_publication import platform_layout

AMD64 = Platform.parse("linux/amd64")
ARM64 = Platform.parse("linux/arm64")


def test_assembly_requires_unique_platform_inputs_and_a_new_output(
    tmp_path: Path,
) -> None:
    amd64 = platform_layout(tmp_path / "amd64", "amd64")

    with pytest.raises(InvalidInvocationError, match="at least one platform"):
        assemble_layout((), output_path=tmp_path / "out", output_reference="candidate")
    with pytest.raises(InvalidInvocationError, match="duplicate platform"):
        assemble_layout(
            (
                PlatformLayout(AMD64, amd64, "qualified"),
                PlatformLayout(AMD64, amd64, "qualified"),
            ),
            output_path=tmp_path / "out",
            output_reference="candidate",
        )
    (tmp_path / "taken").mkdir()
    with pytest.raises(InvalidInvocationError, match="already exists"):
        assemble_layout(
            (PlatformLayout(AMD64, amd64, "qualified"),),
            output_path=tmp_path / "taken",
            output_reference="candidate",
        )


def test_assembly_rejects_layouts_that_do_not_match_their_declared_platform(
    tmp_path: Path,
) -> None:
    arm64 = platform_layout(tmp_path / "arm64", "arm64")

    with pytest.raises(InvalidInvocationError, match="contains linux/arm64"):
        assemble_layout(
            (PlatformLayout(AMD64, arm64, "qualified"),),
            output_path=tmp_path / "out",
            output_reference="candidate",
        )


def test_assembly_rejects_an_index_as_a_platform_input(tmp_path: Path) -> None:
    amd64 = platform_layout(tmp_path / "amd64", "amd64")
    arm64 = platform_layout(tmp_path / "arm64", "arm64")
    index = assemble_layout(
        (
            PlatformLayout(AMD64, amd64, "qualified"),
            PlatformLayout(ARM64, arm64, "qualified"),
        ),
        output_path=tmp_path / "index",
        output_reference="candidate",
    )
    assert index.graph.platforms == (AMD64, ARM64)

    with pytest.raises(InvalidInvocationError, match="select one image manifest"):
        assemble_layout(
            (PlatformLayout(AMD64, index.path, "candidate"),),
            output_path=tmp_path / "out",
            output_reference="candidate",
        )


def test_blob_copies_verify_size_digest_and_regular_files(tmp_path: Path) -> None:
    amd64 = platform_layout(tmp_path / "amd64", "amd64")
    graph = validate_layout(amd64, reference="qualified")
    descriptor = graph.root
    source = amd64 / "blobs" / "sha256" / descriptor.digest.encoded
    destination_root = tmp_path / "destination"
    destination_root.mkdir()

    wrong_digest = Descriptor(
        descriptor.media_type, Digest("sha256:" + "0" * 64), descriptor.size
    )
    with pytest.raises(InvalidInvocationError, match="changed after layout validation"):
        assembly_module._copy_validated_blob(
            source, destination_root / "copy", wrong_digest
        )
    assert list(destination_root.iterdir()) == []

    wrong_size = Descriptor(
        descriptor.media_type, descriptor.digest, descriptor.size + 1
    )
    with pytest.raises(InvalidInvocationError, match="size changed"):
        assembly_module._validate_blob(source, wrong_size)

    with pytest.raises(InvalidInvocationError, match="not regular"):
        assembly_module._validate_blob(amd64, descriptor)

    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(OperationalError, match="Unable to read assembly blob"):
        assembly_module._validate_blob(link, descriptor)
    with pytest.raises(OperationalError, match="Unable to copy assembly blob"):
        assembly_module._copy_validated_blob(
            tmp_path / "missing", destination_root / "copy", descriptor
        )

    assembly_module._copy_validated_blob(source, destination_root / "copy", descriptor)
    assert (destination_root / "copy").read_bytes() == source.read_bytes()
    assembly_module._validate_blob(destination_root / "copy", descriptor)


def test_existing_destination_blobs_are_revalidated_not_overwritten(
    tmp_path: Path,
) -> None:
    amd64 = platform_layout(tmp_path / "amd64", "amd64")
    graph = validate_layout(amd64, reference="qualified")
    destination = tmp_path / "out"
    blobs = destination / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    config = graph.manifests[0].config
    (blobs / config.digest.encoded).write_bytes(b"x" * config.size)

    with pytest.raises(InvalidInvocationError, match="changed after layout validation"):
        assembly_module._copy_graph_blobs(amd64, graph, destination)

    (blobs / config.digest.encoded).unlink()
    (blobs / config.digest.encoded).mkdir()
    with pytest.raises(InvalidInvocationError, match="not regular"):
        assembly_module._copy_graph_blobs(amd64, graph, destination)
