"""Verified assembly of platform OCI layouts into one release subject."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    sha256_bytes,
)
from conclear.oci import (
    OCI_INDEX,
    OCI_MANIFEST,
    Descriptor,
    OCIGraph,
    validate_layout,
)
from conclear.values import Digest, Platform


@dataclass(frozen=True, slots=True)
class PlatformLayout:
    """One accepted platform layout and selected reference."""

    platform: Platform
    path: Path
    reference: str


@dataclass(frozen=True, slots=True)
class AssemblyObservation:
    """One completely revalidated assembled OCI subject."""

    path: Path
    reference: str
    graph: OCIGraph
    platform_manifests: tuple[tuple[Platform, Digest], ...]


def assemble_layout(
    inputs: tuple[PlatformLayout, ...],
    *,
    output_path: Path,
    output_reference: str,
) -> AssemblyObservation:
    """Assemble exact platform manifests without rebuilding or rewriting them."""
    if not inputs:
        raise InvalidInvocationError("Assembly requires at least one platform layout")
    platforms = [item.platform for item in inputs]
    if len(platforms) != len(set(platforms)):
        raise InvalidInvocationError("Assembly contains duplicate platform inputs")
    if output_path.exists():
        raise InvalidInvocationError(f"Assembly output already exists: {output_path}")
    output_path.mkdir(mode=0o700, parents=True)
    (output_path / "blobs" / "sha256").mkdir(mode=0o700, parents=True)
    validated: list[tuple[PlatformLayout, OCIGraph, Descriptor]] = []
    for item in sorted(inputs, key=lambda value: value.platform):
        graph = validate_layout(item.path, reference=item.reference)
        if graph.root.media_type != OCI_MANIFEST or len(graph.manifests) != 1:
            raise InvalidInvocationError(
                f"Platform input {item.platform} must select one image manifest"
            )
        manifest = graph.manifests[0]
        if manifest.platform != item.platform:
            raise InvalidInvocationError(
                f"Platform input {item.platform} contains {manifest.platform}"
            )
        descriptor = Descriptor(
            media_type=graph.root.media_type,
            digest=graph.root.digest,
            size=graph.root.size,
            platform=item.platform,
        )
        validated.append((item, graph, descriptor))
        _copy_graph_blobs(item.path, graph, output_path)
    descriptors = [item[2] for item in validated]
    if len(descriptors) == 1:
        subject = descriptors[0]
    else:
        content = canonical_json_bytes(
            {
                "schemaVersion": 2,
                "mediaType": OCI_INDEX,
                "manifests": [descriptor.to_dict() for descriptor in descriptors],
            }
        )
        digest = Digest(sha256_bytes(content))
        atomic_write_bytes(
            output_path / "blobs" / "sha256" / digest.encoded,
            content,
            mode=0o644,
        )
        subject = Descriptor(OCI_INDEX, digest, len(content))
    root = subject.to_dict()
    root["annotations"] = {"org.opencontainers.image.ref.name": output_reference}
    atomic_write_json(
        output_path / "index.json",
        {"schemaVersion": 2, "manifests": [root]},
        mode=0o644,
    )
    atomic_write_json(
        output_path / "oci-layout", {"imageLayoutVersion": "1.0.0"}, mode=0o644
    )
    graph = validate_layout(output_path, reference=output_reference)
    return AssemblyObservation(
        path=output_path,
        reference=output_reference,
        graph=graph,
        platform_manifests=tuple(
            (item.platform, descriptor.digest) for item, _graph, descriptor in validated
        ),
    )


def _copy_graph_blobs(source: Path, graph: OCIGraph, destination: Path) -> None:
    for descriptor in graph.descriptors:
        source_path = source / "blobs" / "sha256" / descriptor.digest.encoded
        destination_path = destination / "blobs" / "sha256" / descriptor.digest.encoded
        try:
            source_stat = source_path.lstat()
        except OSError as exc:
            raise OperationalError(
                f"Unable to inspect assembly blob {source_path}"
            ) from exc
        if not stat.S_ISREG(source_stat.st_mode):
            raise InvalidInvocationError(f"Assembly blob is not regular: {source_path}")
        if destination_path.exists():
            if destination_path.read_bytes() != source_path.read_bytes():
                raise InvalidInvocationError(
                    f"Conflicting assembly blob content for {descriptor.digest}"
                )
            continue
        try:
            descriptor_fd = os.open(
                source_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            with os.fdopen(descriptor_fd, "rb") as stream:
                content = stream.read()
        except OSError as exc:
            raise OperationalError(
                f"Unable to read assembly blob {source_path}"
            ) from exc
        if len(content) != descriptor.size or sha256_bytes(content) != str(
            descriptor.digest
        ):
            raise InvalidInvocationError(
                f"Assembly blob changed after layout validation: {descriptor.digest}"
            )
        atomic_write_bytes(destination_path, content, mode=0o644)
