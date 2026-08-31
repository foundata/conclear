"""Verified assembly of platform OCI layouts into one release subject."""

import hashlib
import os
import stat
import tempfile
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
            destination_stat = destination_path.lstat()
        except FileNotFoundError:
            _copy_validated_blob(source_path, destination_path, descriptor)
            continue
        except OSError as exc:
            raise OperationalError(
                f"Unable to inspect assembly blob {destination_path}"
            ) from exc
        if not stat.S_ISREG(destination_stat.st_mode):
            raise InvalidInvocationError(
                f"Assembly destination blob is not regular: {destination_path}"
            )
        _validate_blob(source_path, descriptor)
        _validate_blob(destination_path, descriptor)


def _copy_validated_blob(
    source: Path, destination: Path, descriptor: Descriptor
) -> None:
    source_descriptor: int | None = None
    output_descriptor: int | None = None
    temporary_path: Path | None = None
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        source_descriptor = os.open(source, flags)
        initial = _require_blob_stat(source_descriptor, source, descriptor)
        output_descriptor, temporary_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        os.fchmod(output_descriptor, 0o644)
        digest = hashlib.sha256()
        size = 0
        with (
            os.fdopen(source_descriptor, "rb") as input_stream,
            os.fdopen(output_descriptor, "wb") as output_stream,
        ):
            source_descriptor = None
            output_descriptor = None
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
                output_stream.write(chunk)
            finished = os.fstat(input_stream.fileno())
            output_stream.flush()
            os.fsync(output_stream.fileno())
        if not _same_blob_stat(initial, finished):
            raise OperationalError(
                f"Assembly source blob changed while copying: {source}"
            )
        _require_observed_blob(size, digest.hexdigest(), descriptor)
        temporary_path.replace(destination)
        temporary_path = None
        directory_descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise OperationalError(f"Unable to copy assembly blob {source}") from exc
    finally:
        if source_descriptor is not None:
            try:
                os.close(source_descriptor)
            except OSError:
                pass
        if output_descriptor is not None:
            try:
                os.close(output_descriptor)
            except OSError:
                pass
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def _validate_blob(path: Path, descriptor: Descriptor) -> None:
    file_descriptor: int | None = None
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        file_descriptor = os.open(path, flags)
        initial = _require_blob_stat(file_descriptor, path, descriptor)
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(file_descriptor, "rb") as stream:
            file_descriptor = None
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
            finished = os.fstat(stream.fileno())
        if not _same_blob_stat(initial, finished):
            raise OperationalError(f"Assembly blob changed while reading: {path}")
        _require_observed_blob(size, digest.hexdigest(), descriptor)
    except OSError as exc:
        raise OperationalError(f"Unable to read assembly blob {path}") from exc
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass


def _require_blob_stat(
    file_descriptor: int, path: Path, descriptor: Descriptor
) -> os.stat_result:
    observed = os.fstat(file_descriptor)
    if not stat.S_ISREG(observed.st_mode):
        raise InvalidInvocationError(f"Assembly blob is not regular: {path}")
    if observed.st_size != descriptor.size:
        raise InvalidInvocationError(
            f"Assembly blob size changed for {descriptor.digest}"
        )
    return observed


def _require_observed_blob(
    size: int, encoded_digest: str, descriptor: Descriptor
) -> None:
    if size != descriptor.size or f"sha256:{encoded_digest}" != str(descriptor.digest):
        raise InvalidInvocationError(
            f"Assembly blob changed after layout validation: {descriptor.digest}"
        )


def _same_blob_stat(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and first.st_mode == second.st_mode
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )
