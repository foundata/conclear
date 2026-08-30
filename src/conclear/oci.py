"""Recursive validation of OCI image layouts and descriptor graphs."""

import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import sha256_bytes
from conclear.values import Digest, Platform

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYOUT_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class Descriptor:
    """A validated OCI content descriptor."""

    media_type: str
    digest: Digest
    size: int
    platform: Platform | None = None
    annotations: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_untrusted(cls, value: object) -> "Descriptor":
        """Validate an untrusted descriptor object."""
        item = _object(value, "descriptor")
        media_type = _string(item.get("mediaType"), "descriptor.mediaType")
        digest = Digest(_string(item.get("digest"), "descriptor.digest"))
        size = _integer(item.get("size"), "descriptor.size")
        if size < 0:
            raise InvalidInvocationError("OCI descriptor size cannot be negative")
        platform: Platform | None = None
        platform_value = item.get("platform")
        if platform_value is not None:
            platform_item = _object(platform_value, "descriptor.platform")
            operating_system = _string(platform_item.get("os"), "platform.os")
            architecture = _string(
                platform_item.get("architecture"),
                "platform.architecture",
            )
            variant_value = platform_item.get("variant")
            variant = (
                _string(variant_value, "platform.variant")
                if variant_value is not None
                else None
            )
            platform = Platform(
                os=operating_system,
                architecture=architecture,
                variant=variant,
            )
            Platform.parse(str(platform))
        annotations_value = item.get("annotations", {})
        annotations_item = _object(annotations_value, "descriptor.annotations")
        annotations: list[tuple[str, str]] = []
        for key, annotation_value in annotations_item.items():
            if not isinstance(annotation_value, str):
                raise InvalidInvocationError(
                    "OCI descriptor annotations must be strings"
                )
            annotations.append((key, annotation_value))
        return cls(
            media_type=media_type,
            digest=digest,
            size=size,
            platform=platform,
            annotations=tuple(sorted(annotations)),
        )

    def annotation(self, name: str) -> str | None:
        """Return one descriptor annotation when present."""
        return dict(self.annotations).get(name)

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic public descriptor object."""
        value: dict[str, object] = {
            "mediaType": self.media_type,
            "digest": str(self.digest),
            "size": self.size,
        }
        if self.platform is not None:
            platform: dict[str, object] = {
                "os": self.platform.os,
                "architecture": self.platform.architecture,
            }
            if self.platform.variant is not None:
                platform["variant"] = self.platform.variant
            value["platform"] = platform
        if self.annotations:
            value["annotations"] = dict(self.annotations)
        return value


@dataclass(frozen=True, slots=True)
class ManifestObservation:
    """One image manifest and its observed configuration platform."""

    descriptor: Descriptor
    platform: Platform
    config: Descriptor
    layers: tuple[Descriptor, ...]
    config_data: dict[str, object]


@dataclass(frozen=True, slots=True)
class OCIGraph:
    """A recursively verified OCI descriptor graph."""

    root: Descriptor
    descriptors: tuple[Descriptor, ...]
    manifests: tuple[ManifestObservation, ...]

    @property
    def digest(self) -> Digest:
        """Return the selected root content digest."""
        return self.root.digest

    @property
    def platforms(self) -> tuple[Platform, ...]:
        """Return manifest platforms in deterministic order."""
        return tuple(sorted(manifest.platform for manifest in self.manifests))


class LayoutValidator:
    """Validate an OCI image layout without trusting paths or JSON types."""

    def __init__(self, layout_path: Path) -> None:
        """Create a validator rooted at one existing layout directory."""
        self._layout_path = layout_path.resolve(strict=True)
        self._descriptors: dict[Digest, Descriptor] = {}
        self._manifests: dict[Digest, ManifestObservation] = {}
        self._visiting: set[Digest] = set()

    def validate(self, *, reference: str | None = None) -> OCIGraph:
        """Validate the layout recursively and select one root descriptor."""
        layout_header = self._read_json_file(self._layout_path / "oci-layout")
        if layout_header != {"imageLayoutVersion": OCI_LAYOUT_VERSION}:
            raise InvalidInvocationError(
                f"Unsupported or malformed OCI layout header in {self._layout_path}"
            )
        index = _object(
            self._read_json_file(self._layout_path / "index.json"),
            "index.json",
        )
        if _integer(index.get("schemaVersion"), "index.schemaVersion") != 2:
            raise InvalidInvocationError("OCI layout index must use schemaVersion 2")
        descriptors_value = _array(index.get("manifests"), "index.manifests")
        roots = [Descriptor.from_untrusted(value) for value in descriptors_value]
        if reference is not None:
            roots = [
                descriptor
                for descriptor in roots
                if descriptor.annotation("org.opencontainers.image.ref.name")
                == reference
            ]
        if len(roots) != 1:
            requested = f" for reference {reference}" if reference is not None else ""
            raise InvalidInvocationError(
                f"OCI layout must select exactly one root descriptor{requested}"
            )
        root = roots[0]
        if root.media_type not in {OCI_INDEX, OCI_MANIFEST}:
            raise InvalidInvocationError(
                "Selected OCI layout root is not an image or index"
            )
        self._walk(root, inherited_platform=root.platform)
        platforms = [manifest.platform for manifest in self._manifests.values()]
        if len(platforms) != len(set(platforms)):
            raise InvalidInvocationError("OCI graph contains duplicate image platforms")
        return OCIGraph(
            root=root,
            descriptors=tuple(
                sorted(self._descriptors.values(), key=lambda item: str(item.digest))
            ),
            manifests=tuple(
                sorted(
                    self._manifests.values(),
                    key=lambda item: str(item.platform),
                )
            ),
        )

    def _walk(
        self, descriptor: Descriptor, *, inherited_platform: Platform | None
    ) -> None:
        existing = self._descriptors.get(descriptor.digest)
        if existing is not None:
            if existing != descriptor:
                raise InvalidInvocationError(
                    f"Conflicting OCI descriptors for {descriptor.digest}"
                )
            return
        if descriptor.digest in self._visiting:
            raise InvalidInvocationError("OCI descriptor graph contains a cycle")
        self._visiting.add(descriptor.digest)
        content = self._read_blob(descriptor)
        self._descriptors[descriptor.digest] = descriptor
        if descriptor.media_type == OCI_INDEX:
            index = _object(_decode_json(content, descriptor.digest), "image index")
            if _integer(index.get("schemaVersion"), "index.schemaVersion") != 2:
                raise InvalidInvocationError("OCI image index must use schemaVersion 2")
            children = _array(index.get("manifests"), "index.manifests")
            if not children:
                raise InvalidInvocationError("OCI image index cannot be empty")
            for child_value in children:
                child = Descriptor.from_untrusted(child_value)
                if child.media_type not in {OCI_INDEX, OCI_MANIFEST}:
                    raise InvalidInvocationError(
                        "Release image indexes may reference only image indexes or manifests"
                    )
                self._walk(
                    child, inherited_platform=child.platform or inherited_platform
                )
        elif descriptor.media_type == OCI_MANIFEST:
            self._validate_manifest(descriptor, content, inherited_platform)
        self._visiting.remove(descriptor.digest)

    def _validate_manifest(
        self,
        descriptor: Descriptor,
        content: bytes,
        inherited_platform: Platform | None,
    ) -> None:
        manifest = _object(_decode_json(content, descriptor.digest), "image manifest")
        if _integer(manifest.get("schemaVersion"), "manifest.schemaVersion") != 2:
            raise InvalidInvocationError("OCI image manifest must use schemaVersion 2")
        config = Descriptor.from_untrusted(manifest.get("config"))
        if config.media_type != OCI_CONFIG:
            raise InvalidInvocationError(
                "OCI image manifest has a non-image configuration"
            )
        config_content = self._read_blob(config)
        self._descriptors[config.digest] = config
        config_value = _object(
            _decode_json(config_content, config.digest), "image config"
        )
        operating_system = _string(config_value.get("os"), "config.os")
        architecture = _string(config_value.get("architecture"), "config.architecture")
        variant_value = config_value.get("variant")
        variant = (
            _string(variant_value, "config.variant")
            if variant_value is not None
            else None
        )
        platform = Platform(operating_system, architecture, variant)
        Platform.parse(str(platform))
        declared_platform = descriptor.platform or inherited_platform
        if declared_platform is not None and declared_platform != platform:
            raise InvalidInvocationError(
                f"OCI descriptor platform {declared_platform} does not match config {platform}"
            )
        layer_values = _array(manifest.get("layers"), "manifest.layers")
        layers = tuple(Descriptor.from_untrusted(value) for value in layer_values)
        for layer in layers:
            self._read_blob(layer)
            self._descriptors[layer.digest] = layer
        self._manifests[descriptor.digest] = ManifestObservation(
            descriptor=descriptor,
            platform=platform,
            config=config,
            layers=layers,
            config_data=config_value,
        )

    def _read_blob(self, descriptor: Descriptor) -> bytes:
        path = (
            self._layout_path
            / "blobs"
            / descriptor.digest.algorithm
            / descriptor.digest.encoded
        )
        try:
            file_stat = path.lstat()
            if not stat.S_ISREG(file_stat.st_mode):
                raise InvalidInvocationError(f"OCI blob is not a regular file: {path}")
            content = path.read_bytes()
        except OSError as exc:
            raise OperationalError(
                f"Unable to read OCI blob {descriptor.digest}"
            ) from exc
        if len(content) != descriptor.size:
            raise InvalidInvocationError(
                f"OCI blob size mismatch for {descriptor.digest}: "
                f"expected {descriptor.size}, observed {len(content)}"
            )
        observed = sha256_bytes(content)
        if observed != str(descriptor.digest):
            raise InvalidInvocationError(
                f"OCI blob digest mismatch for {descriptor.digest}: observed {observed}"
            )
        return content

    @staticmethod
    def _read_json_file(path: Path) -> object:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise InvalidInvocationError(
                f"Unable to decode OCI JSON file {path}"
            ) from exc


def graph_fingerprint(graph: OCIGraph) -> tuple[tuple[object, ...], ...]:
    """Return the complete descriptor graph in a representation-safe form."""
    return tuple(
        sorted(
            (
                descriptor.media_type,
                str(descriptor.digest),
                descriptor.size,
                str(descriptor.platform) if descriptor.platform is not None else None,
            )
            for descriptor in graph.descriptors
        )
    )


def validate_layout(layout_path: Path, *, reference: str | None = None) -> OCIGraph:
    """Validate an OCI image layout and return its verified graph."""
    return LayoutValidator(layout_path).validate(reference=reference)


def _decode_json(content: bytes, digest: Digest) -> object:
    try:
        return json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InvalidInvocationError(f"OCI JSON blob is malformed: {digest}") from exc


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise InvalidInvocationError(f"{label} must be a JSON object")
    return value


def _array(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise InvalidInvocationError(f"{label} must be a JSON array")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidInvocationError(f"{label} must be a non-empty string")
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidInvocationError(f"{label} must be an integer")
    return value
