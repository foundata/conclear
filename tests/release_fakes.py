"""Stateful adapter fakes for complete hermetic release workflows."""

import base64
import json
from datetime import datetime
from pathlib import Path
from typing import Any, override

from conclear.adapters.buildah import BuildObservation
from conclear.adapters.cosign import (
    CosignAdapter,
    SignatureObservation,
    VerificationObservation,
)
from conclear.adapters.hadolint import HadolintFinding
from conclear.adapters.podman import (
    ContainerObservation,
    ImportObservation,
    RuntimeControlObservation,
)
from conclear.adapters.skopeo import RegistryCopyObservation
from conclear.adapters.trivy import DatabaseObservation, ScanObservation
from conclear.attestations import SPDX_DOCUMENT_TYPE, STATEMENT_TYPE
from conclear.errors import OperationalError
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
)
from conclear.oci import OCI_CONFIG, OCI_MANIFEST, OCIGraph, validate_layout
from conclear.process import CommandRequest, ProcessResult
from conclear.records import ToolIdentity
from conclear.registry_control import TagObservation
from conclear.values import Digest, OCIReference, Platform

DATABASE_METADATA: dict[str, object] = {
    name: {
        "schemaVersion": version,
        "updatedAt": "2026-01-01T00:00:00Z",
        "nextUpdate": "2026-01-02T00:00:00Z",
        "downloadedAt": "2026-01-01T00:01:00Z",
    }
    for name, version in (("vulnerability", 2), ("java", 1))
}


def _write_blob(layout: Path, content: bytes) -> tuple[str, int]:
    digest = sha256_bytes(content)
    path = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return digest, len(content)


class FakeBuilder:
    """Produce one valid OCI layout from observed build inputs."""

    def build(self, **values: Any) -> BuildObservation:
        layout = values["layout_path"]
        platform = values["platform"]
        build_arguments = values["build_arguments"]
        if not isinstance(layout, Path):
            raise AssertionError("layout path is not a Path")
        if not isinstance(platform, Platform):
            raise AssertionError("platform is not validated")
        if not isinstance(build_arguments, dict):
            raise AssertionError("build arguments are not validated")
        layout.mkdir(parents=True)
        (layout / "oci-layout").write_text(
            '{"imageLayoutVersion":"1.0.0"}\n', encoding="utf-8"
        )
        labels = {
            "org.opencontainers.image.source": "https://github.com/example/app",
            "org.opencontainers.image.revision": build_arguments["IMAGE_REVISION"],
            "org.opencontainers.image.created": build_arguments["IMAGE_CREATED"],
            "org.opencontainers.image.version": build_arguments["IMAGE_VERSION"],
            "org.opencontainers.image.licenses": "GPL-3.0-or-later",
            "org.opencontainers.image.title": "Example",
        }
        config, config_size = _write_blob(
            layout,
            canonical_json_bytes(
                {
                    "architecture": platform.architecture,
                    "os": platform.os,
                    "config": {"User": "10001", "Labels": labels},
                    "rootfs": {"type": "layers", "diff_ids": []},
                }
            ),
        )
        manifest, manifest_size = _write_blob(
            layout,
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
        (layout / "index.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "manifests": [
                        {
                            "mediaType": OCI_MANIFEST,
                            "digest": manifest,
                            "size": manifest_size,
                            "platform": {
                                "os": platform.os,
                                "architecture": platform.architecture,
                            },
                            "annotations": {
                                "org.opencontainers.image.ref.name": "qualified"
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        graph = validate_layout(layout, reference="qualified")
        return BuildObservation(
            image_name=str(values["image_name"]),
            layout_path=layout,
            graph=graph,
            build_arguments=tuple(sorted(build_arguments.items())),
        )


class FakePodman:
    """Return effective runtime observations for one run-owned container."""

    def import_layout(self, **values: Any) -> ImportObservation:
        return ImportObservation(str(values["image_name"]), values["expected_digest"])

    def create_container(self, **values: Any) -> ContainerObservation:
        return ContainerObservation(
            str(values["name"]), "container-id", "running", 100, None
        )

    def inspect_controls(self, **values: Any) -> RuntimeControlObservation:
        del values
        return RuntimeControlObservation(
            user="10001",
            read_only=True,
            writable_mounts=(),
            memory_bytes=512 * 1024 * 1024,
            nano_cpus=1_000_000_000,
            pids_limit=128,
            nofile_soft=1024,
            nofile_hard=1024,
            cap_add=(),
            cap_drop=("ALL",),
            effective_capabilities=(),
            security_options=("no-new-privileges",),
        )

    def exec(self, **values: Any) -> str:
        del values
        return ""

    def signal(self, **values: Any) -> None:
        del values

    def wait(self, **values: Any) -> int:
        del values
        return 0

    def remove(self, **values: Any) -> None:
        del values

    def remove_storage(self, **values: Any) -> None:
        del values


class FakeTrivy:
    """Provide one immutable database and empty successful scan observations."""

    def select_database(self, cache_root: Path) -> DatabaseObservation:
        cache_root.mkdir(parents=True, exist_ok=True)
        return DatabaseObservation(cache_root, "sha256:" + "e" * 64, DATABASE_METADATA)

    def refresh_database(self, cache_root: Path) -> DatabaseObservation:
        return self.select_database(cache_root)

    def scan_filesystem(self, **values: Any) -> ScanObservation:
        report_path = values["report_path"]
        if not isinstance(report_path, Path):
            raise AssertionError("scan report path is not a Path")
        return self._write(
            report_path,
            {"ArtifactName": report_path.stem, "Results": []},
        )

    def scan_layout(self, **values: Any) -> ScanObservation:
        report_path = values["report_path"]
        if not isinstance(report_path, Path):
            raise AssertionError("scan report path is not a Path")
        return self._write(
            report_path,
            {"ArtifactName": report_path.stem, "Results": []},
        )

    def generate_spdx(self, **values: Any) -> ScanObservation:
        return self._write(
            values["output_path"],
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "app",
                "documentNamespace": "https://example.invalid/spdx/app",
                "creationInfo": {
                    "creators": ["Tool: test"],
                    "created": "2026-01-01T00:00:00Z",
                },
            },
        )

    @staticmethod
    def _write(path_value: object, value: object) -> ScanObservation:
        if not isinstance(path_value, Path):
            raise AssertionError("scan output path is not a Path")
        atomic_write_json(path_value, value, mode=0o644)
        return ScanObservation(path_value, sha256_file(path_value), value)


class FakeHadolint:
    """Return no external lint diagnostics."""

    def check(self, containerfile: Path) -> tuple[HadolintFinding, ...]:
        if not containerfile.is_file():
            raise AssertionError("Containerfile is unavailable")
        return ()


class NoopRunner:
    """Reject unexpected repository hook execution."""

    def run(self, request: CommandRequest) -> ProcessResult:
        raise AssertionError(f"Unexpected repository hook: {request.argv}")


class FakeRegistry:
    """Track registry tags and one copied OCI graph in memory."""

    def __init__(self, pin_digest: Digest) -> None:
        self.pin_digest = pin_digest
        self.graph: OCIGraph | None = None
        self.tags: dict[str, Digest] = {}

    def resolve_digest(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest:
        del auth_file
        if reference.digest is not None:
            return reference.digest
        if reference.repository_name == "quay.io/example/base":
            return self.pin_digest
        if reference.tag is None or reference.tag not in self.tags:
            raise OperationalError(f"Fake registry has no tag: {reference}")
        return self.tags[reference.tag]

    def resolve_optional(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest | None:
        del auth_file
        return None if reference.tag is None else self.tags.get(reference.tag)

    def copy_layout_to_registry(
        self,
        *,
        layout_path: Path,
        layout_reference: str,
        destination: OCIReference,
        auth_file: Path | None,
    ) -> None:
        del auth_file
        if destination.tag is None:
            raise AssertionError("publication destination has no tag")
        self.graph = validate_layout(layout_path, reference=layout_reference)
        self.tags[destination.tag] = self.graph.digest

    def copy_registry_to_layout(
        self,
        *,
        source: OCIReference,
        layout_path: Path,
        layout_reference: str,
        auth_file: Path | None,
    ) -> RegistryCopyObservation:
        del layout_reference, auth_file
        if self.graph is None:
            raise OperationalError("Fake registry has no published graph")
        return RegistryCopyObservation(source, layout_path, self.graph)


class FakeRegistryControl:
    """Observe tag controls without network access."""

    def __init__(self, tags: dict[str, Digest]) -> None:
        self.tags = tags
        self.expirations: dict[str, datetime] = {}
        self.immutable: set[str] = set()
        self.closed = False

    @property
    def provider(self) -> str:
        return "quay"

    def observe_tag(self, repository: OCIReference, tag: str) -> TagObservation | None:
        del repository
        digest = self.tags.get(tag)
        if digest is None:
            return None
        return TagObservation(
            tag,
            digest,
            self.expirations.get(tag),
            tag in self.immutable,
        )

    def enforce_candidate_lifetime(
        self, repository: OCIReference, tag: str, expiration: datetime
    ) -> TagObservation:
        self.expirations[tag] = expiration
        observed = self.observe_tag(repository, tag)
        if observed is None:
            raise AssertionError("expiration target is absent")
        return observed

    def ensure_tag_immutable(
        self, repository: OCIReference, tag: str
    ) -> TagObservation:
        self.immutable.add(tag)
        observed = self.observe_tag(repository, tag)
        if observed is None:
            raise AssertionError("immutability target is absent")
        return observed

    def ensure_tag_mutable(self, repository: OCIReference, tag: str) -> TagObservation:
        self.immutable.discard(tag)
        observed = self.observe_tag(repository, tag)
        if observed is None:
            raise AssertionError("mutability target is absent")
        return observed

    def assign_tag(
        self, repository: OCIReference, tag: str, digest: Digest
    ) -> TagObservation:
        self.tags[tag] = digest
        observed = self.observe_tag(repository, tag)
        if observed is None:
            raise AssertionError("written tag is absent")
        return observed

    def remove_tag(self, repository: OCIReference, tag: str) -> None:
        del repository
        self.tags.pop(tag, None)
        self.expirations.pop(tag, None)
        self.immutable.discard(tag)

    def close(self) -> None:
        self.closed = True


class FakeSigner(CosignAdapter):
    """Store signatures and real-shape DSSE statements in memory."""

    def __init__(self) -> None:
        self.statements: dict[tuple[str, str], list[dict[str, object]]] = {}
        self.signatures: set[str] = set()

    @override
    def sign(
        self,
        *,
        subject: OCIReference,
        private_key: str,
        passphrase: str | None,
        passphrase_path: Path | None = None,
    ) -> SignatureObservation:
        del private_key, passphrase, passphrase_path
        self.signatures.add(str(subject))
        return SignatureObservation(subject, "signed")

    @override
    def attest(
        self,
        *,
        subject: OCIReference,
        predicate: Path,
        predicate_type: str,
        private_key: str,
        passphrase: str | None,
        passphrase_path: Path | None = None,
    ) -> SignatureObservation:
        del private_key, passphrase, passphrase_path
        statement_type = (
            SPDX_DOCUMENT_TYPE if predicate_type == "spdxjson" else predicate_type
        )
        self._store(subject, statement_type, load_json(predicate))
        return SignatureObservation(subject, "attested")

    @override
    def attest_statement(
        self,
        *,
        subject: OCIReference,
        statement: Path,
        private_key: str,
        passphrase: str | None,
        passphrase_path: Path | None = None,
    ) -> SignatureObservation:
        del private_key, passphrase, passphrase_path
        value = load_json(statement)
        if not isinstance(value, dict) or not isinstance(
            value.get("predicateType"), str
        ):
            raise AssertionError("statement is malformed")
        self.statements.setdefault(
            (str(subject), str(value["predicateType"])), []
        ).append({str(key): item for key, item in value.items()})
        return SignatureObservation(subject, "attested")

    @override
    def verify(
        self, *, subject: OCIReference, public_key: Path
    ) -> VerificationObservation:
        if not public_key.is_file() or str(subject) not in self.signatures:
            raise OperationalError("Fake signature verification failed")
        return VerificationObservation(subject, (self._verification_entry(subject),))

    @override
    def verify_attestation(
        self,
        *,
        subject: OCIReference,
        public_key: Path,
        predicate_type: str,
    ) -> VerificationObservation:
        statement_type = (
            SPDX_DOCUMENT_TYPE if predicate_type == "spdxjson" else predicate_type
        )
        statements = self.statements.get((str(subject), statement_type), [])
        if not public_key.is_file() or not statements:
            raise OperationalError("Fake attestation verification failed")
        return VerificationObservation(
            subject,
            tuple(self._verification_entry(subject) for _statement in statements),
        )

    @override
    def download_attestations(
        self,
        *,
        subject: OCIReference,
        predicate_type: str,
        allow_missing: bool = False,
    ) -> tuple[object, ...]:
        del allow_missing
        return tuple(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(canonical_json_bytes(statement)).decode(
                    "ascii"
                ),
            }
            for statement in self.statements.get((str(subject), predicate_type), [])
        )

    @override
    def download_signatures(self, *, subject: OCIReference) -> tuple[object, ...]:
        return (
            (self._verification_entry(subject),)
            if str(subject) in self.signatures
            else ()
        )

    def _store(
        self, subject: OCIReference, predicate_type: str, predicate: object
    ) -> None:
        if subject.digest is None:
            raise AssertionError("attestation subject is mutable")
        self.statements.setdefault((str(subject), predicate_type), []).append(
            {
                "_type": STATEMENT_TYPE,
                "subject": [
                    {
                        "name": subject.repository_name,
                        "digest": {"sha256": subject.digest.encoded},
                    }
                ],
                "predicateType": predicate_type,
                "predicate": predicate,
            }
        )

    @staticmethod
    def _verification_entry(subject: OCIReference) -> dict[str, object]:
        return {
            "critical": {
                "identity": {"docker-reference": subject.repository_name},
                "image": {"docker-manifest-digest": str(subject.digest)},
                "type": "cosign container image signature",
            },
            "optional": {"Bundle": {"SignedEntryTimestamp": "verified"}},
        }


class FakeRuntime:
    """Expose stateful fakes at every release adapter boundary."""

    def __init__(self, pin_digest: Digest) -> None:
        self.registry = FakeRegistry(pin_digest)
        self.registry_control = FakeRegistryControl(self.registry.tags)
        self.signer = FakeSigner()
        self.builder = FakeBuilder()
        self.podman_adapter = FakePodman()
        self.trivy_adapter = FakeTrivy()
        self.hadolint_adapter = FakeHadolint()
        self.runner = NoopRunner()
        self.environment = {"PATH": "/usr/bin"}
        digest = "sha256:" + "f" * 64
        self.identities = tuple(
            ToolIdentity(name, version, executable_digest=digest)
            for name, version in (
                ("buildah", "1.43.2"),
                ("cosign", "3.1.3"),
                ("hadolint", "2.14.0"),
                ("podman", "5.7.1"),
                ("skopeo", "1.21.0"),
                ("trivy", "0.69.3"),
            )
        )

    def assert_unchanged(self) -> None:
        return None

    def buildah(self) -> FakeBuilder:
        return self.builder

    def podman(self) -> FakePodman:
        return self.podman_adapter

    def trivy(self) -> FakeTrivy:
        return self.trivy_adapter

    def hadolint(self) -> FakeHadolint:
        return self.hadolint_adapter

    def skopeo(self) -> FakeRegistry:
        return self.registry

    def cosign(self) -> FakeSigner:
        return self.signer
