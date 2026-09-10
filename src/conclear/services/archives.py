"""Collect allowlisted release evidence and authenticate retained Sigstore bundles."""

import tempfile
from pathlib import Path
from typing import Protocol

from conclear.adapters.cosign import VerificationObservation
from conclear.archive import ArchiveResult, OpenArchive, member_path, write_archive
from conclear.archive_source import SOURCE_MANIFEST, collect_source, restore_source
from conclear.artifacts import load_candidate, load_release_evidence
from conclear.attestations import (
    RELEASE_VERIFICATION_TYPE,
    RESCAN_TYPE,
    SPDX_DOCUMENT_TYPE,
    decode_dsse_statements,
)
from conclear.config import load_repository_config
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import canonical_json_bytes, load_json, sha256_bytes, sha256_file
from conclear.oci import OCIGraph, validate_layout, validate_layout_metadata
from conclear.parsing import Narrower
from conclear.provenance import SLSA_PROVENANCE_TYPE
from conclear.records import validate_record
from conclear.services.rescan_evidence import verified_predicates
from conclear.source_integrity import require_source_integrity
from conclear.values import OCIReference
from conclear.workspace import RunState, RunWorkspace

_narrow = Narrower(InvalidInvocationError)


class ArchiveSigner(Protocol):
    """Registry reads and independent verification of retained signed material."""

    def verify_attestation(
        self, *, subject: OCIReference, public_key: Path, predicate_type: str
    ) -> VerificationObservation:
        """Read only attestations authenticated by the approved key."""
        ...

    def download_attestations(
        self, *, subject: OCIReference, predicate_type: str, allow_missing: bool = False
    ) -> tuple[object, ...]:
        """Retrieve Sigstore bundles, which still need authenticated binding."""
        ...

    def verify_attestation_bundle(
        self,
        *,
        bundle: Path,
        subject: OCIReference,
        public_key: Path,
        predicate_type: str,
    ) -> VerificationObservation:
        """Verify a saved bundle, including its subject and transparency proof."""
        ...


def create_run_archive(
    workspace: RunWorkspace,
    *,
    directory: Path,
    signer: ArchiveSigner,
    public_key: Path,
    include_image_layers: bool = False,
) -> ArchiveResult:
    """Archive one completed release or rescan, including rejected assessments."""
    snapshot = workspace.load()
    is_release = snapshot.state is RunState.PROMOTED
    primary = "release-verification.json" if is_release else "rescan-result.json"
    record = _record(workspace.root / "records" / primary)
    payload = _narrow.object_value(record.get("payload"), "record payload")
    configuration = _narrow.object_value(
        record.get("repositoryConfiguration"), "record configuration"
    )
    configuration_digest = _narrow.string_value(
        configuration.get("sha256"), "configuration digest"
    )
    image_id = snapshot.immutable_inputs["image"]
    source = workspace.root / "source"
    sources: dict[str, Path | bytes] = {
        f"records/{primary}": workspace.root / "records" / primary
    }
    evidence: list[dict[str, object]] = []
    release_archive_digest: str | None = None
    if is_release:
        repository = load_repository_config(source / "conclear.toml")
        image = repository.release_image(image_id)
        require_source_integrity(workspace, source)
        candidate = load_candidate(workspace, image)
        release_evidence = load_release_evidence(workspace, image)
        subject = image.repository.with_digest(candidate.observation.graph.digest)
        layout = candidate.observation.path
        graph = candidate.observation.graph
        for name in (
            "release-candidate.json",
            "provenance.json",
            "release-verification-statement.json",
        ):
            sources[f"records/{name}"] = workspace.root / "records" / name
        summary = workspace.root / "summary.json"
        if summary.is_file():
            sources["summary.json"] = summary
        for platform in image.platforms:
            name = f"platform-qualification-{platform.key}.json"
            sources[f"records/{name}"] = workspace.root / "records" / name
        for material in release_evidence.provenance_materials:
            if material.uri.startswith("conclear:workspace/"):
                name = material.uri.removeprefix("conclear:workspace/")
                member_path(name)
                sources[name] = workspace.root / name
        _collect_attestations(
            sources, evidence, signer, public_key, subject, RELEASE_VERIFICATION_TYPE
        )
        _collect_attestations(
            sources, evidence, signer, public_key, subject, SLSA_PROVENANCE_TYPE
        )
        for platform, _path, _digest in release_evidence.sboms:
            descriptor = next(
                item.descriptor for item in graph.manifests if item.platform == platform
            )
            _collect_attestations(
                sources,
                evidence,
                signer,
                public_key,
                subject.with_digest(descriptor.digest),
                SPDX_DOCUMENT_TYPE,
            )
    else:
        if record.get("recordType") != "rescanResult":
            raise InvalidInvocationError(
                "Run has no completed release or rescan to archive"
            )
        subject = OCIReference.parse(
            _narrow.string_value(payload.get("subject"), "rescan subject"),
            require_digest=True,
        )
        layout = workspace.root / "layouts" / image_id / "rescan"
        graph = validate_layout(layout, reference="rescan")
        platform_map = _narrow.object_value(
            payload.get("platformManifests"), "rescan platforms"
        )
        if platform_map != {
            str(item.platform): str(item.descriptor.digest) for item in graph.manifests
        }:
            raise InvalidInvocationError("Rescan image graph changed before archival")
        report_root = workspace.root / "reports" / image_id / "rescan"
        for platform in graph.platforms:
            for suffix in (".spdx.json", "-scan.json"):
                name = f"{platform.key}{suffix}"
                sources[f"reports/{image_id}/rescan/{name}"] = report_root / name
        _collect_attestations(
            sources, evidence, signer, public_key, subject, RELEASE_VERIFICATION_TYPE
        )
        if payload.get("authoritative") is True:
            _collect_attestations(
                sources, evidence, signer, public_key, subject, RESCAN_TYPE
            )
            sources["records/rescan-statement.json"] = (
                workspace.root / "records/rescan-statement.json"
            )
        release_archive_digest = snapshot.immutable_inputs.get("releaseArchiveDigest")
    if graph.digest != subject.digest:
        raise InvalidInvocationError("Archive subject differs from its image graph")
    include_source = release_archive_digest is None
    if include_source:
        sources.update(
            collect_source(
                source,
                expected_digest=snapshot.immutable_inputs.get("sourceTreeDigest"),
            )
        )
        if sha256_file(source / "conclear.toml") != configuration_digest:
            raise InvalidInvocationError(
                "Archive source configuration differs from the record"
            )
    _collect_layout(sources, layout, graph, include_layers=include_image_layers)
    metadata: dict[str, object] = {
        "kind": "release" if is_release else "rescan",
        "runId": workspace.run_id,
        "subject": str(subject),
        "imageId": image_id,
        "configurationDigest": configuration_digest,
        "recordPath": f"records/{primary}",
        "source": include_source,
        "imageLayers": include_image_layers,
        "releaseArchiveDigest": release_archive_digest,
        "signedEvidence": evidence,
    }
    if not include_source and "releaseArchiveName" in snapshot.immutable_inputs:
        metadata["releaseArchiveName"] = snapshot.immutable_inputs["releaseArchiveName"]
    return write_archive(
        directory,
        metadata,
        sources,
        validate=lambda archive: verify_archive_signatures(
            archive, signer=signer, public_key=public_key
        ),
    )


def validate_archive_contents(archive: OpenArchive) -> None:
    """Check evidence relationships without treating local checksums as signatures."""
    manifest, root = archive.manifest, archive.root
    record = _record(root / _narrow.string_value(manifest["recordPath"], "record path"))
    if record.get("runId") != manifest["runId"]:
        raise InvalidInvocationError("Archive record belongs to another run")
    expected_type = (
        "releaseVerification" if archive.kind == "release" else "rescanResult"
    )
    if record.get("recordType") != expected_type:
        raise InvalidInvocationError("Archive record has the wrong type")
    configuration = _narrow.object_value(
        record.get("repositoryConfiguration"), "configuration"
    )
    if configuration.get("sha256") != manifest["configurationDigest"]:
        raise InvalidInvocationError(
            "Archive configuration binding differs from its record"
        )
    graph = (validate_layout if manifest["imageLayers"] else validate_layout_metadata)(
        root / "image"
    )
    if graph.digest != archive.subject.digest:
        raise InvalidInvocationError("Archive image metadata names another digest")
    layer_digests = {layer.digest for item in graph.manifests for layer in item.layers}
    expected_blobs = {
        item.digest.encoded
        for item in graph.descriptors
        if manifest["imageLayers"] or item.digest not in layer_digests
    }
    if {
        path.name for path in (root / "image/blobs/sha256").iterdir()
    } != expected_blobs:
        raise InvalidInvocationError(
            "Archive image blobs differ from its declared layer mode"
        )
    payload = _narrow.object_value(record.get("payload"), "record payload")
    platforms = {
        str(item.platform): str(item.descriptor.digest) for item in graph.manifests
    }
    source_digest = sha256_file(root / SOURCE_MANIFEST) if manifest["source"] else None
    if archive.kind == "release":
        if (
            record.get("verdict") != "accepted"
            or payload.get("subject")
            != {
                "repository": archive.subject.repository_name,
                "digest": str(archive.subject.digest),
            }
            or payload.get("platformDigests") != platforms
        ):
            raise InvalidInvocationError(
                "Archive release record does not authorize its image"
            )
        bound = _narrow.object_value(payload.get("evidence"), "release evidence")
        digests = {sha256_file(path) for path in root.rglob("*") if path.is_file()}
        for label in ("platformQualifications", "sboms", "scanResults"):
            required = _narrow.string_array_value(bound.get(label), f"release {label}")
            if not set(required) <= digests:
                raise InvalidInvocationError(
                    f"Archive is missing release-bound {label}"
                )
        qualifications = {
            sha256_file(path): _record(path)
            for path in (root / "records").glob("platform-qualification-*.json")
        }
        if set(qualifications) != set(
            _narrow.string_array_value(
                bound["platformQualifications"], "qualification digests"
            )
        ):
            raise InvalidInvocationError(
                "Archive qualification records differ from the signed release"
            )
        for qualification in qualifications.values():
            qualification_payload = _narrow.object_value(
                qualification.get("payload"), "qualification payload"
            )
            if qualification_payload.get("sourceTreeDigest") != source_digest:
                raise InvalidInvocationError(
                    "Archived source differs from the signed qualification"
                )
            required = _narrow.string_array_value(
                qualification_payload.get("payloadDigests"), "qualification payloads"
            )
            if not set(required) <= digests:
                raise InvalidInvocationError(
                    "Archive is missing qualification payload bytes"
                )
        for name, field in (
            ("provenance.json", "provenance"),
            ("release-candidate.json", "candidateRecord"),
        ):
            if sha256_file(root / "records" / name) != bound.get(field):
                raise InvalidInvocationError(
                    "Archive release record dependency changed"
                )
    elif (
        payload.get("subject") != str(archive.subject)
        or payload.get("platformManifests") != platforms
    ):
        raise InvalidInvocationError("Archive rescan record names another image")
    else:
        if payload.get("releaseArchiveDigest") != manifest["releaseArchiveDigest"] or (
            source_digest is not None
            and payload.get("sourceTreeDigest") != source_digest
        ):
            raise InvalidInvocationError("Archived rescan source binding differs")
        scans = _narrow.array_value(payload.get("scanResults"), "rescan scan results")
        seen: set[str] = set()
        for raw in scans:
            scan = _narrow.object_value(raw, "rescan scan result")
            platform = _narrow.string_value(scan.get("platform"), "rescan platform")
            if platform not in platforms or platform in seen:
                raise InvalidInvocationError("Archive rescan scan coverage differs")
            seen.add(platform)
            report = (
                root
                / "reports"
                / _narrow.string_value(manifest["imageId"], "image id")
                / "rescan"
            )
            key = platform.replace("/", "-")
            if sha256_file(report / f"{key}-scan.json") != scan.get(
                "reportDigest"
            ) or sha256_file(report / f"{key}.spdx.json") != scan.get("sbomDigest"):
                raise InvalidInvocationError(
                    "Archived rescan report differs from its recorded digest"
                )
        if seen != set(platforms):
            raise InvalidInvocationError("Archive rescan omits a platform report")
    if manifest["source"]:
        with tempfile.TemporaryDirectory(prefix="conclear-source-check-") as temporary:
            restored = Path(temporary) / "source"
            restore_source(root, restored)
            if (
                sha256_file(restored / "conclear.toml")
                != manifest["configurationDigest"]
            ):
                raise InvalidInvocationError("Archived source configuration changed")
    elif archive.kind == "release" or manifest["releaseArchiveDigest"] is None:
        raise InvalidInvocationError(
            "Archive has neither source nor a release archive reference"
        )
    predicates = _archived_predicates(archive)
    if archive.kind == "release":
        provenance = _narrow.object_value(
            load_json(root / "records/provenance.json"), "provenance statement"
        )
        expected = sha256_bytes(canonical_json_bytes(provenance.get("predicate")))
        if expected not in predicates.get(
            (str(archive.subject), SLSA_PROVENANCE_TYPE), {}
        ):
            raise InvalidInvocationError("Archive omits the signed release provenance")
        bound = _narrow.object_value(payload["evidence"], "release evidence")
        sboms = set(_narrow.string_array_value(bound["sboms"], "release SBOMs"))
        included: set[str] = set()
        for item in graph.manifests:
            matches = (
                sboms
                & predicates.get(
                    (
                        str(archive.subject.with_digest(item.descriptor.digest)),
                        SPDX_DOCUMENT_TYPE,
                    ),
                    {},
                ).keys()
            )
            if len(matches) != 1:
                raise InvalidInvocationError("Archive omits a signed platform SBOM")
            included.update(matches)
        if included != sboms:
            raise InvalidInvocationError("Archived signed SBOM coverage differs")
    elif payload.get("releaseRecordDigest") not in predicates.get(
        (str(archive.subject), RELEASE_VERIFICATION_TYPE), {}
    ):
        raise InvalidInvocationError("Archive omits its rescan's signed release anchor")
    predicate_type = (
        RELEASE_VERIFICATION_TYPE if archive.kind == "release" else RESCAN_TYPE
    )
    if archive.kind == "release" or payload.get("authoritative") is True:
        if sha256_bytes(canonical_json_bytes(record)) not in predicates.get(
            (str(archive.subject), predicate_type), {}
        ):
            raise InvalidInvocationError(
                "Archive record is not carried by its signed evidence"
            )


def verify_archive_signatures(
    archive: OpenArchive, *, signer: ArchiveSigner, public_key: Path
) -> None:
    """Authenticate retained bundles against an independently configured public key."""
    validate_archive_contents(archive)
    for raw in _narrow.array_value(
        archive.manifest["signedEvidence"], "signed evidence"
    ):
        item = _narrow.object_value(raw, "signed evidence item")
        path = archive.root / _narrow.string_value(item["path"], "bundle path")
        subject = OCIReference.parse(
            _narrow.string_value(item["subject"], "bundle subject"), require_digest=True
        )
        kind = _narrow.string_value(item["predicateType"], "predicate type")
        observation = signer.verify_attestation_bundle(
            bundle=path, subject=subject, public_key=public_key, predicate_type=kind
        )
        if observation.subject != subject or observation.entries != (
            load_json(path, maximum_bytes=128 * 1024 * 1024),
        ):
            raise OperationalError(
                "Bundle verifier did not authenticate the archived bytes"
            )
        verified_predicates(
            decode_dsse_statements(observation.entries),
            predicate_type=kind,
            subject=subject,
        )


def _collect_attestations(
    sources: dict[str, Path | bytes],
    evidence: list[dict[str, object]],
    signer: ArchiveSigner,
    public_key: Path,
    subject: OCIReference,
    kind: str,
) -> None:
    alias = "spdxjson" if kind == SPDX_DOCUMENT_TYPE else kind
    verified = signer.verify_attestation(
        subject=subject, public_key=public_key, predicate_type=alias
    )
    if verified.subject != subject or not verified.entries:
        raise OperationalError(
            "Archive attestation verification returned no authenticated entries"
        )
    verified_predicates(
        decode_dsse_statements(verified.entries), predicate_type=kind, subject=subject
    )
    envelopes = {_envelope_bytes(item) for item in verified.entries}
    downloaded = signer.download_attestations(subject=subject, predicate_type=kind)
    selected: dict[str, bytes] = {}
    for bundle in downloaded:
        if _envelope_bytes(bundle) in envelopes:
            content = canonical_json_bytes(bundle)
            selected[sha256_bytes(content)] = content
    if not selected:
        raise OperationalError(
            "No downloaded Sigstore bundle matches the verified envelopes"
        )
    for digest, content in sorted(selected.items()):
        name = f"signatures/{digest[7:]}.sigstore.json"
        sources[name] = content
        evidence.append({"path": name, "subject": str(subject), "predicateType": kind})


def _envelope_bytes(value: object) -> bytes:
    item = _narrow.object_value(value, "Sigstore envelope")
    return canonical_json_bytes(item.get("dsseEnvelope", item))


def _archived_predicates(
    archive: OpenArchive,
) -> dict[tuple[str, str], dict[str, dict[str, object]]]:
    result: dict[tuple[str, str], dict[str, dict[str, object]]] = {}
    paths: set[str] = set()
    for raw in _narrow.array_value(
        archive.manifest["signedEvidence"], "signed evidence"
    ):
        item = _narrow.object_value(raw, "signed evidence item")
        if set(item) != {"path", "subject", "predicateType"}:
            raise InvalidInvocationError("Malformed archive signed evidence descriptor")
        name = _narrow.string_value(item["path"], "bundle path")
        if member_path(name).parts[0] != "signatures" or name in paths:
            raise InvalidInvocationError("Invalid or duplicate archive bundle path")
        paths.add(name)
        subject = OCIReference.parse(
            _narrow.string_value(item["subject"], "bundle subject"), require_digest=True
        )
        if subject.repository_name != archive.subject.repository_name:
            raise InvalidInvocationError(
                "Archived signed evidence names another repository"
            )
        kind = _narrow.string_value(item["predicateType"], "bundle predicate type")
        values = verified_predicates(
            decode_dsse_statements(
                (load_json(archive.root / name, maximum_bytes=128 * 1024 * 1024),)
            ),
            predicate_type=kind,
            subject=subject,
        )
        result.setdefault((str(subject), kind), {}).update(values)
    return result


def _collect_layout(
    sources: dict[str, Path | bytes],
    root: Path,
    graph: OCIGraph,
    *,
    include_layers: bool,
) -> None:
    sources["image/oci-layout"] = root / "oci-layout"
    sources["image/index.json"] = root / "index.json"
    layers = {layer.digest for item in graph.manifests for layer in item.layers}
    for item in graph.descriptors:
        if include_layers or item.digest not in layers:
            name = f"blobs/sha256/{item.digest.encoded}"
            sources[f"image/{name}"] = root / name


def _record(path: Path) -> dict[str, object]:
    record = _narrow.object_value(load_json(path), "archive record")
    validate_record(record)
    return record
