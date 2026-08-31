import base64
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

import conclear.provenance as provenance_module
import conclear.records as records_module
import conclear.services.publication as publication_module
from conclear.adapters.cosign import (
    SignatureObservation,
    VerificationObservation,
)
from conclear.adapters.quay import QuayTagObservation
from conclear.adapters.skopeo import RegistryCopyObservation
from conclear.assembly import PlatformLayout, assemble_layout
from conclear.attestations import (
    RELEASE_VERIFICATION_TYPE,
    SPDX_DOCUMENT_TYPE,
    STATEMENT_TYPE,
)
from conclear.config import ReleaseMode, ReleaseProfile, load_repository_config
from conclear.errors import OperationalError
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
)
from conclear.oci import OCI_CONFIG, OCI_MANIFEST, OCIGraph
from conclear.provenance import ProvenanceInput, generate_provenance
from conclear.services.assembly import CandidateResult
from conclear.services.publication import (
    ReleaseEvidence,
    VerificationResult,
    attest_candidate,
    promote_candidate,
    publish_candidate,
    verify_candidate,
)
from conclear.values import Digest, OCIReference, Platform, candidate_tag
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
)


class IdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


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


class FakeRegistry:
    def __init__(self, graph: object, tags: dict[str, Digest]) -> None:
        from conclear.oci import OCIGraph

        if not isinstance(graph, OCIGraph):
            raise TypeError("graph must be an OCIGraph")
        self.graph = graph
        self.tags = tags
        self.fail_graph_copy = False

    def resolve_digest(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest:
        del auth_file
        if reference.digest is not None:
            return reference.digest
        if reference.tag is None or reference.tag not in self.tags:
            raise AssertionError(f"unknown fake tag: {reference}")
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
        del layout_path, layout_reference, auth_file
        assert destination.tag is not None
        self.tags[destination.tag] = self.graph.digest

    def copy_registry_to_layout(
        self,
        *,
        source: OCIReference,
        layout_path: Path,
        layout_reference: str,
        auth_file: Path | None,
    ) -> RegistryCopyObservation:
        del auth_file
        if self.fail_graph_copy:
            raise OperationalError("injected remote graph failure")
        return RegistryCopyObservation(source, layout_path, self.graph)


class FakeQuay:
    def __init__(self, tags: dict[str, Digest]) -> None:
        self.tags = tags
        self.expirations: dict[str, datetime] = {}
        self.immutable: set[str] = set()
        self.fail_delete = False

    def get_tag(self, repository: OCIReference, tag: str) -> QuayTagObservation | None:
        del repository
        digest = self.tags.get(tag)
        if digest is None:
            return None
        return QuayTagObservation(
            tag,
            digest,
            self.expirations.get(tag),
            tag in self.immutable,
        )

    def set_expiration(
        self, repository: OCIReference, tag: str, expiration: datetime
    ) -> QuayTagObservation:
        del repository
        self.expirations[tag] = expiration
        observed = self.get_tag(OCIReference("quay.io", "example/app"), tag)
        assert observed is not None
        return observed

    def set_immutable(self, repository: OCIReference, tag: str) -> QuayTagObservation:
        del repository
        self.immutable.add(tag)
        observed = self.get_tag(OCIReference("quay.io", "example/app"), tag)
        assert observed is not None
        return observed

    def write_tag(
        self, repository: OCIReference, tag: str, digest: Digest
    ) -> QuayTagObservation:
        del repository
        self.tags[tag] = digest
        observed = self.get_tag(OCIReference("quay.io", "example/app"), tag)
        assert observed is not None
        return observed

    def delete_tag(self, repository: OCIReference, tag: str) -> None:
        del repository
        if self.fail_delete:
            raise OperationalError("injected candidate deletion failure")
        self.tags.pop(tag, None)
        self.expirations.pop(tag, None)
        self.immutable.discard(tag)


class FakeSigner:
    def __init__(self) -> None:
        self.statements: dict[tuple[str, str], list[dict[str, object]]] = {}
        self.signatures: set[str] = set()
        self.fail_once: str | None = None

    def sign(
        self, *, subject: OCIReference, private_key: str, passphrase: str | None
    ) -> SignatureObservation:
        del private_key, passphrase
        self.signatures.add(str(subject))
        return SignatureObservation(subject, "signed")

    def attest(
        self,
        *,
        subject: OCIReference,
        predicate: Path,
        predicate_type: str,
        private_key: str,
        passphrase: str | None,
    ) -> SignatureObservation:
        del private_key, passphrase
        assert subject.digest is not None
        statement_predicate_type = (
            SPDX_DOCUMENT_TYPE if predicate_type == "spdxjson" else predicate_type
        )
        statement: dict[str, object] = {
            "_type": STATEMENT_TYPE,
            "subject": [
                {
                    "name": subject.repository_name,
                    "digest": {"sha256": subject.digest.encoded},
                }
            ],
            "predicateType": statement_predicate_type,
            "predicate": load_json(predicate),
        }
        self._store(subject, statement_predicate_type, statement)
        return SignatureObservation(subject, "attested")

    def attest_statement(
        self,
        *,
        subject: OCIReference,
        statement: Path,
        private_key: str,
        passphrase: str | None,
    ) -> SignatureObservation:
        del private_key, passphrase
        value = load_json(statement)
        assert isinstance(value, dict)
        predicate_type = value.get("predicateType")
        assert isinstance(predicate_type, str)
        typed = {str(key): item for key, item in value.items()}
        self._store(subject, predicate_type, typed)
        return SignatureObservation(subject, "attested")

    def verify(
        self, *, subject: OCIReference, public_key: Path
    ) -> VerificationObservation:
        assert public_key.is_file()
        assert str(subject) in self.signatures
        return VerificationObservation(subject, ({"verified": True},))

    def verify_attestation(
        self,
        *,
        subject: OCIReference,
        public_key: Path,
        predicate_type: str,
    ) -> VerificationObservation:
        assert public_key.is_file()
        statement_predicate_type = (
            SPDX_DOCUMENT_TYPE if predicate_type == "spdxjson" else predicate_type
        )
        assert (str(subject), statement_predicate_type) in self.statements
        if self.fail_once == predicate_type:
            self.fail_once = None
            raise OperationalError("injected verification interruption")
        return VerificationObservation(subject, ({"verified": True},))

    def download_attestations(
        self, *, subject: OCIReference, predicate_type: str
    ) -> tuple[object, ...]:
        return tuple(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(canonical_json_bytes(statement))
                .decode("ascii")
                .strip(),
            }
            for statement in self.statements.get((str(subject), predicate_type), [])
        )

    def download_signatures(self, *, subject: OCIReference) -> tuple[object, ...]:
        return ({"signature": "present"},) if str(subject) in self.signatures else ()

    def _store(
        self,
        subject: OCIReference,
        predicate_type: str,
        statement: dict[str, object],
    ) -> None:
        self.statements.setdefault((str(subject), predicate_type), []).append(statement)


def test_failed_publication_retains_digest_ownership_and_expiration(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")
    image = repository.image("app")
    workspace = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={"sourceRevision": "b" * 40},
        id_factory=IdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    workspace.transition(RunState.QUALIFIED)
    workspace.transition(RunState.ASSEMBLED)
    layout = platform_layout(tmp_path / "qualified", "amd64")
    observation = assemble_layout(
        (PlatformLayout(Platform.parse("linux/amd64"), layout, "qualified"),),
        output_path=tmp_path / "candidate",
        output_reference="candidate",
    )
    candidate_record = workspace.root / "records" / "release-candidate.json"
    candidate_digest = atomic_write_json(candidate_record, {"accepted": True})
    tag = candidate_tag(
        version="1.2.3",
        run_id=workspace.run_id,
        source_revision="b" * 40,
    )
    candidate = CandidateResult(
        candidate_record,
        candidate_digest,
        observation,
        tag,
        (),
        (),
    )
    tags: dict[str, Digest] = {}
    registry = FakeRegistry(observation.graph, tags)
    registry.fail_graph_copy = True
    quay = FakeQuay(tags)
    now = datetime(2026, 1, 1, tzinfo=UTC)

    with pytest.raises(OperationalError, match="injected remote graph failure"):
        publish_candidate(
            candidate,
            image=image,
            workspace=workspace,
            registry=registry,
            quay=quay,
            auth_file=None,
            now=now,
        )

    entry = workspace.journal.entries()[0]
    assert entry.status is ResourceStatus.FAILED
    assert entry.metadata["digest"] == str(observation.graph.digest)
    assert entry.metadata["expiration"] == "2026-01-08T00:00:00Z"
    assert quay.expirations[tag] == datetime(2026, 1, 8, tzinfo=UTC)
    assert tags[tag] == observation.graph.digest


@pytest.mark.parametrize("delete_fails", [False, True])
def test_remote_workflow_binds_evidence_and_promotes_verified_digest(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    delete_fails: bool,
) -> None:
    identity = ApplicationIdentity(source_revision="c" * 40)
    monkeypatch.setattr(records_module, "IDENTITY", identity)
    monkeypatch.setattr(provenance_module, "IDENTITY", identity)
    monkeypatch.setattr(publication_module, "IDENTITY", identity)
    repository = load_repository_config(repository_factory() / "conclear.toml")
    image = repository.image("app")
    workspace = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={
            "sourceRevision": "b" * 40,
            "image": "app",
            "version": "1.2.3",
            "mode": "local",
        },
        id_factory=IdFactory(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    workspace.transition(RunState.QUALIFIED)
    workspace.transition(RunState.ASSEMBLED)
    layout = platform_layout(tmp_path / "qualified", "amd64")
    observation = assemble_layout(
        (PlatformLayout(Platform.parse("linux/amd64"), layout, "qualified"),),
        output_path=tmp_path / "candidate",
        output_reference="candidate",
    )
    candidate_record = workspace.root / "records" / "release-candidate.json"
    candidate_digest = atomic_write_json(candidate_record, {"accepted": True})
    tag = candidate_tag(
        version="1.2.3",
        run_id=workspace.run_id,
        source_revision="b" * 40,
    )
    candidate = CandidateResult(
        candidate_record,
        candidate_digest,
        observation,
        tag,
        ("sha256:" + "1" * 64,),
        (),
    )
    platform = Platform.parse("linux/amd64")
    sbom = workspace.root / "exports" / "sbom" / "app-linux-amd64.spdx.json"
    sbom_digest = atomic_write_json(
        sbom,
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
    configuration_digest = Digest("sha256:" + "2" * 64)
    provenance = workspace.root / "records" / "provenance.json"
    provenance_digest = generate_provenance(
        ProvenanceInput(
            subject_name=image.repository.repository_name,
            subject_digest=observation.graph.digest,
            platform_manifests=((platform, observation.graph.digest),),
            source_repository=repository.project.source,
            source_revision="b" * 40,
            configuration_digest=configuration_digest,
            image_id=image.image_id,
            version="1.2.3",
            run_id=workspace.run_id,
            mode="local",
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            finished_at=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
            materials=(),
        ),
        provenance,
    )
    evidence = ReleaseEvidence(
        source=records_module.SourceIdentity(repository.project.source, "b" * 40),
        configuration_digest=str(configuration_digest),
        tools=(),
        sboms=((platform, sbom, sbom_digest),),
        scan_digests=("sha256:" + "3" * 64,),
        provenance_path=provenance,
        provenance_digest=provenance_digest,
        provenance_materials=(),
        candidate_record_digest=candidate_digest,
        qualification_digests=candidate.qualification_digests,
    )
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("test public key", encoding="utf-8")
    profile = ReleaseProfile(
        name="test",
        mode=ReleaseMode.LOCAL,
        auth_file=None,
        quay_token_file=None,
        cosign_private_key="test.key",
        cosign_public_key=public_key,
        passphrase_file=None,
        quay_api_url="https://quay.io/api/v1",
        configuration_digest="sha256:" + "4" * 64,
        public_key_digest="sha256:" + "5" * 64,
    )
    tags: dict[str, Digest] = {}
    registry = FakeRegistry(observation.graph, tags)
    quay = FakeQuay(tags)
    signer = FakeSigner()
    published = publish_candidate(
        candidate,
        image=image,
        workspace=workspace,
        registry=registry,
        quay=quay,
        auth_file=None,
        now=datetime(2026, 1, 1, 0, 2, tzinfo=UTC),
    )
    platform_subject = published.reference.with_digest(
        observation.graph.manifests[0].descriptor.digest
    )
    signer.attest(
        subject=platform_subject,
        predicate=sbom,
        predicate_type="spdxjson",
        private_key="test.key",
        passphrase="secret",
    )
    workspace.journal.plan(
        resource_id="sbom-linux-amd64",
        kind=ResourceKind.ATTESTATION,
        identifier=str(platform_subject),
        ephemeral=False,
        metadata={
            "predicateType": SPDX_DOCUMENT_TYPE,
            "payloadDigest": sbom_digest,
        },
    )
    workspace.journal.update("sbom-linux-amd64", ResourceStatus.FAILED)
    attest_candidate(
        published,
        evidence,
        image=image,
        workspace=workspace,
        signer=signer,
        private_key="test.key",
        public_key=public_key,
        passphrase="secret",
        registry=registry,
        auth_file=None,
        now=datetime(2026, 1, 1, 0, 3, tzinfo=UTC),
    )
    assert len(signer.statements[(str(platform_subject), SPDX_DOCUMENT_TYPE)]) == 1

    def run_verification(now: datetime) -> VerificationResult:
        return verify_candidate(
            published,
            candidate,
            evidence,
            workspace=workspace,
            image=image,
            profile=profile,
            signer=signer,
            registry=registry,
            auth_file=None,
            private_key="test.key",
            passphrase="secret",
            signer_mode="managed-key",
            signer_key_id="sha256:" + "4" * 64,
            host_architecture="x86_64",
            ci_identity=None,
            now=now,
        )

    signer.fail_once = RELEASE_VERIFICATION_TYPE
    accepted_graph = registry.graph
    registry.graph = OCIGraph(
        root=accepted_graph.root,
        descriptors=accepted_graph.descriptors[:-1],
        manifests=accepted_graph.manifests,
    )
    with pytest.raises(OperationalError, match="descriptor graph differs"):
        run_verification(datetime(2026, 1, 1, 0, 4, tzinfo=UTC))
    registry.graph = accepted_graph
    with pytest.raises(OperationalError, match="injected"):
        run_verification(datetime(2026, 1, 1, 0, 4, tzinfo=UTC))
    verification = run_verification(datetime(2026, 1, 1, 0, 5, tzinfo=UTC))
    tags["1.2.3"] = observation.graph.digest
    quay.immutable.add("1.2.3")
    workspace.journal.plan(
        resource_id="tag-1.2.3",
        kind=ResourceKind.TAG_WRITE,
        identifier=str(image.repository.with_tag("1.2.3")),
        ephemeral=False,
        metadata={
            "digest": str(observation.graph.digest),
            "immutable": True,
        },
    )
    workspace.journal.update("tag-1.2.3", ResourceStatus.FAILED)
    quay.fail_delete = delete_fails
    promoted = promote_candidate(
        published,
        verification,
        image=image,
        version="1.2.3",
        workspace=workspace,
        quay=quay,
        registry=registry,
        signer=signer,
        public_key=public_key,
        auth_file=None,
        now=datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
    )

    assert workspace.load().state is RunState.PROMOTED
    assert promoted.tags == (
        ("1.2.3", observation.graph.digest),
        ("stable", observation.graph.digest),
    )
    assert promoted.candidate_deleted is not delete_fails
    assert (tag in tags) is delete_fails
    assert tags["1.2.3"] == observation.graph.digest
    assert "1.2.3" in quay.immutable
    candidate_entry = next(
        entry
        for entry in workspace.journal.entries()
        if entry.kind is ResourceKind.CANDIDATE_REFERENCE
    )
    assert candidate_entry.status is (
        ResourceStatus.CREATED if delete_fails else ResourceStatus.REMOVED
    )
    assert sha256_file(verification.record_path) == verification.record_digest
