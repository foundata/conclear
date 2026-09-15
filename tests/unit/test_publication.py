import base64
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import override

import pytest

import conclear.provenance as provenance_module
import conclear.records as records_module
import conclear.services.attestation as attestation_module
import conclear.services.promotion as promotion_module
from conclear.adapters.cosign import (
    SignatureObservation,
    VerificationObservation,
)
from conclear.adapters.skopeo import RegistryCopyObservation
from conclear.artifacts import load_published, load_verification
from conclear.attestations import (
    RELEASE_VERIFICATION_TYPE,
    SPDX_DOCUMENT_TYPE,
    STATEMENT_TYPE,
)
from conclear.config import load_repository_config
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
    UnsupportedOperationError,
)
from conclear.freshness import QualificationWindow
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
)
from conclear.layout_assembly import PlatformLayout, assemble_layout
from conclear.oci import OCI_CONFIG, OCI_MANIFEST, OCIGraph
from conclear.provenance import ProvenanceInput, generate_provenance
from conclear.registry_control import CandidateRetentionObservation, TagObservation
from conclear.release_profile import (
    BuilderConfig,
    CIContextPolicy,
    QuayRegistryConfig,
    RegistryProvider,
    ReleaseProfile,
)
from conclear.services.assembly import CandidateResult
from conclear.services.attestation import (
    ReleaseEvidence,
    attest_candidate,
    validate_release_provenance,
)
from conclear.services.ci_context import PublicCIContext
from conclear.services.promotion import promote_candidate
from conclear.services.publication import publish_candidate
from conclear.services.verification import VerificationResult, verify_candidate
from conclear.spdx import SpdxFormat
from conclear.values import (
    CANDIDATE_TAG_PATTERN,
    Digest,
    OCIReference,
    Platform,
    candidate_tag,
)
from conclear.workspace import (
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
)
from tests.registry_policy_fixtures import STRICT_POLICY

BUILDER_ID = "https://foundata.com/en/projects/conclear/builder/simple-v1/"


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
        self.resolution_overrides: dict[str, Digest] = {}
        self.copied_layout_paths: list[Path] = []

    def resolve_digest(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest:
        del auth_file
        if reference.digest is not None:
            return reference.digest
        if reference.tag is not None and reference.tag in self.resolution_overrides:
            return self.resolution_overrides[reference.tag]
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
        self.copied_layout_paths.append(layout_path)
        if self.fail_graph_copy:
            raise OperationalError("injected remote graph failure")
        return RegistryCopyObservation(source, layout_path, self.graph)


class FakeRegistryControl:
    def __init__(self, tags: dict[str, Digest]) -> None:
        self.tags = tags
        self.expirations: dict[str, datetime] = {}
        self.immutable: set[str] = set()
        self.fail_delete = False
        self.retention: CandidateRetentionObservation | None = None
        self.protected_tags: set[str] = set()

    def verify_tag_policy(
        self,
        repository: OCIReference,
        *,
        version_tags: tuple[str, ...],
        mutable_tags: tuple[str, ...],
    ) -> None:
        self.protected_tags.update(version_tags)

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
        del repository
        self.expirations[tag] = expiration
        observed = self.observe_tag(OCIReference("quay.io", "example/app"), tag)
        assert observed is not None
        return observed

    def ensure_candidate_retention(
        self, repository: OCIReference, maximum_age: timedelta
    ) -> CandidateRetentionObservation:
        self.retention = CandidateRetentionObservation(
            repository, "policy-id", CANDIDATE_TAG_PATTERN, maximum_age
        )
        return self.retention

    def observe_candidate_retention(
        self, repository: OCIReference, maximum_age: timedelta
    ) -> CandidateRetentionObservation | None:
        return self.retention

    def ensure_tag_immutable(
        self, repository: OCIReference, tag: str
    ) -> TagObservation:
        del repository
        self.immutable.add(tag)
        observed = self.observe_tag(OCIReference("quay.io", "example/app"), tag)
        assert observed is not None
        return observed

    def ensure_tag_mutable(self, repository: OCIReference, tag: str) -> TagObservation:
        del repository
        self.immutable.discard(tag)
        observed = self.observe_tag(OCIReference("quay.io", "example/app"), tag)
        assert observed is not None
        return observed

    def assign_tag(
        self, repository: OCIReference, tag: str, digest: Digest
    ) -> TagObservation:
        del repository
        self.tags[tag] = digest
        if tag in self.protected_tags:
            self.immutable.add(tag)
        observed = self.observe_tag(OCIReference("quay.io", "example/app"), tag)
        assert observed is not None
        return observed

    def remove_tag(self, repository: OCIReference, tag: str) -> None:
        del repository
        if self.fail_delete:
            raise OperationalError("injected candidate deletion failure")
        if tag in self.immutable:
            raise OperationalError("immutable tags cannot be deleted")
        self.tags.pop(tag, None)
        self.expirations.pop(tag, None)
        self.immutable.discard(tag)

    def close(self) -> None:
        pass


class FakeSigner:
    def __init__(self) -> None:
        self.statements: dict[tuple[str, str], list[dict[str, object]]] = {}
        self.signatures: set[str] = set()
        self.fail_once: str | None = None

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
        passphrase_path: Path | None = None,
    ) -> SignatureObservation:
        del private_key, passphrase, passphrase_path
        value = load_json(statement)
        assert isinstance(value, dict)
        assert subject.digest is not None
        predicate_type = value.get("predicateType")
        assert isinstance(predicate_type, str)
        predicate = value.get("predicate")
        assert isinstance(predicate, dict)
        # Cosign 3 ignores the caller's statement envelope and wraps the predicate
        # around the one subject it signs, using the v0.1 statement type.
        cosign_statement: dict[str, object] = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": subject.repository_name,
                    "digest": {"sha256": subject.digest.encoded},
                }
            ],
            "predicateType": predicate_type,
            "predicate": predicate,
        }
        self._store(subject, predicate_type, cosign_statement)
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
        return VerificationObservation(
            subject,
            tuple(
                {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": base64.b64encode(canonical_json_bytes(statement)).decode(
                        "ascii"
                    ),
                }
                for statement in self.statements[
                    (str(subject), statement_predicate_type)
                ]
            ),
        )

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


class FailingSignatureSigner(FakeSigner):
    @override
    def verify(
        self, *, subject: OCIReference, public_key: Path
    ) -> VerificationObservation:
        del subject, public_key
        raise OperationalError("signature is absent")


def test_signature_coverage_failure_uses_stable_check_identifier(
    tmp_path: Path,
) -> None:
    subject = OCIReference.parse(
        "quay.io/example/app@sha256:" + "a" * 64, require_digest=True
    )

    with pytest.raises(OperationalError, match="coverage") as caught:
        attestation_module.verify_image_signature(
            FailingSignatureSigner(), subject, tmp_path / "cosign.pub"
        )

    assert caught.value.code == "CC0702"


def test_failed_publication_retains_digest_ownership_and_expiration(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
) -> None:
    repository = load_repository_config(repository_factory() / "conclear.toml")
    image = repository.release_image("app")
    workspace = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={"sourceRevision": "b" * 40, "version": "1.2.3"},
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
        QualificationWindow.start(datetime(2026, 1, 1, tzinfo=UTC)),
    )
    tags: dict[str, Digest] = {}
    registry = FakeRegistry(observation.graph, tags)
    registry_control = FakeRegistryControl(tags)
    now = datetime(2026, 1, 1, tzinfo=UTC)

    tags[tag] = observation.graph.digest
    with pytest.raises(OperationalError, match="already in use"):
        publish_candidate(
            candidate,
            image=image,
            workspace=workspace,
            registry=registry,
            registry_control=registry_control,
            auth_file=None,
            now=now,
            clock=lambda: now,
            policy=STRICT_POLICY,
        )
    assert workspace.journal.entries() == ()
    del tags[tag]
    registry.fail_graph_copy = True

    with pytest.raises(OperationalError, match="injected remote graph failure"):
        publish_candidate(
            candidate,
            image=image,
            workspace=workspace,
            registry=registry,
            registry_control=registry_control,
            auth_file=None,
            now=now,
            clock=lambda: now,
            policy=STRICT_POLICY,
        )

    entry = workspace.journal.entries()[0]
    assert entry.status is ResourceStatus.FAILED
    assert entry.metadata["digest"] == str(observation.graph.digest)
    assert entry.metadata["expiration"] == "2026-01-08T00:00:00Z"
    assert registry_control.expirations[tag] == datetime(2026, 1, 8, tzinfo=UTC)
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
    monkeypatch.setattr(attestation_module, "IDENTITY", identity)
    repository = load_repository_config(repository_factory() / "conclear.toml")
    image = repository.release_image("app")
    workspace = RunWorkspace.create(
        state_home=tmp_path / "state",
        immutable_inputs={
            "sourceRevision": "b" * 40,
            "configurationDigest": "sha256:" + "2" * 64,
            "builderId": BUILDER_ID,
            "image": "app",
            "version": "1.2.3",
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
        QualificationWindow.start(datetime(2026, 1, 1, tzinfo=UTC)),
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
            builder_id=BUILDER_ID,
            image_id=image.image_id,
            version="1.2.3",
            run_id=workspace.run_id,
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            finished_at=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
            materials=(),
        ),
        provenance,
    )
    evidence = ReleaseEvidence(
        source=records_module.SourceIdentity(repository.project.source, "b" * 40),
        configuration_digest=str(configuration_digest),
        tools=(
            records_module.ToolIdentity(
                "trivy",
                "0.69.3",
                executable_digest="sha256:" + "6" * 64,
            ),
        ),
        sboms=((platform, sbom, sbom_digest),),
        sbom_format=SpdxFormat.for_version("SPDX-2.3"),
        scan_digests=("sha256:" + "3" * 64,),
        provenance_path=provenance,
        provenance_digest=provenance_digest,
        provenance_materials=(),
        candidate_record_digest=candidate_digest,
        qualification_digests=candidate.qualification_digests,
    )
    changed_builder_provenance = load_json(provenance)
    changed_builder_provenance["predicate"]["runDetails"]["builder"]["id"] = (
        "https://example.com/builders/other-v1/"
    )
    with pytest.raises(RuleRejectionError, match="builder identity changed") as caught:
        validate_release_provenance(
            changed_builder_provenance,
            observation.graph,
            evidence=evidence,
            workspace=workspace,
            image=image,
        )
    assert caught.value.code == "CC0704"
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("test public key", encoding="utf-8")
    profile = ReleaseProfile(
        name="test",
        ci_context=CIContextPolicy.OBSERVE,
        builder=BuilderConfig(BUILDER_ID),
        auth_file=None,
        registry=QuayRegistryConfig(
            RegistryProvider.QUAY,
            "quay.io",
            "https://quay.io/api/v1",
            None,
            policy=STRICT_POLICY,
        ),
        cosign_private_key="test.key",
        cosign_public_key=public_key,
        passphrase_file=None,
        configuration_digest="sha256:" + "4" * 64,
        public_key_digest="sha256:" + "5" * 64,
        allowed_source_origins=("https://github.com/example/",),
    )
    tags: dict[str, Digest] = {}
    registry = FakeRegistry(observation.graph, tags)
    registry_control = FakeRegistryControl(tags)
    signer = FakeSigner()
    published = publish_candidate(
        candidate,
        image=image,
        workspace=workspace,
        registry=registry,
        registry_control=registry_control,
        auth_file=None,
        now=datetime(2026, 1, 1, 0, 2, tzinfo=UTC),
        clock=lambda: datetime(2026, 1, 1, 0, 2, tzinfo=UTC),
        policy=STRICT_POLICY,
    )
    assert load_published(workspace, candidate, image) == published
    workspace.journal.update(
        "candidate",
        ResourceStatus.CREATED,
        metadata={"digest": "sha256:" + "9" * 64},
    )
    with pytest.raises(RuleRejectionError, match="differs from candidate") as caught:
        load_published(workspace, candidate, image)
    assert caught.value.code == "CC0602"
    workspace.journal.update(
        "candidate",
        ResourceStatus.CREATED,
        metadata={"digest": str(observation.graph.digest)},
    )
    assert registry.copied_layout_paths == [
        workspace.root / "layouts" / "app" / "remote-published"
    ]
    original_sbom = sbom.read_bytes()
    sbom.write_text("{}\n", encoding="utf-8")
    with pytest.raises(RuleRejectionError) as caught:
        attest_candidate(
            published,
            evidence,
            image=image,
            workspace=workspace,
            signer=signer,
            private_key="test.key",
            public_key=public_key,
            passphrase="secret",
            passphrase_path=None,
            registry=registry,
            auth_file=None,
            now=datetime(2026, 1, 1, 0, 3, tzinfo=UTC),
        )
    assert caught.value.code == "CC0504"
    assert caught.value.exit_status == 2
    sbom.write_bytes(original_sbom)
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
        passphrase_path=None,
        registry=registry,
        auth_file=None,
        now=datetime(2026, 1, 1, 0, 3, tzinfo=UTC),
    )
    assert len(signer.statements[(str(platform_subject), SPDX_DOCUMENT_TYPE)]) == 1

    def run_verification(
        now: datetime, profile_value: ReleaseProfile = profile
    ) -> VerificationResult:
        return verify_candidate(
            published,
            candidate,
            evidence,
            workspace=workspace,
            image=image,
            profile=profile_value,
            signer=signer,
            registry=registry,
            auth_file=None,
            private_key="test.key",
            passphrase="secret",
            signer_mode="managed-key",
            signer_key_id="sha256:" + "4" * 64,
            host_architecture="x86_64",
            ci_context=PublicCIContext(
                provider="github-actions",
                repository="foundata/example",
                revision="b" * 40,
                run_id="1234",
            ),
            now=now,
            clock=lambda: now,
        )

    with pytest.raises(InvalidInvocationError, match="builder identity differs"):
        run_verification(
            datetime(2026, 1, 1, 0, 4, tzinfo=UTC),
            replace(
                profile,
                builder=BuilderConfig("https://example.com/builders/other-v1/"),
            ),
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
    assert (
        load_verification(workspace, image, published.immutable_reference)
        == verification
    )
    statement_content = verification.statement_path.read_bytes()
    statement_value = json.loads(statement_content)
    assert statement_value["predicate"]["payload"]["releaseEnvironment"] == {
        "hostArchitecture": "x86_64",
        "runId": workspace.run_id,
        "ciContext": {
            "provider": "github-actions",
            "source": "provider-environment",
            "repository": "foundata/example",
            "revision": "b" * 40,
            "runId": "1234",
        },
    }
    assert statement_value["predicate"]["payload"]["builder"] == {"id": BUILDER_ID}
    statement_value["predicate"]["verdict"] = "rejected"
    verification.statement_path.write_text(
        json.dumps(statement_value), encoding="utf-8"
    )
    with pytest.raises(RuleRejectionError, match="statement changed") as caught:
        load_verification(workspace, image, published.immutable_reference)
    assert caught.value.code == "CC0703"
    verification.statement_path.write_bytes(statement_content)
    expiration = registry_control.expirations.pop(tag)
    with pytest.raises(OperationalError, match="expiration is missing"):
        promote_candidate(
            published,
            verification,
            image=image,
            version="1.2.3",
            workspace=workspace,
            registry_control=registry_control,
            registry=registry,
            signer=signer,
            public_key=public_key,
            auth_file=None,
            now=datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
            clock=lambda: datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
        )
    registry_control.expirations[tag] = expiration
    registry_control.expirations[tag] = datetime(2026, 1, 1, 0, 6, tzinfo=UTC)
    with pytest.raises(RuleRejectionError, match="expired") as caught:
        promote_candidate(
            published,
            verification,
            image=image,
            version="1.2.3",
            workspace=workspace,
            registry_control=registry_control,
            registry=registry,
            signer=signer,
            public_key=public_key,
            auth_file=None,
            now=datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
            clock=lambda: datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
        )
    assert caught.value.code == "CC0603"
    registry_control.expirations[tag] = expiration

    registry.resolution_overrides["race"] = Digest("sha256:" + "9" * 64)
    with pytest.raises(OperationalError, match="did not resolve"):
        promotion_module._write_release_tag(
            "race",
            observation.graph.digest,
            image,
            workspace,
            registry_control,
            registry,
            None,
            immutable=True,
            require_protection=True,
            authorize_tag_write=lambda: None,
        )
    assert tags["race"] == observation.graph.digest
    race_entry = next(
        entry
        for entry in workspace.journal.entries()
        if entry.resource_id == "tag-race"
    )
    assert race_entry.status is ResourceStatus.FAILED
    del registry.resolution_overrides["race"]

    class UnenforcedControl(FakeRegistryControl):
        @override
        def ensure_tag_immutable(
            self, repository: OCIReference, tag: str
        ) -> TagObservation:
            raise UnsupportedOperationError("not enforced")

    with pytest.raises(OperationalError, match="not protected on assignment"):
        promotion_module._write_release_tag(
            "unprotected",
            observation.graph.digest,
            image,
            workspace,
            UnenforcedControl(tags),
            registry,
            None,
            immutable=True,
            require_protection=True,
            authorize_tag_write=lambda: None,
        )
    assert tags["unprotected"] == observation.graph.digest
    unprotected_entry = next(
        entry
        for entry in workspace.journal.entries()
        if entry.resource_id == "tag-unprotected"
    )
    assert unprotected_entry.status is ResourceStatus.FAILED
    image = replace(
        image,
        release=replace(
            image.release,
            version_tags=("{version}", "v{version}"),
        ),
    )
    workspace.journal.plan(
        resource_id="tag-1.2.3",
        kind=ResourceKind.TAG_WRITE,
        identifier=str(image.repository.with_tag("1.2.3")),
        ephemeral=False,
        metadata={
            "digest": str(observation.graph.digest),
            "versionTag": True,
            "registryProtectionRequired": True,
        },
    )
    workspace.journal.update("tag-1.2.3", ResourceStatus.FAILED)
    tags["v1.2.3"] = observation.graph.digest
    registry_control.immutable.add("v1.2.3")
    registry.resolution_overrides["v1.2.3"] = Digest("sha256:" + "9" * 64)
    with pytest.raises(OperationalError, match="conflicting registry observations"):
        promote_candidate(
            published,
            verification,
            image=image,
            version="1.2.3",
            workspace=workspace,
            registry_control=registry_control,
            registry=registry,
            signer=signer,
            public_key=public_key,
            auth_file=None,
            now=datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
            clock=lambda: datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
        )
    assert tags["1.2.3"] == observation.graph.digest
    assert "1.2.3" in registry_control.immutable
    assert "stable" not in tags
    del registry.resolution_overrides["v1.2.3"]
    registry_control.fail_delete = delete_fails
    promoted = promote_candidate(
        published,
        verification,
        image=image,
        version="1.2.3",
        workspace=workspace,
        registry_control=registry_control,
        registry=registry,
        signer=signer,
        public_key=public_key,
        auth_file=None,
        now=datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
        clock=lambda: datetime(2026, 1, 1, 0, 6, tzinfo=UTC),
    )

    assert workspace.load().state is RunState.PROMOTED
    assert promoted.tags == (
        ("1.2.3", observation.graph.digest),
        ("v1.2.3", observation.graph.digest),
        ("stable", observation.graph.digest),
    )
    assert promoted.candidate_deleted is not delete_fails
    assert tuple(finding.check_id for finding in promoted.findings) == (
        ("CC0605",) if delete_fails else ()
    )
    assert (tag in tags) is delete_fails
    assert tags["1.2.3"] == observation.graph.digest
    assert "1.2.3" in registry_control.immutable
    assert tag not in registry_control.immutable
    candidate_entry = next(
        entry
        for entry in workspace.journal.entries()
        if entry.kind is ResourceKind.CANDIDATE_REFERENCE
    )
    assert candidate_entry.status is (
        ResourceStatus.CREATED if delete_fails else ResourceStatus.REMOVED
    )
    assert sha256_file(verification.record_path) == verification.record_digest


def test_sboms_pair_with_published_platforms_across_variant_spellings(
    tmp_path: Path,
) -> None:
    from conclear.services.attestation import match_sboms_to_platforms
    from conclear.values import Platform

    amd64 = Platform.parse("linux/amd64")
    arm64 = Platform.parse("linux/arm64")
    arm64_v8 = Platform.parse("linux/arm64/v8")
    sboms = (
        (amd64, tmp_path / "amd64.spdx.json", "sha256:" + "a" * 64),
        (arm64, tmp_path / "arm64.spdx.json", "sha256:" + "b" * 64),
    )

    matched = match_sboms_to_platforms((amd64, arm64_v8), sboms)

    assert matched == {
        amd64: (tmp_path / "amd64.spdx.json", "sha256:" + "a" * 64),
        arm64_v8: (tmp_path / "arm64.spdx.json", "sha256:" + "b" * 64),
    }
    for platforms, evidence in (
        ((amd64, arm64_v8), sboms[:1]),
        ((amd64,), sboms),
        (
            (amd64, arm64_v8),
            (*sboms, (arm64_v8, tmp_path / "dup", "sha256:" + "c" * 64)),
        ),
    ):
        with pytest.raises(RuleRejectionError, match="SBOM platform coverage"):
            match_sboms_to_platforms(platforms, evidence)
