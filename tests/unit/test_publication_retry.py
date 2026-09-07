"""Attestation and verification retries reconcile the journal with the registry."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conclear.artifacts import load_candidate, load_published, load_release_evidence
from conclear.attestations import SPDX_DOCUMENT_TYPE
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.provenance import SLSA_PROVENANCE_TYPE
from conclear.services import release
from conclear.services.attestation import attest_candidate
from conclear.services.verification import verify_candidate
from conclear.workspace import ResourceStatus, RunState
from tests.unit.test_release_workflow import NOW, Harness


@pytest.fixture
def attested(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_factory: Callable[..., Path],
) -> Harness:
    harness = Harness(tmp_path, monkeypatch, repository_factory)

    def stop_before_verification(*args: Any, **kwargs: Any) -> None:
        raise OperationalError("verification interrupted")

    harness.monkeypatch.setattr(release, "verify_candidate", stop_before_verification)
    with pytest.raises(OperationalError, match="verification interrupted"):
        harness.complete()
    assert harness.workspace.load().state is RunState.INCOMPLETE
    snapshot = harness.workspace.load()
    assert snapshot.resume_state is RunState.ATTESTED
    harness.workspace.resume(snapshot.immutable_inputs, now=NOW)
    return harness


def _attest(harness: Harness) -> None:
    workspace, image = harness.workspace, harness.image
    candidate = load_candidate(workspace, image)
    published = load_published(workspace, candidate, image)
    evidence = load_release_evidence(workspace, image)
    attest_candidate(
        published,
        evidence,
        image=image,
        workspace=workspace,
        signer=harness.runtime.signer,
        private_key="cosign.key",
        public_key=harness.profile.cosign_public_key,
        passphrase=None,
        passphrase_path=None,
        registry=harness.runtime.registry,
        auth_file=None,
        now=NOW,
    )


def _entry(harness: Harness, resource_id: str) -> Any:
    return next(
        entry
        for entry in harness.workspace.journal.entries()
        if entry.resource_id == resource_id
    )


def test_repeated_attestation_reuses_verified_remote_evidence(
    attested: Harness,
) -> None:
    signer = attested.runtime.signer
    statements_before = {key: len(value) for key, value in signer.statements.items()}
    signatures_before = set(signer.signatures)
    snapshot = attested.workspace.load()
    assert snapshot.state is RunState.ATTESTED

    for resource_id in ("provenance", "sbom-linux-amd64", "signature-0"):
        attested.workspace.journal.update(resource_id, ResourceStatus.FAILED)
    state_path = attested.workspace.root / "run.json"
    content = state_path.read_text(encoding="utf-8").replace(
        '"state":"attested"', '"state":"published"'
    )
    state_path.write_text(content, encoding="utf-8")

    _attest(attested)

    assert {key: len(value) for key, value in signer.statements.items()} == (
        statements_before
    )
    assert set(signer.signatures) == signatures_before
    for resource_id in ("provenance", "sbom-linux-amd64", "signature-0"):
        assert _entry(attested, resource_id).status is ResourceStatus.CREATED
    assert attested.workspace.load().state is RunState.ATTESTED


@pytest.mark.parametrize(
    ("resource_id", "predicate_type", "code"),
    [
        ("provenance", SLSA_PROVENANCE_TYPE, None),
        ("sbom-linux-amd64", SPDX_DOCUMENT_TYPE, None),
    ],
)
def test_recorded_attestation_that_vanished_remotely_is_an_operational_failure(
    attested: Harness, resource_id: str, predicate_type: str, code: str | None
) -> None:
    signer = attested.runtime.signer
    state_path = attested.workspace.root / "run.json"
    state_path.write_text(
        state_path.read_text(encoding="utf-8").replace(
            '"state":"attested"', '"state":"published"'
        ),
        encoding="utf-8",
    )
    for key in list(signer.statements):
        if key[1] == predicate_type:
            del signer.statements[key]

    with pytest.raises(OperationalError, match="is missing") as caught:
        _attest(attested)

    assert caught.value.code == code
    assert attested.workspace.load().state is RunState.PUBLISHED


def test_recorded_signature_that_vanished_remotely_uses_the_signing_identifier(
    attested: Harness,
) -> None:
    signer = attested.runtime.signer
    state_path = attested.workspace.root / "run.json"
    state_path.write_text(
        state_path.read_text(encoding="utf-8").replace(
            '"state":"attested"', '"state":"published"'
        ),
        encoding="utf-8",
    )
    signer.signatures.clear()

    with pytest.raises(OperationalError, match="signature is missing") as caught:
        _attest(attested)

    assert caught.value.code == "CC0702"


def test_verification_after_attestation_requires_the_expected_state(
    attested: Harness, tmp_path: Path
) -> None:
    workspace, image = attested.workspace, attested.image
    candidate = load_candidate(workspace, image)
    published = load_published(workspace, candidate, image)
    evidence = load_release_evidence(workspace, image)
    workspace.transition(RunState.VERIFIED)

    with pytest.raises(InvalidInvocationError, match="requires attested state"):
        verify_candidate(
            published,
            candidate,
            evidence,
            workspace=workspace,
            image=image,
            profile=attested.profile,
            signer=attested.runtime.signer,
            registry=attested.runtime.registry,
            auth_file=None,
            private_key="cosign.key",
            passphrase=None,
            signer_mode="managed-key",
            signer_key_id="sha256:" + "4" * 64,
            host_architecture="x86_64",
            ci_context=None,
            now=NOW,
        )
