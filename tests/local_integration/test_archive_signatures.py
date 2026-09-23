"""Verify retained bundles with native Cosign and disposable public-log material."""

import os
from pathlib import Path

import pytest

from conclear.adapters.cosign import VerificationObservation
from conclear.attestations import (
    RELEASE_VERIFICATION_TYPE,
    decode_dsse_statements,
    write_statement,
)
from conclear.errors import ConClearError
from conclear.jsonutil import atomic_write_json, load_json, sha256_bytes
from conclear.process import CommandRequest, OperationKind
from conclear.runtime import ApplicationRuntime
from conclear.services.rescan_evidence import verified_predicates
from conclear.tools import ToolName
from conclear.values import Digest, OCIReference
from tests.local_integration.fixtures import manifest_run_id

pytestmark = pytest.mark.local_integration


def test_native_cosign_retained_bundle_verification(tmp_path: Path) -> None:
    manifest_run_id()
    if os.environ.get("CONCLEAR_TEST_PUBLIC_SIGSTORE") != "1":
        pytest.skip("Public Sigstore writes require explicit test opt-in")
    runtime = ApplicationRuntime.create(
        tmp_path / "environment", names=(ToolName.COSIGN,)
    )
    key = tmp_path / "synthetic"
    subject = OCIReference.parse(
        "quay.io/conclear-testing/archive-fixture@"
        + sha256_bytes(b"synthetic archive fixture"),
        require_digest=True,
    )
    assert subject.digest is not None
    statement = tmp_path / "statement.json"
    predicate: dict[str, object] = {
        "purpose": "ConClear archive verification test; no release authorization"
    }
    write_statement(
        path=statement,
        subject_name=subject.repository_name,
        subject_digest=subject.digest,
        predicate_type=RELEASE_VERIFICATION_TYPE,
        predicate=predicate,
    )
    bundle = tmp_path / "bundle.json"

    def run(*arguments: str) -> None:
        runtime.runner.run(
            CommandRequest(
                argv=(str(runtime.executable(ToolName.COSIGN).path), *arguments),
                environment={**runtime.environment, "COSIGN_PASSWORD": ""},
                timeout_seconds=180,
                operation=OperationKind.WRITE,
            )
        )

    try:
        run("generate-key-pair", "--output-key-prefix", str(key))
        run(
            "attest-blob",
            "--yes",
            "--key",
            str(key.with_suffix(".key")),
            "--statement",
            str(statement),
            "--hash",
            subject.digest.encoded,
            "--bundle",
            str(bundle),
        )
        signer = runtime.cosign()

        def verify(expected: OCIReference) -> VerificationObservation:
            return signer.verify_attestation_bundle(
                bundle=bundle,
                subject=expected,
                public_key=key.with_suffix(".pub"),
                predicate_type=RELEASE_VERIFICATION_TYPE,
            )

        observed = verify(subject)
        assert verified_predicates(
            decode_dsse_statements(observed.entries),
            predicate_type=RELEASE_VERIFICATION_TYPE,
            subject=subject,
        )
        with pytest.raises(ConClearError):
            verify(subject.with_digest(Digest("sha256:" + "0" * 64)))
        value = load_json(bundle)
        assert isinstance(value, dict)
        envelope = value["dsseEnvelope"]
        assert isinstance(envelope, dict)
        signatures = envelope["signatures"]
        assert isinstance(signatures, list) and isinstance(signatures[0], dict)
        signatures[0]["sig"] = "AAAA"
        atomic_write_json(bundle, value)
        with pytest.raises(ConClearError):
            verify(subject)
    finally:
        key.with_suffix(".key").unlink(missing_ok=True)
        runtime.close()
