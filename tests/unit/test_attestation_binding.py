from datetime import UTC, datetime
from pathlib import Path
from typing import override

import pytest

import conclear.records as records_module
from conclear.adapters.cosign import VerificationObservation
from conclear.attestations import RESCAN_TYPE, STATEMENT_TYPE
from conclear.errors import OperationalError
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import canonical_json_bytes, sha256_bytes
from conclear.services.attestation import (
    has_verified_statement,
    require_verified_predicate,
    require_verified_statement,
)
from conclear.services.attestation_reads import verified_statements
from conclear.services.rescan import verified_rescan_history
from conclear.values import OCIReference
from tests.unit.test_attestations import _envelope, _statement
from tests.unit.test_publication import FakeSigner
from tests.unit.test_rescan_history import FINDING, SUBJECT, _record


class BoundarySigner(FakeSigner):
    def __init__(
        self,
        verified: tuple[dict[str, object], ...],
        downloaded: tuple[dict[str, object], ...],
        *,
        wrong_key: bool = False,
    ) -> None:
        super().__init__()
        self.verified = verified
        self.downloaded = downloaded
        self.wrong_key = wrong_key
        self.verifications = 0
        self.downloads = 0

    @override
    def verify_attestation(
        self, *, subject: OCIReference, public_key: Path, predicate_type: str
    ) -> VerificationObservation:
        assert public_key.name == "approved.pub"
        assert predicate_type.startswith("https://")
        self.verifications += 1
        if self.wrong_key:
            raise OperationalError("Attestation was not signed by the approved key")
        return VerificationObservation(
            subject, tuple(_envelope(item) for item in self.verified)
        )

    @override
    def download_attestations(
        self, *, subject: OCIReference, predicate_type: str, allow_missing: bool = False
    ) -> tuple[object, ...]:
        del subject, predicate_type, allow_missing
        self.downloads += 1
        return tuple(_envelope(item) for item in self.downloaded)


@pytest.mark.parametrize("consumer", ["predicate", "statement", "retry"])
@pytest.mark.parametrize("wrong_key", [False, True])
def test_unverified_matching_payload_cannot_replace_verified_evidence(
    tmp_path: Path, consumer: str, wrong_key: bool
) -> None:
    expected = _statement(STATEMENT_TYPE)
    signed = {**expected, "predicate": {"claim": False}}
    signer = BoundarySigner((signed,), (expected,), wrong_key=wrong_key)
    predicate_type = str(expected["predicateType"])
    if consumer == "retry" and not wrong_key:
        assert not has_verified_statement(
            signer,
            subject=SUBJECT,
            public_key=tmp_path / "approved.pub",
            predicate_type=predicate_type,
            expected=expected,
        )
    else:
        with pytest.raises(OperationalError):
            if consumer == "predicate":
                require_verified_predicate(
                    signer,
                    subject=SUBJECT,
                    public_key=tmp_path / "approved.pub",
                    predicate_type=predicate_type,
                    expected=expected["predicate"],
                )
            elif consumer == "statement":
                require_verified_statement(
                    signer,
                    subject=SUBJECT,
                    public_key=tmp_path / "approved.pub",
                    predicate_type=predicate_type,
                    expected=expected,
                )
            else:
                has_verified_statement(
                    signer,
                    subject=SUBJECT,
                    public_key=tmp_path / "approved.pub",
                    predicate_type=predicate_type,
                    expected=expected,
                )
    assert signer.verifications == 1
    assert signer.downloads == (1 if consumer == "retry" else 0)


def test_verified_matching_entry_is_selected_among_multiple_verified_payloads(
    tmp_path: Path,
) -> None:
    expected = _statement(STATEMENT_TYPE)
    other = {**expected, "predicate": {"claim": False}}
    signer = BoundarySigner((other, expected), (other,))
    require_verified_statement(
        signer,
        subject=SUBJECT,
        public_key=tmp_path / "approved.pub",
        predicate_type=str(expected["predicateType"]),
        expected=expected,
    )
    assert signer.downloads == 0


def test_empty_verifier_result_is_not_authenticated_evidence(tmp_path: Path) -> None:
    with pytest.raises(OperationalError, match="no entries"):
        verified_statements(
            BoundarySigner((), ()),
            subject=SUBJECT,
            public_key=tmp_path / "approved.pub",
            predicate_type=RESCAN_TYPE,
        )


def test_rescan_history_uses_verified_records_not_equal_count_downloads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        records_module, "IDENTITY", ApplicationIdentity(source_revision="f" * 40)
    )
    original = _record(None, datetime(2026, 1, 1, tzinfo=UTC))
    replacement = _record(None, datetime(2026, 9, 1, tzinfo=UTC), finding=None)
    envelope = {**_statement(STATEMENT_TYPE), "predicateType": RESCAN_TYPE}
    signer = BoundarySigner(
        ({**envelope, "predicate": original},),
        ({**envelope, "predicate": replacement},),
    )
    history = verified_rescan_history(
        SUBJECT, signer=signer, public_key=tmp_path / "approved.pub"
    )
    assert len(history) == 1
    assert history[0].record_digest == sha256_bytes(canonical_json_bytes(original))
    assert history[0].active_findings == (FINDING,)
    assert history[0].verified_at == datetime(2026, 1, 1, tzinfo=UTC)
