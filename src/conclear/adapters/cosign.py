"""Cosign 3 production signing and verification adapter."""

import hashlib
from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.adapters.parsing import array_value, json_value
from conclear.errors import OperationalError
from conclear.process import OperationKind
from conclear.values import OCIReference

_FORBIDDEN_RELEASE_OPTIONS = frozenset(
    {
        "--tlog-upload=false",
        "--insecure-ignore-tlog",
        "--insecure-ignore-tlog=true",
        "--no-upload",
        "--no-upload=true",
    }
)


@dataclass(frozen=True, slots=True)
class SignatureObservation:
    """One completed signing operation using public transparency logging."""

    subject: OCIReference
    output: str


@dataclass(frozen=True, slots=True)
class VerificationObservation:
    """Parsed Cosign verification results for one immutable subject."""

    subject: OCIReference
    entries: tuple[object, ...]


class CosignAdapter(ToolAdapter):
    """Sign and verify with isolated configuration and default public Rekor use."""

    @staticmethod
    def public_key_fingerprint(public_key: Path) -> str:
        """Return the approved public key's SHA-256 fingerprint."""
        try:
            content = public_key.read_bytes()
        except OSError as exc:
            raise OperationalError("Unable to read approved Cosign public key") from exc
        return "sha256:" + hashlib.sha256(content).hexdigest()

    def sign(
        self,
        *,
        subject: OCIReference,
        private_key: str,
        passphrase: str | None,
    ) -> SignatureObservation:
        """Sign one digest with default public transparency-log upload enabled."""
        self._require_digest(subject)
        result = self._cosign_write(
            (
                "sign",
                "--yes",
                "--use-signing-config=true",
                "--key",
                private_key,
                str(subject),
            ),
            passphrase=passphrase,
        )
        return SignatureObservation(subject, result)

    def attest(
        self,
        *,
        subject: OCIReference,
        predicate: Path,
        predicate_type: str,
        private_key: str,
        passphrase: str | None,
    ) -> SignatureObservation:
        """Attach one signed predicate with default public log upload enabled."""
        self._require_digest(subject)
        result = self._cosign_write(
            (
                "attest",
                "--yes",
                "--use-signing-config=true",
                "--key",
                private_key,
                "--predicate",
                str(predicate),
                "--type",
                predicate_type,
                str(subject),
            ),
            passphrase=passphrase,
            secret_paths=(predicate,),
        )
        return SignatureObservation(subject, result)

    def attach_spdx(self, *, subject: OCIReference, sbom: Path) -> None:
        """Publish raw repository-scoped SPDX JSON alongside its signed attestation."""
        self._require_digest(subject)
        self._execute_release(
            (
                "attach",
                "sbom",
                "--type",
                "spdx",
                "--input-format",
                "json",
                "--sbom",
                str(sbom),
                str(subject),
            ),
            operation=OperationKind.WRITE,
            secret_paths=(sbom,),
        )

    def verify(
        self, *, subject: OCIReference, public_key: Path
    ) -> VerificationObservation:
        """Verify a signature and its public transparency-log inclusion."""
        self._require_digest(subject)
        output = self._execute_release(
            ("verify", "--key", str(public_key), "--output", "json", str(subject)),
            secret_paths=(public_key,),
        )
        return self._verification(subject, output)

    def verify_attestation(
        self,
        *,
        subject: OCIReference,
        public_key: Path,
        predicate_type: str,
    ) -> VerificationObservation:
        """Verify matching attestations and public log inclusion."""
        self._require_digest(subject)
        output = self._execute_release(
            (
                "verify-attestation",
                "--key",
                str(public_key),
                "--type",
                predicate_type,
                "--output",
                "json",
                str(subject),
            ),
            secret_paths=(public_key,),
        )
        return self._verification(subject, output)

    def download_attestations(
        self, *, subject: OCIReference, predicate_type: str
    ) -> tuple[object, ...]:
        """Download matching in-toto envelopes for workflow-level validation."""
        self._require_digest(subject)
        output = self._execute_release(
            (
                "download",
                "attestation",
                "--predicate-type",
                predicate_type,
                str(subject),
            )
        )
        values: list[object] = []
        for line in output.splitlines():
            if line.strip():
                values.append(json_value(line, label="Cosign attestation"))
        return tuple(values)

    def _cosign_write(
        self,
        arguments: tuple[str, ...],
        *,
        passphrase: str | None,
        secret_paths: tuple[Path, ...] = (),
    ) -> str:
        extra = {} if passphrase is None else {"COSIGN_PASSWORD": passphrase}
        return self._execute_release(
            arguments,
            operation=OperationKind.WRITE,
            extra_environment=extra,
            secret_values=(() if passphrase is None else (passphrase,)),
            secret_paths=secret_paths,
        )

    def _execute_release(
        self,
        arguments: tuple[str, ...],
        *,
        operation: OperationKind = OperationKind.READ,
        extra_environment: dict[str, str] | None = None,
        secret_values: tuple[str, ...] = (),
        secret_paths: tuple[Path, ...] = (),
    ) -> str:
        if any(argument in _FORBIDDEN_RELEASE_OPTIONS for argument in arguments):
            raise ValueError(
                "Cosign release operations cannot disable log transparency"
            )
        return self._run(
            arguments,
            timeout_seconds=600,
            operation=operation,
            extra_environment=extra_environment,
            secret_values=secret_values,
            secret_paths=secret_paths,
        ).stdout

    @staticmethod
    def _verification(subject: OCIReference, output: str) -> VerificationObservation:
        entries = array_value(
            json_value(output, label="Cosign verification"),
            label="Cosign verification",
        )
        if not entries:
            raise OperationalError("Cosign verification returned no verified entries")
        return VerificationObservation(subject, tuple(entries))

    @staticmethod
    def _require_digest(subject: OCIReference) -> None:
        if subject.digest is None or subject.tag is not None:
            raise ValueError("Cosign release subjects must use an immutable digest")
