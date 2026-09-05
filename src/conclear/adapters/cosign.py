"""Cosign 3 production signing and verification adapter."""

import hashlib
from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.errors import CommandExecutionError, OperationalError
from conclear.parsing import array_value, json_value
from conclear.process import OperationKind
from conclear.secrets import MAX_PROFILE_BYTES, read_protected_file
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

    def initialize(self) -> None:
        """Initialize and verify access to default public Sigstore trust data."""
        self._execute_release(("initialize",))

    @staticmethod
    def public_key_fingerprint(public_key: Path) -> str:
        """Return the approved public key's SHA-256 fingerprint."""
        content = read_protected_file(
            public_key,
            maximum_bytes=MAX_PROFILE_BYTES,
            allow_group_read=True,
        )
        return "sha256:" + hashlib.sha256(content).hexdigest()

    def sign(
        self,
        *,
        subject: OCIReference,
        private_key: str,
        passphrase: str | None,
        passphrase_path: Path | None = None,
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
            secret_paths=_signing_secret_paths(private_key, passphrase_path),
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
        passphrase_path: Path | None = None,
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
            secret_paths=(
                predicate,
                *_signing_secret_paths(private_key, passphrase_path),
            ),
        )
        return SignatureObservation(subject, result)

    def attest_statement(
        self,
        *,
        subject: OCIReference,
        statement: Path,
        private_key: str,
        passphrase: str | None,
        passphrase_path: Path | None = None,
    ) -> SignatureObservation:
        """Attach one caller-validated in-toto Statement with public log inclusion."""
        self._require_digest(subject)
        result = self._cosign_write(
            (
                "attest",
                "--yes",
                "--use-signing-config=true",
                "--key",
                private_key,
                "--statement",
                str(statement),
                str(subject),
            ),
            passphrase=passphrase,
            secret_paths=(
                statement,
                *_signing_secret_paths(private_key, passphrase_path),
            ),
        )
        return SignatureObservation(subject, result)

    def verify(
        self, *, subject: OCIReference, public_key: Path
    ) -> VerificationObservation:
        """Verify a signature and its public transparency-log inclusion."""
        self._require_digest(subject)
        output = self._execute_release(
            ("verify", "--key", str(public_key), "--output", "json", str(subject)),
            secret_paths=(public_key,),
            check_code="CC0701",
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
            check_code="CC0701",
        )
        return self._verification(subject, output)

    def download_attestations(
        self,
        *,
        subject: OCIReference,
        predicate_type: str,
        allow_missing: bool = False,
    ) -> tuple[object, ...]:
        """Download matching in-toto envelopes for workflow-level validation."""
        self._require_digest(subject)
        try:
            output = self._execute_release(
                (
                    "download",
                    "attestation",
                    "--predicate-type",
                    predicate_type,
                    str(subject),
                )
            )
        except CommandExecutionError as exc:
            if not allow_missing or not _missing_attestation(exc, predicate_type):
                raise
            return ()
        values: list[object] = []
        for line in output.splitlines():
            if line.strip():
                values.append(json_value(line, label="Cosign attestation"))
        return tuple(values)

    def download_signatures(self, *, subject: OCIReference) -> tuple[object, ...]:
        """Download signature payloads for conclusive retry recovery."""
        self._require_digest(subject)
        output = self._execute_release(("download", "signature", str(subject)))
        values: list[object] = []
        for line in output.splitlines():
            if line.strip():
                values.append(json_value(line, label="Cosign signature"))
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
            check_code="CC0701",
        )

    def _execute_release(
        self,
        arguments: tuple[str, ...],
        *,
        operation: OperationKind = OperationKind.READ,
        extra_environment: dict[str, str] | None = None,
        secret_values: tuple[str, ...] = (),
        secret_paths: tuple[Path, ...] = (),
        check_code: str | None = None,
    ) -> str:
        if any(argument in _FORBIDDEN_RELEASE_OPTIONS for argument in arguments):
            raise OperationalError(
                "Cosign release operations cannot disable log transparency",
                code="CC0701",
            )
        try:
            return self._run(
                arguments,
                timeout_seconds=600,
                operation=operation,
                retries=2 if operation is OperationKind.READ else 0,
                extra_environment=extra_environment,
                secret_values=secret_values,
                secret_paths=secret_paths,
            ).stdout
        except CommandExecutionError as exc:
            if check_code is None:
                raise
            raise OperationalError(str(exc), code=check_code) from exc

    @staticmethod
    def _verification(subject: OCIReference, output: str) -> VerificationObservation:
        entries = array_value(
            json_value(output, label="Cosign verification"),
            label="Cosign verification",
        )
        if not entries:
            raise OperationalError(
                "Cosign verification returned no verified entries", code="CC0701"
            )
        return VerificationObservation(subject, tuple(entries))

    @staticmethod
    def _require_digest(subject: OCIReference) -> None:
        if subject.digest is None or subject.tag is not None:
            raise OperationalError(
                "Cosign release subjects must use an immutable digest"
            )


def _missing_attestation(error: CommandExecutionError, predicate_type: str) -> bool:
    expected = {
        "no attestations",
        "no matching attestations",
        f"no attestations with predicate type '{predicate_type}' found",
    }
    messages = {
        line.removeprefix("Error: ").strip()
        for line in (*error.stderr.splitlines(), *error.stdout.splitlines())
    }
    return bool(messages & expected)


def _signing_secret_paths(
    private_key: str, passphrase_path: Path | None
) -> tuple[Path, ...]:
    key_paths = (
        ()
        if private_key.startswith("pkcs11:") or "://" in private_key
        else (Path(private_key),)
    )
    return (*key_paths, *(() if passphrase_path is None else (passphrase_path,)))
