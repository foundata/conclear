"""Skopeo registry and OCI transport adapter."""

from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.errors import (
    CommandExecutionError,
    InvalidInvocationError,
    OperationalError,
)
from conclear.oci import OCIGraph, validate_layout
from conclear.process import OperationKind
from conclear.values import Digest, OCIReference


@dataclass(frozen=True, slots=True)
class RegistryCopyObservation:
    """A locally revalidated copy of a remote immutable subject."""

    reference: OCIReference
    layout_path: Path
    graph: OCIGraph


class SkopeoAdapter(ToolAdapter):
    """Perform digest-preserving image reads, copies and deletes."""

    def resolve_digest(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest:
        """Resolve one tag or digest reference to the registry manifest digest."""
        arguments = ["inspect"]
        if auth_file is not None:
            arguments.extend(("--authfile", str(auth_file)))
        arguments.extend(("--format", "{{.Digest}}", f"docker://{reference}"))
        result = self._run(
            arguments,
            timeout_seconds=120,
            retries=2,
            secret_paths=(() if auth_file is None else (auth_file,)),
        )
        try:
            return Digest(result.stdout.strip())
        except Exception as exc:
            raise OperationalError(
                "Skopeo returned an invalid manifest digest"
            ) from exc

    def resolve_optional(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest | None:
        """Return no digest only for an unambiguously absent registry reference."""
        try:
            return self.resolve_digest(reference, auth_file=auth_file)
        except CommandExecutionError as exc:
            message = str(exc).lower()
            if any(
                marker in message
                for marker in ("manifest unknown", "name unknown", "not found")
            ):
                return None
            raise

    def copy_layout_to_registry(
        self,
        *,
        layout_path: Path,
        layout_reference: str,
        destination: OCIReference,
        auth_file: Path | None,
    ) -> None:
        """Copy every manifest while requiring digest preservation."""
        arguments = ["copy", "--all", "--preserve-digests"]
        if auth_file is not None:
            arguments.extend(("--dest-authfile", str(auth_file)))
        arguments.extend(
            (f"oci:{layout_path}:{layout_reference}", f"docker://{destination}")
        )
        self._run(
            arguments,
            timeout_seconds=1800,
            operation=OperationKind.WRITE,
            secret_paths=(() if auth_file is None else (auth_file,)),
        )

    def copy_registry_to_layout(
        self,
        *,
        source: OCIReference,
        layout_path: Path,
        layout_reference: str,
        auth_file: Path | None,
    ) -> RegistryCopyObservation:
        """Copy a complete remote graph and revalidate all local content digests."""
        arguments = ["copy", "--all", "--preserve-digests"]
        if auth_file is not None:
            arguments.extend(("--src-authfile", str(auth_file)))
        arguments.extend(
            (f"docker://{source}", f"oci:{layout_path}:{layout_reference}")
        )
        self._run(
            arguments,
            timeout_seconds=1800,
            secret_paths=(() if auth_file is None else (auth_file,)),
        )
        graph = validate_layout(layout_path, reference=layout_reference)
        if source.digest is not None and graph.digest != source.digest:
            raise OperationalError(
                f"Remote graph digest {graph.digest} differs from {source.digest}"
            )
        return RegistryCopyObservation(source, layout_path, graph)

    def delete(self, reference: OCIReference, *, auth_file: Path) -> None:
        """Delete one previously journaled registry tag."""
        if reference.tag is None or reference.digest is not None:
            raise InvalidInvocationError("Skopeo deletion requires a tag reference")
        self._run(
            ("delete", "--authfile", str(auth_file), f"docker://{reference}"),
            timeout_seconds=300,
            operation=OperationKind.WRITE,
            secret_paths=(auth_file,),
        )
