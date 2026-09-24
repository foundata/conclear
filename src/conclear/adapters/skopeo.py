"""Skopeo registry and OCI transport adapter."""

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.base import ToolAdapter, prepare_new_layout_path
from conclear.errors import (
    CommandExecutionError,
    InvalidInvocationError,
    OperationalError,
)
from conclear.oci import OCIGraph, validate_layout
from conclear.process import OperationKind
from conclear.values import Digest, OCIReference, Platform


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

    def platform_manifest_digest(
        self,
        reference: OCIReference,
        platform: Platform,
        *,
        auth_file: Path | None = None,
    ) -> Digest:
        """Return the digest of the platform manifest a pinned reference resolves to.

        A single-platform manifest resolves to itself; an image index resolves
        to exactly one manifest whose platform semantically matches.
        """
        # Skopeo rejects a reference that carries both a tag and a digest; the
        # pinned digest alone names the exact index or manifest.
        addressed = (
            reference
            if reference.digest is None
            else reference.with_digest(reference.digest)
        )
        arguments = ["inspect", "--raw"]
        if auth_file is not None:
            arguments.extend(("--authfile", str(auth_file)))
        arguments.append(f"docker://{addressed}")
        result = self._run(
            arguments,
            timeout_seconds=120,
            retries=2,
            secret_paths=(() if auth_file is None else (auth_file,)),
        )
        try:
            document = json.loads(result.stdout)
        except ValueError as exc:
            raise OperationalError("Skopeo returned an unreadable manifest") from exc
        if not isinstance(document, dict):
            raise OperationalError("Skopeo returned an unreadable manifest")
        manifests = document.get("manifests")
        if manifests is None:
            return self.resolve_digest(addressed, auth_file=auth_file)
        if not isinstance(manifests, list):
            raise OperationalError("Skopeo returned a malformed image index")
        matches: list[Digest] = []
        for item in manifests:
            if not isinstance(item, dict) or not isinstance(item.get("platform"), dict):
                continue
            declared = item["platform"]
            try:
                candidate = Platform(
                    str(declared.get("os")),
                    str(declared.get("architecture")),
                    declared.get("variant") or None,
                )
            except Exception:
                continue
            if candidate.semantically_matches(platform) and isinstance(
                item.get("digest"), str
            ):
                matches.append(Digest(item["digest"]))
        if len(matches) != 1:
            raise OperationalError(
                f"Image index {reference} resolves {len(matches)} manifests for "
                f"{platform}, expected exactly one"
            )
        return matches[0]

    def resolve_optional(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest | None:
        """Return no digest only for an unambiguously absent registry reference."""
        try:
            return self.resolve_digest(reference, auth_file=auth_file)
        except CommandExecutionError as exc:
            diagnostic = "\n".join((exc.stdout, exc.stderr)).lower()
            if any(
                marker in diagnostic for marker in ("manifest unknown", "name unknown")
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
        prepare_new_layout_path(layout_path)
        arguments = ["copy", "--all", "--preserve-digests"]
        if auth_file is not None:
            arguments.extend(("--src-authfile", str(auth_file)))
        arguments.extend(
            (f"docker://{source}", f"oci:{layout_path}:{layout_reference}")
        )
        try:
            self._run(
                arguments,
                timeout_seconds=1800,
                retries=2,
                secret_paths=(() if auth_file is None else (auth_file,)),
            )
        except CommandExecutionError:
            shutil.rmtree(layout_path, ignore_errors=True)
            raise
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
