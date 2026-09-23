"""Trivy database, scan and SPDX adapter."""

import os
import re
import shutil
import tempfile
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.errors import OperationalError
from conclear.fileio import create_new_file, locked_file
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
)
from conclear.parsing import array_value, object_value, string_value
from conclear.process import OperationKind
from conclear.records import format_timestamp
from conclear.scan_identity import (
    ScanIdentity,
    neutralize_scan_report,
    neutralize_spdx_document,
)
from conclear.spdx import SPDX_2_3, validate_spdx_document
from conclear.values import Digest


@dataclass(frozen=True, slots=True)
class DatabaseObservation:
    """One validated immutable Trivy vulnerability database snapshot."""

    path: Path
    digest: str
    metadata: dict[str, object]


@dataclass(frozen=True, slots=True)
class ScanObservation:
    """One Trivy result bound to its exact stored bytes."""

    path: Path
    digest: str
    value: object


class TrivyAdapter(ToolAdapter):
    """Refresh a run-selected database and scan only explicit local targets."""

    def select_database(self, cache_root: Path) -> DatabaseObservation:
        """Select a validated database snapshot without silently accepting corruption."""
        pointer = object_value(
            load_json(cache_root / "current.json"), label="Trivy DB pointer"
        )
        if pointer.get("schemaVersion") != 1:
            raise OperationalError("Trivy DB pointer has an unsupported schema")
        expected_digest = string_value(
            pointer.get("databaseDigest"), label="Trivy DB digest"
        )
        snapshot_name = string_value(pointer.get("snapshot"), label="Trivy DB snapshot")
        if re.fullmatch(r"[0-9a-f]{64}", snapshot_name) is None:
            raise OperationalError("Trivy DB snapshot name is malformed")
        snapshot = cache_root / "snapshots" / snapshot_name
        observation = _database_observation(snapshot)
        if observation.digest != expected_digest:
            raise OperationalError(
                "Trivy database snapshot digest does not match pointer"
            )
        return observation

    def select_database_by_digest(
        self, cache_root: Path, expected_digest: Digest
    ) -> DatabaseObservation:
        """Select a named snapshot and recompute its exact content digest."""
        snapshot = cache_root / "snapshots" / expected_digest.encoded
        observation = _database_observation(snapshot)
        if observation.digest != str(expected_digest):
            raise OperationalError(
                "Trivy database snapshot content differs from the expected digest"
            )
        return observation

    def refresh_database(self, cache_root: Path) -> DatabaseObservation:
        """Refresh in a same-filesystem directory and atomically install the snapshot."""
        cache_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with locked_file(cache_root / ".db.lock", label="Trivy database cache"):
            temporary = Path(tempfile.mkdtemp(prefix=".db.", dir=cache_root))
            try:
                for download in ("--download-db-only", "--download-java-db-only"):
                    self._execute(
                        (
                            "image",
                            download,
                            "--cache-dir",
                            self._path(temporary, writable=True, name="cache"),
                        ),
                        timeout_seconds=900,
                        operation=OperationKind.WRITE,
                        network=True,
                    )
                observation = _database_observation(temporary)
                snapshot_name = observation.digest.removeprefix("sha256:")
                snapshots = cache_root / "snapshots"
                snapshots.mkdir(mode=0o700, parents=True, exist_ok=True)
                installed = snapshots / snapshot_name
                if not installed.exists():
                    temporary.replace(installed)
                    temporary = installed
                atomic_write_json(
                    cache_root / "current.json",
                    {
                        "schemaVersion": 1,
                        "databaseDigest": observation.digest,
                        "snapshot": snapshot_name,
                    },
                )
                directory = os.open(snapshots, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                return DatabaseObservation(
                    installed, observation.digest, observation.metadata
                )
            except OSError as exc:
                raise OperationalError(
                    "Unable to install refreshed Trivy database"
                ) from exc
            finally:
                if temporary.parent == cache_root:
                    shutil.rmtree(temporary, ignore_errors=True)

    def scan_filesystem(
        self,
        *,
        path: Path,
        report_path: Path,
        cache_root: Path,
        scanners: tuple[str, ...],
        identity: ScanIdentity | None = None,
    ) -> ScanObservation:
        """Scan an explicit source tree for secrets and configuration findings."""
        return self._scan(
            (
                "filesystem",
                "--cache-dir",
                self._path(cache_root, writable=True, name="cache"),
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
                "--scanners",
                ",".join(scanners),
                "--format",
                "json",
                "--output",
                self._path(report_path, writable=True, name="reports"),
                self._path(path, name="source"),
            ),
            report_path,
            identity=identity,
        )

    def scan_layout(
        self,
        *,
        layout_path: Path,
        report_path: Path,
        cache_root: Path,
        identity: ScanIdentity | None = None,
    ) -> ScanObservation:
        """Scan one exact OCI layout using the selected immutable database cache."""
        seen_layout = self._path(layout_path, name="layout")
        observation = self._scan(
            (
                "image",
                "--input",
                seen_layout,
                "--cache-dir",
                self._path(cache_root, writable=True, name="cache"),
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
                "--scanners",
                "vuln,secret,misconfig",
                "--image-config-scanners",
                "misconfig,secret",
                "--include-non-failures",
                "--format",
                "json",
                "--output",
                self._path(report_path, writable=True, name="reports"),
            ),
            report_path,
            identity=_as_seen(identity, layout_path, seen_layout),
        )
        _require_image_config_coverage(observation.value)
        return observation

    def generate_spdx(
        self,
        *,
        layout_path: Path,
        output_path: Path,
        cache_root: Path,
        identity: ScanIdentity | None = None,
    ) -> ScanObservation:
        """Generate an SPDX JSON inventory from one exact OCI layout."""
        seen_layout = self._path(layout_path, name="layout")
        observation = self._scan(
            (
                "image",
                "--input",
                seen_layout,
                "--cache-dir",
                self._path(cache_root, writable=True, name="cache"),
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
                "--format",
                "spdx-json",
                "--output",
                self._path(output_path, writable=True, name="exports"),
            ),
            output_path,
        )
        document = validate_spdx_document(
            observation.value, label="Trivy SPDX document", spdx_version=SPDX_2_3
        )
        identity = _as_seen(identity, layout_path, seen_layout)
        if identity is not None:
            document = neutralize_spdx_document(document, identity)
        # Attestation envelopes preserve JSON values, not the scanner's formatting.
        atomic_write_json(output_path, document, mode=0o644)
        return ScanObservation(output_path, sha256_file(output_path), document)

    def scan_sbom(
        self,
        *,
        sbom_path: Path,
        report_path: Path,
        cache_root: Path,
        identity: ScanIdentity | None = None,
    ) -> ScanObservation:
        """Match current vulnerability data against one retained SPDX inventory."""
        seen_sbom = self._path(sbom_path, name="sbom")
        return self._scan(
            (
                "sbom",
                "--cache-dir",
                self._path(cache_root, writable=True, name="cache"),
                "--skip-db-update",
                "--skip-java-db-update",
                "--offline-scan",
                "--format",
                "json",
                "--output",
                self._path(report_path, writable=True, name="reports"),
                seen_sbom,
            ),
            report_path,
            identity=_as_seen(identity, sbom_path, seen_sbom),
        )

    def _scan(
        self,
        arguments: tuple[str, ...],
        output_path: Path,
        *,
        identity: ScanIdentity | None = None,
    ) -> ScanObservation:
        self._execute(arguments, timeout_seconds=1800)
        value = load_json(output_path)
        if identity is not None:
            # Evidence names the subject, never the release host.
            value = neutralize_scan_report(value, identity)
            atomic_write_json(output_path, value, mode=0o644)
        return ScanObservation(output_path, sha256_file(output_path), value)

    def _execute(
        self,
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float,
        operation: OperationKind = OperationKind.READ,
        network: bool = False,
    ) -> None:
        """Exclude ambient and repository suppression files from every invocation."""
        root = (self._log_directory.parent / "trivy-invocations").absolute()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            directory = Path(temporary)
            config = directory / "trivy.json"
            ignore = directory / ".trivyignore"
            secret = directory / "trivy-secret.yaml"
            create_new_file(config, b"{}\n", mode=0o600)
            create_new_file(ignore, b"", mode=0o600)
            create_new_file(secret, b"{}\n", mode=0o600)
            self._path(directory, name="invocation")
            options: tuple[str, ...] = (
                "--config",
                self._path(config),
                "--ignorefile",
                self._path(ignore),
                "--disable-telemetry",
                "--skip-version-check",
            )
            if arguments[0] in {"image", "filesystem"}:
                options += ("--secret-config", self._path(secret))
            self._run(
                (arguments[0], *options, *arguments[1:]),
                cwd=directory,
                timeout_seconds=timeout_seconds,
                operation=operation,
                network=network,
            )


def _as_seen(
    identity: ScanIdentity | None, host_path: Path, seen_path: str
) -> ScanIdentity | None:
    """Return the identity naming the artifact by the path the tool saw.

    Neutralization rewrites the artifact path Trivy repeats in its output; a
    tool run from its image repeats the mounted path, not the host one.
    """
    if identity is None or str(host_path.absolute()) == seen_path:
        return identity
    return replace(identity, artifact_path=Path(seen_path))


def _require_image_config_coverage(value: object) -> None:
    report = object_value(value, label="Trivy image report")
    results = array_value(report.get("Results"), label="Trivy image results")
    if report.get("ArtifactType") != "container_image" or not any(
        isinstance(result, dict)
        and result.get("Class") == "config"
        and result.get("Type") == "dockerfile"
        and result.get("Target") == report.get("ArtifactName")
        and isinstance(result.get("Misconfigurations"), list)
        and bool(result["Misconfigurations"])
        for result in results
    ):
        raise OperationalError("Trivy report lacks OCI configuration scan coverage")


def _database_observation(snapshot: Path) -> DatabaseObservation:
    components = {
        "vulnerability": (
            snapshot / "db" / "trivy.db",
            snapshot / "db" / "metadata.json",
        ),
        "java": (
            snapshot / "java-db" / "trivy-java.db",
            snapshot / "java-db" / "metadata.json",
        ),
    }
    identity: dict[str, object] = {}
    metadata: dict[str, object] = {}
    for name, (database_path, metadata_path) in components.items():
        component = _database_metadata(
            object_value(load_json(metadata_path), label=f"Trivy {name} DB metadata"),
            label=f"Trivy {name} DB metadata",
        )
        metadata[name] = component
        # Download time is local; upstream freshness metadata belongs to the
        # immutable snapshot so changing it invalidates a pinned selection.
        identity[name] = {
            "contentDigest": sha256_file(database_path),
            "schemaVersion": component["schemaVersion"],
            "updatedAt": component["updatedAt"],
            "nextUpdate": component["nextUpdate"],
        }
    digest = sha256_bytes(canonical_json_bytes(identity))
    return DatabaseObservation(snapshot, digest, metadata)


def _database_metadata(value: dict[str, object], *, label: str) -> dict[str, object]:
    version = value.get("Version", value.get("version"))
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise OperationalError(f"{label} version is malformed")
    return {
        "schemaVersion": version,
        "updatedAt": _metadata_timestamp(
            value.get("UpdatedAt", value.get("updatedAt")), label, "updated-at"
        ),
        "nextUpdate": _metadata_timestamp(
            value.get("NextUpdate", value.get("nextUpdate")), label, "next-update"
        ),
        "downloadedAt": _metadata_timestamp(
            value.get("DownloadedAt", value.get("downloadedAt")),
            label,
            "downloaded-at",
        ),
    }


def _metadata_timestamp(value: object, label: str, field: str) -> str:
    if not isinstance(value, str):
        raise OperationalError(f"{label} {field} time is malformed")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperationalError(f"{label} {field} time is malformed") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise OperationalError(f"{label} {field} time lacks a timezone")
    # Trivy writes sub-second precision; records carry whole seconds only.
    return format_timestamp(timestamp.astimezone(UTC).replace(microsecond=0))
