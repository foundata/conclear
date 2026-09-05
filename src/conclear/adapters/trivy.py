"""Trivy database, scan and SPDX adapter."""

import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.adapters.parsing import object_value, string_value
from conclear.errors import OperationalError
from conclear.fileio import locked_file
from conclear.jsonutil import (
    atomic_write_json,
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_file,
)
from conclear.process import OperationKind
from conclear.spdx import validate_spdx_document
from conclear.values import Digest


@dataclass(frozen=True, slots=True)
class DatabaseObservation:
    """One validated immutable Trivy vulnerability database snapshot."""

    path: Path
    digest: str
    metadata: dict[str, object]


@dataclass(frozen=True, slots=True)
class ScanObservation:
    """One raw Trivy report bound to its exact stored bytes."""

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
                self._run(
                    ("image", "--download-db-only", "--cache-dir", str(temporary)),
                    timeout_seconds=900,
                    operation=OperationKind.WRITE,
                )
                self._run(
                    (
                        "image",
                        "--download-java-db-only",
                        "--cache-dir",
                        str(temporary),
                    ),
                    timeout_seconds=900,
                    operation=OperationKind.WRITE,
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
    ) -> ScanObservation:
        """Scan an explicit source tree for secrets and configuration findings."""
        return self._scan(
            (
                "filesystem",
                "--cache-dir",
                str(cache_root),
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
                "--scanners",
                ",".join(scanners),
                "--format",
                "json",
                "--output",
                str(report_path),
                str(path),
            ),
            report_path,
        )

    def scan_layout(
        self,
        *,
        layout_path: Path,
        report_path: Path,
        cache_root: Path,
    ) -> ScanObservation:
        """Scan one exact OCI layout using the selected immutable database cache."""
        return self._scan(
            (
                "image",
                "--input",
                str(layout_path),
                "--cache-dir",
                str(cache_root),
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
                "--scanners",
                "vuln,secret,misconfig",
                "--format",
                "json",
                "--output",
                str(report_path),
            ),
            report_path,
        )

    def generate_spdx(
        self,
        *,
        layout_path: Path,
        output_path: Path,
        cache_root: Path,
    ) -> ScanObservation:
        """Generate an SPDX JSON inventory from one exact OCI layout."""
        observation = self._scan(
            (
                "image",
                "--input",
                str(layout_path),
                "--cache-dir",
                str(cache_root),
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
                "--format",
                "spdx-json",
                "--output",
                str(output_path),
            ),
            output_path,
        )
        validate_spdx_document(observation.value, label="Trivy SPDX document")
        return observation

    def scan_sbom(
        self,
        *,
        sbom_path: Path,
        report_path: Path,
        cache_root: Path,
    ) -> ScanObservation:
        """Match current vulnerability data against one retained SPDX inventory."""
        return self._scan(
            (
                "sbom",
                "--cache-dir",
                str(cache_root),
                "--skip-db-update",
                "--skip-java-db-update",
                "--offline-scan",
                "--format",
                "json",
                "--output",
                str(report_path),
                str(sbom_path),
            ),
            report_path,
        )

    def _scan(self, arguments: tuple[str, ...], output_path: Path) -> ScanObservation:
        self._run(arguments, timeout_seconds=1800)
        value = load_json(output_path)
        return ScanObservation(output_path, sha256_file(output_path), value)


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
    digests: dict[str, str] = {}
    metadata: dict[str, object] = {}
    for name, (database_path, metadata_path) in components.items():
        digests[name] = sha256_file(database_path)
        metadata[name] = _database_metadata(
            object_value(load_json(metadata_path), label=f"Trivy {name} DB metadata"),
            label=f"Trivy {name} DB metadata",
        )
    digest = sha256_bytes(canonical_json_bytes(digests))
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
    return timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")
