"""Trivy database, scan and SPDX adapter."""

import fcntl
import os
import re
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from conclear.adapters.base import ToolAdapter
from conclear.adapters.parsing import object_value, string_value
from conclear.errors import OperationalError
from conclear.jsonutil import atomic_write_json, load_json, sha256_file
from conclear.process import OperationKind


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
        current = snapshot / "db" / "trivy.db"
        metadata_path = snapshot / "db" / "metadata.json"
        metadata = object_value(load_json(metadata_path), label="Trivy DB metadata")
        digest = sha256_file(current)
        if digest != expected_digest:
            raise OperationalError(
                "Trivy database snapshot digest does not match pointer"
            )
        return DatabaseObservation(snapshot, digest, metadata)

    def refresh_database(self, cache_root: Path) -> DatabaseObservation:
        """Refresh in a same-filesystem directory and atomically install the snapshot."""
        cache_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with _locked_file(cache_root / ".db.lock"):
            temporary = Path(tempfile.mkdtemp(prefix=".db.", dir=cache_root))
            try:
                self._run(
                    ("image", "--download-db-only", "--cache-dir", str(temporary)),
                    timeout_seconds=900,
                    operation=OperationKind.WRITE,
                )
                database = temporary / "db" / "trivy.db"
                metadata_path = temporary / "db" / "metadata.json"
                metadata = object_value(
                    load_json(metadata_path), label="Trivy DB metadata"
                )
                digest = sha256_file(database)
                snapshot_name = digest.removeprefix("sha256:")
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
                        "databaseDigest": digest,
                        "snapshot": snapshot_name,
                    },
                )
                directory = os.open(snapshots, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                return DatabaseObservation(installed, digest, metadata)
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
                "--format",
                "spdx-json",
                "--output",
                str(output_path),
            ),
            output_path,
        )
        document = object_value(observation.value, label="SPDX document")
        version = string_value(document.get("spdxVersion"), label="SPDX version")
        if version != "SPDX-2.3":
            raise OperationalError(f"Unsupported SPDX document version: {version}")
        return observation

    def _scan(self, arguments: tuple[str, ...], output_path: Path) -> ScanObservation:
        self._run(arguments, timeout_seconds=1800)
        value = load_json(output_path)
        return ScanObservation(output_path, sha256_file(output_path), value)


@contextmanager
def _locked_file(path: Path) -> Iterator[IO[bytes]]:
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        stream = os.fdopen(descriptor, "r+b")
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield stream
    except OSError as exc:
        raise OperationalError(f"Unable to lock Trivy database cache {path}") from exc
    finally:
        if "stream" in locals():
            stream.close()
