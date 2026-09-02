"""SLSA Provenance v1 generation from accepted release observations."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from conclear.config import normalize_builder_id
from conclear.errors import OperationalError
from conclear.identity import IDENTITY
from conclear.jsonutil import atomic_write_json, sha256_file
from conclear.schema import validate_external
from conclear.values import (
    Digest,
    Platform,
    validate_run_id,
    validate_source_revision,
)

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://github.com/foundata/conclear/build/v1"


@dataclass(frozen=True, slots=True)
class ProvenanceMaterial:
    """One integrity-checked SLSA resolved dependency."""

    uri: str
    digest: Digest


@dataclass(frozen=True, slots=True)
class ProvenanceInput:
    """Observed facts required to construct release provenance."""

    subject_name: str
    subject_digest: Digest
    platform_manifests: tuple[tuple[Platform, Digest], ...]
    source_repository: str
    source_revision: str
    configuration_digest: Digest
    builder_id: str
    image_id: str
    version: str | None
    run_id: str
    started_at: datetime
    finished_at: datetime
    materials: tuple[ProvenanceMaterial, ...]


def generate_provenance(value: ProvenanceInput, output_path: Path) -> str:
    """Generate, schema-validate and atomically write SLSA Provenance v1."""
    validate_run_id(value.run_id)
    validate_source_revision(value.source_revision)
    validate_source_revision(IDENTITY.source_revision)
    builder_id = normalize_builder_id(value.builder_id)
    if value.started_at.tzinfo is None or value.finished_at.tzinfo is None:
        raise OperationalError("Provenance timestamps must be timezone-aware")
    if value.finished_at < value.started_at:
        raise OperationalError("Provenance finish time precedes its start")
    subjects: list[dict[str, object]] = [
        {
            "name": value.subject_name,
            "digest": {"sha256": value.subject_digest.encoded},
        }
    ]
    for platform, digest in sorted(value.platform_manifests):
        subjects.append(
            {
                "name": f"{value.subject_name}#{platform}",
                "digest": {"sha256": digest.encoded},
            }
        )
    dependencies = [
        {
            "uri": value.source_repository,
            "digest": {"gitCommit": value.source_revision},
        },
        {
            "uri": "conclear.toml",
            "digest": {"sha256": value.configuration_digest.encoded},
        },
    ]
    dependencies.extend(
        {
            "uri": material.uri,
            "digest": {"sha256": material.digest.encoded},
        }
        for material in sorted(value.materials, key=lambda item: item.uri)
    )
    statement: dict[str, object] = {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": SLSA_PROVENANCE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "imageId": value.image_id,
                    "version": value.version,
                    "runId": value.run_id,
                    "platforms": [
                        str(platform) for platform, _digest in value.platform_manifests
                    ],
                },
                "internalParameters": {},
                "resolvedDependencies": dependencies,
            },
            "runDetails": {
                "builder": {
                    "id": builder_id,
                    "version": {
                        "conclear": IDENTITY.version,
                        "conclearSourceRevision": IDENTITY.source_revision,
                    },
                },
                "metadata": {
                    "invocationId": value.run_id,
                    "startedOn": _timestamp(value.started_at),
                    "finishedOn": _timestamp(value.finished_at),
                },
                "byproducts": [],
            },
        },
    }
    validate_external(statement, "provenance.schema.json", label="provenance")
    atomic_write_json(output_path, statement, mode=0o644)
    return sha256_file(output_path)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OperationalError("Provenance timestamp is not timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
