from datetime import UTC, datetime
from pathlib import Path

import pytest

import conclear.provenance as provenance_module
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import load_json
from conclear.provenance import (
    ProvenanceInput,
    ProvenanceMaterial,
    generate_provenance,
)
from conclear.values import Digest, Platform


def test_provenance_separates_configured_builder_and_conclear_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        provenance_module,
        "IDENTITY",
        ApplicationIdentity(source_revision="c" * 40),
    )
    digest = Digest("sha256:" + "a" * 64)
    output = tmp_path / "provenance.json"
    generated = generate_provenance(
        ProvenanceInput(
            subject_name="quay.io/foundata/example",
            subject_digest=digest,
            platform_manifests=((Platform.parse("linux/amd64"), digest),),
            source_repository="https://github.com/foundata/example",
            source_revision="b" * 40,
            configuration_digest=digest,
            builder_id=("https://foundata.com/en/projects/conclear/builder/simple-v1/"),
            image_id="example",
            version="1.2.3",
            run_id="01arz3ndektsv4rrffq69g5fav",
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            finished_at=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
            materials=(ProvenanceMaterial("Containerfile", digest),),
        ),
        output,
    )

    value = load_json(output)
    assert generated.startswith("sha256:")
    assert value["subject"][0]["digest"]["sha256"] == "a" * 64
    assert value["predicate"]["runDetails"]["builder"] == {
        "id": "https://foundata.com/en/projects/conclear/builder/simple-v1/",
        "version": {
            "conclear": "0.1.0",
            "conclearSourceRevision": "c" * 40,
        },
    }
    assert (
        value["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"][
            "gitCommit"
        ]
        == "b" * 40
    )
