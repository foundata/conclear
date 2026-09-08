import os
from pathlib import Path

import pytest

from conclear.attestations import (
    SPDX_DOCUMENT_TYPE,
    decode_dsse_statements,
    statement_matches,
)
from conclear.jsonutil import atomic_write_json, load_json
from conclear.runtime import ApplicationRuntime
from conclear.secrets import (
    MAX_PROFILE_BYTES,
    read_protected_file,
    read_secret_file,
)
from conclear.tools import ToolName
from conclear.values import OCIReference

pytestmark = pytest.mark.network


def test_real_cosign_spdx_attestation_round_trip(tmp_path: Path) -> None:
    values = _authorized_environment()
    subject = OCIReference.parse(values["subject"])
    if subject.digest is None or subject.tag is not None:
        pytest.fail("network test subject must be a digest-only reference")
    expected_repository = OCIReference.parse(values["repository"])
    if (
        expected_repository.registry != "quay.io"
        or expected_repository.tag is not None
        or expected_repository.digest is not None
    ):
        pytest.fail("network test repository must be a bare quay.io repository")
    if subject.repository_name != expected_repository.repository_name:
        pytest.fail("network test subject is outside the disposable repository")

    runtime = ApplicationRuntime.create(
        tmp_path / "environment", names=(ToolName.COSIGN,)
    )
    docker_directory = runtime.root / "home" / ".docker"
    docker_directory.mkdir(mode=0o700)
    docker_config = Path(values["docker_config"])
    (docker_directory / "config.json").write_bytes(
        read_protected_file(docker_config, maximum_bytes=MAX_PROFILE_BYTES)
    )
    predicate = tmp_path / "sbom.spdx.json"
    expected: dict[str, object] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "conclear-cosign-round-trip",
        "documentNamespace": (
            "https://example.invalid/conclear/tests/" + values["run_id"]
        ),
        "creationInfo": {
            "created": "2026-01-01T00:00:00Z",
            "creators": ["Tool: ConClear-test"],
        },
        "packages": [],
    }
    atomic_write_json(predicate, expected)
    private_key = Path(values["private_key"])
    public_key = Path(values["public_key"])
    signer = runtime.cosign()

    signer.attest(
        subject=subject,
        predicate=predicate,
        predicate_type="spdxjson",
        private_key=str(private_key),
        passphrase=read_secret_file(Path(values["passphrase_file"])),
    )
    verified = signer.verify_attestation(
        subject=subject,
        public_key=public_key,
        predicate_type="spdxjson",
    )
    statements = decode_dsse_statements(verified.entries)

    assert subject.digest is not None
    assert any(
        statement_matches(
            statement,
            subject_name=subject.repository_name,
            subject_digest=subject.digest,
            predicate_type=SPDX_DOCUMENT_TYPE,
            predicate=expected,
        )
        for statement in statements
    )


def _authorized_environment() -> dict[str, str]:
    names = {
        "authorized": "CONCLEAR_TEST_NETWORK_AUTHORIZED",
        "run_id": "CONCLEAR_TEST_RUN_ID",
        "manifest": "CONCLEAR_TEST_RESOURCE_MANIFEST",
        "repository": "CONCLEAR_TEST_QUAY_REPOSITORY",
        "subject": "CONCLEAR_TEST_COSIGN_SUBJECT",
        "docker_config": "CONCLEAR_TEST_DOCKER_CONFIG",
        "private_key": "CONCLEAR_TEST_COSIGN_PRIVATE_KEY",
        "public_key": "CONCLEAR_TEST_COSIGN_PUBLIC_KEY",
        "passphrase_file": "CONCLEAR_TEST_COSIGN_PASSPHRASE_FILE",
    }
    values = {key: os.environ.get(name) for key, name in names.items()}
    missing = [names[key] for key, value in values.items() if value is None]
    if missing:
        pytest.skip("network test inputs are unavailable: " + ", ".join(missing))
    present = {key: value for key, value in values.items() if value is not None}
    if present["authorized"] != "yes":
        pytest.skip("network mutations require explicit disposable-test authorization")
    manifest = Path(present["manifest"]).resolve(strict=True)
    repository_root = Path.cwd().resolve(strict=True)
    if manifest.is_relative_to(repository_root):
        pytest.fail("resource manifest must be outside the repository")
    manifest_value = load_json(manifest)
    if not isinstance(manifest_value, dict):
        pytest.fail("resource manifest must be a JSON object")
    if manifest_value.get("run_id") != present["run_id"]:
        pytest.fail("resource manifest does not own the selected run ID")
    created = manifest_value.get("created")
    repositories = (
        created.get("registry_repositories") if isinstance(created, dict) else None
    )
    if not isinstance(repositories, list) or present["repository"] not in repositories:
        pytest.fail("resource manifest does not own the disposable repository")
    return present
