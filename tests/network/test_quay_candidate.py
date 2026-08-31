import os
from pathlib import Path

import pytest

from conclear.adapters.quay import QuayAdapter
from conclear.jsonutil import load_json
from conclear.secrets import read_secret_file
from conclear.values import Digest, OCIReference

pytestmark = pytest.mark.network


def test_real_quay_candidate_can_be_unlocked_and_deleted() -> None:
    values = _authorized_environment()
    tagged = OCIReference.parse(values["candidate"], require_tag=True)
    if tagged.registry != "quay.io" or tagged.tag is None or tagged.digest is not None:
        pytest.fail("network test candidate must be a tagged quay.io reference")
    repository = OCIReference(tagged.registry, tagged.repository)
    if repository.repository_name != values["repository"]:
        pytest.fail("network test candidate is outside the disposable repository")
    expected = Digest(values["digest"])
    token_file = Path(values["token_file"])
    quay = QuayAdapter(
        api_url="https://quay.io/api/v1",
        token_provider=lambda: read_secret_file(token_file),
    )
    try:
        initial = quay.get_tag(repository, tagged.tag)
        assert initial is not None
        assert initial.digest == expected

        immutable = quay.set_immutable(repository, tagged.tag)
        assert immutable.digest == expected
        assert immutable.immutable

        mutable = quay.set_mutable(repository, tagged.tag)
        assert mutable.digest == expected
        assert not mutable.immutable

        quay.delete_tag(repository, tagged.tag)
        assert quay.get_tag(repository, tagged.tag) is None
    finally:
        quay.close()


def _authorized_environment() -> dict[str, str]:
    names = {
        "authorized": "CONCLEAR_TEST_NETWORK_AUTHORIZED",
        "run_id": "CONCLEAR_TEST_RUN_ID",
        "manifest": "CONCLEAR_TEST_RESOURCE_MANIFEST",
        "repository": "CONCLEAR_TEST_QUAY_REPOSITORY",
        "candidate": "CONCLEAR_TEST_QUAY_CANDIDATE",
        "digest": "CONCLEAR_TEST_QUAY_CANDIDATE_DIGEST",
        "token_file": "CONCLEAR_TEST_QUAY_TOKEN_FILE",
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
    tags = created.get("registry_tags") if isinstance(created, dict) else None
    if not isinstance(repositories, list) or present["repository"] not in repositories:
        pytest.fail("resource manifest does not own the disposable repository")
    if not isinstance(tags, list) or present["candidate"] not in tags:
        pytest.fail("resource manifest does not own the disposable candidate tag")
    return present
