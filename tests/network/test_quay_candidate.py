from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conclear.adapters.quay import QuayAdapter
from conclear.registry_policy import CandidateCleanupMode, TagProtectionMode
from conclear.secrets import read_secret_file
from conclear.values import Digest, OCIReference
from tests.network_support import authorized_environment, owned_tag, policy_modes

pytestmark = pytest.mark.network


def test_real_quay_candidate_honors_selected_cleanup() -> None:
    values = authorized_environment(
        {
            "candidate": "CONCLEAR_TEST_QUAY_CANDIDATE",
            "digest": "CONCLEAR_TEST_QUAY_CANDIDATE_DIGEST",
            "token_file": "CONCLEAR_TEST_QUAY_TOKEN_FILE",
        }
    )
    _protection, cleanup = policy_modes()
    tagged = owned_tag(values, "candidate")
    assert tagged.tag is not None
    repository = OCIReference(tagged.registry, tagged.repository)
    if repository.repository_name != values["repository"]:
        pytest.fail("network test candidate is outside the disposable repository")
    expected = Digest(values["digest"])
    quay = _quay(values)
    try:
        initial = quay.observe_tag(repository, tagged.tag)
        assert initial is not None
        assert initial.digest == expected

        assert not initial.immutable
        if cleanup is not CandidateCleanupMode.MANUAL:
            expiration = datetime.now(UTC).replace(microsecond=0) + timedelta(hours=1)
            observed = quay.enforce_candidate_lifetime(
                repository, tagged.tag, expiration
            )
            assert observed.digest == expected
            assert observed.expiration == expiration
        final = quay.observe_tag(repository, tagged.tag)
        assert final is not None and final.digest == expected and not final.immutable

        quay.remove_tag(repository, tagged.tag)
        assert quay.observe_tag(repository, tagged.tag) is None
    finally:
        quay.close()


def test_real_quay_selected_version_policy() -> None:
    values = authorized_environment({"token_file": "CONCLEAR_TEST_QUAY_TOKEN_FILE"})
    protection, _cleanup = policy_modes()
    if protection is not TagProtectionMode.REQUIRED:
        pytest.skip("version-tag protection is not selected")
    values = authorized_environment(
        {
            "token_file": "CONCLEAR_TEST_QUAY_TOKEN_FILE",
            "version_tag": "CONCLEAR_TEST_QUAY_VERSION_TAG",
            "moving_tag": "CONCLEAR_TEST_QUAY_MOVING_TAG",
            "candidate": "CONCLEAR_TEST_QUAY_CANDIDATE",
        }
    )
    tags: list[str] = []
    for name in ("version_tag", "moving_tag", "candidate"):
        tag = owned_tag(values, name).tag
        assert tag is not None
        tags.append(tag)
    quay = _quay(values)
    try:
        quay.verify_tag_policy(
            OCIReference.parse(values["repository"]),
            version_tags=(tags[0],),
            mutable_tags=(tags[1], tags[2]),
        )
    finally:
        quay.close()


def test_real_quay_selected_auto_prune_policy() -> None:
    values = authorized_environment({"token_file": "CONCLEAR_TEST_QUAY_TOKEN_FILE"})
    _protection, cleanup = policy_modes()
    if cleanup is not CandidateCleanupMode.AUTO_PRUNE:
        pytest.skip("auto-prune is not selected")
    quay = _quay(values)
    repository = OCIReference.parse(values["repository"])
    try:
        policy = quay.ensure_candidate_retention(repository, timedelta(days=7))
        observed = quay.observe_candidate_retention(repository, timedelta(days=7))
        assert policy == observed
    finally:
        quay.close()


def _quay(values: dict[str, str]) -> QuayAdapter:
    return QuayAdapter(
        api_url="https://quay.io/api/v1",
        registry="quay.io",
        token_provider=lambda: read_secret_file(Path(values["token_file"])),
    )
