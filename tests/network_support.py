"""Require explicit ownership before optional external-service tests run."""

import os
from pathlib import Path
from typing import Any

import pytest

from conclear.jsonutil import load_json
from conclear.registry_policy import CandidateCleanupMode, TagProtectionMode
from conclear.values import OCIReference

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def authorized_environment(names: dict[str, str]) -> dict[str, str]:
    """Skip unrequested tests, but fail incomplete explicitly authorized tests."""
    if os.environ.get("CONCLEAR_TEST_NETWORK_AUTHORIZED") != "yes":
        pytest.skip("network mutations require explicit disposable-test authorization")
    names = {
        "run_id": "CONCLEAR_TEST_RUN_ID",
        "manifest": "CONCLEAR_TEST_RESOURCE_MANIFEST",
        "repository": "CONCLEAR_TEST_QUAY_REPOSITORY",
        **names,
    }
    values = {key: os.environ.get(name, "") for key, name in names.items()}
    missing = [names[key] for key, value in values.items() if not value]
    if missing:
        pytest.fail("authorized network test needs: " + ", ".join(missing))
    manifest_path = external_path(values["manifest"])
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("run_id") != values["run_id"]:
        pytest.fail("resource manifest does not own the selected run ID")
    created = manifest.get("created")
    repositories = (
        created.get("registry_repositories") if isinstance(created, dict) else None
    )
    if not isinstance(repositories, list) or values["repository"] not in repositories:
        pytest.fail("resource manifest does not own the disposable repository")
    repository = OCIReference.parse(values["repository"])
    if repository.registry != "quay.io" or repository.tag or repository.digest:
        pytest.fail("network tests require a bare disposable quay.io repository")
    for name in names:
        if name.endswith("_file") or name in {
            "docker_config",
            "private_key",
            "public_key",
        }:
            external_path(values[name])
    return values


def external_path(value: str) -> Path:
    """Keep credentials, manifests and evidence outside the checkout."""
    path = Path(value)
    if not path.is_absolute():
        pytest.fail("network test paths must be absolute")
    path = path.resolve(strict=True)
    if path.is_relative_to(REPOSITORY_ROOT):
        pytest.fail("network test inputs must be outside the repository")
    return path


def owned_tag(values: dict[str, str], key: str) -> OCIReference:
    """Validate the exact tag against both repository and manifest ownership."""
    tagged = OCIReference.parse(values[key], require_tag=True)
    if tagged.digest or tagged.repository_name != values["repository"]:
        pytest.fail("network test tag is outside the disposable repository")
    manifest = load_json(Path(values["manifest"]))
    tags = manifest["created"].get("registry_tags")
    if not isinstance(tags, list) or str(tagged) not in tags:
        pytest.fail("resource manifest does not own the selected tag")
    return tagged


def policy_modes() -> tuple[TagProtectionMode, CandidateCleanupMode]:
    """Never infer or downgrade a provider policy during an acceptance test."""
    try:
        return (
            TagProtectionMode(os.environ.get("CONCLEAR_TEST_TAG_PROTECTION", "")),
            CandidateCleanupMode(os.environ.get("CONCLEAR_TEST_CANDIDATE_CLEANUP", "")),
        )
    except ValueError:
        pytest.fail(
            "select CONCLEAR_TEST_TAG_PROTECTION and CONCLEAR_TEST_CANDIDATE_CLEANUP"
        )


def manifest_workspace(values: dict[str, str]) -> tuple[Path, dict[str, Any]]:
    """Locate the disposable workspace recorded by the operator."""
    manifest = load_json(Path(values["manifest"]))
    workspace = manifest.get("workspace")
    if not isinstance(workspace, str):
        pytest.fail("resource manifest needs an absolute workspace")
    path = external_path(workspace)
    if (
        not path.is_dir()
        or REPOSITORY_ROOT.is_relative_to(path)
        or path.stat().st_uid != os.getuid()
        or path.stat().st_mode & 0o077
    ):
        pytest.fail("manifest workspace must be a dedicated owner-only directory")
    return path, manifest
