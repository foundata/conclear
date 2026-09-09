"""Opt-in retained-wheel release, authoritative rescan and boundary recovery."""

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from conclear.adapters.registry_backends import create_registry_control
from conclear.config import load_repository_config
from conclear.jsonutil import atomic_write_json, load_json
from conclear.release_profile import load_release_profile
from conclear.values import OCIReference
from tests.network_support import (
    authorized_environment,
    external_path,
    manifest_workspace,
    policy_modes,
)
from tests.release_scenarios import (
    repeat_release_and_rescan,
    resume_published_candidate,
)

pytestmark = pytest.mark.network


class RetainedCli:
    """Preserve command evidence and discovered run IDs outside the checkout."""

    def __init__(
        self,
        executable: Path,
        workspace: Path,
        manifest: Path,
        environment: dict[str, str],
    ) -> None:
        self.executable = executable
        self.workspace = workspace
        self.manifest = manifest
        self.environment = environment
        self.sequence = 0

    def run(self, *arguments: str, expect: int = 0) -> dict[str, Any]:
        self.sequence += 1
        prefix = self.workspace / f"{self.sequence:03d}-{arguments[0]}"
        # Native tool diagnostics may contain sensitive paths. Keep all raw output protected.
        with (
            prefix.with_suffix(".stdout").open("xb") as stdout,
            prefix.with_suffix(".stderr").open("xb") as stderr,
        ):
            Path(stdout.name).chmod(0o600)
            Path(stderr.name).chmod(0o600)
            completed = subprocess.run(
                [str(self.executable), *arguments, "--format", "json"],
                cwd=self.workspace,
                env=self.environment,
                stdout=stdout,
                stderr=stderr,
                timeout=3600,
                check=False,
            )
        value = load_json(prefix.with_suffix(".stdout"))
        assert isinstance(value, dict)
        run_id = value.get("data", {}).get("runId")
        if run_id is not None:
            manifest = load_json(self.manifest)
            runs = manifest["created"].setdefault("conclear_runs", [])
            if run_id not in runs:
                runs.append(run_id)
                atomic_write_json(self.manifest, manifest)
        assert completed.returncode == expect, (
            f"CLI exited {completed.returncode}; inspect {prefix}.*"
        )
        return dict(value)


def test_retained_cli_repeat_release_rescan_and_publication_recovery() -> None:
    if os.environ.get("CONCLEAR_TEST_RELEASE_LIFECYCLE") != "yes":
        pytest.skip("release lifecycle scenario is not selected")
    values = authorized_environment({"scenario_file": "CONCLEAR_TEST_RELEASE_SCENARIO"})
    workspace, _manifest = manifest_workspace(values)
    scenario = load_json(Path(values["scenario_file"]))
    assert isinstance(scenario, dict)

    def owned_path(name: str) -> Path:
        path = external_path(scenario[name])
        assert path.is_relative_to(workspace), (
            f"{name} must be inside the manifest workspace"
        )
        return path

    executable = owned_path("cli")
    source = owned_path("source")
    state = owned_path("state_home")
    cache = owned_path("cache_home")
    config = owned_path("config_home")
    assert os.access(executable, os.X_OK)
    assert re.fullmatch(r"[a-f0-9]{40}", scenario["revision"])
    repository = load_repository_config(source / "conclear.toml")
    assert len(repository.release_images) == 1
    image = repository.release_image(None)
    assert image.repository.repository_name == values["repository"]
    assert "latest" in image.release.moving_tags
    tags = (
        *image.release.render_versions(scenario["version"]),
        *image.release.moving_tags,
    )
    profile = load_release_profile(scenario["profile"], config_home=config)
    assert (
        profile.registry.policy.tag_protection.mode,
        profile.registry.policy.candidate_cleanup.mode,
    ) == policy_modes()
    for secret in (
        profile.auth_file,
        profile.registry.token_file,
        profile.cosign_private_key,
        profile.cosign_public_key,
        profile.passphrase_file,
    ):
        assert secret is not None
        assert external_path(str(secret)).is_relative_to(workspace), (
            "use dedicated file-based test credentials"
        )
    directory = workspace / "release-lifecycle"
    directory.mkdir(mode=0o700)
    environment = {
        **os.environ,
        "XDG_STATE_HOME": str(state),
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
    }
    cli = RetainedCli(executable, directory, Path(values["manifest"]), environment)
    identity = cli.run("version")
    assert identity["sourceRevision"] == scenario["conclear_revision"]
    assert re.fullmatch(r"[a-f0-9]{40}", identity["sourceRevision"])
    control = create_registry_control(profile, destinations=(image.repository,))

    def observe_tags() -> dict[str, str | None]:
        result: dict[str, str | None] = {}
        for tag in tags:
            observation = control.observe_tag(image.repository, tag)
            result[tag] = None if observation is None else str(observation.digest)
        return result

    def observe_candidate(reference: str) -> str | None:
        candidate = OCIReference.parse(reference, require_tag=True)
        assert (
            candidate.repository_name == values["repository"]
            and candidate.tag is not None
        )
        observation = control.observe_tag(image.repository, candidate.tag)
        return None if observation is None else str(observation.digest)

    arguments = (
        "--source",
        str(source),
        "--revision",
        scenario["revision"],
        "--version",
        scenario["version"],
    )
    try:
        assert all(value is None for value in observe_tags().values()), (
            "use unused fixture tags"
        )
        subject = repeat_release_and_rescan(
            cli,
            source_arguments=arguments,
            config=source / "conclear.toml",
            profile=profile.name,
            observe_tags=observe_tags,
        )
        resume_published_candidate(
            cli,
            source_arguments=arguments,
            source=source,
            profile=profile.name,
            platforms=tuple(str(platform) for platform in image.platforms),
            directory=directory,
            expected_subject=subject,
            observe_tags=observe_tags,
            observe_candidate=observe_candidate,
        )
    finally:
        control.close()
