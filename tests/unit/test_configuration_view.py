"""Configuration inspection reports defaults and decisions without qualification."""

import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conclear.cli import main
from conclear.config import SYSTEMD_WRITABLE_MOUNTS, load_repository_config
from conclear.config_decisions import RESOURCE_DECISIONS, unresolved_decisions
from conclear.errors import InvalidInvocationError, RuleRejectionError
from conclear.pins import PinStore, check_image_pins
from conclear.services.configuration_view import configuration_view
from tests.unit.test_commands import release_profile
from tests.unit.test_config import _image_text
from tests.unit.test_pins import Resolver


def test_effective_configuration_shows_defaults_limits_and_explicit_measurements_without_tools(
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8") + '\n[images.limits]\npin_freshness = "1h"\n',
        encoding="utf-8",
    )
    before = {item.name: item.read_bytes() for item in root.iterdir()}
    monkeypatch.setenv("PATH", "")
    assert main(["config", "show", "--config", str(path), "--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["command"] == "config show"
    [image] = result["data"]["images"]
    values = image["values"]
    assert values["containerfile"]["origin"] == "default"
    assert values["limits.pin_freshness"] == {
        "value": "1h",
        "origin": "repository",
        "maximum": "24h",
        "reason": "",
    }
    assert values["runtime.read_only"]["value"] is True
    assert values["scanner"]["origin"] == "fixed policy"
    assert values["runtime.profile_mounts"]["value"] == []
    assert values["release.version_tags"]["reason"] == "Requires --version."
    for key, reason in RESOURCE_DECISIONS.items():
        assert values[f"runtime.{key}"]["origin"] == "repository"
        assert values[f"runtime.{key}"]["reason"] == reason
    assert {item.name: item.read_bytes() for item in root.iterdir()} == before


def test_effective_systemd_mounts_are_separate_from_repository_mounts(
    repository_factory: Callable[..., Path],
) -> None:
    path = repository_factory() / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            'profile = "service"\nuser = 10001',
            'profile = "systemd"\nuser = 0\nwritable_mounts = ["/var/lib/app"]',
        )
        + """
[images.runtime.root_requirement]
rationale = "Systemd manages system services."
owner = "platform"
review_trigger = "Lifecycle changes"
[images.runtime.systemd]
required_units = ["multi-user.target"]
""",
        encoding="utf-8",
    )
    result = configuration_view(
        load_repository_config(path), image_id=None, version="1.2.3", profile=None
    )
    encoded = json.loads(json.dumps(result.to_dict()))
    values = encoded["data"]["images"][0]["values"]
    assert values["runtime.profile_mounts"]["value"] == list(SYSTEMD_WRITABLE_MOUNTS)
    assert set(values["runtime.writable_mounts"]["value"]) == {
        *SYSTEMD_WRITABLE_MOUNTS,
        "/var/lib/app",
    }
    assert values["runtime.root_requirement"]["value"]["owner"] == "platform"
    assert values["release.rendered_version_tags"]["value"] == ["1.2.3"]
    assert "runtime.systemd.required_units" in values


def test_effective_view_covers_all_images_and_keeps_profile_secrets_out(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
) -> None:
    path = repository_factory() / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            '[images.test]\ndependencies = ["helper"]\n\n[images.release]',
        )
        + _image_text("helper", releasable=False),
        encoding="utf-8",
    )
    repository = load_repository_config(path)
    profile = replace(
        release_profile(tmp_path, token="quay-secret-token"),
        passphrase_file=tmp_path / "signing-passphrase",
    )
    result = configuration_view(
        repository, image_id=None, version=None, profile=profile
    )
    data = json.loads(json.dumps(result.to_dict()))["data"]
    assert [image["id"] for image in data["images"]] == ["app", "helper"]
    assert "release.version_tags" not in data["images"][1]["values"]
    assert data["releaseProfile"]["builderId"] == profile.builder.id
    rendered = json.dumps(data) + str(result.details)
    for secret_path in (
        profile.auth_file,
        profile.cosign_private_key,
        profile.passphrase_file,
        profile.registry.token_file,
    ):
        assert secret_path is not None
        assert str(secret_path) not in rendered
    selected = configuration_view(
        repository, image_id="helper", version=None, profile=None
    )
    assert len(json.loads(json.dumps(selected.to_dict()))["data"]["images"]) == 1


def test_config_command_reports_all_pending_values_in_one_diagnostic(
    repository_factory: Callable[..., Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = repository_factory() / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace('memory = "512MiB"', 'memory = "DECIDE: measured peak"')
        .replace("cpus = 1.0", 'cpus = "DECIDE: measured quota"'),
        encoding="utf-8",
    )
    assert main(["config", "show", "--config", str(path), "--format", "json"]) == 64
    value = json.loads(capsys.readouterr().out)
    assert "images.0.runtime.memory: measured peak" in value["message"]
    assert "images.0.runtime.cpus: measured quota" in value["message"]


def test_missing_measured_fields_are_reported_together(
    repository_factory: Callable[..., Path],
) -> None:
    path = repository_factory() / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8")
        .replace('memory = "512MiB"\n', "")
        .replace("cpus = 1.0\n", ""),
        encoding="utf-8",
    )
    with pytest.raises(InvalidInvocationError) as caught:
        load_repository_config(path)
    assert "'memory' is a required property" in str(caught.value)
    assert "'cpus' is a required property" in str(caught.value)


def test_pending_decisions_have_exact_paths_and_do_not_match_ordinary_words() -> None:
    decisions = unresolved_decisions(
        {
            "runtime": {"memory": " DECIDE "},
            "test": ["DECIDE: owner choice", "DECIDED", 12],
        }
    )
    assert [item.to_dict() for item in decisions] == [
        {"field": "runtime.memory", "reason": "Owner decision required."},
        {"field": "test.0", "reason": "owner choice"},
    ]
    nested: dict[str, object] = {}
    for _ in range(150):
        nested = {"child": nested}
    with pytest.raises(InvalidInvocationError, match="nesting"):
        unresolved_decisions(nested)


@pytest.mark.parametrize("version", ["stable", "bad/tag"])
def test_config_show_validates_rendered_tags(
    repository_factory: Callable[..., Path],
    capsys: pytest.CaptureFixture[str],
    version: str,
) -> None:
    path = repository_factory() / "conclear.toml"
    assert (
        main(
            [
                "config",
                "show",
                "--config",
                str(path),
                "--version",
                version,
                "--format",
                "json",
            ]
        )
        == 64
    )
    assert json.loads(capsys.readouterr().out)["status"] == "invalidInvocation"


def test_pin_check_rejects_omitted_input_before_any_resolution(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").split("[[images.pins]]")[0], encoding="utf-8"
    )
    image = load_repository_config(path).release_image(None)
    resolver = Resolver("sha256:" + "a" * 64)
    with pytest.raises(RuleRejectionError, match="undeclared") as caught:
        check_image_pins(
            PinStore(tmp_path / "state"),
            image,
            resolver=resolver,
            now=datetime(2026, 9, 9, tzinfo=UTC),
        )
    assert caught.value.code == "CC0203"
    assert not (tmp_path / "state").exists()


def test_empty_release_tags_and_fixed_scanner_options_are_rejected(
    repository_factory: Callable[..., Path],
) -> None:
    path = repository_factory() / "conclear.toml"
    original = path.read_text(encoding="utf-8")
    path.write_text(
        original.replace('version_tags = ["{version}"]\n', "").replace(
            'moving_tags = ["stable"]\n', ""
        ),
        encoding="utf-8",
    )
    with pytest.raises(InvalidInvocationError, match="at least one"):
        load_repository_config(path)
    path.write_text(
        original.replace('id = "app"', 'id = "app"\nscanner = "trivy"'),
        encoding="utf-8",
    )
    with pytest.raises(InvalidInvocationError, match="scanner"):
        load_repository_config(path)


@pytest.mark.parametrize("mode", ["presence-only", "escalation"])
def test_effective_permission_controls_follow_reviewed_requirements(
    repository_factory: Callable[..., Path],
    mode: str,
) -> None:
    path = repository_factory() / "conclear.toml"
    extra = f'''
[images.runtime.sudo_requirement]
rationale = "Integration tests exercise sudo."
owner = "platform"
review_trigger = "Test workflow changes"
mode = "{mode}"
scope = "Only the declared test operation"
[images.runtime.writable_root_requirement]
rationale = "Tests replace installed configuration."
owner = "platform"
review_trigger = "Runtime changes"
[[images.runtime.setid_requirements]]
path = "/usr/bin/helper"
rationale = "The test target exercises this helper."
owner = "platform"
review_trigger = "Package changes"
'''
    if mode == "escalation":
        extra += """
[images.test.sudo]
user = 10001
denied_user = 10002
command = ["/usr/bin/id", "-u"]
expected_stdout = "0\\n"
"""
    path.write_text(path.read_text(encoding="utf-8") + extra, encoding="utf-8")
    repository = load_repository_config(path)
    result = configuration_view(repository, image_id=None, version=None, profile=None)
    values = json.loads(json.dumps(result.to_dict()))["data"]["images"][0]["values"]
    assert values["runtime.read_only"]["value"] is False
    assert values["runtime.no_new_privileges"]["value"] is (mode == "presence-only")
    assert values["runtime.sudo_requirement"]["value"]["mode"] == mode
    assert values["runtime.setid_requirements"]["value"][0]["path"] == "/usr/bin/helper"


def test_effective_configuration_lists_declared_exceptions(
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.release]",
            """[[images.configuration_exceptions]]
path = "usr/lib/python3/dist-packages/ansible/galaxy/data/**/Dockerfile.j2"
checks = ["DS-0011", "DS-0001"]
rationale = "Galaxy template data shipped by ansible-core, not the build definition."
owner = "security@example.com"
review_trigger = "ansible-core package update"
expires = "2026-12-31"

[images.release]""",
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PATH", "")
    assert main(["config", "show", "--config", str(path), "--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)
    [image] = result["data"]["images"]
    values = image["values"]
    assert values["configuration_exceptions"] == {
        "value": [
            {
                "path": "usr/lib/python3/dist-packages/ansible/galaxy/data/**/Dockerfile.j2",
                "checks": ["DS-0001", "DS-0011"],
                "owner": "security@example.com",
                "expires": "2026-12-31",
            }
        ],
        "origin": "repository",
        "reason": "",
        "maximum": None,
    }
    assert values["vulnerability_exceptions"]["value"] == []
    assert values["package_assessment_exception"]["value"] is None

    assert main(["config", "show", "--config", str(path)]) == 0
    human = capsys.readouterr().out
    assert "configuration_exceptions = " in human
    assert "Dockerfile.j2" in human
