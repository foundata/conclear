"""Every command declares exactly the tools, profile and credentials it uses."""

import click

from conclear.cli import root
from conclear.dependencies import (
    COMMAND_DEPENDENCIES,
    DOCTOR_SCOPES,
    CommandDependencies,
    ProfileUse,
    command_tools,
    scope_dependencies,
)
from conclear.tools import ToolName


def _public_commands(command: click.Command, path: tuple[str, ...]) -> set[str]:
    names: set[str] = set()
    if path and not isinstance(command, click.Group):
        names.add(" ".join(path))
    if isinstance(command, click.Group):
        for name, child in command.commands.items():
            names |= _public_commands(child, (*path, name))
    return names


def test_every_public_command_has_one_declaration() -> None:
    assert set(COMMAND_DEPENDENCIES) | {"doctor"} == _public_commands(root, ())


def test_declarations_are_deterministic_and_well_formed() -> None:
    for name, item in COMMAND_DEPENDENCIES.items():
        assert len(item.tools) == len(set(item.tools)), name
        if item.profile is ProfileUse.NONE:
            assert not item.registry_credentials, name
            assert not item.registry_control, name
            assert not item.signing, name
        if item.signing:
            assert ToolName.COSIGN in item.tools, name
        if item.transparency_log:
            assert ToolName.COSIGN in item.tools, name


def test_qualification_never_needs_cosign_and_static_checks_need_no_profile() -> None:
    assert ToolName.COSIGN not in command_tools("qualify")
    assert ToolName.COSIGN not in command_tools("build")
    assert ToolName.COSIGN not in command_tools("test")
    assert COMMAND_DEPENDENCIES["check"] == CommandDependencies(
        tools=(ToolName.HADOLINT,)
    )
    assert COMMAND_DEPENDENCIES["publish"].tools == (ToolName.GIT, ToolName.SKOPEO)
    for name in ("attest", "verify", "promote"):
        assert set(command_tools(name)) == {
            ToolName.GIT,
            ToolName.SKOPEO,
            ToolName.COSIGN,
        }, name
    assert set(command_tools("release")) == set(ToolName)


def test_doctor_scopes_are_cumulative_unions_of_their_commands() -> None:
    check = scope_dependencies("check")
    qualify = scope_dependencies("qualify")
    release = scope_dependencies("release")

    assert check == CommandDependencies(tools=(ToolName.HADOLINT,))
    assert set(qualify.tools) == set(ToolName) - {ToolName.COSIGN}
    assert qualify.profile is ProfileUse.OPTIONAL
    assert qualify.registry_credentials and not qualify.registry_control
    assert not qualify.signing and not qualify.transparency_log
    assert set(release.tools) == set(ToolName)
    assert release.profile is ProfileUse.REQUIRED
    assert release.registry_control and release.signing and release.transparency_log
    assert set(DOCTOR_SCOPES["check"]) <= set(DOCTOR_SCOPES["qualify"])
    assert set(DOCTOR_SCOPES["qualify"]) <= set(DOCTOR_SCOPES["release"])
    assert set(DOCTOR_SCOPES["release"]) == set(COMMAND_DEPENDENCIES) - {"version"}
    assert list(qualify.tools) == [tool for tool in ToolName if tool in qualify.tools]


def test_inventory_form_names_every_dependency() -> None:
    assert COMMAND_DEPENDENCIES["rescan"].to_dict() == {
        "tools": ["skopeo", "trivy", "cosign"],
        "profile": "required",
        "registryCredentials": True,
        "registryControl": False,
        "signing": True,
        "transparencyLog": True,
    }
