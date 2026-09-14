"""Every command declares exactly the tools, profile and credentials it uses."""

from types import SimpleNamespace
from typing import Any

import click
import pytest

from conclear.cli import root
from conclear.dependencies import (
    COMMAND_DEPENDENCIES,
    COMMAND_ESCALATIONS,
    DOCTOR_SCOPES,
    CommandDependencies,
    ProfileUse,
    RegistryAccess,
    SigningUse,
    command_dependencies,
    command_tools,
    require_profile_capabilities,
    scope_dependencies,
)
from conclear.errors import InvalidInvocationError
from conclear.tools import ToolName


def _public_commands(command: click.Command, path: tuple[str, ...]) -> set[str]:
    names: set[str] = set()
    if path and not isinstance(command, click.Group):
        names.add(" ".join(path))
    if isinstance(command, click.Group):
        for name, child in command.commands.items():
            names |= _public_commands(child, (*path, name))
    return names


def _command(path: tuple[str, ...]) -> click.Command:
    current: click.Command = root
    for name in path:
        assert isinstance(current, click.Group)
        current = current.commands[name]
    return current


def test_every_public_command_has_one_declaration() -> None:
    assert set(COMMAND_DEPENDENCIES) | {"doctor"} == _public_commands(root, ())


def test_every_escalation_names_a_real_option_of_a_declared_command() -> None:
    for name, escalations in COMMAND_ESCALATIONS.items():
        assert name in COMMAND_DEPENDENCIES
        options = {
            option
            for parameter in _command(tuple(name.split(" "))).params
            for option in getattr(parameter, "opts", ())
        }
        for option, item in escalations.items():
            assert option in options, (name, option)
            assert set(item.tools) >= set(COMMAND_DEPENDENCIES[name].tools)
            assert item.profile is ProfileUse.REQUIRED


def test_declarations_are_deterministic_and_well_formed() -> None:
    for name, item in COMMAND_DEPENDENCIES.items():
        assert len(item.tools) == len(set(item.tools)), name
        if item.profile is ProfileUse.NONE:
            assert item.registry_access is RegistryAccess.NONE, name
            assert not item.registry_control, name
            assert item.signing is SigningUse.NONE, name
        if item.signing is not SigningUse.NONE or item.transparency_log:
            assert ToolName.COSIGN in item.tools, name
        if item.registry_access is RegistryAccess.WRITE:
            assert item.profile is ProfileUse.REQUIRED, name
    assert COMMAND_DEPENDENCIES["promote"].registry_access is RegistryAccess.READ
    assert COMMAND_DEPENDENCIES["promote"].registry_control


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
    assert qualify.registry_access is RegistryAccess.READ
    assert not qualify.registry_control
    assert qualify.signing is SigningUse.NONE and not qualify.transparency_log
    assert set(release.tools) == set(ToolName)
    assert release.profile is ProfileUse.REQUIRED
    assert release.registry_access is RegistryAccess.WRITE
    assert release.registry_control and release.transparency_log
    assert release.signing is SigningUse.SIGN
    assert set(DOCTOR_SCOPES["check"]) <= set(DOCTOR_SCOPES["qualify"])
    assert set(DOCTOR_SCOPES["qualify"]) <= set(DOCTOR_SCOPES["release"])
    assert set(DOCTOR_SCOPES["release"]) == set(COMMAND_DEPENDENCIES) - {"version"}
    assert list(qualify.tools) == [tool for tool in ToolName if tool in qualify.tools]


def test_authoritative_rescan_escalates_to_registry_writes_and_signing() -> None:
    diagnostic = command_dependencies("rescan")
    authoritative = command_dependencies("rescan", "--authoritative")

    assert diagnostic == COMMAND_DEPENDENCIES["rescan"]
    assert diagnostic.registry_access is RegistryAccess.READ
    assert diagnostic.signing is SigningUse.VERIFY
    assert authoritative.tools == diagnostic.tools
    assert authoritative.profile is ProfileUse.REQUIRED
    assert authoritative.registry_access is RegistryAccess.WRITE
    assert authoritative.signing is SigningUse.SIGN
    assert authoritative.transparency_log and not authoritative.registry_control
    with pytest.raises(InvalidInvocationError, match="no auth_file"):
        require_profile_capabilities(_profile(auth_file=None), authoritative)
    with pytest.raises(InvalidInvocationError, match="no Cosign signing key"):
        require_profile_capabilities(_profile(cosign_private_key=None), authoritative)
    require_profile_capabilities(
        _profile(auth_file=None, cosign_private_key=None), diagnostic
    )
    with pytest.raises(KeyError):
        command_dependencies("rescan", "--diagnostic")
    with pytest.raises(KeyError):
        command_dependencies("check", "--authoritative")


def test_inventory_form_names_every_dependency() -> None:
    assert COMMAND_DEPENDENCIES["rescan"].to_dict() == {
        "tools": ["skopeo", "trivy", "cosign"],
        "profile": "required",
        "registryAccess": "read",
        "registryControl": False,
        "signing": "verify",
        "transparencyLog": True,
    }


def _profile(**changes: Any) -> Any:
    values: dict[str, Any] = {
        "name": "production",
        "auth_file": "/secure/auth.json",
        "cosign_private_key": "/secure/cosign.key",
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_profile_capabilities_fail_closed_for_writes_and_signing() -> None:
    for name in ("publish", "attest", "verify", "release"):
        with pytest.raises(InvalidInvocationError, match="no auth_file"):
            require_profile_capabilities(
                _profile(auth_file=None), COMMAND_DEPENDENCIES[name]
            )
    for name in ("attest", "verify", "release"):
        with pytest.raises(InvalidInvocationError, match="no Cosign signing key"):
            require_profile_capabilities(
                _profile(cosign_private_key=None), COMMAND_DEPENDENCIES[name]
            )
    for name in ("pins check", "build", "qualify", "assemble", "promote", "rescan"):
        require_profile_capabilities(
            _profile(auth_file=None, cosign_private_key=None),
            COMMAND_DEPENDENCIES[name],
        )
    require_profile_capabilities(_profile(), scope_dependencies("release"))
    require_profile_capabilities(
        _profile(auth_file=None, cosign_private_key=None),
        scope_dependencies("qualify"),
    )


def test_build_declares_the_registry_reader_that_base_annotation_checks_need() -> None:
    """A build verifies base annotations against the pinned base manifest."""
    from conclear.dependencies import command_tools
    from conclear.tools import ToolName

    assert ToolName.SKOPEO in command_tools("build")
    assert ToolName.SKOPEO in command_tools("qualify")
