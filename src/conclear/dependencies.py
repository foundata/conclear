"""Typed per-command declarations of host tools, profile use and credentials.

Each public command declares only what its production call path executes: the
host executables it runs, whether it needs a maintainer-controlled release
profile, and which credentials and external services it touches. Commands
resolve exactly the declared tools, `doctor` validates a scope through the union
of the commands the scope covers, and the compatibility inventory renders the
declarations so a change is a reviewable diff.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from conclear.tools import ToolName


class ProfileUse(StrEnum):
    """Whether a command loads a release profile."""

    NONE = "none"
    OPTIONAL = "optional"
    REQUIRED = "required"


@dataclass(frozen=True, slots=True)
class CommandDependencies:
    """Host tools, profile use and external trust inputs of one command."""

    tools: tuple[ToolName, ...]
    profile: ProfileUse = ProfileUse.NONE
    registry_credentials: bool = False
    registry_control: bool = False
    signing: bool = False
    transparency_log: bool = False

    def to_dict(self) -> dict[str, object]:
        """Return the public inventory form."""
        return {
            "tools": [tool.value for tool in self.tools],
            "profile": self.profile.value,
            "registryCredentials": self.registry_credentials,
            "registryControl": self.registry_control,
            "signing": self.signing,
            "transparencyLog": self.transparency_log,
        }


_ALL_TOOLS = tuple(ToolName)

COMMAND_DEPENDENCIES: Mapping[str, CommandDependencies] = {
    "version": CommandDependencies(tools=()),
    "check": CommandDependencies(tools=(ToolName.HADOLINT,)),
    "pins check": CommandDependencies(
        tools=(ToolName.SKOPEO,),
        profile=ProfileUse.OPTIONAL,
        registry_credentials=True,
    ),
    "pins propose": CommandDependencies(
        tools=(ToolName.GIT, ToolName.SKOPEO),
        profile=ProfileUse.OPTIONAL,
        registry_credentials=True,
    ),
    "pins apply": CommandDependencies(tools=(ToolName.GIT,)),
    "build": CommandDependencies(
        tools=(ToolName.GIT, ToolName.BUILDAH),
        profile=ProfileUse.OPTIONAL,
        registry_credentials=True,
    ),
    "test": CommandDependencies(tools=(ToolName.GIT, ToolName.PODMAN)),
    "qualify": CommandDependencies(
        tools=(
            ToolName.GIT,
            ToolName.BUILDAH,
            ToolName.PODMAN,
            ToolName.SKOPEO,
            ToolName.HADOLINT,
            ToolName.TRIVY,
        ),
        profile=ProfileUse.OPTIONAL,
        registry_credentials=True,
    ),
    "transport export": CommandDependencies(tools=(ToolName.GIT,)),
    "assemble": CommandDependencies(tools=(ToolName.GIT,), profile=ProfileUse.OPTIONAL),
    "provenance": CommandDependencies(tools=(ToolName.GIT,)),
    "publish": CommandDependencies(
        tools=(ToolName.GIT, ToolName.SKOPEO),
        profile=ProfileUse.REQUIRED,
        registry_credentials=True,
        registry_control=True,
    ),
    "attest": CommandDependencies(
        tools=(ToolName.GIT, ToolName.SKOPEO, ToolName.COSIGN),
        profile=ProfileUse.REQUIRED,
        registry_credentials=True,
        signing=True,
        transparency_log=True,
    ),
    "verify": CommandDependencies(
        tools=(ToolName.GIT, ToolName.SKOPEO, ToolName.COSIGN),
        profile=ProfileUse.REQUIRED,
        registry_credentials=True,
        signing=True,
        transparency_log=True,
    ),
    "promote": CommandDependencies(
        tools=(ToolName.GIT, ToolName.SKOPEO, ToolName.COSIGN),
        profile=ProfileUse.REQUIRED,
        registry_credentials=True,
        registry_control=True,
        transparency_log=True,
    ),
    "release": CommandDependencies(
        tools=_ALL_TOOLS,
        profile=ProfileUse.REQUIRED,
        registry_credentials=True,
        registry_control=True,
        signing=True,
        transparency_log=True,
    ),
    "rescan": CommandDependencies(
        tools=(ToolName.SKOPEO, ToolName.TRIVY, ToolName.COSIGN),
        profile=ProfileUse.REQUIRED,
        registry_credentials=True,
        signing=True,
        transparency_log=True,
    ),
    "cleanup": CommandDependencies(
        tools=(ToolName.GIT, ToolName.BUILDAH, ToolName.PODMAN),
        profile=ProfileUse.OPTIONAL,
        registry_control=True,
    ),
}

DOCTOR_SCOPES: Mapping[str, tuple[str, ...]] = {
    "check": ("check",),
    "qualify": ("check", "pins check", "build", "test", "qualify", "transport export"),
    "release": tuple(name for name in COMMAND_DEPENDENCIES if name != "version"),
}


def command_tools(command: str) -> tuple[ToolName, ...]:
    """Return the host tools one command executes, in resolution order."""
    return COMMAND_DEPENDENCIES[command].tools


def scope_dependencies(scope: str) -> CommandDependencies:
    """Return the union of what every command in one doctor scope needs."""
    selected = tuple(COMMAND_DEPENDENCIES[name] for name in DOCTOR_SCOPES[scope])
    used = {tool for item in selected for tool in item.tools}
    levels = [ProfileUse.NONE, ProfileUse.OPTIONAL, ProfileUse.REQUIRED]
    return CommandDependencies(
        tools=tuple(tool for tool in ToolName if tool in used),
        profile=max((item.profile for item in selected), key=levels.index),
        registry_credentials=any(item.registry_credentials for item in selected),
        registry_control=any(item.registry_control for item in selected),
        signing=any(item.signing for item in selected),
        transparency_log=any(item.transparency_log for item in selected),
    )
