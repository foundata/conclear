"""Typed per-command declarations of host tools, profile use and credentials.

Each public command declares only what its production call path executes: the
host executables it runs, whether it needs a maintainer-controlled release
profile, and which credentials and external services it touches. Commands
resolve exactly the declared tools, `doctor` validates a scope through the union
of the commands the scope covers, and the compatibility inventory renders the
declarations so a change is a reviewable diff. An option that changes what a
command executes, such as `rescan --authoritative`, declares its escalation
separately; `command_dependencies` unions the declaration of one invocation.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from conclear.errors import InvalidInvocationError
from conclear.release_profile import ReleaseProfile
from conclear.tools import ToolName


class ProfileUse(StrEnum):
    """Whether a command loads a release profile."""

    NONE = "none"
    OPTIONAL = "optional"
    REQUIRED = "required"


class RegistryAccess(StrEnum):
    """How a command uses the release profile's registry authentication."""

    NONE = "none"
    READ = "read"
    WRITE = "write"


class SigningUse(StrEnum):
    """Whether a command verifies with the trust root or signs with the key."""

    NONE = "none"
    VERIFY = "verify"
    SIGN = "sign"


@dataclass(frozen=True, slots=True)
class CommandDependencies:
    """Host tools, profile use and external trust inputs of one command."""

    tools: tuple[ToolName, ...]
    profile: ProfileUse = ProfileUse.NONE
    registry_access: RegistryAccess = RegistryAccess.NONE
    registry_control: bool = False
    signing: SigningUse = SigningUse.NONE
    transparency_log: bool = False

    def to_dict(self) -> dict[str, object]:
        """Return the public inventory form."""
        return {
            "tools": [tool.value for tool in self.tools],
            "profile": self.profile.value,
            "registryAccess": self.registry_access.value,
            "registryControl": self.registry_control,
            "signing": self.signing.value,
            "transparencyLog": self.transparency_log,
        }


_ALL_TOOLS = tuple(ToolName)

COMMAND_DEPENDENCIES: Mapping[str, CommandDependencies] = {
    "version": CommandDependencies(tools=()),
    "adopt": CommandDependencies(tools=(ToolName.GIT,)),
    "config show": CommandDependencies(tools=(), profile=ProfileUse.OPTIONAL),
    "check": CommandDependencies(tools=(ToolName.HADOLINT,)),
    "pins check": CommandDependencies(
        tools=(ToolName.SKOPEO,),
        profile=ProfileUse.OPTIONAL,
        registry_access=RegistryAccess.READ,
    ),
    "pins propose": CommandDependencies(
        tools=(ToolName.GIT, ToolName.SKOPEO),
        profile=ProfileUse.OPTIONAL,
        registry_access=RegistryAccess.READ,
    ),
    "pins apply": CommandDependencies(tools=(ToolName.GIT,)),
    "build": CommandDependencies(
        tools=(ToolName.GIT, ToolName.BUILDAH, ToolName.SKOPEO),
        profile=ProfileUse.OPTIONAL,
        registry_access=RegistryAccess.READ,
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
        registry_access=RegistryAccess.READ,
    ),
    "transport export": CommandDependencies(tools=(ToolName.GIT,)),
    "archive create": CommandDependencies(
        tools=(ToolName.COSIGN,),
        profile=ProfileUse.REQUIRED,
        registry_access=RegistryAccess.READ,
        signing=SigningUse.VERIFY,
        transparency_log=True,
    ),
    "archive verify": CommandDependencies(
        tools=(ToolName.COSIGN,),
        profile=ProfileUse.REQUIRED,
        signing=SigningUse.VERIFY,
        transparency_log=True,
    ),
    "assemble": CommandDependencies(tools=(ToolName.GIT,), profile=ProfileUse.OPTIONAL),
    "provenance": CommandDependencies(tools=(ToolName.GIT,)),
    "publish": CommandDependencies(
        tools=(ToolName.GIT, ToolName.SKOPEO),
        profile=ProfileUse.REQUIRED,
        registry_access=RegistryAccess.WRITE,
        registry_control=True,
    ),
    "attest": CommandDependencies(
        tools=(ToolName.GIT, ToolName.SKOPEO, ToolName.COSIGN),
        profile=ProfileUse.REQUIRED,
        registry_access=RegistryAccess.WRITE,
        signing=SigningUse.SIGN,
        transparency_log=True,
    ),
    "verify": CommandDependencies(
        tools=(ToolName.GIT, ToolName.SKOPEO, ToolName.COSIGN),
        profile=ProfileUse.REQUIRED,
        registry_access=RegistryAccess.WRITE,
        signing=SigningUse.SIGN,
        transparency_log=True,
    ),
    "promote": CommandDependencies(
        tools=(ToolName.GIT, ToolName.SKOPEO, ToolName.COSIGN),
        profile=ProfileUse.REQUIRED,
        registry_access=RegistryAccess.READ,
        registry_control=True,
        signing=SigningUse.VERIFY,
        transparency_log=True,
    ),
    "release": CommandDependencies(
        tools=_ALL_TOOLS,
        profile=ProfileUse.REQUIRED,
        registry_access=RegistryAccess.WRITE,
        registry_control=True,
        signing=SigningUse.SIGN,
        transparency_log=True,
    ),
    "rescan": CommandDependencies(
        tools=(ToolName.SKOPEO, ToolName.TRIVY, ToolName.COSIGN),
        profile=ProfileUse.REQUIRED,
        registry_access=RegistryAccess.READ,
        signing=SigningUse.VERIFY,
        transparency_log=True,
    ),
    "cleanup": CommandDependencies(
        tools=(ToolName.GIT, ToolName.BUILDAH, ToolName.PODMAN),
        profile=ProfileUse.OPTIONAL,
        registry_control=True,
    ),
}

COMMAND_ESCALATIONS: Mapping[str, Mapping[str, CommandDependencies]] = {
    "rescan": {
        "--authoritative": CommandDependencies(
            tools=(ToolName.SKOPEO, ToolName.TRIVY, ToolName.COSIGN),
            profile=ProfileUse.REQUIRED,
            registry_access=RegistryAccess.WRITE,
            signing=SigningUse.SIGN,
            transparency_log=True,
        ),
    },
}

DOCTOR_SCOPES: Mapping[str, tuple[str, ...]] = {
    "check": ("check",),
    "qualify": ("check", "pins check", "build", "test", "qualify", "transport export"),
    "release": tuple(name for name in COMMAND_DEPENDENCIES if name != "version"),
}


def command_tools(command: str) -> tuple[ToolName, ...]:
    """Return the host tools one command executes, in resolution order."""
    return COMMAND_DEPENDENCIES[command].tools


def command_dependencies(command: str, *options: str) -> CommandDependencies:
    """Return what one invocation needs: the command escalated by its options.

    Each option must be declared in `COMMAND_ESCALATIONS` for the command;
    an undeclared option is a programming error and raises `KeyError`.
    """
    base = COMMAND_DEPENDENCIES[command]
    if not options:
        return base
    escalations = COMMAND_ESCALATIONS.get(command, {})
    selected = (base, *(escalations[option] for option in options))
    added = tuple(
        tool for item in selected[1:] for tool in item.tools if tool not in base.tools
    )
    return _union(selected, tools=(*base.tools, *dict.fromkeys(added)))


def scope_dependencies(scope: str) -> CommandDependencies:
    """Return the union of what every command in one doctor scope needs.

    Option escalations count: a scope that covers `rescan` also covers an
    authoritative rescan.
    """
    selected = tuple(
        item
        for name in DOCTOR_SCOPES[scope]
        for item in (
            COMMAND_DEPENDENCIES[name],
            *COMMAND_ESCALATIONS.get(name, {}).values(),
        )
    )
    used = {tool for item in selected for tool in item.tools}
    return _union(selected, tools=tuple(tool for tool in ToolName if tool in used))


def _union(
    selected: tuple[CommandDependencies, ...], *, tools: tuple[ToolName, ...]
) -> CommandDependencies:
    return CommandDependencies(
        tools=tools,
        profile=_strongest(ProfileUse, (item.profile for item in selected)),
        registry_access=_strongest(
            RegistryAccess, (item.registry_access for item in selected)
        ),
        registry_control=any(item.registry_control for item in selected),
        signing=_strongest(SigningUse, (item.signing for item in selected)),
        transparency_log=any(item.transparency_log for item in selected),
    )


def require_profile_capabilities(
    profile: ReleaseProfile, dependencies: CommandDependencies
) -> None:
    """Fail closed when the profile lacks an input the dependencies will use.

    This checks configuration only: nothing is written, signed or contacted.
    Registry write access needs the profile's auth file, signing needs its
    private key; the control-plane token is demanded by the backend selection.
    """
    if (
        dependencies.registry_access is RegistryAccess.WRITE
        and profile.auth_file is None
    ):
        raise InvalidInvocationError(
            f"Release profile {profile.name} has no auth_file for registry writes"
        )
    if dependencies.signing is SigningUse.SIGN and profile.cosign_private_key is None:
        raise InvalidInvocationError("Release profile has no Cosign signing key")


def _strongest[E: StrEnum](kind: type[E], values: Iterable[E]) -> E:
    order = list(kind)
    return max(values, key=order.index, default=order[0])
