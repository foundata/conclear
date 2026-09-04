"""Native and QEMU user-mode execution detection for platform workflows.

A platform whose architecture differs from the host can only build and run
through a registered, enabled `binfmt_misc` handler. ConClear observes that
handler before it builds or tests such a platform, records the resulting
execution mode, and rejects a recorded observation that contradicts the host
and target architectures.
"""

from dataclasses import dataclass
from pathlib import Path

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.values import Platform

BINFMT_ROOT = Path("/proc/sys/fs/binfmt_misc")
MAX_BINFMT_BYTES = 64 * 1024
_HANDLER_NAMES: dict[str, tuple[str, ...]] = {
    "arm64": ("qemu-aarch64", "qemu-arm64"),
    "amd64": ("qemu-x86_64", "qemu-amd64"),
}
_ARCHITECTURES = {"x86_64": "amd64", "aarch64": "arm64"}


@dataclass(frozen=True, slots=True)
class BinfmtHandler:
    """One enabled `binfmt_misc` handler observed on the host."""

    name: str
    interpreter: str
    flags: str


@dataclass(frozen=True, slots=True)
class ExecutionMode:
    """The execution mechanism selected for one target platform on this host."""

    target: Platform
    host_architecture: str
    handler: BinfmtHandler | None

    @property
    def native(self) -> bool:
        """Return whether the target runs without emulation."""
        return self.handler is None

    @property
    def mechanism(self) -> str:
        """Return the recorded execution mechanism."""
        return "native" if self.native else "qemu-user"

    def to_dict(self) -> dict[str, object]:
        """Return the public execution observation stored in evidence."""
        return {
            "targetPlatform": str(self.target),
            "hostArchitecture": self.host_architecture,
            "executionArchitecture": self.target.architecture,
            "mechanism": self.mechanism,
        }


def normalize_architecture(value: str) -> str:
    """Map a kernel machine name to its OCI architecture."""
    normalized = value.lower()
    return _ARCHITECTURES.get(normalized, normalized)


def binfmt_handler(
    architecture: str, *, root: Path = BINFMT_ROOT
) -> BinfmtHandler | None:
    """Return the enabled QEMU user-mode handler for one architecture, if any."""
    for name in _HANDLER_NAMES.get(architecture, (f"qemu-{architecture}",)):
        path = root / name
        try:
            content = path.read_text(encoding="ascii", errors="replace")
        except OSError:
            continue
        lines = content[:MAX_BINFMT_BYTES].splitlines()
        if "enabled" not in lines:
            continue
        values: dict[str, str] = {}
        for line in lines:
            key, separator, item = line.partition(" ")
            if separator:
                values[key.rstrip(":")] = item.strip()
        return BinfmtHandler(
            name=name,
            interpreter=values.get("interpreter", ""),
            flags=values.get("flags", ""),
        )
    return None


def detect_execution_mode(
    host_architecture: str,
    platform: Platform,
    *,
    binfmt_root: Path = BINFMT_ROOT,
) -> ExecutionMode:
    """Select native execution or a verified emulation handler for a platform.

    Raises:
        OperationalError: If the platform is foreign and no enabled handler
            exists, so the platform cannot be built, tested or qualified here.
    """
    if normalize_architecture(host_architecture) == platform.architecture:
        return ExecutionMode(platform, host_architecture, None)
    handler = binfmt_handler(platform.architecture, root=binfmt_root)
    if handler is None:
        raise OperationalError(
            f"No enabled binfmt handler for {platform.architecture} on this "
            f"{host_architecture} host; {platform} cannot be built or tested "
            "here and is not qualified"
        )
    return ExecutionMode(platform, host_architecture, handler)


def validate_execution_observation(value: object, *, platform: Platform) -> None:
    """Reject an execution observation whose mechanism contradicts its inputs."""
    if not isinstance(value, dict):
        raise InvalidInvocationError("Execution observation must be an object")
    host = value.get("hostArchitecture")
    mechanism = value.get("mechanism")
    if not isinstance(host, str) or not isinstance(mechanism, str):
        raise InvalidInvocationError("Execution observation is malformed")
    if value.get("targetPlatform") != str(platform) or (
        value.get("executionArchitecture") != platform.architecture
    ):
        raise InvalidInvocationError(
            f"Execution observation does not describe {platform}"
        )
    native = normalize_architecture(host) == platform.architecture
    expected = "native" if native else "qemu-user"
    if mechanism != expected:
        raise InvalidInvocationError(
            f"Execution observation claims {mechanism} for {platform} on a "
            f"{host} host; expected {expected}"
        )
