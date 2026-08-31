"""Read-only release environment diagnostics."""

import platform as host_platform
from dataclasses import dataclass
from pathlib import Path

from conclear.adapters.quay import QuayAdapter
from conclear.config import ReleaseProfile, RepositoryConfig
from conclear.errors import OperationalError
from conclear.runtime import ApplicationRuntime


@dataclass(frozen=True, slots=True)
class DoctorObservation:
    """Validated tool, storage, execution, trust and service observations."""

    tools: tuple[dict[str, object], ...]
    native_architecture: str
    emulated_architectures: tuple[str, ...]
    quay_access: bool
    sigstore_access: bool


def diagnose_environment(
    repository: RepositoryConfig,
    profile: ReleaseProfile,
    runtime: ApplicationRuntime,
    *,
    quay: QuayAdapter,
) -> DoctorObservation:
    """Exercise read-only prerequisites without publishing or signing content."""
    runtime.buildah().info(
        root=runtime.root / "doctor" / "buildah" / "root",
        runroot=runtime.root / "doctor" / "buildah" / "runroot",
    )
    runtime.podman().info(
        root=runtime.root / "doctor" / "podman" / "root",
        runroot=runtime.root / "doctor" / "podman" / "runroot",
    )
    native = _architecture(host_platform.machine())
    requested = {
        item.architecture for image in repository.images for item in image.platforms
    }
    emulated = tuple(sorted(item for item in requested if item != native))
    unavailable = [item for item in emulated if not _binfmt_available(item)]
    if unavailable:
        raise OperationalError(
            "No enabled binfmt handler was observed for: " + ", ".join(unavailable)
        )
    for image in repository.images:
        quay.get_tag(image.repository, "conclear-doctor-read-probe")
    runtime.cosign().initialize()
    runtime.assert_unchanged()
    return DoctorObservation(
        tools=tuple(item.to_dict() for item in runtime.identities),
        native_architecture=native,
        emulated_architectures=emulated,
        quay_access=True,
        sigstore_access=True,
    )


def _binfmt_available(architecture: str) -> bool:
    candidates = {
        "arm64": ("qemu-aarch64", "qemu-arm64"),
        "amd64": ("qemu-x86_64", "qemu-amd64"),
    }.get(architecture, (f"qemu-{architecture}",))
    for name in candidates:
        path = Path("/proc/sys/fs/binfmt_misc") / name
        try:
            content = path.read_text(encoding="ascii")
        except OSError:
            continue
        if "enabled" in content.splitlines():
            return True
    return False


def _architecture(value: str) -> str:
    normalized = value.lower()
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(normalized, normalized)
