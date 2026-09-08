"""Embedded ConClear and normative guide identity."""

from dataclasses import asdict, dataclass
from importlib import import_module


def _load_source_revision() -> str:
    try:
        module = import_module("conclear._embedded_identity")
    except ModuleNotFoundError:
        try:
            module = import_module("conclear._development_identity")
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "ConClear distribution has no embedded source identity"
            ) from exc
    value = getattr(module, "SOURCE_REVISION", None)
    if not isinstance(value, str):
        raise RuntimeError("Embedded source identity is malformed")
    return value


VERSION = "1.0.0"
SOURCE_REVISION = _load_source_revision()
GUIDE_TITLE = "OCI container image build and release guide"
GUIDE_REPOSITORY = "https://github.com/foundata/guidelines"
GUIDE_PATH = "oci-container-image-guide.md"
GUIDE_REVISION = "50240520ec9aef8d3725fae6c1be9a931cb465b1"


@dataclass(frozen=True, slots=True)
class GuideIdentity:
    """Identify the exact normative guide implemented by this build."""

    title: str = GUIDE_TITLE
    repository: str = GUIDE_REPOSITORY
    path: str = GUIDE_PATH
    revision: str = GUIDE_REVISION


@dataclass(frozen=True, slots=True)
class ApplicationIdentity:
    """Identify this ConClear build."""

    name: str = "conclear"
    version: str = VERSION
    source_revision: str = SOURCE_REVISION
    guide: GuideIdentity = GuideIdentity()

    def to_public_dict(self) -> dict[str, object]:
        """Return the stable public version object."""
        guide = asdict(self.guide)
        return {
            "name": self.name,
            "version": self.version,
            "sourceRevision": self.source_revision,
            "guide": guide,
        }


IDENTITY = ApplicationIdentity()


def is_release_build() -> bool:
    """Return whether an external build input embedded a full source revision."""
    return len(SOURCE_REVISION) in {40, 64} and all(
        character in "0123456789abcdef" for character in SOURCE_REVISION
    )


def human_version() -> str:
    """Return the normative human-readable version output."""
    return (
        f"ConClear {VERSION} (commit {SOURCE_REVISION})\n"
        f'Implements the automatable rules of foundata "{GUIDE_TITLE}", '
        f"{GUIDE_PATH} at commit {GUIDE_REVISION}"
    )
