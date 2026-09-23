"""Resolve a tool from its pinned publisher image into a run-owned store.

Bootstrapping stays with host executables: the run's Podman pulls the image by
its pinned index digest into a private store, and the run's Cosign verifies the
publisher signature where one exists. The version is read inside the image, and
the platform manifest that actually ran is recorded beside the pinned index,
because the index is what ConClear pins while the manifest differs per
architecture.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from conclear.errors import InvalidInvocationError, OperationalError
from conclear.parsing import array_value, json_value, string_value
from conclear.process import CommandRequest, OperationKind, ProcessResult
from conclear.records import ToolIdentity
from conclear.tools import (
    SUPPORTED_TOOLS,
    ResolvedTool,
    Runner,
    ToolImage,
    ToolName,
    ToolVersion,
)
from conclear.values import Digest

TOOL_IMAGES_VARIABLE = "CONCLEAR_TOOL_IMAGES"


def selected_tool_images(environ: Mapping[str, str]) -> frozenset[ToolName]:
    """Return the tools a maintainer asked to run from their pinned images.

    While the mode carries no promise the switch is an environment variable, a
    comma-separated list of tool names, and appears in no profile, repository
    configuration or record.
    """
    selected: set[ToolName] = set()
    for item in environ.get(TOOL_IMAGES_VARIABLE, "").split(","):
        text = item.strip()
        if not text:
            continue
        try:
            name = ToolName(text)
        except ValueError:
            raise InvalidInvocationError(
                f"{TOOL_IMAGES_VARIABLE} names an unknown tool: {text}"
            ) from None
        if SUPPORTED_TOOLS[name].image is None:
            raise InvalidInvocationError(
                f"{TOOL_IMAGES_VARIABLE}: {name.value} has no pinned image"
            )
        selected.add(name)
    return frozenset(selected)


def bootstrap_tools(images: Iterable[ToolName]) -> tuple[ToolName, ...]:
    """Return the host executables that pull, verify and run the selected images."""
    specs = [SUPPORTED_TOOLS[name] for name in images]
    if not specs:
        return ()
    if any(spec.image is not None and spec.image.signer is not None for spec in specs):
        return (ToolName.PODMAN, ToolName.COSIGN)
    return (ToolName.PODMAN,)


@dataclass(frozen=True, slots=True)
class ToolImageStore:
    """One run-owned rootless Podman store that holds pinned tool images."""

    root: Path
    runroot: Path

    @classmethod
    def below(cls, directory: Path) -> "ToolImageStore":
        """Create the store directories below a run-owned directory."""
        store = cls(directory / "root", directory / "runroot")
        try:
            for path in (store.root, store.runroot):
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise OperationalError(
                f"Unable to create the tool image store below {directory}"
            ) from exc
        return store

    @property
    def arguments(self) -> tuple[str, ...]:
        """Return the Podman storage selection for this store."""
        return ("--root", str(self.root), "--runroot", str(self.runroot))


def reset_store(
    runner: Runner,
    environment: Mapping[str, str],
    podman: ResolvedTool,
    store: ToolImageStore,
) -> None:
    """Empty a tool image store inside the rootless user namespace.

    Pulled layers hold files owned by subordinate user IDs that the host user
    cannot unlink, so the store is reset by Podman before its directory goes.
    """
    runner.run(
        CommandRequest(
            argv=(str(podman.path), *store.arguments, "system", "reset", "--force"),
            environment=environment,
            timeout_seconds=300,
            operation=OperationKind.WRITE,
        )
    )


@dataclass(frozen=True, slots=True)
class ImageBackedTool:
    """A tool executed from its pinned image through the run's Podman."""

    name: ToolName
    image: ToolImage
    version: str
    reported_version: str
    manifest_digest: str
    executor: ResolvedTool
    store: ToolImageStore
    runner: Runner = field(repr=False, compare=False)
    environment: Mapping[str, str] = field(repr=False, compare=False)

    @property
    def binding_digest(self) -> str:
        """Return the digest a run binds this tool's identity to."""
        return self.image.digest

    def assert_unchanged(self) -> None:
        """Reject a changed Podman executable or a changed image in the store."""
        self.executor.assert_unchanged()
        observed = _inspect(
            self.runner,
            self.environment,
            self.executor,
            self.store,
            self.image.pinned_reference,
            "{{.Digest}}",
        )
        if observed.strip() != self.image.digest:
            raise OperationalError(
                f"Resolved {self.name.value} image changed during the run"
            )

    def record_identity(self) -> ToolIdentity:
        """Return the normalized public tool identity."""
        return ToolIdentity(
            name=self.name.value,
            version=self.version,
            image_digest=self.image.digest,
            image_manifest_digest=self.manifest_digest,
        )


type Tool = ResolvedTool | ImageBackedTool


class ImageResolver(Protocol):
    """Resolve one tool from its pinned image."""

    def resolve(
        self, name: ToolName, *, environment: Mapping[str, str]
    ) -> ImageBackedTool:
        """Return the image-backed tool, pulled, verified and probed."""
        ...


class ImageResolverFactory(Protocol):
    """Build an image resolver once the bootstrapping executables are known."""

    def __call__(
        self,
        *,
        runner: Runner,
        store: ToolImageStore,
        podman: ResolvedTool,
        cosign: ResolvedTool | None,
    ) -> ImageResolver:
        """Return a resolver bound to the run's store and host tools."""
        ...


class ToolImageResolver:
    """Pull, verify and probe a pinned tool image with the run's host tools."""

    def __init__(
        self,
        *,
        runner: Runner,
        store: ToolImageStore,
        podman: ResolvedTool,
        cosign: ResolvedTool | None,
    ) -> None:
        """Bind the resolver to the run's store and its bootstrapping executables."""
        self._runner = runner
        self._store = store
        self._podman = podman
        self._cosign = cosign

    def resolve(
        self, name: ToolName, *, environment: Mapping[str, str]
    ) -> ImageBackedTool:
        """Pull the pinned image, verify it and read the tool version inside it."""
        spec = SUPPORTED_TOOLS[name]
        image = spec.image
        if image is None:
            raise OperationalError(f"{name.value} has no pinned image")
        if image.signer is not None and self._cosign is None:
            raise OperationalError(
                f"Verifying the {name.value} image signature requires cosign"
            )
        self._podman_run(
            environment,
            ("pull", "--quiet", image.pinned_reference),
            timeout_seconds=900,
            operation=OperationKind.WRITE,
        )
        observed = _inspect(
            self._runner,
            environment,
            self._podman,
            self._store,
            image.pinned_reference,
            "{{.Digest}}",
        ).strip()
        if observed != image.digest:
            raise OperationalError(
                f"Pulled {name.value} image digest {observed} differs from the pin "
                f"{image.digest}"
            )
        manifest_digest = self._manifest_digest(environment, image)
        if image.signer is not None:
            self._verify_signature(environment, image)
        reported = self._probe_version(environment, image, spec.version_arguments)
        match = spec.version_pattern.search(reported)
        if match is None:
            raise OperationalError(f"Unable to parse {name.value} version output")
        try:
            version = ToolVersion.parse(match.group("version"))
        except ValueError as exc:
            raise OperationalError(
                f"{name.value} reported a noncanonical version {match.group('version')!r}"
            ) from exc
        if version != image.version:
            raise OperationalError(
                f"Pinned {name.value} image reports version {version}, "
                f"the pin declares {image.version}"
            )
        return ImageBackedTool(
            name=name,
            image=image,
            version=str(version),
            reported_version=reported,
            manifest_digest=manifest_digest,
            executor=self._podman,
            store=self._store,
            runner=self._runner,
            environment=environment,
        )

    def _manifest_digest(self, environment: Mapping[str, str], image: ToolImage) -> str:
        """Return the platform manifest digest Podman selected from the index.

        `RepoDigests` lists the index the pull named and the manifest it chose;
        a single-platform image lists only the manifest, which then is the pin.
        """
        output = _inspect(
            self._runner,
            environment,
            self._podman,
            self._store,
            image.pinned_reference,
            "{{json .RepoDigests}}",
        )
        label = f"{image.reference} repository digests"
        digests: set[str] = set()
        for item in array_value(json_value(output, label=label), label=label):
            reference = string_value(item, label=label)
            _repository, separator, digest = reference.rpartition("@")
            if not separator:
                raise OperationalError(f"Podman listed a digest-less {label}")
            digests.add(str(Digest(digest)))
        digests.discard(image.digest)
        if not digests:
            return image.digest
        if len(digests) > 1:
            raise OperationalError(
                f"Podman lists several platform manifests for {image.pinned_reference}"
            )
        return digests.pop()

    def _verify_signature(
        self, environment: Mapping[str, str], image: ToolImage
    ) -> None:
        """Verify the publisher's keyless signature on the pinned index."""
        signer = image.signer
        cosign = self._cosign
        if signer is None or cosign is None:  # pragma: no cover - guarded by resolve
            raise OperationalError(
                "Signature verification was requested without a signer"
            )
        self._run(
            environment,
            (str(cosign.path), "initialize"),
            timeout_seconds=600,
            operation=OperationKind.WRITE,
        )
        result = self._run(
            environment,
            (
                str(cosign.path),
                "verify",
                "--certificate-oidc-issuer",
                signer.issuer,
                "--certificate-identity-regexp",
                signer.identity_pattern,
                "--output",
                "json",
                image.pinned_reference,
            ),
            timeout_seconds=600,
        )
        label = f"{image.reference} signature verification"
        if not array_value(json_value(result.stdout, label=label), label=label):
            raise OperationalError(
                f"Cosign verified no signature on {image.pinned_reference}"
            )

    def _probe_version(
        self,
        environment: Mapping[str, str],
        image: ToolImage,
        version_arguments: tuple[str, ...],
    ) -> str:
        result = self._podman_run(
            environment,
            (
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--entrypoint",
                image.executable,
                image.pinned_reference,
                *version_arguments,
            ),
            timeout_seconds=120,
        )
        return f"{result.stdout}\n{result.stderr}".strip()

    def _podman_run(
        self,
        environment: Mapping[str, str],
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float,
        operation: OperationKind = OperationKind.READ,
    ) -> ProcessResult:
        return self._run(
            environment,
            (str(self._podman.path), *self._store.arguments, *arguments),
            timeout_seconds=timeout_seconds,
            operation=operation,
        )

    def _run(
        self,
        environment: Mapping[str, str],
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        operation: OperationKind = OperationKind.READ,
    ) -> ProcessResult:
        return self._runner.run(
            CommandRequest(
                argv=argv,
                environment=environment,
                timeout_seconds=timeout_seconds,
                operation=operation,
            )
        )


def _inspect(
    runner: Runner,
    environment: Mapping[str, str],
    podman: ResolvedTool,
    store: ToolImageStore,
    reference: str,
    template: str,
) -> str:
    result = runner.run(
        CommandRequest(
            argv=(
                str(podman.path),
                *store.arguments,
                "image",
                "inspect",
                "--format",
                template,
                reference,
            ),
            environment=environment,
            timeout_seconds=120,
        )
    )
    return result.stdout
