"""Run-owned external-tool environment and adapter construction."""

import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.adapters.buildah import BuildahAdapter
from conclear.adapters.cosign import CosignAdapter
from conclear.adapters.git import GitAdapter
from conclear.adapters.hadolint import HadolintAdapter
from conclear.adapters.podman import PodmanAdapter
from conclear.adapters.skopeo import SkopeoAdapter
from conclear.adapters.trivy import TrivyAdapter
from conclear.errors import ConClearError, OperationalError
from conclear.process import ProcessEnvironment, ProcessRunner
from conclear.records import ToolIdentity
from conclear.runtime_directory import (
    prepare_runtime_directory,
    remove_runtime_directory,
    session_bus_environment,
)
from conclear.tool_images import (
    ImageResolver,
    ImageResolverFactory,
    Tool,
    ToolImageResolver,
    ToolImageStore,
    bootstrap_tools,
    reset_store,
    selected_tool_images,
)
from conclear.tools import ResolvedTool, ToolName, ToolResolver
from conclear.workspace import ResourceJournal, ResourceKind, ResourceStatus

TOOL_IMAGE_STORE = "tool-images"


@dataclass(frozen=True, slots=True)
class ToolProblem:
    """One host tool that could not be resolved for a diagnosis."""

    name: ToolName
    failure: ConClearError

    @property
    def message(self) -> str:
        """Return the failure text prefixed by the tool name."""
        return f"{self.name.value}: {self.failure}"


@dataclass(frozen=True, slots=True)
class _Selection:
    """Which declared tools run from images and which host executables that takes."""

    host: tuple[ToolName, ...]
    images: tuple[ToolName, ...]

    @classmethod
    def plan(
        cls, names: tuple[ToolName, ...], images: frozenset[ToolName] | None
    ) -> "_Selection":
        selected = selected_tool_images(os.environ) if images is None else images
        from_images = tuple(name for name in dict.fromkeys(names) if name in selected)
        host = [name for name in dict.fromkeys(names) if name not in selected]
        host.extend(name for name in bootstrap_tools(from_images) if name not in host)
        return cls(host=tuple(host), images=from_images)


@dataclass(frozen=True, slots=True)
class ApplicationRuntime:
    """Resolved tools and adapters held immutable for one command or release run.

    A runtime resolves only the tools its command executes; the identities it
    records are exactly those tools. A tool selected to run from its pinned
    image adds the host executables that pull, verify and run it.
    """

    root: Path
    environment: dict[str, str]
    runner: ProcessRunner
    tools: dict[ToolName, Tool]
    _adapters: dict[ToolName, ToolAdapter] = field(
        default_factory=dict,
        init=False,
        repr=False,
        compare=False,
    )

    @classmethod
    def create(
        cls,
        root: Path,
        *,
        names: tuple[ToolName, ...] = tuple(ToolName),
        resolver: ToolResolver | None = None,
        journal: ResourceJournal | None = None,
        images: frozenset[ToolName] | None = None,
        image_resolver: ImageResolverFactory | None = None,
    ) -> "ApplicationRuntime":
        """Create isolated XDG paths and resolve exactly the requested tools."""
        selection = _Selection.plan(names, images)
        store_directory = root / TOOL_IMAGE_STORE
        pulled = False
        try:
            environment, runner = cls._prepare(
                root, names=selection.host, journal=journal
            )
            resolved = (resolver or ToolResolver(runner=runner)).resolve_all(
                environment=environment,
                names=selection.host,
            )
            tools: dict[ToolName, Tool] = {item.name: item for item in resolved}
            if selection.images:
                if journal is not None:
                    journal.plan(
                        resource_id=TOOL_IMAGE_STORE,
                        kind=ResourceKind.TOOL_IMAGE_STORE,
                        identifier=str(store_directory),
                        ephemeral=True,
                    )
                image_tools = _image_resolver(
                    root, tools, runner, image_resolver, selection.images
                )
                pulled = True
                for name in selection.images:
                    tools[name] = image_tools.resolve(name, environment=environment)
                if journal is not None:
                    journal.update(TOOL_IMAGE_STORE, ResourceStatus.CREATED)
        except BaseException:
            if journal is not None:
                if pulled:
                    journal.mark_failed(TOOL_IMAGE_STORE)
            else:
                if pulled:
                    _release_store(runner, environment, tools, store_directory)
                remove_runtime_directory(root)
            raise
        return cls(root=root, environment=environment, runner=runner, tools=tools)

    @classmethod
    def diagnose(
        cls,
        root: Path,
        *,
        names: tuple[ToolName, ...],
        resolver: ToolResolver | None = None,
        images: frozenset[ToolName] | None = None,
        image_resolver: ImageResolverFactory | None = None,
    ) -> tuple["ApplicationRuntime", tuple[ToolProblem, ...]]:
        """Resolve every requested tool and report each failure instead of the first.

        The returned runtime holds only the tools that resolved; a diagnosis
        must not proceed to use it while problems remain.
        """
        selection = _Selection.plan(names, images)
        environment, runner = cls._prepare(root, names=selection.host)
        selected = resolver or ToolResolver(runner=runner)
        tools: dict[ToolName, Tool] = {}
        problems: list[ToolProblem] = []
        for name in selection.host:
            try:
                tools[name] = selected.resolve(name, environment=environment)
            except ConClearError as exc:
                problems.append(ToolProblem(name, exc))
        if selection.images:
            try:
                image_tools = _image_resolver(
                    root, tools, runner, image_resolver, selection.images
                )
            except ConClearError as exc:
                problems.extend(ToolProblem(name, exc) for name in selection.images)
            else:
                for name in selection.images:
                    try:
                        tools[name] = image_tools.resolve(name, environment=environment)
                    except ConClearError as exc:
                        problems.append(ToolProblem(name, exc))
        return (
            cls(root=root, environment=environment, runner=runner, tools=tools),
            tuple(problems),
        )

    @staticmethod
    def _prepare(
        root: Path,
        *,
        names: tuple[ToolName, ...],
        journal: ResourceJournal | None = None,
    ) -> tuple[dict[str, str], ProcessRunner]:
        paths = {
            "home": root / "home",
            "config": root / "config",
            "cache": root / "cache",
            "state": root / "state",
            "logs": root / "logs",
        }
        for path in paths.values():
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        container_tools = bool({ToolName.BUILDAH, ToolName.PODMAN} & set(names))
        runtime_dir = prepare_runtime_directory(
            root,
            required=container_tools,
            journal=journal,
        )
        environment = ProcessEnvironment(
            home=paths["home"],
            config_home=paths["config"],
            cache_home=paths["cache"],
            state_home=paths["state"],
            runtime_dir=runtime_dir,
        ).values(session_bus_environment(runtime_dir) if container_tools else None)
        return environment, ProcessRunner()

    def close(self) -> None:
        """Remove command-scoped transient files after all child processes finish."""
        self.release_tool_images()
        remove_runtime_directory(self.root)

    def release_tool_images(self) -> None:
        """Reset and remove the store of pulled tool images, if this runtime has one.

        A run workspace keeps its store for `cleanup` like every other
        journaled store; a command-scoped runtime has no journal and releases
        it here, before its directory is removed.
        """
        if self.tool_image_store is not None:
            _release_store(
                self.runner, self.environment, self.tools, self.root / TOOL_IMAGE_STORE
            )

    @property
    def identities(self) -> tuple[ToolIdentity, ...]:
        """Return sorted public identities for every selected tool."""
        return tuple(self.tools[name].record_identity() for name in sorted(self.tools))

    @property
    def tool_image_store(self) -> ToolImageStore | None:
        """Return the store holding this runtime's tool images, if any were pulled."""
        stores = {
            tool.store
            for tool in self.tools.values()
            if not isinstance(tool, ResolvedTool)
        }
        if len(stores) > 1:  # pragma: no cover - one runtime owns one store
            raise OperationalError("Runtime tool images live in several stores")
        return next(iter(stores), None)

    def assert_unchanged(self) -> None:
        """Recheck every selected tool before a later phase uses it."""
        for tool in self.tools.values():
            tool.assert_unchanged()

    def executable(self, name: ToolName) -> ResolvedTool:
        """Return one tool that runs as a host executable, never from an image."""
        tool = self.tools.get(name)
        if tool is None:
            raise OperationalError(f"Runtime did not resolve {name.value}")
        if not isinstance(tool, ResolvedTool):
            raise OperationalError(f"{name.value} runs from its image, not the host")
        return tool

    def git(self) -> GitAdapter:
        """Return the resolved Git adapter."""
        return self._adapter(GitAdapter, ToolName.GIT)

    def buildah(self) -> BuildahAdapter:
        """Return the resolved Buildah adapter."""
        return self._adapter(BuildahAdapter, ToolName.BUILDAH)

    def podman(self) -> PodmanAdapter:
        """Return the resolved Podman adapter."""
        return self._adapter(PodmanAdapter, ToolName.PODMAN)

    def skopeo(self) -> SkopeoAdapter:
        """Return the resolved Skopeo adapter."""
        return self._adapter(SkopeoAdapter, ToolName.SKOPEO)

    def hadolint(self) -> HadolintAdapter:
        """Return the resolved Hadolint adapter."""
        return self._adapter(HadolintAdapter, ToolName.HADOLINT)

    def trivy(self) -> TrivyAdapter:
        """Return the resolved Trivy adapter."""
        return self._adapter(TrivyAdapter, ToolName.TRIVY)

    def cosign(self, *, auth_file: Path | None = None) -> CosignAdapter:
        """Return the resolved Cosign adapter, with registry credentials when given."""
        adapter = self._adapter(CosignAdapter, ToolName.COSIGN)
        if auth_file is not None:
            adapter.use_registry_credentials(auth_file)
        return adapter

    def _adapter[T: ToolAdapter](self, adapter: type[T], name: ToolName) -> T:
        cached = self._adapters.get(name)
        if cached is not None:
            if not isinstance(cached, adapter):  # pragma: no cover - internal invariant
                raise OperationalError(f"Runtime adapter type changed for {name.value}")
            return cached
        tool = self.tools.get(name)
        if tool is None:
            raise OperationalError(f"Runtime did not resolve {name.value}")
        value = adapter(
            tool=tool,
            runner=self.runner,
            environment=self.environment,
            log_directory=self.root / "logs",
        )
        self._adapters[name] = value
        return value


def _release_store(
    runner: ProcessRunner,
    environment: Mapping[str, str],
    tools: Mapping[ToolName, Tool],
    directory: Path,
) -> None:
    podman = tools.get(ToolName.PODMAN)
    if isinstance(podman, ResolvedTool) and directory.is_dir():
        reset_store(runner, environment, podman, ToolImageStore.below(directory))
    shutil.rmtree(directory, ignore_errors=True)


def _image_resolver(
    root: Path,
    tools: Mapping[ToolName, Tool],
    runner: ProcessRunner,
    factory: ImageResolverFactory | None,
    images: tuple[ToolName, ...],
) -> ImageResolver:
    podman = tools.get(ToolName.PODMAN)
    if not isinstance(podman, ResolvedTool):
        raise OperationalError(
            "Running "
            + ", ".join(name.value for name in images)
            + " from an image requires the podman executable"
        )
    cosign = tools.get(ToolName.COSIGN)
    if cosign is not None and not isinstance(cosign, ResolvedTool):
        raise OperationalError("Cosign cannot verify tool images from an image")
    store = ToolImageStore.below(root / TOOL_IMAGE_STORE)
    return (factory or ToolImageResolver)(
        runner=runner, store=store, podman=podman, cosign=cosign
    )
