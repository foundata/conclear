"""Run-owned external-tool environment and adapter construction."""

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
from conclear.tools import ResolvedTool, ToolName, ToolResolver


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
class ApplicationRuntime:
    """Resolved tools and adapters held immutable for one command or release run.

    A runtime resolves only the tools its command executes; the identities it
    records are exactly those tools.
    """

    root: Path
    environment: dict[str, str]
    runner: ProcessRunner
    tools: dict[ToolName, ResolvedTool]
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
    ) -> "ApplicationRuntime":
        """Create isolated XDG paths and resolve exactly the requested tools."""
        environment, runner = cls._prepare(root)
        resolved = (resolver or ToolResolver(runner=runner)).resolve_all(
            environment=environment,
            names=names,
        )
        return cls(
            root=root,
            environment=environment,
            runner=runner,
            tools={item.name: item for item in resolved},
        )

    @classmethod
    def diagnose(
        cls,
        root: Path,
        *,
        names: tuple[ToolName, ...],
        resolver: ToolResolver | None = None,
    ) -> tuple["ApplicationRuntime", tuple[ToolProblem, ...]]:
        """Resolve every requested tool and report each failure instead of the first.

        The returned runtime holds only the tools that resolved; a diagnosis
        must not proceed to use it while problems remain.
        """
        environment, runner = cls._prepare(root)
        selected = resolver or ToolResolver(runner=runner)
        tools: dict[ToolName, ResolvedTool] = {}
        problems: list[ToolProblem] = []
        for name in dict.fromkeys(names):
            try:
                tools[name] = selected.resolve(name, environment=environment)
            except ConClearError as exc:
                problems.append(ToolProblem(name, exc))
        return (
            cls(root=root, environment=environment, runner=runner, tools=tools),
            tuple(problems),
        )

    @staticmethod
    def _prepare(root: Path) -> tuple[dict[str, str], ProcessRunner]:
        paths = {
            "home": root / "home",
            "config": root / "config",
            "cache": root / "cache",
            "state": root / "state",
            "runtime": root / "runtime",
            "logs": root / "logs",
        }
        for path in paths.values():
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment = ProcessEnvironment(
            home=paths["home"],
            config_home=paths["config"],
            cache_home=paths["cache"],
            state_home=paths["state"],
            runtime_dir=paths["runtime"],
        ).values()
        return environment, ProcessRunner()

    @property
    def identities(self) -> tuple[ToolIdentity, ...]:
        """Return sorted public identities for every selected executable."""
        return tuple(self.tools[name].record_identity() for name in sorted(self.tools))

    def assert_unchanged(self) -> None:
        """Recheck every selected executable before a later phase uses it."""
        for tool in self.tools.values():
            tool.assert_unchanged()

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
