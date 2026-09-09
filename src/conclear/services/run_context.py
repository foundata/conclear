"""Creation and reopening of isolated source qualification runs."""

import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from conclear.config import (
    RepositoryConfig,
    load_repository_config,
    normalize_observed_source_url,
)
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
    bind_failed_run,
)
from conclear.hooks import HookRunner
from conclear.jsonutil import sha256_bytes
from conclear.records import SourceIdentity, utc_now
from conclear.runtime import ApplicationRuntime
from conclear.source_integrity import require_source_integrity, source_tree_digest
from conclear.tools import ToolName
from conclear.workspace import (
    IdFactory,
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
    UlidFactory,
)


@dataclass(frozen=True, slots=True)
class SourceRun:
    """One detached source checkout with validated configuration and tools."""

    workspace: RunWorkspace
    repository: RepositoryConfig
    source: SourceIdentity
    source_time: datetime
    runtime: ApplicationRuntime


def finish_run_failure(
    workspace: RunWorkspace, failure: BaseException, *, now: datetime | None = None
) -> None:
    """Settle a run that failed before reaching a terminal state.

    A rule rejection ends the run as rejected. Any other failure, including an
    interrupt or an internal error, leaves it incomplete so `cleanup` can remove
    the journaled resources and `release --resume` can continue where allowed.
    A run that already reached a terminal state is left alone.
    """
    state = workspace.load().state
    if state in {RunState.REJECTED, RunState.INCOMPLETE, RunState.PROMOTED}:
        return
    workspace.transition(
        RunState.REJECTED
        if isinstance(failure, RuleRejectionError)
        else RunState.INCOMPLETE,
        now=now,
    )


def hook_runner(
    runtime: ApplicationRuntime, repository: RepositoryConfig, workspace: RunWorkspace
) -> HookRunner:
    """Bind repository hooks to one run's isolated checkout and tool environment."""
    return HookRunner(
        runner=runtime.runner,
        environment=runtime.environment,
        source_root=repository.path.parent,
        log_directory=workspace.root / "logs",
    )


def create_source_run(
    *,
    source_root: Path,
    selector: str,
    image_id: str | None,
    version: str | None,
    state_home: Path,
    names: tuple[ToolName, ...],
    profile_name: str = "none",
    additional_inputs: dict[str, str] | None = None,
    id_factory: IdFactory | None = None,
    now: datetime | None = None,
) -> SourceRun:
    """Resolve a commit and create a detached, immutable-input-bound run."""
    created_at = now or utc_now()
    source_repository = source_root.resolve(strict=True)
    state_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".conclear-bootstrap-", dir=state_home
    ) as temporary:
        bootstrap = ApplicationRuntime.create(Path(temporary), names=(ToolName.GIT,))
        observation = bootstrap.git().observe(source_repository, selector)
        observed_source = normalize_observed_source_url(observation.remote_url)
        config_text = bootstrap.git().read_text(
            source_repository, observation.revision, "conclear.toml"
        )
    reserved_inputs = {
        "sourceRoot",
        "sourceRevision",
        "sourceRepository",
        "sourceTreeDigest",
        "image",
        "version",
        "profile",
    }
    additions = additional_inputs or {}
    conflicts = reserved_inputs & additions.keys()
    if conflicts:
        raise InvalidInvocationError(
            "Additional run inputs conflict: " + ", ".join(sorted(conflicts))
        )
    workspace = RunWorkspace.create(
        state_home=state_home,
        immutable_inputs={
            "sourceRoot": str(source_repository),
            "sourceRevision": observation.revision,
            "sourceRepository": observed_source,
            **({"image": image_id} if image_id is not None else {}),
            "version": version or "",
            "profile": profile_name,
            **additions,
        },
        id_factory=id_factory or UlidFactory(),
        now=created_at,
    )
    try:
        runtime = ApplicationRuntime.create(
            workspace.root / "environment", names=(ToolName.GIT,)
        )
        workspace.bind_immutable_inputs(
            {
                "configurationDigest": sha256_bytes(config_text.encode("utf-8")),
                **_tool_inputs(runtime),
            },
            now=created_at,
        )
        worktree = workspace.root / "source"
        workspace.journal.plan(
            resource_id="source-worktree",
            kind=ResourceKind.GIT_WORKTREE,
            identifier=str(worktree),
            ephemeral=True,
            metadata={"repository": str(source_repository)},
        )
        try:
            runtime.git().create_worktree(
                source_repository, worktree, observation.revision
            )
        except Exception:
            workspace.journal.update("source-worktree", ResourceStatus.FAILED)
            raise
        workspace.journal.update("source-worktree", ResourceStatus.CREATED)
        repository = load_repository_config(worktree / "conclear.toml")
        if sha256_bytes(repository.raw_bytes) != sha256_bytes(
            config_text.encode("utf-8")
        ):
            raise OperationalError("Checked-out configuration differs from Git object")
        if observed_source != repository.project.source:
            raise RuleRejectionError(
                "Observed Git origin differs from configured project source",
                code="CC0001",
            )
        image = repository.release_image(image_id)
        image.release.render_versions(version)
        runtime = ApplicationRuntime.create(
            workspace.root / "environment", names=_with_git(names)
        )
        workspace.bind_immutable_inputs(
            {
                "image": image.image_id,
                "sourceTreeDigest": source_tree_digest(worktree),
                **_tool_inputs(runtime),
            },
            now=created_at,
        )
    except BaseException as exc:
        # The run exists from here on, so the failure names it even though the
        # caller never receives the workspace.
        finish_run_failure(workspace, exc, now=created_at)
        bind_failed_run(exc, workspace.run_id)
        raise
    return SourceRun(
        workspace,
        repository,
        SourceIdentity(repository.project.source, observation.revision),
        observation.commit_time,
        runtime,
    )


def open_source_run(
    *,
    state_home: Path,
    run_id: str,
    names: tuple[ToolName, ...],
) -> SourceRun:
    """Reopen one run and revalidate checkout, configuration and tool identities.

    The phase resolves only the tools it executes. Each resolved identity must
    equal the one an earlier phase recorded; a tool used for the first time is
    bound now and held constant for the rest of the run.
    """
    workspace = RunWorkspace.open(state_home=state_home, run_id=run_id)
    snapshot = workspace.load()
    worktree = workspace.root / "source"
    try:
        worktree_stat = worktree.lstat()
    except OSError as exc:
        raise InvalidInvocationError(
            "Workspace source checkout is unavailable"
        ) from exc
    if stat.S_ISLNK(worktree_stat.st_mode) or not stat.S_ISDIR(worktree_stat.st_mode):
        raise InvalidInvocationError("Workspace source checkout is not a directory")
    source_entries = [
        entry
        for entry in workspace.journal.entries()
        if entry.resource_id == "source-worktree"
        and entry.kind is ResourceKind.GIT_WORKTREE
        and entry.status is ResourceStatus.CREATED
        and entry.identifier == str(worktree)
    ]
    if len(source_entries) != 1:
        raise InvalidInvocationError("Workspace source ownership is not established")
    repository = load_repository_config(worktree / "conclear.toml")
    configuration_digest = sha256_bytes(repository.raw_bytes)
    if snapshot.immutable_inputs.get("configurationDigest") != configuration_digest:
        raise InvalidInvocationError("Workspace repository configuration changed")
    if snapshot.immutable_inputs.get("sourceRepository") != repository.project.source:
        raise InvalidInvocationError("Workspace source repository identity changed")
    image_id = snapshot.immutable_inputs.get("image")
    if image_id is None:
        raise InvalidInvocationError("Workspace has no selected image")
    repository.release_image(image_id)
    runtime = ApplicationRuntime.create(
        workspace.root / "environment", names=_with_git(names)
    )
    observed_tools = _tool_inputs(runtime)
    for key, value in observed_tools.items():
        recorded = snapshot.immutable_inputs.get(key)
        if recorded is not None and recorded != value:
            raise InvalidInvocationError(f"Workspace tool identity changed: {key}")
    # A tool this phase uses for the first time is pinned from here on; tools
    # earlier phases recorded were compared above.
    workspace.bind_tool_identities(observed_tools)
    revision = snapshot.immutable_inputs.get("sourceRevision")
    if revision is None:
        raise InvalidInvocationError("Workspace has no source revision")
    observation = runtime.git().observe(worktree, "HEAD")
    if observation.revision != revision:
        raise InvalidInvocationError("Workspace source checkout changed")
    require_source_integrity(workspace, worktree)
    return SourceRun(
        workspace,
        repository,
        SourceIdentity(repository.project.source, revision),
        observation.commit_time,
        runtime,
    )


def _with_git(names: tuple[ToolName, ...]) -> tuple[ToolName, ...]:
    return tuple(dict.fromkeys((ToolName.GIT, *names)))


def _tool_inputs(runtime: ApplicationRuntime) -> dict[str, str]:
    return {
        f"tool.{tool.name.value}": f"{tool.version}@{tool.executable_digest}"
        for tool in runtime.tools.values()
    }
