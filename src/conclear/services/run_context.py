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
from conclear.release_profile import origin_is_allowed
from conclear.runtime import ApplicationRuntime
from conclear.source_integrity import require_source_integrity, source_tree_digest
from conclear.tools import ToolName
from conclear.workspace import (
    TERMINAL_STATES,
    IdFactory,
    ResourceKind,
    ResourceStatus,
    RunState,
    RunWorkspace,
    UlidFactory,
)


@dataclass(frozen=True, slots=True)
class SourceRun:
    """One detached source checkout with validated configuration and tools.

    `origin` is the normalized HTTPS Git origin of the checkout. It exists only
    to compare against release-profile policy and CI context in memory; no
    record, attestation, label or result may carry it.
    """

    workspace: RunWorkspace
    repository: RepositoryConfig
    source: SourceIdentity
    source_time: datetime
    runtime: ApplicationRuntime
    origin: str


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
    if state is RunState.INCOMPLETE or state in TERMINAL_STATES:
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
    allowed_origins: tuple[str, ...] | None = None,
    id_factory: IdFactory | None = None,
    now: datetime | None = None,
) -> SourceRun:
    """Resolve a commit and create a detached, immutable-input-bound run.

    `allowed_origins` is the release profile's origin allowlist. When it is
    given, the checkout's Git origin must fall under one prefix before any run
    exists; without a profile no origin policy applies.
    """
    created_at = now or utc_now()
    source_repository = source_root.resolve(strict=True)
    state_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".conclear-bootstrap-", dir=state_home
    ) as temporary:
        bootstrap = ApplicationRuntime.create(Path(temporary), names=(ToolName.GIT,))
        observation = bootstrap.git().observe(source_repository, selector)
        origin = normalize_observed_source_url(observation.remote_url)
        _require_allowed_origin(origin, allowed_origins)
        config_text = bootstrap.git().read_text(
            source_repository, observation.revision, "conclear.toml"
        )
    reserved_inputs = {
        "sourceRoot",
        "sourceRevision",
        "projectSource",
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
            workspace.root / "environment",
            names=(ToolName.GIT,),
            journal=workspace.journal,
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
        image = repository.release_image(image_id)
        image.release.render_versions(version)
        runtime = ApplicationRuntime.create(
            workspace.root / "environment",
            names=_with_git(names),
            journal=workspace.journal,
        )
        workspace.bind_immutable_inputs(
            {
                "image": image.image_id,
                # The declared public source URL is public by definition and
                # lets transported records be checked against the run.
                "projectSource": repository.project.source,
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
        origin=origin,
    )


def open_source_run(
    *,
    state_home: Path,
    run_id: str,
    names: tuple[ToolName, ...],
    allowed_origins: tuple[str, ...] | None = None,
) -> SourceRun:
    """Reopen one run and revalidate checkout, configuration and tool identities.

    The phase resolves only the tools it executes. Each resolved identity must
    equal the one an earlier phase recorded; a tool used for the first time is
    bound now and held constant for the rest of the run. A phase that runs with
    a release profile also re-applies the profile's origin allowlist.
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
    image_id = snapshot.immutable_inputs.get("image")
    if image_id is None:
        raise InvalidInvocationError("Workspace has no selected image")
    repository.release_image(image_id)
    runtime = ApplicationRuntime.create(
        workspace.root / "environment",
        names=_with_git(names),
        journal=workspace.journal,
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
    origin = normalize_observed_source_url(observation.remote_url)
    _require_allowed_origin(origin, allowed_origins)
    require_source_integrity(workspace, worktree)
    return SourceRun(
        workspace,
        repository,
        SourceIdentity(repository.project.source, revision),
        observation.commit_time,
        runtime,
        origin=origin,
    )


def _require_allowed_origin(origin: str, allowed: tuple[str, ...] | None) -> None:
    """Reject a checkout whose Git origin the release profile does not allow.

    The message names neither the origin nor the allowlist: both may identify
    internal hosts, and rejection messages end up in command results.
    """
    if allowed is not None and not origin_is_allowed(origin, allowed):
        raise RuleRejectionError(
            "Observed Git origin matches no allowed source origin in the release profile",
            code="CC0004",
        )


def _with_git(names: tuple[ToolName, ...]) -> tuple[ToolName, ...]:
    return tuple(dict.fromkeys((ToolName.GIT, *names)))


def _tool_inputs(runtime: ApplicationRuntime) -> dict[str, str]:
    return {
        f"tool.{tool.name.value}": f"{tool.version}@{tool.executable_digest}"
        for tool in runtime.tools.values()
    }
