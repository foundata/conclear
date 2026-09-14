"""Git source-selection adapter."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from conclear.adapters.base import ToolAdapter
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.process import OperationKind
from conclear.values import validate_source_revision


@dataclass(frozen=True, slots=True)
class SourceObservation:
    """Source facts observed from the selected Git commit."""

    revision: str
    remote_url: str
    commit_time: datetime


class GitAdapter(ToolAdapter):
    """Resolve source identity and manage detached worktrees."""

    def observe(self, repository: Path, selector: str) -> SourceObservation:
        """Resolve a selector and observe source facts from Git itself."""
        revision_result = self._run(
            ("-C", str(repository), "rev-parse", "--verify", f"{selector}^{{commit}}"),
            timeout_seconds=30,
        )
        revision = validate_source_revision(revision_result.stdout.strip())
        remote = self._run(
            ("-C", str(repository), "remote", "get-url", "origin"),
            timeout_seconds=30,
        ).stdout.strip()
        if not remote:
            raise OperationalError("Git origin URL is empty")
        timestamp_text = self._run(
            ("-C", str(repository), "show", "-s", "--format=%ct", revision),
            timeout_seconds=30,
        ).stdout.strip()
        try:
            timestamp = int(timestamp_text)
            commit_time = datetime.fromtimestamp(timestamp, tz=UTC)
        except (ValueError, OverflowError, OSError) as exc:
            raise OperationalError("Git returned an invalid commit timestamp") from exc
        return SourceObservation(revision, remote, commit_time)

    def tags_at(self, repository: Path, revision: str) -> tuple[str, ...]:
        """Return the tags that point at a revision, sorted."""
        output = self._run(
            ("-C", str(repository), "tag", "--points-at", revision),
            timeout_seconds=30,
        ).stdout
        return tuple(
            sorted(line.strip() for line in output.splitlines() if line.strip())
        )

    def create_worktree(
        self, repository: Path, destination: Path, revision: str
    ) -> None:
        """Create an isolated detached checkout of an observed commit."""
        validate_source_revision(revision)
        self._run(
            (
                "-C",
                str(repository),
                "worktree",
                "add",
                "--detach",
                str(destination),
                revision,
            ),
            timeout_seconds=120,
            operation=OperationKind.WRITE,
        )

    def export_index(self, worktree: Path, destination: Path) -> None:
        """Export the tracked tree of a detached checkout into a new directory.

        `checkout-index` writes exactly the index entries, which in a detached
        worktree are the selected commit's tree: no untracked or ignored files,
        the same filters and modes as the checkout itself.
        """
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        self._run(
            (
                "-C",
                str(worktree),
                "checkout-index",
                "--all",
                "--force",
                f"--prefix={destination}/",
            ),
            timeout_seconds=300,
            operation=OperationKind.WRITE,
        )

    def read_text(self, repository: Path, revision: str, relative_path: str) -> str:
        """Read one UTF-8 repository file from an observed commit without checkout."""
        validate_source_revision(revision)
        if (
            not relative_path
            or relative_path.startswith("/")
            or ".." in Path(relative_path).parts
            or "\\" in relative_path
        ):
            raise InvalidInvocationError("Git object path must be a safe relative path")
        return self._run(
            ("-C", str(repository), "show", f"{revision}:{relative_path}"),
            timeout_seconds=30,
        ).stdout

    def remove_worktree(self, repository: Path, destination: Path) -> None:
        """Remove one run-owned worktree without affecting the ordinary checkout."""
        self._run(
            (
                "-C",
                str(repository),
                "worktree",
                "remove",
                "--force",
                str(destination),
            ),
            timeout_seconds=120,
            operation=OperationKind.WRITE,
        )
