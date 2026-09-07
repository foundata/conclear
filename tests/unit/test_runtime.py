import hashlib
from pathlib import Path
from typing import cast

import pytest

from conclear.errors import OperationalError, RuleRejectionError
from conclear.process import ProcessRunner
from conclear.runtime import ApplicationRuntime
from conclear.tools import ResolvedTool, ToolName, ToolResolver


def test_runtime_reuses_adapter_instances_for_monotonic_evidence_logs(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "git"
    executable.write_bytes(b"test executable")
    executable.chmod(0o700)
    runtime = ApplicationRuntime(
        root=tmp_path,
        environment={"PATH": "/usr/bin", "HOME": str(tmp_path)},
        runner=ProcessRunner(),
        tools={
            ToolName.GIT: ResolvedTool(
                name=ToolName.GIT,
                path=executable,
                version="test",
                executable_digest="sha256:"
                + hashlib.sha256(b"test executable").hexdigest(),
                reported_version="test",
            )
        },
    )

    assert runtime.git() is runtime.git()


class _Resolver:
    """Resolve fake tools; fail the ones named in `broken`."""

    def __init__(self, broken: dict[ToolName, Exception], root: Path) -> None:
        self.broken = broken
        self.root = root
        self.requested: list[ToolName] = []

    def resolve(self, name: ToolName, *, environment: dict[str, str]) -> ResolvedTool:
        self.requested.append(name)
        failure = self.broken.get(name)
        if failure is not None:
            raise failure
        executable = self.root / name.value
        executable.write_bytes(name.value.encode())
        return ResolvedTool(
            name=name,
            path=executable,
            version="1.0.0",
            executable_digest="sha256:"
            + hashlib.sha256(name.value.encode()).hexdigest(),
            reported_version="1.0.0",
        )

    def resolve_all(
        self, *, environment: dict[str, str], names: tuple[ToolName, ...]
    ) -> tuple[ResolvedTool, ...]:
        return tuple(self.resolve(name, environment=environment) for name in names)


def test_create_resolves_exactly_the_requested_tools(tmp_path: Path) -> None:
    resolver = _Resolver({}, tmp_path)

    runtime = ApplicationRuntime.create(
        tmp_path / "environment",
        names=(ToolName.GIT, ToolName.SKOPEO),
        resolver=cast(ToolResolver, resolver),
    )

    assert resolver.requested == [ToolName.GIT, ToolName.SKOPEO]
    assert tuple(runtime.tools) == (ToolName.GIT, ToolName.SKOPEO)
    assert [item.name for item in runtime.identities] == ["git", "skopeo"]
    with pytest.raises(OperationalError, match="did not resolve cosign"):
        runtime.cosign()


def test_diagnose_reports_every_failure_and_keeps_resolved_tools(
    tmp_path: Path,
) -> None:
    resolver = _Resolver(
        {
            ToolName.COSIGN: OperationalError("Required tool is unavailable: cosign"),
            ToolName.TRIVY: RuleRejectionError(
                "Unsupported trivy version 0.1.0; supported: 0.69.3", code="CC0301"
            ),
        },
        tmp_path,
    )

    runtime, problems = ApplicationRuntime.diagnose(
        tmp_path / "environment",
        names=(ToolName.GIT, ToolName.TRIVY, ToolName.COSIGN, ToolName.GIT),
        resolver=cast(ToolResolver, resolver),
    )

    assert resolver.requested == [ToolName.GIT, ToolName.TRIVY, ToolName.COSIGN]
    assert tuple(runtime.tools) == (ToolName.GIT,)
    assert [problem.message for problem in problems] == [
        "trivy: Unsupported trivy version 0.1.0; supported: 0.69.3",
        "cosign: Required tool is unavailable: cosign",
    ]
    assert isinstance(problems[0].failure, RuleRejectionError)
