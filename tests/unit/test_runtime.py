import hashlib
from pathlib import Path

from conclear.process import ProcessRunner
from conclear.runtime import ApplicationRuntime
from conclear.tools import ResolvedTool, ToolName


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
