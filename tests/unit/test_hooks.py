from pathlib import Path

import pytest

from conclear.config import HookConfig
from conclear.errors import InvalidInvocationError
from conclear.hooks import HookRunner, HookStatus
from conclear.process import CommandRequest, ProcessResult


class NoopRunner:
    def run(self, request: CommandRequest) -> ProcessResult:
        raise AssertionError(f"Unexpected hook: {request.argv}")


def _runner(root: Path) -> HookRunner:
    (root / "logs").mkdir(exist_ok=True)
    return HookRunner(
        runner=NoopRunner(),
        environment={"PATH": ""},
        source_root=root,
        log_directory=root / "logs",
    )


def test_an_absent_relative_hook_is_skipped_not_rejected(tmp_path: Path) -> None:
    root = tmp_path / "source"
    (root / "hooks").mkdir(parents=True)
    runner = _runner(root)

    optional = HookConfig("optional", ("hooks/absent.sh",), 60, required=False)
    required = HookConfig("required", ("hooks/absent.sh",), 60, required=True)

    for hook in (optional, required):
        observation = runner.run(hook, supplied_environment={})
        assert observation.status is HookStatus.SKIPPED
        assert observation.required is hook.required
        assert observation.executable is None


def test_a_relative_hook_cannot_leave_the_source_root(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    runner = _runner(root)

    with pytest.raises(InvalidInvocationError, match="unsafe component"):
        runner.run(
            HookConfig("escape", ("../outside.sh",), 60, required=False),
            supplied_environment={},
        )
