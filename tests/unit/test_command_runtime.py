"""A command-scoped runtime releases its tool images before its directory goes."""

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import conclear.commands.common as common


class _Runtime:
    def __init__(self) -> None:
        self.released = 0

    def release_tool_images(self) -> None:
        self.released += 1


def test_command_runtime_releases_tool_images_even_when_the_command_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    fake = _Runtime()
    monkeypatch.setattr(
        common,
        "ApplicationRuntime",
        SimpleNamespace(
            create=lambda root, names: fake,
            diagnose=lambda root, names: (fake, ()),
        ),
    )

    with common.command_runtime(()) as runtime:
        assert cast(object, runtime) is fake
    assert fake.released == 1

    with pytest.raises(RuntimeError, match="boom"):
        with common.command_runtime(()):
            raise RuntimeError("boom")
    assert fake.released == 2

    with common.diagnostic_runtime(()) as (runtime, problems):
        assert cast(object, runtime) is fake
        assert problems == ()
    assert fake.released == 3
