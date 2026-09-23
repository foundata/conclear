"""Stdout is the product, stderr is the story: how the story is rendered."""

import ast
import io
import logging
from pathlib import Path
from typing import override

import pytest

from conclear import narration

SOURCE = Path(narration.__file__).parent


class Terminal(io.StringIO):
    """A stream that claims to be a terminal."""

    @override
    def isatty(self) -> bool:
        return True


class Closed(io.StringIO):
    """A stream that refuses the question, as a closed file does."""

    @override
    def isatty(self) -> bool:
        raise ValueError("I/O operation on closed file")


def _info_openings() -> list[tuple[str, int, str]]:
    """The first word of every INFO message a module logger can emit.

    A ``%s``-only message is an echo of something computed, such as a command
    line, and carries no verb of its own.
    """
    found: list[tuple[str, int, str]] = []
    for path in sorted(SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "info"
                and node.args
            ):
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                word = first.value.split(" ")[0]
                if not word.startswith("%"):
                    found.append((str(path.relative_to(SOURCE)), node.lineno, word))
    return found


def test_every_narrated_line_starts_with_a_known_verb() -> None:
    # The colour is applied by position, and a reader scans the first word of
    # each line, so the vocabulary is closed on purpose.
    openings = _info_openings()

    assert openings, "the source scan found no narrated line"
    unknown = [
        f"{name}:{line}: {word!r}"
        for name, line, word in openings
        if word not in narration.VERBS
    ]
    assert not unknown, "not in narration.VERBS: " + ", ".join(unknown)


@pytest.mark.parametrize(
    ("stream", "environ", "expected"),
    [
        (Terminal(), {}, True),
        (Terminal(), {"NO_COLOR": "1"}, False),
        (Terminal(), {"TERM": "dumb"}, False),
        (Terminal(), {"NO_COLOR": "1", "FORCE_COLOR": "1"}, False),
        (Terminal(), {"NO_COLOR": ""}, True),
        (io.StringIO(), {}, False),
        (io.StringIO(), {"FORCE_COLOR": "1"}, True),
        (Closed(), {}, False),
    ],
    ids=[
        "terminal",
        "no-color",
        "dumb-terminal",
        "no-color-wins",
        "empty-no-color-is-unset",
        "redirected",
        "forced",
        "closed",
    ],
)
def test_colour_follows_the_stream_and_the_conventional_variables(
    stream: io.StringIO, environ: dict[str, str], expected: bool
) -> None:
    # A redirected story is the record of a run; escape sequences in it would
    # be noise in the record.
    assert narration.wants_colour(stream, environ) is expected


def _record(level: int, message: str, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord("conclear.test", level, __file__, 1, message, (), None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_a_coloured_line_paints_the_marker_the_verb_and_the_prefix_only() -> None:
    handler = narration.StoryHandler(io.StringIO(), colour=True)

    assert handler.render(_record(logging.INFO, "Building app for linux/amd64")) == (
        "\033[2m»\033[0m \033[32mBuilding\033[0m app for linux/amd64"
    )
    assert handler.render(_record(logging.INFO, "Would run: uv build")) == (
        "\033[2m»\033[0m \033[33mWould\033[0m run: uv build"
    )
    assert handler.render(
        _record(logging.INFO, "podman info", **{narration.COMMAND: True})
    ) == ("\033[1m$\033[0m podman info")
    assert handler.render(_record(logging.WARNING, "cache is stale")) == (
        "\033[33mWARNING:\033[0m cache is stale"
    )
    assert handler.render(_record(logging.ERROR, "no such run")) == (
        "\033[31m\033[1mError:\033[0m no such run"
    )


def test_without_colour_the_line_is_exactly_the_plain_text() -> None:
    # Everything that reads this output through a pipe, including the whole
    # test suite, must see no escape sequence at all.
    handler = narration.StoryHandler(io.StringIO(), colour=False)

    assert handler.render(_record(logging.INFO, "Recorded qualification")) == (
        "» Recorded qualification"
    )
    assert handler.render(
        _record(logging.INFO, "git status", **{narration.COMMAND: True})
    ) == ("$ git status")
    assert handler.render(_record(logging.ERROR, "failed")) == "Error: failed"
    assert handler.render(
        _record(logging.ERROR, "CC0107 error: rejected", **{narration.VERBATIM: True})
    ) == ("CC0107 error: rejected")


def test_a_command_line_names_the_program_and_quotes_for_the_shell() -> None:
    # The program was found in PATH, so its plain name is what belongs on
    # screen; the line stays runnable.
    assert narration.program("/usr/bin/podman") == "podman"
    assert narration.render(["/usr/bin/git", "tag", "-m", "version 1.0.0"]) == (
        "git tag -m 'version 1.0.0'"
    )


def test_the_installed_handler_tells_the_story_and_quiet_keeps_the_errors() -> None:
    stream = io.StringIO()
    logger = logging.getLogger("conclear.test.story")
    try:
        narration.install(stream)
        logger.info("Checking %s", "pins")
        narration.command(logger, ["/usr/bin/skopeo", "inspect", "x"], cwd=Path("/w"))
        logger.warning("registry answered slowly")

        narration.be_quiet()
        logger.info("Building app")
        logger.error("no such run")
        narration.verbatim(logger, logging.ERROR, "CC0107 error: rejected")
    finally:
        narration.uninstall()
    logger.info("Building app again")

    assert stream.getvalue() == (
        "» Checking pins\n"
        "» Running in /w\n"
        "$ skopeo inspect x\n"
        "WARNING: registry answered slowly\n"
        "Error: no such run\n"
        "CC0107 error: rejected\n"
    )


def test_installing_again_replaces_the_previous_stream() -> None:
    first, second = io.StringIO(), io.StringIO()
    logger = logging.getLogger("conclear.test.replace")
    try:
        narration.install(first)
        narration.install(second)
        logger.info("Checking %s", "once")
    finally:
        narration.uninstall()

    assert first.getvalue() == ""
    assert second.getvalue() == "» Checking once\n"
    assert not [
        item
        for item in logging.getLogger().handlers
        if isinstance(item, narration.StoryHandler)
    ]


def test_the_story_is_scoped_to_one_command_and_restores_the_root_level() -> None:
    # A handler left behind would write into a stream that no longer exists.
    root_logger = logging.getLogger()
    before = root_logger.level
    stream = io.StringIO()
    logger = logging.getLogger("conclear.test.scoped")

    with narration.story(stream):
        assert root_logger.level == logging.INFO
        logger.info("Checking %s", "inside")
    logger.info("Checking %s", "outside")

    assert stream.getvalue() == "» Checking inside\n"
    assert root_logger.level == before
    assert not [
        item
        for item in root_logger.handlers
        if isinstance(item, narration.StoryHandler)
    ]
