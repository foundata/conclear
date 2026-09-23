"""What the tool says while it works.

A qualification or release is minutes of container work whose outcome is
consequential, so the person running one should see what is happening: which
phase is under way, which external command really ran, and what was decided
in between. That narration is also the audit trail when nobody watched.

Result data goes to standard output and this narration to standard error. It
is ordinary ``logging`` at INFO level from each module's logger; nothing here
is a second channel. A command-line entry point installs the one handler
that renders those records, so library callers and evidence stay silent, and
no narrated line can enter a record, an archive or anything that is hashed.
"""

import logging
import os
import shlex
import sys
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO, override

# Weight carries hierarchy and hue carries meaning: the dim marker locates a
# line, the bold `$` marks an external command that really ran, and colour is
# spent only on the verb and the Error:/WARNING: prefixes. Prose is never
# recoloured, so it reads on a light and a dark terminal alike.
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"

# Every narrated line starts with one of these, so a reader scans the first
# word of each line and knows what happened. A participle is work in progress,
# a past tense is work that is done, and "Would" is work that was declined.
VERBS = frozenset(
    {
        "Assembling",
        "Attesting",
        "Building",
        "Checked",
        "Checking",
        "Imported",
        "Promoting",
        "Publishing",
        "Qualifying",
        "Recorded",
        "Removing",
        "Rescanning",
        "Retained",
        "Retrying",
        "Running",
        "Scanning",
        "Testing",
        "Verified",
        "Verifying",
        "Would",
        "Wrote",
    }
)

COMMAND = "conclear_command"
"""Record attribute marking the echo of an external command that ran."""

VERBATIM = "conclear_verbatim"
"""Record attribute for a diagnostic that carries its own labelling."""


def wants_colour(stream: TextIO, environ: Mapping[str, str] | None = None) -> bool:
    """Whether ``stream`` should carry ANSI styling.

    Redirected output is the record of a run and stays plain, so the terminal
    decides by default. ``NO_COLOR`` suppresses styling and wins over
    ``FORCE_COLOR``, which demands it where no terminal is detected, such as a
    CI log viewer; ``TERM=dumb`` declines it.
    """
    env = os.environ if environ is None else environ
    if env.get("NO_COLOR"):
        return False
    if env.get("FORCE_COLOR"):
        return True
    if env.get("TERM") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def program(path: str) -> str:
    """The name to show for an executable: what a reader would type."""
    return Path(path).name


def render(argv: Sequence[str]) -> str:
    """Quote an argument list the way a shell expects it.

    The first element is a resolved absolute path, because every program is
    located before it runs; the line is for a reader and stays runnable with
    the plain name, since that is where it was found.
    """
    return shlex.join([program(argv[0]), *(str(argument) for argument in argv[1:])])


class StoryHandler(logging.Handler):
    """Renders the narration, one line per record, to one stream.

    INFO records are phases and are written verb first, the verb carrying the
    colour; a record flagged ``COMMAND`` is an echoed command line; WARNING
    and ERROR records get their prefix and are never dropped by ``--quiet``.
    """

    def __init__(self, stream: TextIO, *, colour: bool | None = None) -> None:
        """Render to ``stream``; by default the stream decides on colour."""
        super().__init__(level=logging.INFO)
        self.stream = stream
        self._colour = wants_colour(stream) if colour is None else colour

    @override
    def emit(self, record: logging.LogRecord) -> None:
        """Write one rendered line."""
        try:
            self.stream.write(self.render(record) + "\n")
            self.stream.flush()
        except Exception:  # logging must never fail the command it narrates
            self.handleError(record)

    def render(self, record: logging.LogRecord) -> str:
        """Return the line for one record, styled when the stream allows."""
        message = record.getMessage()
        if getattr(record, VERBATIM, False):
            return message
        if record.levelno >= logging.ERROR:
            return f"{self._style('Error:', _RED + _BOLD)} {message}"
        if record.levelno >= logging.WARNING:
            return f"{self._style('WARNING:', _YELLOW)} {message}"
        if getattr(record, COMMAND, False):
            return f"{self._style('$', _BOLD)} {message}"
        word, separator, rest = message.partition(" ")
        hue = _YELLOW if word == "Would" else _GREEN
        return f"{self._style('»', _DIM)} {self._style(word, hue)}{separator}{rest}"

    def _style(self, text: str, style: str) -> str:
        return f"{style}{text}{_RESET}" if self._colour else text


_previous_root_level: int | None = None


def install(stream: TextIO | None = None, *, quiet: bool = False) -> StoryHandler:
    """Route the narration to ``stream`` until ``uninstall``; entry points call it.

    Replaces any handler a previous call installed, so a stream captured by a
    test or replaced by a caller is the one written to. ``quiet`` keeps
    stdout and drops the narration: warnings and errors still get through.
    The root logger is lowered to INFO so those records reach the handler at
    all.
    """
    global _previous_root_level
    uninstall()
    handler = StoryHandler(sys.stderr if stream is None else stream)
    if quiet:
        handler.setLevel(logging.WARNING)
    root = logging.getLogger()
    root.addHandler(handler)
    if root.level == logging.NOTSET or root.level > logging.INFO:
        _previous_root_level = root.level
        root.setLevel(logging.INFO)
    return handler


def uninstall() -> None:
    """Remove every story handler and restore the root level; INFO falls silent."""
    global _previous_root_level
    root = logging.getLogger()
    for handler in [item for item in root.handlers if isinstance(item, StoryHandler)]:
        root.removeHandler(handler)
        handler.close()
    if _previous_root_level is not None:
        root.setLevel(_previous_root_level)
        _previous_root_level = None


@contextmanager
def story(stream: TextIO | None = None, *, quiet: bool = False) -> Iterator[None]:
    """Narrate to ``stream`` for one command, then fall silent again.

    A handler left behind would write into a stream that no longer exists, so
    the entry point scopes it to the command it narrates.
    """
    install(stream, quiet=quiet)
    try:
        yield
    finally:
        uninstall()


def be_quiet() -> None:
    """Drop the narration from every installed handler; errors keep flowing."""
    for handler in logging.getLogger().handlers:
        if isinstance(handler, StoryHandler):
            handler.setLevel(logging.WARNING)


def command(
    logger: logging.Logger, argv: Sequence[str], *, cwd: Path | None = None
) -> None:
    """Narrate an external command, verbatim enough to paste.

    ``argv`` must already be redacted; this echoes what it is given. A command
    running outside the reader's assumed directory is preceded by where it ran,
    because the echoed line would otherwise not reproduce.
    """
    if cwd is not None:
        logger.info("Running in %s", cwd)
    logger.info("%s", render(argv), extra={COMMAND: True})


def verbatim(logger: logging.Logger, level: int, message: str) -> None:
    """Emit a diagnostic that carries its own labelling, without a prefix."""
    logger.log(level, "%s", message, extra={VERBATIM: True})
