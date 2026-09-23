"""ConClear command hierarchy and process-boundary error mapping."""

import json
import logging
import sys
from collections.abc import Sequence
from typing import Any

import click

from conclear import narration
from conclear.commands.adopt import adopt_command
from conclear.commands.archive import archive_group
from conclear.commands.configuration import config_group
from conclear.commands.local import (
    assemble_command,
    build_command,
    check_command,
    qualify_command,
    test_command,
)
from conclear.commands.maintenance import (
    cleanup_command,
    doctor_command,
    pins_group,
    rescan_command,
)
from conclear.commands.remote import (
    attest_command,
    promote_command,
    provenance_command,
    publish_command,
    release_command,
    verify_command,
)
from conclear.commands.transport import transport_group
from conclear.commands.version import version_command, write_version
from conclear.errors import ConClearError, ExitStatus, failed_run_id
from conclear.presentation import CommandResult, Finding, ResultStatus

LOGGER = logging.getLogger(__name__)


def _version_callback(
    context: click.Context,
    _parameter: click.Parameter,
    value: bool,
) -> None:
    if not value or context.resilient_parsing:
        return
    write_version("human", sys.stdout)
    context.exit(ExitStatus.SUCCESS)


@click.group()
@click.option(
    "--version",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_version_callback,
    help="Show version and guide identity, then exit.",
)
@click.option(
    "quiet",
    "-q",
    "--quiet",
    is_flag=True,
    help="Keep the result on stdout and drop the progress from stderr.",
)
def root(quiet: bool) -> None:
    """Qualify and release OCI container images through verified digests.

    Standard output carries the result, standard error carries what the
    command is doing on the way. Errors are never dropped, quiet or not.
    """
    if quiet:
        narration.be_quiet()


root.add_command(version_command)
root.add_command(adopt_command)
root.add_command(archive_group)
root.add_command(config_group)
root.add_command(doctor_command)
root.add_command(check_command)
root.add_command(pins_group)
root.add_command(build_command)
root.add_command(test_command)
root.add_command(qualify_command)
root.add_command(transport_group)
root.add_command(assemble_command)
root.add_command(provenance_command)
root.add_command(publish_command)
root.add_command(attest_command)
root.add_command(verify_command)
root.add_command(promote_command)
root.add_command(release_command)
root.add_command(rescan_command)
root.add_command(cleanup_command)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Click application and map public failure categories."""
    arguments = list(argv) if argv is not None else sys.argv[1:]
    wants_json = _requests_json(arguments)
    with narration.to(sys.stderr):
        return _run(arguments, wants_json=wants_json)


def _run(arguments: list[str], *, wants_json: bool) -> int:
    try:
        result: Any = root.main(
            args=arguments,
            prog_name="conclear",
            standalone_mode=False,
        )
    except click.ClickException as exc:
        exc.show(file=sys.stderr)
        data = _failed_run_data(exc)
        if wants_json:
            _write_error_json(
                command=_command_name(arguments),
                status=ResultStatus.INVALID_INVOCATION,
                message=exc.format_message(),
                data=data,
            )
        return int(ExitStatus.INVALID_INVOCATION)
    except click.Abort as exc:
        LOGGER.error("Aborted.")
        data = _failed_run_data(exc)
        if wants_json:
            _write_error_json(
                command=_command_name(arguments),
                status=ResultStatus.OPERATIONAL_FAILURE,
                message="Operation was interrupted",
                data=data,
            )
        return int(ExitStatus.OPERATIONAL_FAILURE)
    except ConClearError as exc:
        findings = _error_findings(exc)
        if findings:
            for finding in findings:
                where = f" ({finding.location})" if finding.location else ""
                narration.verbatim(
                    LOGGER,
                    logging.ERROR,
                    f"{finding.check_id} {finding.severity}: {finding.message}{where}",
                )
        else:
            LOGGER.error("%s", exc)
        data = _failed_run_data(exc)
        if wants_json:
            status = ResultStatus(exc.error_type)
            _write_error_json(
                command=_command_name(arguments),
                status=status,
                message=str(exc),
                findings=findings,
                data=data,
            )
        return int(exc.exit_status)
    except Exception as exc:
        data = _failed_run_data(exc)
        if not wants_json:
            raise
        message = "ConClear encountered an internal error"
        LOGGER.debug(
            "%s (%s); traceback: %s",
            message,
            type(exc).__name__,
            _traceback_locations(exc),
        )
        LOGGER.error("%s (%s)", message, type(exc).__name__)
        _write_error_json(
            command=_command_name(arguments),
            status=ResultStatus.OPERATIONAL_FAILURE,
            message=message,
            data=data,
        )
        return int(ExitStatus.OPERATIONAL_FAILURE)
    return int(result) if isinstance(result, int) else int(ExitStatus.SUCCESS)


def _error_findings(exc: ConClearError) -> tuple[Finding, ...]:
    """Return the concrete findings behind a failure, or its summary as one."""
    if exc.findings:
        return exc.findings
    if exc.code is not None:
        return (Finding(exc.code, "error", str(exc)),)
    return ()


def _failed_run_data(failure: BaseException) -> dict[str, object]:
    """Report the run a failing command created so its resources can be found."""
    run_id = failed_run_id(failure)
    if run_id is None:
        return {}
    narration.verbatim(
        LOGGER,
        logging.ERROR,
        f"Run {run_id} keeps its journaled resources; remove them with: "
        f"conclear cleanup {run_id}",
    )
    return {"runId": run_id}


def _requests_json(arguments: Sequence[str]) -> bool:
    return any(
        argument == "--format=json"
        or (argument == "json" and index > 0 and arguments[index - 1] == "--format")
        for index, argument in enumerate(arguments)
    )


def _command_name(arguments: Sequence[str]) -> str:
    return next(
        (argument for argument in arguments if not argument.startswith("-")), "root"
    )


def _traceback_locations(exc: Exception) -> str:
    """Return traceback locations without exception values or source text."""
    locations: list[str] = []
    traceback = exc.__traceback__
    while traceback is not None:
        code = traceback.tb_frame.f_code
        locations.append(f"{code.co_filename}:{traceback.tb_lineno} in {code.co_name}")
        traceback = traceback.tb_next
    return " <- ".join(locations)


def _write_error_json(
    *,
    command: str,
    status: ResultStatus,
    message: str,
    findings: tuple[Finding, ...] = (),
    data: dict[str, object] | None = None,
) -> None:
    result = CommandResult(
        command=command,
        status=status,
        message=message,
        findings=findings,
        data=dict(data or {}),
    )
    json.dump(result.to_dict(), sys.stdout, ensure_ascii=True, sort_keys=True)
    sys.stdout.write("\n")
