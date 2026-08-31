"""ConClear command hierarchy and process-boundary error mapping."""

import json
import logging
import sys
from collections.abc import Sequence
from typing import Any

import click

from conclear.commands.local import (
    assemble_command,
    build_command,
    check_command,
    evidence_command,
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
from conclear.commands.version import version_command, write_version
from conclear.errors import ConClearError, ExitStatus, RuleRejectionError
from conclear.presentation import CommandResult, Finding, ResultStatus


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
def root() -> None:
    """Qualify and release OCI container images through verified digests."""


root.add_command(version_command)
root.add_command(doctor_command)
root.add_command(check_command)
root.add_command(pins_group)
root.add_command(build_command)
root.add_command(test_command)
root.add_command(evidence_command)
root.add_command(qualify_command)
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
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    try:
        result: Any = root.main(
            args=arguments,
            prog_name="conclear",
            standalone_mode=False,
        )
    except click.ClickException as exc:
        exc.show(file=sys.stderr)
        if wants_json:
            _write_error_json(
                command=_command_name(arguments),
                status=ResultStatus.INVALID_INVOCATION,
                message=exc.format_message(),
            )
        return int(ExitStatus.INVALID_INVOCATION)
    except click.Abort:
        print("Aborted.", file=sys.stderr)
        if wants_json:
            _write_error_json(
                command=_command_name(arguments),
                status=ResultStatus.OPERATIONAL_FAILURE,
                message="Operation was interrupted",
            )
        return int(ExitStatus.OPERATIONAL_FAILURE)
    except ConClearError as exc:
        finding = (
            Finding(exc.code, "error", str(exc))
            if isinstance(exc, RuleRejectionError) and exc.code is not None
            else None
        )
        diagnostic = (
            f"{finding.check_id} {finding.severity}: {finding.message}"
            if finding is not None
            else str(exc)
        )
        print(diagnostic, file=sys.stderr)
        if wants_json:
            status = ResultStatus(exc.error_type)
            _write_error_json(
                command=_command_name(arguments),
                status=status,
                message=str(exc),
                findings=(() if finding is None else (finding,)),
            )
        return int(exc.exit_status)
    except Exception as exc:
        message = "ConClear encountered an internal error"
        print(f"{message} ({type(exc).__name__})", file=sys.stderr)
        if wants_json:
            _write_error_json(
                command=_command_name(arguments),
                status=ResultStatus.OPERATIONAL_FAILURE,
                message=message,
            )
        return int(ExitStatus.OPERATIONAL_FAILURE)
    return int(result) if isinstance(result, int) else int(ExitStatus.SUCCESS)


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


def _write_error_json(
    *,
    command: str,
    status: ResultStatus,
    message: str,
    findings: tuple[Finding, ...] = (),
) -> None:
    result = CommandResult(
        command=command,
        status=status,
        message=message,
        findings=findings,
    )
    json.dump(result.to_dict(), sys.stdout, ensure_ascii=True, sort_keys=True)
    sys.stdout.write("\n")
