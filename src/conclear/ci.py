"""Runtime validation of protected CI identity observations."""

import re
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlparse

from conclear.config import normalize_source_url
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import atomic_write_json
from conclear.records import SourceIdentity
from conclear.values import validate_source_revision

PUBLIC_CI_SERVERS = frozenset({"https://github.com", "https://gitlab.com"})


def observe_ci_identity(environment: Mapping[str, str]) -> dict[str, object]:
    """Return a narrow validated identity for a supported protected CI provider."""
    if environment.get("GITHUB_ACTIONS") == "true":
        server = _https_url(environment.get("GITHUB_SERVER_URL"), "GitHub server")
        repository = _name(environment.get("GITHUB_REPOSITORY"), "GitHub repository")
        workflow = _name(environment.get("GITHUB_WORKFLOW_REF"), "GitHub workflow")
        run_id = _digits(environment.get("GITHUB_RUN_ID"), "GitHub run id")
        revision = validate_source_revision(
            _name(environment.get("GITHUB_SHA"), "GitHub revision")
        )
        return {
            "provider": "github-actions",
            "server": server,
            "repository": repository,
            "workflow": workflow,
            "runId": run_id,
            "revision": revision,
        }
    if environment.get("GITLAB_CI") == "true":
        server = _https_url(environment.get("CI_SERVER_URL"), "GitLab server")
        project = _name(environment.get("CI_PROJECT_PATH"), "GitLab project")
        pipeline = _digits(environment.get("CI_PIPELINE_ID"), "GitLab pipeline id")
        job = _digits(environment.get("CI_JOB_ID"), "GitLab job id")
        revision = validate_source_revision(
            _name(environment.get("CI_COMMIT_SHA"), "GitLab revision")
        )
        return {
            "provider": "gitlab-ci",
            "server": server,
            "repository": project,
            "pipelineId": pipeline,
            "jobId": job,
            "revision": revision,
        }
    raise InvalidInvocationError("CI release mode requires a supported CI identity")


def validate_ci_identity(
    identity: Mapping[str, object],
    source: SourceIdentity,
    *,
    diagnostic_path: Path | None = None,
) -> dict[str, object]:
    """Bind CI metadata to the checkout and return its public representation."""
    provider = identity.get("provider")
    result: dict[str, object]
    if provider == "github-actions":
        expected_keys = {
            "provider",
            "server",
            "repository",
            "workflow",
            "runId",
            "revision",
        }
        server = _https_url(_optional_string(identity.get("server")), "GitHub server")
        repository = _name(
            _optional_string(identity.get("repository")), "GitHub repository"
        )
        workflow = _name(_optional_string(identity.get("workflow")), "GitHub workflow")
        run_id = _digits(_optional_string(identity.get("runId")), "GitHub run id")
        if not workflow.startswith(f"{repository}/.github/workflows/"):
            raise OperationalError(
                "GitHub workflow identity differs from its claimed repository"
            )
        result = {
            "provider": provider,
            "server": server,
            "repository": repository,
            "workflow": workflow,
            "runId": run_id,
            "revision": _revision(identity.get("revision")),
        }
    elif provider == "gitlab-ci":
        expected_keys = {
            "provider",
            "server",
            "repository",
            "pipelineId",
            "jobId",
            "revision",
        }
        server = _https_url(_optional_string(identity.get("server")), "GitLab server")
        repository = _name(
            _optional_string(identity.get("repository")), "GitLab project"
        )
        result = {
            "provider": provider,
            "server": server,
            "repository": repository,
            "pipelineId": _digits(
                _optional_string(identity.get("pipelineId")), "GitLab pipeline id"
            ),
            "jobId": _digits(_optional_string(identity.get("jobId")), "GitLab job id"),
            "revision": _revision(identity.get("revision")),
        }
    else:
        raise OperationalError("Observed CI provider is unsupported")
    if set(identity) != expected_keys:
        raise OperationalError("Observed CI identity fields are malformed")
    try:
        claimed_source = normalize_source_url(f"{server}/{repository}")
    except InvalidInvocationError as exc:
        raise OperationalError("Observed CI repository is malformed") from exc
    if claimed_source != source.repository:
        raise OperationalError(
            "Observed CI repository differs from the isolated checkout"
        )
    if result["revision"] != source.revision:
        raise OperationalError(
            "Observed CI revision differs from the isolated checkout"
        )
    if diagnostic_path is not None:
        atomic_write_json(
            diagnostic_path,
            {"schemaVersion": 1, "ciIdentity": result},
        )
    if server not in PUBLIC_CI_SERVERS:
        result.pop("server")
    return result


def _name(value: str | None, label: str) -> str:
    if (
        value is None
        or not value
        or len(value) > 1024
        or any(character.isspace() for character in value)
    ):
        raise InvalidInvocationError(f"{label} is missing or malformed")
    return value


def _digits(value: str | None, label: str) -> str:
    result = _name(value, label)
    if re.fullmatch(r"[1-9][0-9]*", result) is None:
        raise InvalidInvocationError(f"{label} is malformed")
    return result


def _https_url(value: str | None, label: str) -> str:
    result = _name(value, label)
    parsed = urlparse(result)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username is not None:
        raise InvalidInvocationError(f"{label} must be a credential-free HTTPS URL")
    return result.rstrip("/")


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _revision(value: object) -> str:
    try:
        return validate_source_revision(_name(_optional_string(value), "CI revision"))
    except InvalidInvocationError as exc:
        raise OperationalError("Observed CI revision is malformed") from exc
