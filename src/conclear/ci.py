"""Runtime validation of protected CI identity observations."""

import re
from collections.abc import Mapping
from urllib.parse import urlparse

from conclear.errors import InvalidInvocationError
from conclear.values import validate_source_revision


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
