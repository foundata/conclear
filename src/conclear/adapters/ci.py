"""Typed observations from supported CI provider environments."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from conclear.errors import InvalidInvocationError
from conclear.values import validate_source_revision


@dataclass(frozen=True, slots=True)
class CIContextAbsent:
    """No supported CI provider marker was observed."""


@dataclass(frozen=True, slots=True)
class CIContextInvalid:
    """A provider marker was observed without a usable complete context."""

    provider: str | None
    diagnostic: str


@dataclass(frozen=True, slots=True)
class ObservedCIContext:
    """Narrow provider metadata observed from the current process environment."""

    provider: str
    server: str
    repository: str
    revision: str
    run_id: str


type CIContextObservation = CIContextAbsent | CIContextInvalid | ObservedCIContext

_REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9._~-]+$")


@dataclass(frozen=True, slots=True)
class _ProviderSpec:
    provider: str
    server_variable: str
    repository_variable: str
    revision_variable: str
    run_variable: str


_PROVIDERS = {
    "forgejo-actions": _ProviderSpec(
        "forgejo-actions",
        "FORGEJO_SERVER_URL",
        "FORGEJO_REPOSITORY",
        "FORGEJO_SHA",
        "FORGEJO_RUN_ID",
    ),
    # Gitea's native gitea.* values are expression contexts; its documented
    # process environment retains GITHUB_* for these identity fields.
    "gitea-actions": _ProviderSpec(
        "gitea-actions",
        "GITHUB_SERVER_URL",
        "GITHUB_REPOSITORY",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
    ),
    "github-actions": _ProviderSpec(
        "github-actions",
        "GITHUB_SERVER_URL",
        "GITHUB_REPOSITORY",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
    ),
    "gitlab-ci": _ProviderSpec(
        "gitlab-ci",
        "CI_SERVER_URL",
        "CI_PROJECT_PATH",
        "CI_COMMIT_SHA",
        "CI_PIPELINE_ID",
    ),
    "woodpecker-ci": _ProviderSpec(
        "woodpecker-ci",
        "CI_FORGE_URL",
        "CI_REPO",
        "CI_COMMIT_SHA",
        "CI_PIPELINE_NUMBER",
    ),
}


def observe_ci_context(environment: Mapping[str, str]) -> CIContextObservation:
    """Observe and validate a supported provider's ordinary environment metadata."""
    providers = list(_detected_providers(environment))
    github_compatible = (
        environment.get("GITHUB_ACTIONS") == "true"
        and environment.get("FORGEJO_ACTIONS") != "true"
        and environment.get("GITEA_ACTIONS") != "true"
    )
    if github_compatible:
        if not _is_github_environment(environment):
            return CIContextInvalid(
                None,
                "GitHub-compatible CI variables lack a provider-specific marker",
            )
        providers.append("github-actions")
    if not providers:
        return CIContextAbsent()
    if len(providers) != 1:
        return CIContextInvalid(None, "Multiple CI provider markers were observed")
    provider = providers[0]
    spec = _PROVIDERS[provider]
    try:
        return ObservedCIContext(
            provider=provider,
            server=_https_url(environment.get(spec.server_variable), "CI server"),
            repository=_repository(
                environment.get(spec.repository_variable), "CI repository"
            ),
            revision=validate_source_revision(
                _text(environment.get(spec.revision_variable), "CI revision")
            ),
            run_id=_text(environment.get(spec.run_variable), "CI run identifier"),
        )
    except (InvalidInvocationError, ValueError) as exc:
        return CIContextInvalid(provider, str(exc))


def _detected_providers(environment: Mapping[str, str]) -> tuple[str, ...]:
    providers: list[str] = []
    forgejo = environment.get("FORGEJO_ACTIONS") == "true"
    gitea = environment.get("GITEA_ACTIONS") == "true"
    if forgejo:
        providers.append("forgejo-actions")
    if gitea:
        providers.append("gitea-actions")
    if environment.get("GITLAB_CI") == "true":
        providers.append("gitlab-ci")
    if (
        environment.get("CI") == "woodpecker"
        or environment.get("CI_SYSTEM_NAME") == "woodpecker"
    ):
        providers.append("woodpecker-ci")
    return tuple(providers)


def _is_github_environment(environment: Mapping[str, str]) -> bool:
    server = environment.get("GITHUB_SERVER_URL", "").rstrip("/")
    api = environment.get("GITHUB_API_URL", "").rstrip("/")
    if server == "https://github.com":
        return api == "https://api.github.com"
    return bool(server) and api == f"{server}/api/v3"


def _text(value: str | None, label: str) -> str:
    if (
        value is None
        or not value
        or len(value) > 1024
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{label} is missing or malformed")
    return value


def _repository(value: str | None, label: str) -> str:
    result = _text(value, label)
    components = result.split("/")
    if (
        len(components) < 2
        or result.endswith(".git")
        or any(
            component in {"", ".", ".."}
            or _REPOSITORY_COMPONENT.fullmatch(component) is None
            for component in components
        )
    ):
        raise ValueError(f"{label} is malformed")
    return result


def _https_url(value: str | None, label: str) -> str:
    result = _text(value, label)
    try:
        parsed = urlsplit(result)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} is malformed") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be a credential-free HTTPS URL")
    authority = parsed.hostname.lower() + ("" if port is None else f":{port}")
    return urlunsplit(("https", authority, parsed.path.rstrip("/"), "", ""))
