"""Synchronous Quay REST API adapter."""

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import quote

import httpx
import regex

from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    UnsupportedOperationError,
)
from conclear.parsing import array_value, object_value, string_value
from conclear.registry_control import CandidateRetentionObservation, TagObservation
from conclear.values import CANDIDATE_TAG_PATTERN, Digest, OCIReference

MAX_QUAY_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_IMMUTABILITY_POLICIES = 100
POLICY_MATCH_TIMEOUT_SECONDS = 0.1


class _QuayAPIError(OperationalError):
    """Retain a non-secret HTTP status for operation-specific classification."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"Quay API request failed with status {status_code}")
        self.status_code = status_code


class QuayAdapter:
    """Bounded Quay API operations with post-write ambiguity resolution."""

    def __init__(
        self,
        *,
        api_url: str,
        registry: str,
        token_provider: Callable[[], str],
        client: httpx.Client | None = None,
    ) -> None:
        """Create an adapter with an injectable HTTP transport."""
        if not api_url.startswith("https://"):
            raise InvalidInvocationError("Quay API URL must use HTTPS")
        self._api_url = api_url.rstrip("/")
        self._registry = registry
        self._token_provider = token_provider
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(connect=10, read=30, write=30, pool=10)
        )

    def close(self) -> None:
        """Close an internally created HTTP client."""
        if self._owns_client:
            self._client.close()

    @property
    def provider(self) -> str:
        """Return the compiled backend identifier."""
        return "quay"

    def observe_tag(self, repository: OCIReference, tag: str) -> TagObservation | None:
        """Resolve one exact Quay tag without accepting ambiguous list results."""
        try:
            response = self._request(
                "GET",
                self._tag_list_path(repository),
                params={"specificTag": tag, "onlyActiveTags": "true"},
            )
        except httpx.TransportError as exc:
            raise OperationalError("Unable to read Quay tag state") from exc
        value = object_value(self._decode(response), label="Quay tag response")
        tags = value.get("tags")
        if not isinstance(tags, list):
            raise OperationalError("Quay tag response has no tag array")
        matches = [
            item for item in tags if isinstance(item, dict) and item.get("name") == tag
        ]
        if not matches:
            return None
        if len(matches) != 1:
            raise OperationalError(f"Quay returned ambiguous state for tag {tag}")
        item = object_value(matches[0], label="Quay tag")
        return TagObservation(
            name=tag,
            digest=Digest(
                string_value(item.get("manifest_digest"), label="Quay digest")
            ),
            expiration=_tag_expiration(item),
            immutable=item.get("immutable") is True,
        )

    def enforce_candidate_lifetime(
        self, repository: OCIReference, tag: str, expiration: datetime
    ) -> TagObservation:
        """Set expiration and require an exact post-write observation."""
        if expiration.tzinfo is None or expiration.utcoffset() is None:
            raise OperationalError("Candidate expiration must be timezone-aware")
        epoch = int(expiration.astimezone(UTC).timestamp())
        self._write_with_observation(
            repository, tag, {"expiration": epoch}, expected_digest=None
        )
        observed = self._required_tag(repository, tag)
        if observed.expiration is None or int(observed.expiration.timestamp()) != epoch:
            raise OperationalError("Quay did not retain the requested tag expiration")
        return observed

    def ensure_candidate_retention(
        self, repository: OCIReference, maximum_age: timedelta
    ) -> CandidateRetentionObservation:
        """Create or reuse a candidate-only age policy and verify it before upload.

        The policy belongs to the repository, not a release run. Existing rules
        are never broadened, relaxed or deleted, including on ambiguous writes.
        """
        seconds = int(maximum_age.total_seconds())
        if seconds <= 0 or maximum_age != timedelta(seconds=seconds):
            raise InvalidInvocationError(
                "Candidate retention needs positive whole seconds"
            )
        namespace, name = self._repository_parts(repository)
        path = f"/repository/{namespace}/{name}/autoprunepolicy/"
        try:
            observed = self._candidate_retention(repository, path, maximum_age)
            if observed is not None:
                return observed
            try:
                self._request(
                    "POST",
                    path,
                    json_body={
                        "method": "creation_date",
                        "value": f"{seconds}s",
                        "tagPattern": CANDIDATE_TAG_PATTERN,
                        "tagPatternMatches": True,
                    },
                )
            except httpx.TransportError:
                pass
            except _QuayAPIError as exc:
                if exc.status_code not in {400, 409}:
                    raise
            observed = self._candidate_retention(repository, path, maximum_age)
            if observed is None:
                raise OperationalError(
                    "Quay did not retain the required candidate retention policy",
                    code="CC0603",
                )
            return observed
        except _QuayAPIError as exc:
            if exc.status_code in {401, 403, 404, 405}:
                raise UnsupportedOperationError(
                    "Quay candidate retention is unavailable or unauthorized; no candidate was uploaded",
                    code="CC0603",
                ) from exc
            raise
        except httpx.TransportError as exc:
            raise OperationalError(
                "Unable to verify Quay candidate retention", code="CC0603"
            ) from exc

    def _candidate_retention(
        self, repository: OCIReference, path: str, maximum_age: timedelta
    ) -> CandidateRetentionObservation | None:
        response = self._request("GET", path)
        value = object_value(self._decode(response), label="Quay retention response")
        matches: list[CandidateRetentionObservation] = []
        for raw in array_value(value.get("policies"), label="Quay retention policies"):
            policy = object_value(raw, label="Quay retention policy")
            if (
                policy.get("method") != "creation_date"
                or policy.get("tagPattern") != CANDIDATE_TAG_PATTERN
                or policy.get("tagPatternMatches") is not True
            ):
                continue
            age = _retention_age(policy.get("value"))
            if age <= maximum_age:
                matches.append(
                    CandidateRetentionObservation(
                        repository,
                        string_value(
                            policy.get("uuid"), label="Quay retention policy ID"
                        ),
                        CANDIDATE_TAG_PATTERN,
                        age,
                    )
                )
        return (
            min(matches, key=lambda item: (item.maximum_age, item.policy_id))
            if matches
            else None
        )

    def ensure_tag_immutable(
        self, repository: OCIReference, tag: str
    ) -> TagObservation:
        """Enable Quay tag immutability and verify the observed control."""
        try:
            self._write_with_observation(
                repository, tag, {"immutable": True}, expected_digest=None
            )
        except _QuayAPIError as exc:
            if exc.status_code in {403, 404, 405}:
                raise UnsupportedOperationError(
                    "Quay tag immutability is unavailable for this repository"
                ) from exc
            raise
        observed = self._required_tag(repository, tag)
        if not observed.immutable:
            raise UnsupportedOperationError(
                "Quay accepted the immutability request but does not enforce "
                "tag immutability for this repository"
            )
        return observed

    def verify_tag_policy(
        self,
        repository: OCIReference,
        *,
        version_tags: tuple[str, ...],
        mutable_tags: tuple[str, ...],
    ) -> None:
        """Check repository and inherited organization policies without changing them.

        Quay uses regex.fullmatch with an optional inverted match rule. Use the
        same engine with a bounded match time and reject unreadable policies.
        """
        namespace, name = self._repository_parts(repository)
        protected: set[str] = set()
        try:
            for path in (
                f"/repository/{namespace}/{name}/immutabilitypolicy/",
                f"/organization/{namespace}/immutabilitypolicy/",
            ):
                response = self._request("GET", path)
                value = object_value(self._decode(response), "Quay policy response")
                policies = array_value(value.get("policies"), "Quay tag policies")
                if len(policies) > MAX_IMMUTABILITY_POLICIES:
                    raise OperationalError("Quay has too many immutability policies")
                for raw in policies:
                    policy = object_value(raw, "Quay immutability policy")
                    pattern = string_value(policy.get("tagPattern"), "tag pattern")
                    matches = policy.get("tagPatternMatches")
                    if not 0 < len(pattern) <= 256 or not isinstance(matches, bool):
                        raise OperationalError("Quay immutability policy is malformed")
                    for tag in (*version_tags, *mutable_tags):
                        matched = (
                            regex.fullmatch(
                                pattern, tag, timeout=POLICY_MATCH_TIMEOUT_SECONDS
                            )
                            is not None
                        )
                        if matched == matches:
                            protected.add(tag)
        except _QuayAPIError as exc:
            if exc.status_code in {401, 403, 404, 405}:
                raise UnsupportedOperationError(
                    "Quay immutability policies are unavailable or unauthorized; "
                    "repository and organization policy read access is required",
                    code="CC0604",
                ) from exc
            raise
        except (httpx.TransportError, regex.error, TimeoutError) as exc:
            raise OperationalError(
                "Unable to verify Quay immutability policies", code="CC0604"
            ) from exc
        missing = sorted(set(version_tags) - protected)
        blocked = sorted(set(mutable_tags) & protected)
        if missing or blocked:
            raise OperationalError(
                "Quay requires selective tag immutability before publication; "
                f"unprotected release tags={missing}, protected mutable tags={blocked}",
                code="CC0604",
            )
        for tag in mutable_tags:
            observed = self.observe_tag(repository, tag)
            if observed is not None and observed.immutable:
                raise OperationalError(
                    f"Mutable tag is individually protected in Quay: {tag}",
                    code="CC0604",
                )

    def ensure_tag_mutable(self, repository: OCIReference, tag: str) -> TagObservation:
        """Disable Quay tag immutability and verify the observed control."""
        self._write_with_observation(
            repository, tag, {"immutable": False}, expected_digest=None
        )
        observed = self._required_tag(repository, tag)
        if observed.immutable:
            raise OperationalError("Quay did not remove tag immutability")
        return observed

    def assign_tag(
        self, repository: OCIReference, tag: str, digest: Digest
    ) -> TagObservation:
        """Write a digest tag once, resolving a transport ambiguity by reading state."""
        self._write_with_observation(
            repository,
            tag,
            {"manifest_digest": str(digest)},
            expected_digest=digest,
        )
        observed = self._required_tag(repository, tag)
        if observed.digest != digest:
            raise OperationalError(
                f"Quay tag {tag} resolved to {observed.digest}, expected {digest}"
            )
        return observed

    def remove_tag(self, repository: OCIReference, tag: str) -> None:
        """Delete one owned tag and verify it is absent."""
        try:
            response = self._request("DELETE", self._tag_path(repository, tag))
            if response.status_code not in {200, 204}:
                self._raise_response(response)
        except httpx.TransportError:
            if self.observe_tag(repository, tag) is not None:
                raise OperationalError(
                    "Quay tag deletion has unknown remote state"
                ) from None
            return
        if self.observe_tag(repository, tag) is not None:
            raise OperationalError("Quay tag remains after deletion")

    def _write_with_observation(
        self,
        repository: OCIReference,
        tag: str,
        body: dict[str, object],
        *,
        expected_digest: Digest | None,
    ) -> None:
        try:
            response = self._request(
                "PUT", self._tag_path(repository, tag), json_body=body
            )
            if response.status_code not in {200, 201, 204}:
                self._raise_response(response)
        except httpx.TransportError as exc:
            observed = self.observe_tag(repository, tag)
            if observed is not None and (
                expected_digest is None or observed.digest == expected_digest
            ):
                return
            raise OperationalError("Quay tag write has unknown remote state") from exc

    def _required_tag(self, repository: OCIReference, tag: str) -> TagObservation:
        observed = self.observe_tag(repository, tag)
        if observed is None:
            raise OperationalError(f"Quay tag is absent after write: {tag}")
        return observed

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: dict[str, object] | None = None,
    ) -> httpx.Response:
        token = self._token_provider()
        if not token or any(character.isspace() for character in token):
            raise OperationalError("Quay API token provider returned an invalid token")
        try:
            with self._client.stream(
                method,
                f"{self._api_url}{path}",
                headers={"Authorization": f"Bearer {token}"},
                params=params,
                json=json_body,
            ) as streamed:
                if streamed.status_code >= 400:
                    self._raise_response(streamed)
                content = bytearray()
                for chunk in streamed.iter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_QUAY_RESPONSE_BYTES:
                        raise OperationalError("Quay response exceeds the size limit")
                response = httpx.Response(
                    streamed.status_code,
                    headers=streamed.headers,
                    content=bytes(content),
                    request=streamed.request,
                )
        finally:
            token = ""
        return response

    @staticmethod
    def _decode(response: httpx.Response) -> object:
        try:
            return response.json()
        except ValueError as exc:
            raise OperationalError("Quay returned malformed JSON") from exc

    @staticmethod
    def _raise_response(response: httpx.Response) -> None:
        raise _QuayAPIError(response.status_code)

    def _repository_parts(self, repository: OCIReference) -> tuple[str, str]:
        if repository.registry != self._registry or repository.tag or repository.digest:
            raise InvalidInvocationError(
                f"Quay API operations require an untagged {self._registry} repository"
            )
        namespace, separator, name = repository.repository.partition("/")
        if not separator or "/" in name:
            raise InvalidInvocationError(
                "Quay API supports namespace/repository destinations"
            )
        return quote(namespace, safe=""), quote(name, safe="")

    def _tag_list_path(self, repository: OCIReference) -> str:
        namespace, name = self._repository_parts(repository)
        return f"/repository/{namespace}/{name}/tag/"

    def _tag_path(self, repository: OCIReference, tag: str) -> str:
        namespace, name = self._repository_parts(repository)
        return f"/repository/{namespace}/{name}/tag/{quote(tag, safe='')}"


def _retention_age(value: object) -> timedelta:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[1-9][0-9]{0,8}[smhdw]", value) is None
    ):
        raise OperationalError(
            "Quay candidate retention age is malformed", code="CC0603"
        )
    seconds = (
        int(value[:-1])
        * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[value[-1]]
    )
    return timedelta(seconds=seconds)


def _tag_expiration(item: dict[str, object]) -> datetime | None:
    """Read a tag's expiration from the epoch Quay returns as `end_ts`.

    Quay reports the deadline twice: `end_ts` as an integer epoch and
    `expiration` as an RFC 2822 string. The epoch is authoritative; the string
    is accepted only when the epoch is absent.
    """
    epoch = item.get("end_ts")
    if epoch is not None:
        if not isinstance(epoch, int) or isinstance(epoch, bool):
            raise OperationalError("Quay tag expiration is malformed")
        return datetime.fromtimestamp(epoch, tz=UTC).replace(microsecond=0)
    text = item.get("expiration")
    if text is None:
        return None
    if isinstance(text, int) and not isinstance(text, bool):
        return datetime.fromtimestamp(text, tz=UTC).replace(microsecond=0)
    if not isinstance(text, str):
        raise OperationalError("Quay tag expiration is malformed")
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError) as exc:
        raise OperationalError("Quay tag expiration is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        # Quay writes "-0000", which RFC 2822 defines as an unknown offset and
        # Python parses as naive; the value is UTC.
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).replace(microsecond=0)
