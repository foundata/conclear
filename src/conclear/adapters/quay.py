"""Synchronous Quay REST API adapter."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote

import httpx

from conclear.adapters.parsing import object_value, string_value
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    UnsupportedOperationError,
)
from conclear.values import Digest, OCIReference

MAX_QUAY_RESPONSE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class QuayTagObservation:
    """Observed Quay tag state."""

    name: str
    digest: Digest
    expiration: datetime | None
    immutable: bool


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
        token_provider: Callable[[], str],
        client: httpx.Client | None = None,
    ) -> None:
        """Create an adapter with an injectable HTTP transport."""
        if not api_url.startswith("https://"):
            raise InvalidInvocationError("Quay API URL must use HTTPS")
        self._api_url = api_url.rstrip("/")
        self._token_provider = token_provider
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(connect=10, read=30, write=30, pool=10)
        )

    def close(self) -> None:
        """Close an internally created HTTP client."""
        if self._owns_client:
            self._client.close()

    def get_tag(self, repository: OCIReference, tag: str) -> QuayTagObservation | None:
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
        expiration_value = item.get("expiration")
        expiration: datetime | None = None
        if expiration_value is not None:
            if not isinstance(expiration_value, int) or isinstance(
                expiration_value, bool
            ):
                raise OperationalError("Quay tag expiration is malformed")
            expiration = datetime.fromtimestamp(expiration_value, tz=UTC)
        return QuayTagObservation(
            name=tag,
            digest=Digest(
                string_value(item.get("manifest_digest"), label="Quay digest")
            ),
            expiration=expiration,
            immutable=item.get("immutable") is True,
        )

    def set_expiration(
        self, repository: OCIReference, tag: str, expiration: datetime
    ) -> QuayTagObservation:
        """Set expiration and require an exact post-write observation."""
        if expiration.tzinfo is None or expiration.utcoffset() is None:
            raise OperationalError("Candidate expiration must be timezone-aware")
        epoch = int(expiration.astimezone(UTC).timestamp())
        self._write_with_observation(
            repository, tag, {"expiration": str(epoch)}, expected_digest=None
        )
        observed = self._required_tag(repository, tag)
        if observed.expiration is None or int(observed.expiration.timestamp()) != epoch:
            raise OperationalError("Quay did not retain the requested tag expiration")
        return observed

    def set_immutable(self, repository: OCIReference, tag: str) -> QuayTagObservation:
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
            raise OperationalError("Quay did not retain tag immutability")
        return observed

    def set_mutable(self, repository: OCIReference, tag: str) -> QuayTagObservation:
        """Disable Quay tag immutability and verify the observed control."""
        self._write_with_observation(
            repository, tag, {"immutable": False}, expected_digest=None
        )
        observed = self._required_tag(repository, tag)
        if observed.immutable:
            raise OperationalError("Quay did not remove tag immutability")
        return observed

    def write_tag(
        self, repository: OCIReference, tag: str, digest: Digest
    ) -> QuayTagObservation:
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

    def delete_tag(self, repository: OCIReference, tag: str) -> None:
        """Delete one owned tag and verify it is absent."""
        try:
            response = self._request("DELETE", self._tag_path(repository, tag))
            if response.status_code not in {200, 204}:
                self._raise_response(response)
        except httpx.TransportError:
            if self.get_tag(repository, tag) is not None:
                raise OperationalError(
                    "Quay tag deletion has unknown remote state"
                ) from None
            return
        if self.get_tag(repository, tag) is not None:
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
            observed = self.get_tag(repository, tag)
            if observed is not None and (
                expected_digest is None or observed.digest == expected_digest
            ):
                return
            raise OperationalError("Quay tag write has unknown remote state") from exc

    def _required_tag(self, repository: OCIReference, tag: str) -> QuayTagObservation:
        observed = self.get_tag(repository, tag)
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

    @staticmethod
    def _repository_parts(repository: OCIReference) -> tuple[str, str]:
        if repository.registry != "quay.io" or repository.tag or repository.digest:
            raise InvalidInvocationError(
                "Quay API operations require an untagged quay.io repository"
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
