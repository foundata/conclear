"""Compiled release-registry backend selection."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from conclear.adapters.quay import QuayAdapter
from conclear.config import (
    QuayRegistryConfig,
    RegistryConfig,
    RegistryProvider,
    ReleaseProfile,
)
from conclear.errors import InvalidInvocationError
from conclear.registry_control import RegistryControl
from conclear.secrets import token_provider
from conclear.values import OCIReference


@dataclass(frozen=True, slots=True)
class _RegistryBackendSpec:
    """One compiled backend and its configuration boundary."""

    provider: RegistryProvider
    factory: Callable[[RegistryConfig], RegistryControl]
    validate_destination: Callable[[RegistryConfig, OCIReference], None]


def _quay_config(config: RegistryConfig) -> QuayRegistryConfig:
    if not isinstance(config, QuayRegistryConfig):
        raise InvalidInvocationError("Quay registry configuration is malformed")
    return config


def _quay_control(config: RegistryConfig) -> RegistryControl:
    selected = _quay_config(config)
    token_file = selected.token_file
    if token_file is None:
        raise InvalidInvocationError("Quay registry backend requires an API token")
    return QuayAdapter(
        api_url=selected.api_url,
        registry=selected.host,
        token_provider=lambda: token_provider(token_file),
    )


def _validate_quay_destination(
    config: RegistryConfig, destination: OCIReference
) -> None:
    selected = _quay_config(config)
    if destination.registry != selected.host:
        raise InvalidInvocationError(
            f"Registry backend quay does not support {destination.registry}"
        )
    if len(destination.repository.split("/")) != 2:
        raise InvalidInvocationError(
            "Quay registry destinations require namespace/repository form"
        )


_BACKENDS = {
    RegistryProvider.QUAY: _RegistryBackendSpec(
        provider=RegistryProvider.QUAY,
        factory=_quay_control,
        validate_destination=_validate_quay_destination,
    )
}


def supported_registry_backends() -> tuple[str, ...]:
    """Return stable identifiers for the compiled registry backend matrix."""
    return tuple(sorted(provider.value for provider in _BACKENDS))


def validate_registry_destinations(
    profile: ReleaseProfile, destinations: Sequence[OCIReference]
) -> None:
    """Reject destinations outside the selected backend before remote mutation."""
    config = profile.registry
    spec = _BACKENDS.get(config.provider)
    if spec is None:
        raise InvalidInvocationError(
            f"Registry backend is unsupported: {config.provider.value}"
        )
    for destination in destinations:
        if destination.tag is not None or destination.digest is not None:
            raise InvalidInvocationError(
                "Registry backend destinations must be untagged repositories"
            )
        spec.validate_destination(config, destination)


def create_registry_control(
    profile: ReleaseProfile,
    *,
    destinations: Sequence[OCIReference] = (),
) -> RegistryControl:
    """Create the explicitly selected registry control backend."""
    validate_registry_destinations(profile, destinations)
    spec = _BACKENDS[profile.registry.provider]
    return spec.factory(profile.registry)
