from pathlib import Path

import pytest

from conclear.adapters.registry_backends import (
    create_registry_control,
    supported_registry_backends,
)
from conclear.config import (
    BuilderConfig,
    CIContextPolicy,
    QuayRegistryConfig,
    RegistryProvider,
    ReleaseProfile,
)
from conclear.errors import InvalidInvocationError
from conclear.values import OCIReference


def _profile(tmp_path: Path) -> ReleaseProfile:
    return ReleaseProfile(
        name="test",
        ci_context=CIContextPolicy.OMIT,
        builder=BuilderConfig(
            "https://foundata.com/en/projects/conclear/builder/simple-v1/"
        ),
        auth_file=None,
        registry=QuayRegistryConfig(
            provider=RegistryProvider.QUAY,
            host="quay.io",
            api_url="https://quay.io/api/v1",
            token_file=tmp_path / "quay-token",
        ),
        cosign_private_key=None,
        cosign_public_key=tmp_path / "cosign.pub",
        passphrase_file=None,
        configuration_digest="sha256:" + "1" * 64,
        public_key_digest="sha256:" + "2" * 64,
    )


def test_supported_registry_backend_matrix_contains_only_quay() -> None:
    assert supported_registry_backends() == ("quay",)


def test_quay_backend_accepts_its_declared_destination(tmp_path: Path) -> None:
    control = create_registry_control(
        _profile(tmp_path),
        destinations=(OCIReference.parse("quay.io/foundata/example"),),
    )
    try:
        assert control.provider == "quay"
    finally:
        control.close()


def test_quay_backend_rejects_an_unsupported_destination_before_construction(
    tmp_path: Path,
) -> None:
    with pytest.raises(InvalidInvocationError, match=r"does not support docker\.io"):
        create_registry_control(
            _profile(tmp_path),
            destinations=(OCIReference.parse("docker.io/foundata/example"),),
        )
