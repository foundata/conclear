from pathlib import Path

import pytest

from conclear.emulation import (
    BinfmtHandler,
    binfmt_handler,
    detect_execution_mode,
    normalize_architecture,
    validate_execution_observation,
)
from conclear.errors import ExitStatus, InvalidInvocationError, OperationalError
from conclear.values import Platform

ARM64 = Platform.parse("linux/arm64")
AMD64 = Platform.parse("linux/amd64")


def register_handler(
    root: Path, name: str = "qemu-aarch64", *, enabled: bool = True
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_text(
        f"{'enabled' if enabled else 'disabled'}\n"
        f"interpreter /usr/bin/{name}-static\n"
        "flags: OCF\n"
        "offset 0\n"
        "magic 7f454c460201010000000000000000000200b700\n",
        encoding="ascii",
    )
    return path


def test_native_platform_needs_no_handler(tmp_path: Path) -> None:
    mode = detect_execution_mode("x86_64", AMD64, binfmt_root=tmp_path / "missing")

    assert mode.native
    assert mode.mechanism == "native"
    assert mode.handler is None
    assert mode.to_dict() == {
        "targetPlatform": "linux/amd64",
        "hostArchitecture": "x86_64",
        "executionArchitecture": "amd64",
        "mechanism": "native",
    }


def test_foreign_platform_without_enabled_handler_is_an_operational_failure(
    tmp_path: Path,
) -> None:
    register_handler(tmp_path, enabled=False)

    with pytest.raises(OperationalError, match="No enabled binfmt handler") as caught:
        detect_execution_mode("x86_64", ARM64, binfmt_root=tmp_path)

    assert caught.value.exit_status is ExitStatus.OPERATIONAL_FAILURE
    assert "not qualified" in str(caught.value)
    assert binfmt_handler("arm64", root=tmp_path) is None
    assert binfmt_handler("arm64", root=tmp_path / "absent") is None


def test_foreign_platform_records_the_enabled_handler(tmp_path: Path) -> None:
    register_handler(tmp_path, "qemu-arm64")

    mode = detect_execution_mode("x86_64", ARM64, binfmt_root=tmp_path)

    assert not mode.native
    assert mode.mechanism == "qemu-user"
    assert mode.handler == BinfmtHandler(
        "qemu-arm64", "/usr/bin/qemu-arm64-static", "OCF"
    )
    assert mode.to_dict()["mechanism"] == "qemu-user"
    assert mode.to_dict()["hostArchitecture"] == "x86_64"
    assert mode.to_dict()["executionArchitecture"] == "arm64"


def test_aarch64_host_runs_arm64_natively_and_amd64_through_a_handler(
    tmp_path: Path,
) -> None:
    assert normalize_architecture("aarch64") == "arm64"
    assert normalize_architecture("riscv64") == "riscv64"
    assert detect_execution_mode("aarch64", ARM64, binfmt_root=tmp_path).native
    register_handler(tmp_path, "qemu-x86_64")
    assert not detect_execution_mode("aarch64", AMD64, binfmt_root=tmp_path).native


def test_false_native_or_emulated_observations_are_rejected() -> None:
    validate_execution_observation(
        {
            "targetPlatform": "linux/arm64",
            "hostArchitecture": "x86_64",
            "executionArchitecture": "arm64",
            "mechanism": "qemu-user",
        },
        platform=ARM64,
    )
    with pytest.raises(InvalidInvocationError, match="claims native"):
        validate_execution_observation(
            {
                "targetPlatform": "linux/arm64",
                "hostArchitecture": "x86_64",
                "executionArchitecture": "arm64",
                "mechanism": "native",
            },
            platform=ARM64,
        )
    with pytest.raises(InvalidInvocationError, match="claims qemu-user"):
        validate_execution_observation(
            {
                "targetPlatform": "linux/amd64",
                "hostArchitecture": "x86_64",
                "executionArchitecture": "amd64",
                "mechanism": "qemu-user",
            },
            platform=AMD64,
        )
    with pytest.raises(InvalidInvocationError, match="does not describe"):
        validate_execution_observation(
            {
                "targetPlatform": "linux/amd64",
                "hostArchitecture": "x86_64",
                "executionArchitecture": "amd64",
                "mechanism": "native",
            },
            platform=ARM64,
        )
    with pytest.raises(InvalidInvocationError, match="malformed"):
        validate_execution_observation(
            {"targetPlatform": "linux/amd64", "mechanism": 1}, platform=AMD64
        )
    with pytest.raises(InvalidInvocationError, match="must be an object"):
        validate_execution_observation(["native"], platform=AMD64)
