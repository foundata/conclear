"""Tool compatibility policies accept bounded versions and keep exact identity."""

from pathlib import Path

import pytest

from conclear.errors import OperationalError, RuleRejectionError
from conclear.process import CommandRequest, ProcessResult
from conclear.tools import (
    SUPPORTED_TOOLS,
    ToolName,
    ToolResolver,
    ToolSpec,
    ToolVersion,
    VersionPolicy,
)


def _version(text: str) -> ToolVersion:
    return ToolVersion.parse(text)


POLICY = VersionPolicy(
    _version("1.2.0"),
    _version("2.0.0"),
    frozenset({_version("1.5.1")}),
    excluded=frozenset({_version("1.4.0")}),
)


@pytest.mark.parametrize(
    ("text", "accepted"),
    [
        ("1.2.0", True),
        ("1.1.9", False),
        ("1.99.99", True),
        ("2.0.0", False),
        ("1.4.0", False),
        ("1.4.1", True),
        ("0.9.0", False),
    ],
)
def test_policy_bounds_and_exclusions(text: str, accepted: bool) -> None:
    assert POLICY.accepts(_version(text)) is accepted


def test_policy_description_renders_interval_exclusions_and_tested_versions() -> None:
    assert POLICY.describe() == (
        "accepted 1.2.0 <= version < 2.0.0; excluded: 1.4.0; "
        "real-tool tested (not the only accepted versions): 1.5.1"
    )
    assert POLICY.interval == "1.2.0 <= version < 2.0.0"


@pytest.mark.parametrize(
    "text",
    ["1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.3-beta", "v1.2.3", "1.2.3 ", ""],
)
def test_noncanonical_versions_are_rejected(text: str) -> None:
    with pytest.raises(ValueError, match="canonical"):
        ToolVersion.parse(text)


def test_versions_compare_numerically_not_lexically() -> None:
    assert _version("1.10.0") > _version("1.9.9")
    assert _version("2.0.0") > _version("1.99.99")
    assert str(_version("1.10.0")) == "1.10.0"


@pytest.mark.parametrize(
    ("minimum", "maximum", "tested", "excluded", "message"),
    [
        ("2.0.0", "1.0.0", {"1.5.0"}, set(), "minimum must be below"),
        ("1.0.0", "2.0.0", set(), set(), "at least one tested"),
        ("1.0.0", "2.0.0", {"1.5.0"}, {"2.5.0"}, "outside the accepted interval"),
        ("1.0.0", "2.0.0", {"2.5.0"}, set(), "is not accepted"),
        ("1.0.0", "2.0.0", {"1.5.0"}, {"1.5.0"}, "is not accepted"),
    ],
)
def test_inconsistent_policies_are_rejected(
    minimum: str, maximum: str, tested: set[str], excluded: set[str], message: str
) -> None:
    with pytest.raises(OperationalError, match=message):
        VersionPolicy(
            _version(minimum),
            _version(maximum),
            frozenset(_version(item) for item in tested),
            excluded=frozenset(_version(item) for item in excluded),
        )


def test_every_production_policy_is_bounded_and_its_tested_versions_accepted() -> None:
    for name in ToolName:
        policy = SUPPORTED_TOOLS[name].policy
        assert policy.minimum < policy.maximum, name
        assert policy.tested, name
        assert all(policy.accepts(version) for version in policy.tested), name
        assert not policy.tested & policy.excluded, name
        assert policy.accepts(policy.minimum), name
        assert not policy.accepts(policy.maximum), name


def test_production_policies_pin_the_documented_floors_and_ceilings() -> None:
    expected: dict[ToolName, tuple[str, str, set[str]]] = {
        ToolName.GIT: ("2.43.0", "3.0.0", set()),
        ToolName.BUILDAH: ("1.40.0", "1.44.0", set()),
        ToolName.PODMAN: ("5.8.4", "6.0.0", set()),
        ToolName.SKOPEO: ("1.14.0", "2.0.0", set()),
        ToolName.HADOLINT: ("2.12.0", "3.0.0", set()),
        ToolName.TRIVY: ("0.74.0", "0.75.0", set()),
        ToolName.COSIGN: ("3.1.3", "4.0.0", set()),
    }
    for name, (minimum, maximum, excluded) in expected.items():
        policy = SUPPORTED_TOOLS[name].policy
        assert (str(policy.minimum), str(policy.maximum)) == (minimum, maximum), name
        assert {str(item) for item in policy.excluded} == excluded, name


class _Runner:
    def __init__(self, output: str) -> None:
        self.output = output

    def run(self, request: CommandRequest) -> ProcessResult:
        return ProcessResult(request.argv, 0, self.output, "", 0.0, 0, False, False)


def _resolver(tmp_path: Path, output: str) -> tuple[ToolResolver, Path]:
    executable = tmp_path / "podman"
    executable.write_bytes(b"executable")
    executable.chmod(0o700)
    return (
        ToolResolver(
            runner=_Runner(output), locator=lambda _name, _path: str(executable)
        ),
        executable,
    )


@pytest.mark.parametrize(
    ("output", "accepted"),
    [
        ("podman version 5.8.4", True),
        ("podman version 5.8.6", True),
        ("podman version 5.8.3", False),
        ("podman version 6.0.0", False),
        ("podman version 6.1.1", False),
    ],
)
def test_resolver_applies_the_bounded_policy(
    tmp_path: Path, output: str, accepted: bool
) -> None:
    resolver, _executable = _resolver(tmp_path, output)

    if accepted:
        tool = resolver.resolve(ToolName.PODMAN, environment={"PATH": "/usr/bin"})
        assert tool.version == output.removeprefix("podman version ")
        assert tool.executable_digest.startswith("sha256:")
        assert tool.record_identity().to_dict()["version"] == tool.version
    else:
        with pytest.raises(
            RuleRejectionError, match="Unsupported podman version"
        ) as failure:
            resolver.resolve(ToolName.PODMAN, environment={"PATH": "/usr/bin"})
        assert failure.value.code == "CC0301"
        assert "accepted 5.8.4 <= version < 6.0.0" in str(failure.value)


def test_resolver_reports_an_excluded_version_with_its_exclusion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = SUPPORTED_TOOLS[ToolName.TRIVY]
    monkeypatch.setitem(
        SUPPORTED_TOOLS,
        ToolName.TRIVY,
        ToolSpec(
            spec.version_arguments,
            spec.version_pattern,
            VersionPolicy(
                _version("0.74.0"),
                _version("0.75.0"),
                frozenset({_version("0.74.0")}),
                excluded=frozenset({_version("0.74.2")}),
            ),
        ),
    )
    executable = tmp_path / "trivy"
    executable.write_bytes(b"executable")
    executable.chmod(0o700)
    resolver = ToolResolver(
        runner=_Runner("Version: 0.74.2"), locator=lambda _name, _path: str(executable)
    )

    with pytest.raises(RuleRejectionError, match=r"excluded: 0\.74\.2") as failure:
        resolver.resolve(ToolName.TRIVY, environment={"PATH": "/usr/bin"})
    assert "Unsupported trivy version 0.74.2" in str(failure.value)
    assert "accepted 0.74.0 <= version < 0.75.0" in str(failure.value)


@pytest.mark.parametrize(
    "output",
    [
        "podman version 5.8.4-dev",
        "podman version 05.8.4",
        "podman version 5.8",
        "podman 5.8.4",
    ],
)
def test_resolver_fails_closed_on_malformed_or_noncanonical_versions(
    tmp_path: Path, output: str
) -> None:
    resolver, _executable = _resolver(tmp_path, output)

    with pytest.raises(OperationalError, match="version"):
        resolver.resolve(ToolName.PODMAN, environment={"PATH": "/usr/bin"})


def test_resolved_tool_rejects_a_mutated_executable(tmp_path: Path) -> None:
    resolver, executable = _resolver(tmp_path, "podman version 5.8.4")
    tool = resolver.resolve(ToolName.PODMAN, environment={"PATH": "/usr/bin"})
    tool.assert_unchanged()

    executable.write_bytes(b"replaced")

    with pytest.raises(OperationalError, match="executable changed during the run"):
        tool.assert_unchanged()
