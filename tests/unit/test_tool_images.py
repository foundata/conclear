"""A pinned tool image is pulled, verified and probed before a run trusts it."""

import hashlib
import json
from pathlib import Path

import pytest

from conclear.errors import OperationalError
from conclear.process import CommandRequest, ProcessResult
from conclear.tool_images import ImageBackedTool, ToolImageResolver, ToolImageStore
from conclear.tools import SUPPORTED_TOOLS, ResolvedTool, ToolName

INDEX = "sha256:" + "1" * 64
MANIFEST = "sha256:" + "2" * 64
ENVIRONMENT = {"PATH": "/usr/bin", "HOME": "/run/home"}


def _result(stdout: str = "", stderr: str = "") -> ProcessResult:
    return ProcessResult(("/tool",), 0, stdout, stderr, 0.0, 1, False, False)


class ScriptedRunner:
    """Answer Podman and Cosign requests by their shape and record them all."""

    def __init__(
        self,
        *,
        reference: str,
        index: str = INDEX,
        repo_digests: list[str] | None = None,
        version_output: str = "Version: 0.74.0",
        verify_output: str = '[{"critical": {}}]',
    ) -> None:
        self.index = index
        self.repo_digests = (
            [f"{reference}@{index}", f"{reference}@{MANIFEST}"]
            if repo_digests is None
            else repo_digests
        )
        self.version_output = version_output
        self.verify_output = verify_output
        self.requests: list[CommandRequest] = []

    def run(self, request: CommandRequest) -> ProcessResult:
        self.requests.append(request)
        argv = request.argv
        if "pull" in argv:
            return _result("0123456789ab\n")
        if "inspect" in argv and "{{.Digest}}" in argv:
            return _result(self.index + "\n")
        if "inspect" in argv and "{{json .RepoDigests}}" in argv:
            return _result(json.dumps(self.repo_digests) + "\n")
        if argv[1:2] == ("initialize",):
            return _result()
        if argv[1:2] == ("verify",):
            return _result(self.verify_output)
        if "run" in argv:
            return _result(self.version_output)
        raise AssertionError(f"unexpected request {argv}")

    def argv_containing(self, token: str) -> list[tuple[str, ...]]:
        return [request.argv for request in self.requests if token in request.argv]


def _host_tool(tmp_path: Path, name: ToolName) -> ResolvedTool:
    executable = tmp_path / name.value
    executable.write_bytes(name.value.encode())
    executable.chmod(0o700)
    return ResolvedTool(
        name=name,
        path=executable,
        version="5.8.4",
        executable_digest="sha256:" + hashlib.sha256(name.value.encode()).hexdigest(),
        reported_version="test",
    )


def _resolver(
    tmp_path: Path, runner: ScriptedRunner, *, with_cosign: bool = True
) -> tuple[ToolImageResolver, ToolImageStore, ResolvedTool]:
    podman = _host_tool(tmp_path, ToolName.PODMAN)
    store = ToolImageStore.below(tmp_path / "tool-images")
    resolver = ToolImageResolver(
        runner=runner,
        store=store,
        podman=podman,
        cosign=_host_tool(tmp_path, ToolName.COSIGN) if with_cosign else None,
    )
    return resolver, store, podman


def _trivy_reference() -> str:
    image = SUPPORTED_TOOLS[ToolName.TRIVY].image
    assert image is not None
    return image.reference


def test_a_signed_image_is_pulled_verified_probed_and_recorded(tmp_path: Path) -> None:
    image = SUPPORTED_TOOLS[ToolName.TRIVY].image
    assert image is not None
    runner = ScriptedRunner(reference=image.reference, index=image.digest)
    resolver, store, podman = _resolver(tmp_path, runner)

    tool = resolver.resolve(ToolName.TRIVY, environment=ENVIRONMENT)

    assert isinstance(tool, ImageBackedTool)
    assert tool.version == "0.74.0"
    assert tool.binding_digest == image.digest
    assert tool.manifest_digest == MANIFEST
    assert tool.record_identity().to_dict() == {
        "name": "trivy",
        "version": "0.74.0",
        "imageDigest": image.digest,
        "imageManifestDigest": MANIFEST,
    }
    (pull,) = runner.argv_containing("pull")
    assert pull[: 1 + len(store.arguments)] == (str(podman.path), *store.arguments)
    assert pull[-1] == image.pinned_reference
    (verify,) = runner.argv_containing("verify")
    assert verify[0].endswith("cosign")
    assert (
        "--certificate-oidc-issuer" in verify
        and "--certificate-identity-regexp" in verify
    )
    assert verify[verify.index("--certificate-oidc-issuer") + 1] == (
        "https://token.actions.githubusercontent.com"
    )
    assert verify[-1] == image.pinned_reference
    assert runner.argv_containing("initialize")
    (probe,) = runner.argv_containing("run")
    assert probe[probe.index("--entrypoint") + 1] == image.executable
    for flag in ("--rm", "--read-only", "none", "never"):
        assert flag in probe
    assert probe[-2:] == (image.pinned_reference, "--version")
    assert all(request.environment == ENVIRONMENT for request in runner.requests)


def test_an_unsigned_image_needs_no_cosign(tmp_path: Path) -> None:
    image = SUPPORTED_TOOLS[ToolName.HADOLINT].image
    assert image is not None
    runner = ScriptedRunner(
        reference=image.reference,
        index=image.digest,
        version_output="Haskell Dockerfile Linter 2.14.0",
    )
    resolver, _store, _podman = _resolver(tmp_path, runner, with_cosign=False)

    tool = resolver.resolve(ToolName.HADOLINT, environment=ENVIRONMENT)

    assert tool.version == "2.14.0"
    assert not runner.argv_containing("verify")
    assert not runner.argv_containing("initialize")


def test_a_signed_image_without_cosign_is_refused_before_any_pull(
    tmp_path: Path,
) -> None:
    runner = ScriptedRunner(reference=_trivy_reference())
    resolver, _store, _podman = _resolver(tmp_path, runner, with_cosign=False)

    with pytest.raises(OperationalError, match="requires cosign"):
        resolver.resolve(ToolName.TRIVY, environment=ENVIRONMENT)
    assert runner.requests == []


def test_a_tool_without_a_pinned_image_cannot_be_resolved_from_one(
    tmp_path: Path,
) -> None:
    runner = ScriptedRunner(reference="example.invalid/git")
    resolver, _store, _podman = _resolver(tmp_path, runner)

    with pytest.raises(OperationalError, match="has no pinned image"):
        resolver.resolve(ToolName.GIT, environment=ENVIRONMENT)


def test_a_pulled_digest_that_differs_from_the_pin_is_refused(tmp_path: Path) -> None:
    runner = ScriptedRunner(reference=_trivy_reference(), index="sha256:" + "f" * 64)
    resolver, _store, _podman = _resolver(tmp_path, runner)

    with pytest.raises(OperationalError, match="differs from the pin"):
        resolver.resolve(ToolName.TRIVY, environment=ENVIRONMENT)
    assert not runner.argv_containing("verify")


def test_an_image_reporting_another_version_than_pinned_is_refused(
    tmp_path: Path,
) -> None:
    image = SUPPORTED_TOOLS[ToolName.TRIVY].image
    assert image is not None
    runner = ScriptedRunner(
        reference=image.reference, index=image.digest, version_output="Version: 0.74.1"
    )
    resolver, _store, _podman = _resolver(tmp_path, runner)

    with pytest.raises(OperationalError, match=r"reports version 0\.74\.1"):
        resolver.resolve(ToolName.TRIVY, environment=ENVIRONMENT)


def test_a_verification_without_signatures_is_a_failure(tmp_path: Path) -> None:
    image = SUPPORTED_TOOLS[ToolName.TRIVY].image
    assert image is not None
    runner = ScriptedRunner(
        reference=image.reference, index=image.digest, verify_output="[]"
    )
    resolver, _store, _podman = _resolver(tmp_path, runner)

    with pytest.raises(OperationalError, match="verified no signature"):
        resolver.resolve(ToolName.TRIVY, environment=ENVIRONMENT)


@pytest.mark.parametrize(
    ("repo_digests", "expected", "message"),
    [
        (["{ref}@" + INDEX], INDEX, None),
        (["{ref}@" + INDEX, "{ref}@" + MANIFEST], MANIFEST, None),
        (
            ["{ref}@" + INDEX, "{ref}@" + MANIFEST, "{ref}@sha256:" + "3" * 64],
            None,
            "several platform manifests",
        ),
        (["{ref}:0.74.0"], None, "digest-less"),
    ],
)
def test_the_platform_manifest_is_the_repository_digest_that_is_not_the_pin(
    tmp_path: Path, repo_digests: list[str], expected: str | None, message: str | None
) -> None:
    image = SUPPORTED_TOOLS[ToolName.TRIVY].image
    assert image is not None
    # The pin is the index; the runner answers with it so only the manifest varies.
    runner = ScriptedRunner(
        reference=image.reference,
        index=image.digest,
        repo_digests=[
            item.replace("{ref}", image.reference).replace(INDEX, image.digest)
            for item in repo_digests
        ],
    )
    resolver, _store, _podman = _resolver(tmp_path, runner)

    if message is None:
        tool = resolver.resolve(ToolName.TRIVY, environment=ENVIRONMENT)
        assert tool.manifest_digest == (image.digest if expected == INDEX else expected)
    else:
        with pytest.raises(OperationalError, match=message):
            resolver.resolve(ToolName.TRIVY, environment=ENVIRONMENT)


def test_an_image_backed_tool_rechecks_its_executor_and_its_image(
    tmp_path: Path,
) -> None:
    image = SUPPORTED_TOOLS[ToolName.HADOLINT].image
    assert image is not None
    runner = ScriptedRunner(
        reference=image.reference,
        index=image.digest,
        version_output="Haskell Dockerfile Linter 2.14.0",
    )
    resolver, _store, podman = _resolver(tmp_path, runner, with_cosign=False)
    tool = resolver.resolve(ToolName.HADOLINT, environment=ENVIRONMENT)

    tool.assert_unchanged()

    runner.index = "sha256:" + "e" * 64
    with pytest.raises(OperationalError, match="image changed during the run"):
        tool.assert_unchanged()

    runner.index = image.digest
    podman.path.write_bytes(b"replaced")
    with pytest.raises(OperationalError, match="executable changed during the run"):
        tool.assert_unchanged()


def test_the_store_is_created_below_the_run_directory(tmp_path: Path) -> None:
    store = ToolImageStore.below(tmp_path / "environment" / "tool-images")

    assert store.root.is_dir() and store.runroot.is_dir()
    assert store.arguments == (
        "--root",
        str(store.root),
        "--runroot",
        str(store.runroot),
    )
