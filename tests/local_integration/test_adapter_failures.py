"""Real-tool failure semantics that the adapter fakes can only imitate.

Every case here drives an installed tool into an error that the adapters
classify, using only run-owned storage, run-owned repositories and a closed
local port. Nothing listens, nothing is pulled and nothing is published.
"""

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from conclear.adapters.buildah import BuildObservation
from conclear.errors import (
    CommandExecutionError,
    InvalidInvocationError,
    OperationalError,
)
from conclear.jsonutil import sha256_bytes
from conclear.path_safety import contained_path
from conclear.process import CommandRequest, OperationKind
from conclear.runtime import ApplicationRuntime
from conclear.tools import ToolName
from conclear.values import Digest, OCIReference, Platform
from tests.local_integration.fixtures import (
    compile_fixture,
    manifest_run_id,
    runtime_config,
)

pytestmark = pytest.mark.local_integration

CLOSED_REGISTRY = "localhost:1"
AMD64 = Platform.parse("linux/amd64")


def _logs(runtime: ApplicationRuntime, tool: ToolName) -> list[Path]:
    return sorted((runtime.root / "logs").glob(f"{tool.value}-*.json"))


def _git(
    runtime: ApplicationRuntime,
    *arguments: str,
    extra_environment: dict[str, str] | None = None,
) -> str:
    return runtime.runner.run(
        CommandRequest(
            argv=(
                str(runtime.executable(ToolName.GIT).path),
                "-c",
                "user.name=ConClear Integration",
                "-c",
                "user.email=integration@example.invalid",
                "-c",
                "commit.gpgsign=false",
                *arguments,
            ),
            environment={**runtime.environment, **(extra_environment or {})},
            timeout_seconds=60,
            operation=OperationKind.WRITE,
        )
    ).stdout


def test_real_git_observation_worktrees_and_object_reads(tmp_path: Path) -> None:
    run_id = manifest_run_id()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(root / "environment", names=(ToolName.GIT,))
    repository = root / "repository"
    _git(runtime, "init", "--quiet", "--initial-branch=main", str(repository))
    (repository / "README.md").write_text("observed content\n", encoding="utf-8")
    _git(runtime, "-C", str(repository), "add", "README.md")
    _git(runtime, "-C", str(repository), "commit", "--quiet", "-m", "initial")
    revision = _git(runtime, "-C", str(repository), "rev-parse", "HEAD").strip()
    git = runtime.git()

    # A repository without an origin is an operational failure of Git itself.
    with pytest.raises(CommandExecutionError) as no_origin:
        git.observe(repository, "HEAD")
    assert no_origin.value.returncode == 2
    assert "No such remote" in no_origin.value.stderr

    _git(
        runtime,
        "-C",
        str(repository),
        "remote",
        "add",
        "origin",
        "https://github.com/example/app.git",
    )
    observation = git.observe(repository, "main")
    assert observation.revision == revision
    assert observation.remote_url == "https://github.com/example/app.git"
    assert observation.commit_time.isoformat().endswith("+00:00")
    assert str(int(observation.commit_time.timestamp())) == (
        _git(
            runtime, "-C", str(repository), "show", "-s", "--format=%ct", revision
        ).strip()
    )
    with pytest.raises(CommandExecutionError):
        git.observe(repository, "does-not-exist")

    # Object reads never check anything out and reject unsafe paths before Git runs.
    assert git.read_text(repository, revision, "README.md") == "observed content\n"
    with pytest.raises(CommandExecutionError) as missing:
        git.read_text(repository, revision, "missing.txt")
    assert "does not exist" in missing.value.stderr
    logs_before = len(_logs(runtime, ToolName.GIT))
    for unsafe in ("", "/etc/passwd", "../README.md", "docs\\README.md"):
        with pytest.raises(InvalidInvocationError, match="safe relative path"):
            git.read_text(repository, revision, unsafe)
    with pytest.raises(InvalidInvocationError, match="full lowercase hexadecimal"):
        git.read_text(repository, "HEAD", "README.md")
    assert len(_logs(runtime, ToolName.GIT)) == logs_before

    # Detached worktrees are created for observed commits only and removed cleanly.
    worktree = root / "worktree"
    with pytest.raises(InvalidInvocationError, match="full lowercase hexadecimal"):
        git.create_worktree(repository, worktree, "main")
    with pytest.raises(CommandExecutionError) as unknown:
        git.create_worktree(repository, worktree, "d" * 40)
    assert "invalid reference" in unknown.value.stderr
    assert not worktree.exists()
    git.create_worktree(repository, worktree, revision)
    assert (worktree / "README.md").read_text(encoding="utf-8") == "observed content\n"
    assert _git(runtime, "-C", str(worktree), "rev-parse", "HEAD").strip() == revision
    assert (
        _git(runtime, "-C", str(worktree), "rev-parse", "--abbrev-ref", "HEAD").strip()
        == "HEAD"
    )
    git.remove_worktree(repository, worktree)
    assert not worktree.exists()
    assert str(worktree) not in _git(runtime, "-C", str(repository), "worktree", "list")

    # A commit time that Git accepts but that no calendar can represent is refused.
    far_future = "@99999999999999 +0000"
    _git(
        runtime,
        "-C",
        str(repository),
        "commit",
        "--quiet",
        "--allow-empty",
        "--date",
        far_future,
        "-m",
        "future",
        extra_environment={"GIT_COMMITTER_DATE": far_future},
    )
    with pytest.raises(OperationalError, match="invalid commit timestamp"):
        git.observe(repository, "HEAD")


def test_real_buildah_output_paths_and_failed_builds(tmp_path: Path) -> None:
    run_id = manifest_run_id()
    resource_id = run_id.lower()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(root / "environment", names=(ToolName.BUILDAH,))
    buildah_root = root / "buildah" / "root"
    buildah_runroot = root / "buildah" / "runroot"
    buildah = runtime.buildah()
    ready = False
    locked = root / "locked"
    try:
        assert buildah.info(root=buildah_root, runroot=buildah_runroot)
        ready = True
        context = compile_fixture(runtime, root=root, architecture="amd64")

        def build(
            layout_path: Path,
            *,
            containerfile: Path | None = None,
            build_context: Path | None = None,
            auth_file: Path | None = None,
            build_arguments: dict[str, str] | None = None,
        ) -> BuildObservation:
            return buildah.build(
                root=buildah_root,
                runroot=buildah_runroot,
                containerfile=containerfile or context / "Containerfile",
                context=build_context or context,
                platform=AMD64,
                image_name=f"localhost/conclear-{resource_id}-failures:fixture",
                layout_path=layout_path,
                layout_reference="fixture",
                source_epoch=946684800,
                build_arguments=build_arguments or {},
                auth_file=auth_file,
            )

        # Output-path problems are classified before Buildah is ever invoked.
        logs_before = len(_logs(runtime, ToolName.BUILDAH))
        regular_file = root / "file"
        regular_file.write_text("not a directory\n", encoding="utf-8")
        with pytest.raises(OperationalError, match="Unable to inspect output layout"):
            build(regular_file / "layout")
        existing = root / "existing-layout"
        existing.mkdir(mode=0o700)
        with pytest.raises(InvalidInvocationError, match="already exists"):
            build(existing)
        real_parent = root / "real-parent"
        real_parent.mkdir(mode=0o700)
        link_parent = root / "link-parent"
        link_parent.symlink_to(real_parent, target_is_directory=True)
        with pytest.raises(InvalidInvocationError, match="not a regular directory"):
            build(link_parent / "layout")
        if os.geteuid() != 0:
            locked.mkdir(mode=0o500)
            with pytest.raises(OperationalError, match="Unable to create output"):
                build(locked / "child" / "layout")
        assert len(_logs(runtime, ToolName.BUILDAH)) == logs_before

        # A failing build surfaces Buildah's own diagnostic and leaves no layout.
        broken = root / "broken"
        broken.mkdir(mode=0o700)
        broken_containerfile = broken / "Containerfile"
        broken_containerfile.write_text(
            "FROM scratch\nCOPY missing-fixture-file /missing\n", encoding="utf-8"
        )
        failed_layout = root / "layouts" / "failed"
        with pytest.raises(CommandExecutionError) as failed:
            build(
                failed_layout, containerfile=broken_containerfile, build_context=broken
            )
        assert failed.value.returncode not in (None, 0)
        assert "missing-fixture-file" in failed.value.stderr
        assert not failed_layout.exists()

        # A successful build honours explicit auth and build-argument options.
        auth_file = root / "auth.json"
        auth_file.write_text('{"auths": {}}\n', encoding="utf-8")
        auth_file.chmod(0o600)
        observation = build(
            root / "layouts" / "amd64",
            auth_file=auth_file,
            build_arguments={
                "IMAGE_VERSION": "failures",
                "IMAGE_CREATED": "2000-01-01T00:00:00Z",
            },
        )
        assert observation.graph.platforms == (AMD64,)
        assert observation.build_arguments == (
            ("IMAGE_CREATED", "2000-01-01T00:00:00Z"),
            ("IMAGE_VERSION", "failures"),
        )
        build_log = json.loads(
            _logs(runtime, ToolName.BUILDAH)[-2].read_text(encoding="utf-8")
        )
        assert "--authfile" in build_log["argv"]
        assert str(auth_file) not in json.dumps(build_log)
    finally:
        if locked.exists():
            locked.chmod(0o700)
        if ready:
            buildah.remove_storage(root=buildah_root, runroot=buildah_runroot)


def test_real_podman_import_exec_and_capability_semantics(tmp_path: Path) -> None:
    run_id = manifest_run_id()
    resource_id = run_id.lower()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(
        root / "environment", names=(ToolName.BUILDAH, ToolName.PODMAN)
    )
    buildah_root = root / "buildah" / "root"
    buildah_runroot = root / "buildah" / "runroot"
    podman_root = root / "podman" / "root"
    podman_runroot = root / "podman" / "runroot"
    podman = runtime.podman()
    containers = (f"cc-{resource_id}-caps", f"cc-{resource_id}-oneshot-rm")
    absent = f"cc-{resource_id}-absent"
    buildah_ready = False
    podman_ready = False
    try:
        assert runtime.buildah().info(root=buildah_root, runroot=buildah_runroot)
        buildah_ready = True
        assert podman.info(root=podman_root, runroot=podman_runroot)
        podman_ready = True
        context = compile_fixture(runtime, root=root, architecture="amd64")
        built = runtime.buildah().build(
            root=buildah_root,
            runroot=buildah_runroot,
            containerfile=context / "Containerfile",
            context=context,
            platform=AMD64,
            image_name=f"localhost/conclear-{resource_id}-failures:build",
            layout_path=root / "layouts" / "amd64",
            layout_reference="fixture",
            source_epoch=946684800,
            build_arguments={},
            auth_file=None,
        )
        image_name = f"localhost/conclear-{resource_id}-failures:runtime"

        # The imported digest must equal the layout digest; Podman's answer is checked.
        with pytest.raises(OperationalError, match="differs from layout") as mismatch:
            podman.import_layout(
                root=podman_root,
                runroot=podman_runroot,
                layout_path=built.layout_path,
                layout_reference="fixture",
                image_name=image_name,
                expected_digest=Digest("sha256:" + "0" * 64),
            )
        assert mismatch.value.code == "CC0305"
        imported = podman.import_layout(
            root=podman_root,
            runroot=podman_runroot,
            layout_path=built.layout_path,
            layout_reference="fixture",
            image_name=image_name,
            expected_digest=built.graph.digest,
        )
        assert imported.digest == built.graph.digest

        # Podman's own failures are never mistaken for container observations.
        with pytest.raises(CommandExecutionError) as inspect_absent:
            podman.inspect_container(
                root=podman_root, runroot=podman_runroot, name=absent
            )
        assert inspect_absent.value.returncode == 125
        with pytest.raises(CommandExecutionError) as exec_absent:
            podman.exec_observe(
                root=podman_root,
                runroot=podman_runroot,
                name=absent,
                command=("/app/conclear-fixture", "health"),
                timeout_seconds=30,
            )
        assert exec_absent.value.returncode == 125
        with pytest.raises(CommandExecutionError):
            podman.wait(
                root=podman_root,
                runroot=podman_runroot,
                name=absent,
                timeout_seconds=30,
            )

        # Declared capabilities are added on top of the dropped set and observable.
        privileged = replace(
            runtime_config(profile="service"), capabilities=("CAP_NET_BIND_SERVICE",)
        )
        service = podman.create_container(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[0],
            image_name=image_name,
            runtime=privileged,
            platform=AMD64,
            environment=(("FIXTURE_NOTE", "capabilities"),),
        )
        assert service.status == "running"
        controls = podman.inspect_controls(
            root=podman_root, runroot=podman_runroot, name=containers[0]
        )
        # Podman reports CapAdd relative to its default set, so an added default
        # capability shows up only in the bounding and effective sets.
        assert controls.cap_add == ()
        assert controls.bounding_capabilities == ("CAP_NET_BIND_SERVICE",)
        assert controls.effective_capabilities == ("CAP_NET_BIND_SERVICE",)
        assert controls.cap_drop
        failed_command = podman.exec_observe(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[0],
            command=("/app/conclear-fixture", "arch-check", "not-an-architecture"),
            timeout_seconds=30,
        )
        assert failed_command.exit_status == 3
        assert failed_command.stdout == ""
        healthy = podman.exec_observe(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[0],
            command=("/app/conclear-fixture", "arch-check", "amd64"),
            timeout_seconds=30,
        )
        assert healthy.exit_status == 0
        assert healthy.stdout.strip() == "amd64"
        podman.signal(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[0],
            signal_name="TERM",
        )
        assert (
            podman.wait(
                root=podman_root,
                runroot=podman_runroot,
                name=containers[0],
                timeout_seconds=30,
            )
            == 0
        )

        # A finished container is removable without force, and removal is idempotent.
        podman.create_container(
            root=podman_root,
            runroot=podman_runroot,
            name=containers[1],
            image_name=image_name,
            runtime=runtime_config(profile="one-shot"),
            platform=AMD64,
            arguments=("one-shot",),
        )
        assert (
            podman.wait(
                root=podman_root,
                runroot=podman_runroot,
                name=containers[1],
                timeout_seconds=30,
            )
            == 0
        )
        podman.remove(root=podman_root, runroot=podman_runroot, name=containers[1])
        with pytest.raises(CommandExecutionError):
            podman.inspect_container(
                root=podman_root, runroot=podman_runroot, name=containers[1]
            )
        podman.remove(root=podman_root, runroot=podman_runroot, name=containers[1])
    finally:
        if podman_ready:
            for name in containers:
                podman.remove(
                    root=podman_root, runroot=podman_runroot, name=name, force=True
                )
            podman.remove_storage(root=podman_root, runroot=podman_runroot)
        if buildah_ready:
            runtime.buildah().remove_storage(root=buildah_root, runroot=buildah_runroot)


def _write_minimal_layout(path: Path, reference: str) -> Digest:
    """Write a valid single-manifest OCI layout with no layers."""
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": []},
        }
    ).encode()
    config_digest = sha256_bytes(config)
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [],
        }
    ).encode()
    manifest_digest = sha256_bytes(manifest)
    blobs = path / "blobs" / "sha256"
    blobs.mkdir(mode=0o700, parents=True)
    (blobs / config_digest.removeprefix("sha256:")).write_bytes(config)
    (blobs / manifest_digest.removeprefix("sha256:")).write_bytes(manifest)
    (path / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}\n')
    (path / "index.json").write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": manifest_digest,
                        "size": len(manifest),
                        "annotations": {"org.opencontainers.image.ref.name": reference},
                    }
                ],
            }
        )
    )
    return Digest(manifest_digest)


def test_real_skopeo_never_treats_transport_failure_as_absence(tmp_path: Path) -> None:
    run_id = manifest_run_id()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(root / "environment", names=(ToolName.SKOPEO,))
    skopeo = runtime.skopeo()
    repository = f"{CLOSED_REGISTRY}/conclear/{run_id.lower()}"
    tagged = OCIReference.parse(f"{repository}:probe")
    by_digest = OCIReference.parse(f"{repository}@sha256:{'a' * 64}")
    auth_file = root / "auth.json"
    auth_file.write_text('{"auths": {}}\n', encoding="utf-8")
    auth_file.chmod(0o600)

    with pytest.raises(CommandExecutionError) as refused:
        skopeo.resolve_digest(tagged)
    assert "connection refused" in refused.value.stderr
    first_log = json.loads(
        _logs(runtime, ToolName.SKOPEO)[0].read_text(encoding="utf-8")
    )
    assert first_log["attempts"] == 3

    # A refused connection is ambiguous, so it is never reported as "absent".
    with pytest.raises(CommandExecutionError):
        skopeo.resolve_optional(tagged, auth_file=auth_file)

    # The layout parent is created for Skopeo, and a failed copy leaves no layout.
    copied_layout = root / "layouts" / "copied"
    with pytest.raises(CommandExecutionError) as pull_failure:
        skopeo.copy_registry_to_layout(
            source=by_digest,
            layout_path=copied_layout,
            layout_reference="copied",
            auth_file=auth_file,
        )
    assert "connection refused" in pull_failure.value.stderr
    assert copied_layout.parent.is_dir()
    assert not copied_layout.exists()
    logs_before = len(_logs(runtime, ToolName.SKOPEO))
    copied_layout.mkdir()
    with pytest.raises(InvalidInvocationError, match="already exists"):
        skopeo.copy_registry_to_layout(
            source=by_digest,
            layout_path=copied_layout,
            layout_reference="copied",
            auth_file=None,
        )
    assert len(_logs(runtime, ToolName.SKOPEO)) == logs_before

    layout = root / "layouts" / "minimal"
    _write_minimal_layout(layout, "minimal")
    for auth in (None, auth_file):
        with pytest.raises(CommandExecutionError) as push_failure:
            skopeo.copy_layout_to_registry(
                layout_path=layout,
                layout_reference="minimal",
                destination=tagged,
                auth_file=auth,
            )
        assert "connection refused" in push_failure.value.stderr
    push_log = json.loads(
        _logs(runtime, ToolName.SKOPEO)[-1].read_text(encoding="utf-8")
    )
    assert "--dest-authfile" in push_log["argv"]
    assert str(auth_file) not in json.dumps(push_log)

    logs_before = len(_logs(runtime, ToolName.SKOPEO))
    with pytest.raises(InvalidInvocationError, match="requires a tag reference"):
        skopeo.delete(by_digest, auth_file=auth_file)
    with pytest.raises(InvalidInvocationError, match="requires a tag reference"):
        skopeo.delete(OCIReference.parse(repository), auth_file=auth_file)
    assert len(_logs(runtime, ToolName.SKOPEO)) == logs_before
    with pytest.raises(CommandExecutionError) as delete_failure:
        skopeo.delete(tagged, auth_file=auth_file)
    assert "connection refused" in delete_failure.value.stderr


def test_real_hadolint_failures_and_configuration_paths(tmp_path: Path) -> None:
    run_id = manifest_run_id()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(
        root / "environment", names=(ToolName.HADOLINT,)
    )
    hadolint = runtime.hadolint()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Findings on a non-zero exit are retained; a missing file is a failure.
    containerfile = root / "Containerfile"
    containerfile.write_text("FROM debian:latest\n", encoding="utf-8")
    findings = hadolint.check(containerfile, config_directory=root)
    assert "DL3007" in {finding.code for finding in findings}
    assert all(finding.line >= 1 for finding in findings)
    with pytest.raises(CommandExecutionError) as missing:
        hadolint.check(root / "absent-containerfile", config_directory=root)
    assert missing.value.stdout == ""
    assert "does not exist" in missing.value.stderr

    # Configuration discovery refuses an uninspectable context.
    regular_file = root / "not-a-directory"
    regular_file.write_text("x\n", encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="Unable to inspect Hadolint"):
        hadolint.check(containerfile, config_directory=regular_file)


def test_runtime_resolves_only_requested_tools(tmp_path: Path) -> None:
    run_id = manifest_run_id()
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(root / "environment", names=(ToolName.GIT,))

    assert [identity.name for identity in runtime.identities] == ["git"]
    runtime.assert_unchanged()
    assert runtime.git() is runtime.git()
    with pytest.raises(OperationalError, match="did not resolve skopeo"):
        runtime.skopeo()
    with pytest.raises(OperationalError, match="did not resolve cosign"):
        runtime.cosign()
