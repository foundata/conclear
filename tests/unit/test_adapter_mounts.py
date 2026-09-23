"""An adapter running a tool from its image sees only what it mounted."""

import hashlib
from pathlib import Path

import pytest

from conclear.adapters.base import ToolAdapter
from conclear.errors import OperationalError
from conclear.process import CommandRequest, ProcessResult
from conclear.tool_images import ImageBackedTool, ToolImageStore
from conclear.tools import SUPPORTED_TOOLS, ResolvedTool, ToolName

MANIFEST = "sha256:" + "2" * 64
ENVIRONMENT = {"PATH": "/usr/bin", "HOME": "/run/home"}


def _result(stdout: str = "") -> ProcessResult:
    return ProcessResult(("/tool",), 0, stdout, "", 0.0, 1, False, False)


class RecordingRunner:
    """Answer the image recheck with the pinned digest and record every run."""

    def __init__(self, digest: str) -> None:
        self.digest = digest
        self.runs: list[CommandRequest] = []

    def run(self, request: CommandRequest) -> ProcessResult:
        if "inspect" in request.argv:
            return _result(self.digest + "\n")
        self.runs.append(request)
        return _result()


class _Probe(ToolAdapter):
    """Expose the protected helpers to the tests without an adapter of its own."""

    def path(self, path: Path, **options: object) -> str:
        return self._path(path, **options)  # type: ignore[arg-type]

    def run(self, arguments: tuple[str, ...], **options: object) -> ProcessResult:
        return self._run(arguments, timeout_seconds=10, **options)  # type: ignore[arg-type]


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


def _image_probe(tmp_path: Path) -> tuple[_Probe, RecordingRunner, ImageBackedTool]:
    image = SUPPORTED_TOOLS[ToolName.TRIVY].image
    assert image is not None
    runner = RecordingRunner(image.digest)
    tool = ImageBackedTool(
        name=ToolName.TRIVY,
        image=image,
        version="0.74.0",
        reported_version="Version: 0.74.0",
        manifest_digest=MANIFEST,
        executor=_host_tool(tmp_path, ToolName.PODMAN),
        store=ToolImageStore.below(tmp_path / "tool-images"),
        runner=runner,
        environment=ENVIRONMENT,
    )
    probe = _Probe(
        tool=tool, runner=runner, environment=ENVIRONMENT, log_directory=tmp_path
    )
    return probe, runner, tool


def _host_probe(tmp_path: Path) -> tuple[_Probe, RecordingRunner]:
    tool = _host_tool(tmp_path, ToolName.HADOLINT)
    runner = RecordingRunner("unused")
    probe = _Probe(
        tool=tool, runner=runner, environment=ENVIRONMENT, log_directory=tmp_path
    )
    return probe, runner


def _mounts(argv: tuple[str, ...]) -> list[str]:
    return [argv[index + 1] for index, item in enumerate(argv) if item == "--mount"]


def test_a_host_executable_sees_absolute_host_paths_and_no_mounts(
    tmp_path: Path,
) -> None:
    probe, runner = _host_probe(tmp_path)
    layout = tmp_path / "layout"
    layout.mkdir()

    assert probe.path(layout) == str(layout)
    assert probe.path(tmp_path / "out" / "report.json", writable=True) == str(
        tmp_path / "out" / "report.json"
    )
    probe.run(("--format", "json", str(layout)), cwd=tmp_path)

    (request,) = runner.runs
    assert request.argv == (str(probe._tool.path), "--format", "json", str(layout))  # type: ignore[union-attr]
    assert request.cwd == tmp_path
    assert request.environment == ENVIRONMENT


def test_an_image_runs_read_only_offline_with_exactly_the_registered_mounts(
    tmp_path: Path,
) -> None:
    probe, runner, tool = _image_probe(tmp_path)
    layout = tmp_path / "layout"
    layout.mkdir()
    report = tmp_path / "reports" / "image-scan.json"
    report.parent.mkdir()
    invocation = tmp_path / "invocation"
    invocation.mkdir()

    seen_layout = probe.path(layout, name="layout")
    seen_report = probe.path(report, writable=True, name="reports")
    probe.run(
        ("image", "--input", seen_layout, "--output", seen_report),
        cwd=invocation,
        extra_environment={"TRIVY_NO_PROGRESS": "true"},
    )

    assert seen_layout == "/conclear/layout"
    assert seen_report == "/conclear/reports/image-scan.json"
    (request,) = runner.runs
    argv = request.argv
    assert argv[: 1 + len(tool.store.arguments)] == (
        str(tool.executor.path),
        *tool.store.arguments,
    )
    head = argv[1 + len(tool.store.arguments) :]
    assert head[:6] == ("run", "--rm", "--pull", "never", "--read-only", "--network")
    assert head[6] == "none"
    assert argv[argv.index("--workdir") + 1] == "/conclear/mount2"
    assert _mounts(argv) == [
        f"type=bind,src={layout},target=/conclear/layout,ro,nosuid,nodev,relabel=private",
        f"type=bind,src={report.parent},target=/conclear/reports,rw,nosuid,nodev,"
        "relabel=private",
        f"type=bind,src={invocation},target=/conclear/mount2,ro,nosuid,nodev,"
        "relabel=private",
    ]
    assert argv[argv.index("--env") + 1] == "TRIVY_NO_PROGRESS=true"
    tail = argv[argv.index("--entrypoint") :]
    assert tail == (
        "--entrypoint",
        tool.image.executable,
        tool.image.pinned_reference,
        "image",
        "--input",
        "/conclear/layout",
        "--output",
        "/conclear/reports/image-scan.json",
    )
    # Podman itself runs in the sanitized environment; the call's variables
    # reach only the tool, and the container has no host working directory.
    assert request.environment == ENVIRONMENT
    assert request.cwd is None


def test_a_call_that_needs_the_network_says_so_and_nothing_else_changes(
    tmp_path: Path,
) -> None:
    probe, runner, _tool = _image_probe(tmp_path)

    probe.run(("image", "--download-db-only"), network=True)

    (request,) = runner.runs
    assert "--network" not in request.argv
    assert "--read-only" in request.argv


def test_paths_below_a_registered_directory_reuse_and_may_widen_its_mount(
    tmp_path: Path,
) -> None:
    probe, runner, _tool = _image_probe(tmp_path)
    workspace = tmp_path / "workspace"
    nested = workspace / "source" / "context"
    nested.mkdir(parents=True)
    containerfile = nested / "Containerfile"
    containerfile.write_text("FROM scratch\n")

    root = probe.path(workspace, name="workspace")
    assert (
        probe.path(containerfile) == "/conclear/workspace/source/context/Containerfile"
    )
    assert probe.path(nested) == "/conclear/workspace/source/context"
    assert probe.path(workspace / "out" / "result.json", writable=True) == (
        "/conclear/workspace/out/result.json"
    )
    probe.run((root,))

    (request,) = runner.runs
    assert _mounts(request.argv) == [
        f"type=bind,src={workspace},target=/conclear/workspace,rw,nosuid,nodev,"
        "relabel=private"
    ]


def test_registered_mounts_do_not_leak_into_the_next_call(tmp_path: Path) -> None:
    probe, runner, _tool = _image_probe(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()

    probe.path(first)
    probe.run(())
    assert probe.path(second) == "/conclear/mount0"
    probe.run(())

    assert [_mounts(request.argv) for request in runner.runs] == [
        [
            f"type=bind,src={first},target=/conclear/mount0,ro,nosuid,nodev,relabel=private"
        ],
        [
            f"type=bind,src={second},target=/conclear/mount0,ro,nosuid,nodev,relabel=private"
        ],
    ]


def test_two_directories_cannot_share_one_mount_name(tmp_path: Path) -> None:
    probe, _runner, _tool = _image_probe(tmp_path)
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()

    probe.path(tmp_path / "a", name="same")
    with pytest.raises(OperationalError, match="already taken"):
        probe.path(tmp_path / "b", name="same")


def test_secret_files_are_mounted_read_only_and_still_named_for_redaction(
    tmp_path: Path,
) -> None:
    probe, runner, _tool = _image_probe(tmp_path)
    secret = tmp_path / "keys" / "cosign.key"
    secret.parent.mkdir()
    secret.write_text("private")

    probe.run(("sign",), secret_paths=(secret,))

    (request,) = runner.runs
    assert _mounts(request.argv) == [
        f"type=bind,src={secret.parent},target=/conclear/mount0,ro,nosuid,nodev,"
        "relabel=private"
    ]
    assert request.secret_paths == (secret,)


def test_the_image_is_rechecked_before_every_call(tmp_path: Path) -> None:
    probe, runner, _tool = _image_probe(tmp_path)

    probe.run(())
    runner.digest = "sha256:" + "e" * 64
    with pytest.raises(OperationalError, match="image changed during the run"):
        probe.run(())
    assert len(runner.runs) == 1
