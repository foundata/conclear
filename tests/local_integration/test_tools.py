import os
from pathlib import Path

import pytest

from conclear.path_safety import contained_path
from conclear.process import CommandRequest, OperationKind
from conclear.runtime import ApplicationRuntime
from conclear.tools import SUPPORTED_TOOLS, ToolName

pytestmark = pytest.mark.local_integration


def test_supported_real_tool_matrix_and_read_only_interfaces(tmp_path: Path) -> None:
    runtime = ApplicationRuntime.create(tmp_path / "environment")

    assert {name: runtime.tools[name].version for name in ToolName} == {
        name: next(iter(SUPPORTED_TOOLS[name].supported_versions)) for name in ToolName
    }
    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    (repository / "tracked.txt").write_text("test\n", encoding="utf-8")
    git = runtime.tools[ToolName.GIT].path
    for arguments in (
        ("init",),
        ("add", "tracked.txt"),
        (
            "-c",
            "user.name=ConClear test",
            "-c",
            "user.email=conclear@example.invalid",
            "commit",
            "-m",
            "test: create integration fixture",
        ),
        (
            "remote",
            "add",
            "origin",
            "https://github.com/example/conclear-integration.git",
        ),
    ):
        runtime.runner.run(
            CommandRequest(
                argv=(str(git), *arguments),
                environment={
                    **runtime.environment,
                    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
                    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
                },
                timeout_seconds=30,
                cwd=repository,
                operation=OperationKind.WRITE,
            )
        )
    observation = runtime.git().observe(repository, "HEAD")
    assert len(observation.revision) in {40, 64}
    cosign = runtime.tools[ToolName.COSIGN].path
    help_text: dict[str, str] = {}
    for command in ("sign", "sign-blob", "verify-blob"):
        help_text[command] = runtime.runner.run(
            CommandRequest(
                argv=(str(cosign), command, "--help"),
                environment=runtime.environment,
                timeout_seconds=30,
            )
        ).stdout
    assert "--use-signing-config" in help_text["sign"]
    assert "--bundle" in help_text["sign-blob"]
    assert "--signing-config" in help_text["sign-blob"]
    assert "--bundle" in help_text["verify-blob"]
    assert "--insecure-ignore-tlog" in help_text["verify-blob"]


def test_real_rootless_storage_and_local_analysis_are_run_owned(
    tmp_path: Path,
) -> None:
    run_id = os.environ.get("CONCLEAR_TEST_RUN_ID", "pytest-local-integration")
    root = contained_path(tmp_path, run_id, must_exist=False)
    runtime = ApplicationRuntime.create(
        root / "environment",
        names=(
            ToolName.BUILDAH,
            ToolName.PODMAN,
            ToolName.HADOLINT,
            ToolName.TRIVY,
        ),
    )
    buildah_root = root / "buildah" / "root"
    buildah_runroot = root / "buildah" / "runroot"
    podman_root = root / "podman" / "root"
    podman_runroot = root / "podman" / "runroot"

    assert runtime.buildah().info(root=buildah_root, runroot=buildah_runroot)
    podman_info = runtime.podman().info(root=podman_root, runroot=podman_runroot)
    assert podman_info
    assert buildah_root.is_relative_to(root)
    assert podman_root.is_relative_to(root)

    containerfile = root / "Containerfile"
    containerfile.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    containerfile.write_text(
        'FROM scratch\nUSER 65532:65532\nENTRYPOINT ["/app"]\n',
        encoding="utf-8",
    )
    assert runtime.hadolint().check(containerfile) == ()

    source = root / "source"
    source.mkdir(mode=0o700)
    (source / "settings.yaml").write_text("enabled: true\n", encoding="utf-8")
    report = root / "reports" / "filesystem.json"
    report.parent.mkdir(mode=0o700)
    cache = root / "trivy-cache"
    cache.mkdir(mode=0o700)
    scan = runtime.trivy().scan_filesystem(
        path=source,
        report_path=report,
        cache_root=cache,
        scanners=("secret", "misconfig"),
    )
    assert scan.path == report
    assert report.is_file()
