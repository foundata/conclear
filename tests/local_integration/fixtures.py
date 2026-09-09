"""Run-owned fixtures shared by the local-integration and emulation tiers."""

import os
import shutil
from pathlib import Path

import pytest

from conclear.config import RuntimeConfig
from conclear.process import CommandRequest, OperationKind
from conclear.runtime import ApplicationRuntime
from conclear.tools import ToolName, ToolResolver

FIXTURE_SOURCE = r"""
package main

import (
	"fmt"
	"os"
	"runtime"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

func waitForSignal() os.Signal {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	return <-signals
}

func main() {
	mode := "service"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "health", "one-shot":
		return
	case "arch-check":
		if len(os.Args) < 3 || os.Args[2] != runtime.GOARCH {
			os.Exit(3)
		}
		fmt.Println(runtime.GOARCH)
		return
	case "keygen":
		if err := os.WriteFile("/output/key", []byte("private-test-key"), 0600); err != nil {
			os.Exit(1)
		}
		return
	case "prepare":
		input, err := os.ReadFile("/input/value")
		if err != nil || string(input) != "fixture-value" {
			os.Exit(1)
		}
		key, err := os.ReadFile("/key/key")
		if err != nil || string(key) != "private-test-key" {
			os.Exit(1)
		}
		if err := os.WriteFile("/output/result", []byte("compatible"), 0600); err != nil {
			os.Exit(1)
		}
		return
	case "health-input":
		result, err := os.ReadFile("/input/result")
		if err != nil || string(result) != "compatible" || os.Getenv("SERVICE_SELECTOR") != "test" {
			os.Exit(1)
		}
		if _, err := os.Stat("/tmp/conclear-service-ready"); err != nil {
			fmt.Fprintln(os.Stderr, "service is initializing")
			os.Exit(1)
		}
		fmt.Println("service is ready")
		return
	case "one-shot-input":
		result, err := os.ReadFile("/input/result")
		if err != nil || string(result) != "compatible" || os.Getenv("SERVICE_SELECTOR") != "test" {
			os.Exit(1)
		}
		return
	case "service-input":
		result, err := os.ReadFile("/input/result")
		if err != nil || string(result) != "compatible" || os.Getenv("SERVICE_SELECTOR") != "test" {
			os.Exit(1)
		}
		time.Sleep(750 * time.Millisecond)
		if err := os.WriteFile("/tmp/conclear-service-ready", []byte("ok"), 0600); err != nil {
			os.Exit(1)
		}
		waitForSignal()
		return
	case "supervisor-health":
		if _, err := os.Stat("/tmp/conclear-supervisor-ready"); err != nil {
			os.Exit(1)
		}
		return
	case "write-immutable":
		if err := os.WriteFile("/app/mutation", []byte("unexpected"), 0600); err == nil {
			os.Exit(1)
		}
		return
	case "write-temporary":
		if err := os.WriteFile("/tmp/conclear-fixture", []byte("ok"), 0600); err != nil {
			os.Exit(1)
		}
		if err := os.Remove("/tmp/conclear-fixture"); err != nil {
			os.Exit(1)
		}
		return
	case "child":
		waitForSignal()
		return
	case "supervisor":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(signals)
		child := exec.Command("/app/conclear-fixture", "child")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(1)
		}
		if err := os.WriteFile("/tmp/conclear-supervisor-ready", []byte("ok"), 0600); err != nil {
			_ = child.Process.Kill()
			os.Exit(1)
		}
		received := <-signals
		_ = os.Remove("/tmp/conclear-supervisor-ready")
		if err := child.Process.Signal(received); err != nil {
			os.Exit(1)
		}
		if err := child.Wait(); err != nil {
			if status, ok := err.(*exec.ExitError); ok {
				os.Exit(status.ExitCode())
			}
			os.Exit(1)
		}
		return
	case "service":
		waitForSignal()
		return
	default:
		os.Exit(64)
	}
}
"""

FIXTURE_CONTAINERFILE = """\
FROM scratch AS runtime
ARG IMAGE_CREATED
ARG IMAGE_REVISION
ARG IMAGE_SOURCE
ARG IMAGE_VERSION
COPY conclear-fixture /app/conclear-fixture
LABEL org.opencontainers.image.created=$IMAGE_CREATED
LABEL org.opencontainers.image.revision=$IMAGE_REVISION
LABEL org.opencontainers.image.source=$IMAGE_SOURCE
LABEL org.opencontainers.image.version=$IMAGE_VERSION
HEALTHCHECK CMD [\"/app/conclear-fixture\", \"health\"]
USER 65532:65532
ENTRYPOINT [\"/app/conclear-fixture\"]
CMD [\"service\"]
"""


def manifest_run_id() -> str:
    value = os.environ.get("CONCLEAR_TEST_RUN_ID")
    if value is None:
        pytest.skip("local integration tests require a manifest-owned run ID")
    return value


def compile_fixture(
    runtime: ApplicationRuntime,
    *,
    root: Path,
    architecture: str,
) -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("the scratch integration fixture requires Go")
    context = root / "contexts" / architecture
    context.mkdir(mode=0o700, parents=True)
    source = context / "main.go"
    source.write_text(FIXTURE_SOURCE, encoding="utf-8")
    (context / "Containerfile").write_text(
        FIXTURE_CONTAINERFILE,
        encoding="utf-8",
    )
    (context / ".containerignore").write_text(
        "main.go\nContainerfile\n.containerignore\n",
        encoding="utf-8",
    )
    runtime.runner.run(
        CommandRequest(
            argv=(
                str(Path(go).resolve(strict=True)),
                "build",
                "-trimpath",
                "-ldflags=-buildid=",
                "-o",
                str(context / "conclear-fixture"),
                str(source),
            ),
            environment={
                **runtime.environment,
                "CGO_ENABLED": "0",
                "GOARCH": architecture,
                "GOOS": "linux",
            },
            timeout_seconds=300,
            cwd=context,
            operation=OperationKind.WRITE,
        )
    )
    return context


def runtime_config(*, profile: str) -> RuntimeConfig:
    return RuntimeConfig(
        profile=profile,
        user=65532,
        read_only=True,
        writable_mounts=("/tmp",),
        memory="128MiB",
        cpus=1.0,
        pids=64,
        nofile=256,
        health_command=("/app/conclear-fixture", "health"),
        immutable_paths=("/app",),
        capabilities=(),
        startup_timeout_seconds=30,
        shutdown_timeout_seconds=30,
    )


def tool_locator(name: str, search_path: str) -> str | None:
    """Locate a tool, honoring the Trivy release override.

    `CONCLEAR_TEST_TRIVY` names the absolute path of a verified Trivy release
    build inside the manifest-owned workspace, so the tier can exercise a
    version the workstation does not install without replacing the host tool.
    """
    override = os.environ.get("CONCLEAR_TEST_TRIVY")
    if name == ToolName.TRIVY.value and override:
        return override
    return shutil.which(name, path=search_path)


def tool_resolver() -> ToolResolver:
    """Return the resolver every real-tool case uses."""
    return ToolResolver(locator=tool_locator)
