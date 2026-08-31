"""Provider-independent clean-checkout distribution release gate."""

import os
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from conclear.build_identity import write_embedded_identity
from conclear.errors import (
    CommandExecutionError,
    CommandTimeoutError,
    ConClearError,
    OperationalError,
)
from conclear.identity import GUIDE_REVISION
from conclear.path_safety import extract_tar_safely
from conclear.process import (
    CommandRequest,
    OperationKind,
    ProcessEnvironment,
    ProcessResult,
    ProcessRunner,
)
from conclear.values import validate_source_revision

_PYTHON_VERSIONS = ("3.12", "3.13", "3.14")
_FORBIDDEN_PARTS = frozenset(
    {
        ".git",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
    }
)


@dataclass(frozen=True, slots=True)
class GateRuntime:
    """Resolved tools and sanitized environment for one release-check run."""

    git: Path
    uv: Path
    pythons: dict[str, Path]
    environment: dict[str, str]
    runner: ProcessRunner

    @classmethod
    def create(cls, temporary_root: Path) -> "GateRuntime":
        """Resolve required local tools and construct a run-owned environment."""
        paths = {
            "home": temporary_root / "home",
            "config": temporary_root / "config",
            "cache": temporary_root / "cache",
            "state": temporary_root / "state",
            "runtime": temporary_root / "runtime",
        }
        for path in paths.values():
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment = ProcessEnvironment(
            home=paths["home"],
            config_home=paths["config"],
            cache_home=paths["cache"],
            state_home=paths["state"],
            runtime_dir=paths["runtime"],
        ).values(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "NO_COLOR": "1",
                "UV_NO_PROGRESS": "1",
                "UV_PYTHON_DOWNLOADS": "never",
            }
        )
        return cls(
            git=_executable("git"),
            uv=_executable("uv"),
            pythons={
                version: _executable(f"python{version}") for version in _PYTHON_VERSIONS
            },
            environment=environment,
            runner=ProcessRunner(),
        )

    def run(
        self,
        label: str,
        argv: tuple[str, ...],
        *,
        cwd: Path | None = None,
        timeout_seconds: float = 1800,
        operation: OperationKind = OperationKind.READ,
    ) -> ProcessResult:
        """Run one bounded gate step with actionable failure context."""
        print(f"release-check: {label}", flush=True)
        try:
            return self.runner.run(
                CommandRequest(
                    argv=argv,
                    environment=self.environment,
                    timeout_seconds=timeout_seconds,
                    cwd=cwd,
                    operation=operation,
                    max_output_bytes=4 * 1024 * 1024,
                )
            )
        except (CommandExecutionError, CommandTimeoutError) as exc:
            raise OperationalError(
                f"Release check failed during {label}: {exc}"
            ) from exc


def run_release_check(repository: Path | None = None) -> None:
    """Run all local release-readiness checks from one clean committed tree."""
    selected = (repository or Path.cwd()).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="conclear-release-check-") as value:
        temporary_root = Path(value)
        runtime = GateRuntime.create(temporary_root)
        root = _repository_root(runtime, selected)
        _require_clean(runtime, root)
        revision = _revision(runtime, root)
        archive = temporary_root / "source.tar"
        runtime.run(
            "create clean source archive",
            (
                str(runtime.git),
                "-C",
                str(root),
                "archive",
                "--format=tar",
                f"--output={archive}",
                revision,
            ),
            operation=OperationKind.WRITE,
        )
        staged = temporary_root / "checkout"
        extract_tar_safely(archive, staged)
        write_embedded_identity(staged / "src" / "conclear", revision)
        _run_source_gates(runtime, staged)
        _clear_generated_files(staged)
        artifacts = temporary_root / "artifacts"
        artifacts.mkdir(mode=0o700)
        runtime.run(
            "build source distribution",
            (
                str(runtime.uv),
                "build",
                "--sdist",
                "--out-dir",
                str(artifacts),
                str(staged),
            ),
            timeout_seconds=600,
            operation=OperationKind.WRITE,
        )
        sdist = _one_artifact(artifacts, "*.tar.gz")
        validate_distribution_artifact(sdist, kind="sdist")
        runtime.run(
            "build wheel from source distribution",
            (
                str(runtime.uv),
                "build",
                "--wheel",
                "--out-dir",
                str(artifacts),
                str(sdist),
            ),
            timeout_seconds=600,
            operation=OperationKind.WRITE,
        )
        wheel = _one_artifact(artifacts, "*.whl")
        validate_distribution_artifact(wheel, kind="wheel")
        _smoke_wheel(runtime, temporary_root, wheel, revision)
    print("release-check: all checks passed", flush=True)


def validate_distribution_artifact(path: Path, *, kind: str) -> None:
    """Reject unsafe, generated or identity-incomplete distribution contents."""
    if kind == "sdist":
        names = _tar_names(path)
        suffixes = {
            "pyproject.toml",
            "uv.lock",
            "docs/conformance.md",
            "LICENSES/GPL-3.0-or-later.txt",
            "src/conclear/_embedded_identity.py",
        }
    elif kind == "wheel":
        names = _wheel_names(path)
        suffixes = {
            "conclear/_embedded_identity.py",
            "conclear/data/checks.json",
            "conclear/schemas/config.schema.json",
            "conclear/schemas/profile.schema.json",
            "conclear/schemas/provenance.schema.json",
            "conclear/schemas/record.schema.json",
            "conclear/schemas/result.schema.json",
        }
        if any(name.endswith("conclear/_development_identity.py") for name in names):
            raise OperationalError("Wheel contains development-only source identity")
    else:
        raise ValueError(f"Unknown distribution kind: {kind}")
    for suffix in suffixes:
        if not any(name == suffix or name.endswith(f"/{suffix}") for name in names):
            raise OperationalError(f"{kind} is missing required file {suffix}")
    for name in names:
        member = _artifact_member(name)
        if any(part in _FORBIDDEN_PARTS for part in member.parts):
            raise OperationalError(f"{kind} contains generated path {name}")
        if member.suffix in {".pyc", ".pyo"} or member.name == ".coverage":
            raise OperationalError(f"{kind} contains generated file {name}")


def _run_source_gates(runtime: GateRuntime, staged: Path) -> None:
    python_312 = runtime.pythons["3.12"]
    runtime.run(
        "synchronize Python 3.12 development environment",
        (
            str(runtime.uv),
            "sync",
            "--frozen",
            "--all-groups",
            "--python",
            str(python_312),
        ),
        cwd=staged,
        timeout_seconds=600,
        operation=OperationKind.WRITE,
    )
    for label, arguments in (
        ("check formatting", ("ruff", "format", "--check", ".")),
        ("lint", ("ruff", "check", ".")),
        ("strict type check", ("mypy", "--strict", "src", "tests")),
        (
            "check generated conformance documentation",
            ("python", "-m", "conclear.conformance", "--check"),
        ),
    ):
        runtime.run(
            label,
            (str(runtime.uv), "run", "--frozen", *arguments),
            cwd=staged,
            timeout_seconds=600,
        )
    for version in _PYTHON_VERSIONS:
        runtime.run(
            f"synchronize Python {version} test environment",
            (
                str(runtime.uv),
                "sync",
                "--frozen",
                "--all-groups",
                "--python",
                str(runtime.pythons[version]),
            ),
            cwd=staged,
            timeout_seconds=600,
            operation=OperationKind.WRITE,
        )
        coverage = (
            (
                "--cov=conclear",
                "--cov-branch",
                "--cov-report=term-missing",
            )
            if version == "3.12"
            else ()
        )
        runtime.run(
            f"run Python {version} unit tests",
            (
                str(runtime.uv),
                "run",
                "--frozen",
                "pytest",
                "-m",
                "unit",
                "--strict-markers",
                "--strict-config",
                *coverage,
            ),
            cwd=staged,
            timeout_seconds=600,
        )


def _smoke_wheel(
    runtime: GateRuntime,
    temporary_root: Path,
    wheel: Path,
    revision: str,
) -> None:
    install = temporary_root / "wheel-install"
    runtime.run(
        "create clean wheel environment",
        (
            str(runtime.uv),
            "venv",
            "--python",
            str(runtime.pythons["3.12"]),
            str(install),
        ),
        operation=OperationKind.WRITE,
    )
    python = install / "bin" / "python"
    command = install / "bin" / "conclear"
    runtime.run(
        "install wheel",
        (str(runtime.uv), "pip", "install", "--python", str(python), str(wheel)),
        timeout_seconds=600,
        operation=OperationKind.WRITE,
    )
    runtime.run(
        "import installed package",
        (
            str(python),
            "-c",
            (
                "import conclear; "
                "from conclear.identity import IDENTITY; "
                f"assert IDENTITY.source_revision == {revision!r}"
            ),
        ),
    )
    version = runtime.run("smoke --version", (str(command), "--version"))
    if revision not in version.stdout or GUIDE_REVISION not in version.stdout:
        raise OperationalError("Installed --version omitted embedded identities")
    help_result = runtime.run("smoke --help", (str(command), "--help"))
    if "Usage: conclear" not in help_result.stdout:
        raise OperationalError("Installed --help output is malformed")


def _repository_root(runtime: GateRuntime, selected: Path) -> Path:
    result = runtime.run(
        "locate repository",
        (str(runtime.git), "-C", str(selected), "rev-parse", "--show-toplevel"),
    )
    try:
        root = Path(result.stdout.strip()).resolve(strict=True)
    except OSError as exc:
        raise OperationalError("Git returned an invalid repository root") from exc
    if not (root / "pyproject.toml").is_file() or not (root / "uv.lock").is_file():
        raise OperationalError("Release check must run in the ConClear repository")
    return root


def _require_clean(runtime: GateRuntime, root: Path) -> None:
    result = runtime.run(
        "verify clean checkout",
        (
            str(runtime.git),
            "-C",
            str(root),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ),
    )
    if result.stdout:
        raise OperationalError("Release check requires a clean checkout")


def _revision(runtime: GateRuntime, root: Path) -> str:
    result = runtime.run(
        "resolve source revision",
        (str(runtime.git), "-C", str(root), "rev-parse", "HEAD"),
    )
    revision = result.stdout.strip()
    validate_source_revision(revision)
    return revision


def _one_artifact(directory: Path, pattern: str) -> Path:
    matches = tuple(directory.glob(pattern))
    if len(matches) != 1:
        raise OperationalError(
            f"Expected exactly one release artifact matching {pattern}"
        )
    return matches[0]


def _tar_names(path: Path) -> tuple[str, ...]:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            names: list[str] = []
            for member in archive.getmembers():
                _artifact_member(member.name)
                if (
                    member.issym()
                    or member.islnk()
                    or not (member.isfile() or member.isdir())
                ):
                    raise OperationalError(
                        f"Source distribution contains unsafe member {member.name}"
                    )
                names.append(member.name)
            return tuple(names)
    except (OSError, tarfile.TarError) as exc:
        raise OperationalError(f"Unable to inspect source distribution {path}") from exc


def _wheel_names(path: Path) -> tuple[str, ...]:
    try:
        with zipfile.ZipFile(path) as archive:
            names: list[str] = []
            for member in archive.infolist():
                _artifact_member(member.filename)
                unix_mode = member.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    raise OperationalError(
                        f"Wheel contains symbolic link {member.filename}"
                    )
                names.append(member.filename)
            return tuple(names)
    except (OSError, zipfile.BadZipFile) as exc:
        raise OperationalError(f"Unable to inspect wheel {path}") from exc


def _artifact_member(value: str) -> PurePosixPath:
    if "\x00" in value or "\\" in value:
        raise OperationalError(f"Distribution contains unsafe path {value!r}")
    member = PurePosixPath(value)
    if member.is_absolute() or any(part in {"", ".", ".."} for part in member.parts):
        raise OperationalError(f"Distribution contains unsafe path {value!r}")
    return member


def _clear_generated_files(staged: Path) -> None:
    for name in (
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "htmlcov",
    ):
        shutil.rmtree(staged / name, ignore_errors=True)
    for name in (".coverage",):
        try:
            (staged / name).unlink()
        except FileNotFoundError:
            continue


def _executable(name: str) -> Path:
    value = shutil.which(name)
    if value is None:
        raise OperationalError(f"Release check requires executable {name}")
    try:
        path = Path(value).resolve(strict=True)
    except OSError as exc:
        raise OperationalError(
            f"Release-check executable is unavailable: {name}"
        ) from exc
    if not path.is_file() or not os.access(path, os.X_OK):
        raise OperationalError(f"Release-check executable is not runnable: {name}")
    return path


def main() -> int:
    """Run the release gate as a Python module."""
    try:
        run_release_check()
    except (ConClearError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
