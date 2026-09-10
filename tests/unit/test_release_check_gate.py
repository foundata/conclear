"""Distribution-gate helpers refuse unsafe artifacts and destinations."""

import io
import os
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import cast

import pytest

import conclear.release_check as release_check_module
from conclear.errors import (
    CommandExecutionError,
    InvalidInvocationError,
    OperationalError,
)
from conclear.jsonutil import load_json, sha256_file
from conclear.process import CommandRequest, ProcessResult
from conclear.release_check import (
    GateRuntime,
    main,
    retain_distribution_artifacts,
    validate_distribution_artifact,
)

REVISION = "a" * 40


def _artifacts(tmp_path: Path) -> tuple[Path, Path]:
    sdist = tmp_path / "conclear-1.0.0.tar.gz"
    sdist.write_bytes(b"sdist")
    wheel = tmp_path / "conclear-1.0.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    return sdist, wheel


def test_retained_artifacts_are_published_atomically_with_their_digests(
    tmp_path: Path,
) -> None:
    sdist, wheel = _artifacts(tmp_path)
    parent = tmp_path / "distributions"
    parent.mkdir(mode=0o700)

    retained = retain_distribution_artifacts(
        sdist=sdist,
        wheel=wheel,
        destination=parent / REVISION,
        source_revision=REVISION,
    )

    assert retained.directory == parent / REVISION
    assert retained.sdist_digest == sha256_file(sdist)
    assert retained.wheel_digest == sha256_file(wheel)
    manifest = load_json(retained.directory / "artifacts.json")
    assert manifest["conclearRevision"] == REVISION
    assert [item["filename"] for item in manifest["artifacts"]] == [
        sdist.name,
        wheel.name,
    ]
    assert stat.S_IMODE(retained.wheel.stat().st_mode) == 0o644
    assert [path.name for path in parent.iterdir()] == [REVISION]

    with pytest.raises(OperationalError, match="must not already exist"):
        retain_distribution_artifacts(
            sdist=sdist,
            wheel=wheel,
            destination=parent / REVISION,
            source_revision=REVISION,
        )


def test_artifact_destination_refuses_unsafe_parents(tmp_path: Path) -> None:
    sdist, wheel = _artifacts(tmp_path)

    def attempt(destination: Path) -> None:
        retain_distribution_artifacts(
            sdist=sdist, wheel=wheel, destination=destination, source_revision=REVISION
        )

    with pytest.raises(OperationalError, match="name a new directory"):
        attempt(Path("/"))
    with pytest.raises(OperationalError, match="parent is unavailable"):
        attempt(tmp_path / "missing" / REVISION)
    file_parent = tmp_path / "file"
    file_parent.write_text("x", encoding="utf-8")
    with pytest.raises(OperationalError, match="not a directory"):
        attempt(file_parent / REVISION)
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(OperationalError, match="cannot cross a symbolic link"):
        attempt(link / REVISION)
    if os.geteuid() != 0:
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(0o775)
        with pytest.raises(OperationalError, match="group- or other-writable"):
            attempt(shared / REVISION)
    with pytest.raises(InvalidInvocationError, match="lowercase hexadecimal"):
        retain_distribution_artifacts(
            sdist=sdist, wheel=wheel, destination=real / "x", source_revision="HEAD"
        )
    assert list(real.iterdir()) == []


def test_retention_rejects_symlinked_or_missing_distributions(tmp_path: Path) -> None:
    sdist, wheel = _artifacts(tmp_path)
    parent = tmp_path / "distributions"
    parent.mkdir(mode=0o700)
    linked = tmp_path / "linked.whl"
    linked.symlink_to(wheel)

    with pytest.raises(OperationalError, match="not a regular file"):
        retain_distribution_artifacts(
            sdist=sdist,
            wheel=linked,
            destination=parent / REVISION,
            source_revision=REVISION,
        )
    with pytest.raises(OperationalError, match="unavailable"):
        retain_distribution_artifacts(
            sdist=tmp_path / "absent.tar.gz",
            wheel=wheel,
            destination=parent / REVISION,
            source_revision=REVISION,
        )
    assert list(parent.iterdir()) == []


def _sdist(path: Path, names: list[str], *, symlink: str | None = None) -> Path:
    with tarfile.open(path, mode="w:gz") as archive:
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        if symlink is not None:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "pyproject.toml"
            archive.addfile(info)
    return path


REQUIRED_SDIST = [
    "conclear-1.0.0/pyproject.toml",
    "conclear-1.0.0/uv.lock",
    "conclear-1.0.0/docs/compatibility-inventory.json",
    "conclear-1.0.0/docs/conformance.md",
    "conclear-1.0.0/docs/guide-options-1.0.0.md",
    "conclear-1.0.0/docs/implementation.md",
    "conclear-1.0.0/LICENSES/GPL-3.0-or-later.txt",
    "conclear-1.0.0/src/conclear/_embedded_identity.py",
]


def test_source_distribution_hygiene(tmp_path: Path) -> None:
    validate_distribution_artifact(
        _sdist(tmp_path / "ok.tar.gz", REQUIRED_SDIST), kind="sdist"
    )

    with pytest.raises(OperationalError, match="missing required file"):
        validate_distribution_artifact(
            _sdist(tmp_path / "incomplete.tar.gz", REQUIRED_SDIST[:-1]), kind="sdist"
        )
    with pytest.raises(OperationalError, match="generated path"):
        validate_distribution_artifact(
            _sdist(
                tmp_path / "venv.tar.gz", [*REQUIRED_SDIST, "conclear-1.0.0/.venv/bin"]
            ),
            kind="sdist",
        )
    with pytest.raises(OperationalError, match="generated file"):
        validate_distribution_artifact(
            _sdist(
                tmp_path / "pyc.tar.gz",
                [*REQUIRED_SDIST, "conclear-1.0.0/src/conclear/cli.pyc"],
            ),
            kind="sdist",
        )
    with pytest.raises(OperationalError, match="unsafe member"):
        validate_distribution_artifact(
            _sdist(
                tmp_path / "link.tar.gz", REQUIRED_SDIST, symlink="conclear-1.0.0/link"
            ),
            kind="sdist",
        )
    with pytest.raises(OperationalError, match="unsafe path"):
        validate_distribution_artifact(
            _sdist(tmp_path / "escape.tar.gz", [*REQUIRED_SDIST, "../escape"]),
            kind="sdist",
        )
    with pytest.raises(OperationalError, match="Unable to inspect"):
        validate_distribution_artifact(tmp_path / "absent.tar.gz", kind="sdist")
    with pytest.raises(OperationalError, match="Unknown distribution kind"):
        validate_distribution_artifact(tmp_path / "ok.tar.gz", kind="egg")


def test_wheel_hygiene_rejects_symlinks_and_unreadable_archives(tmp_path: Path) -> None:
    wheel = tmp_path / "link.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        info = zipfile.ZipInfo("conclear/link.py")
        info.external_attr = 0o120777 << 16
        archive.writestr(info, "cli.py")
    with pytest.raises(OperationalError, match="symbolic link"):
        validate_distribution_artifact(wheel, kind="wheel")

    corrupt = tmp_path / "corrupt.whl"
    corrupt.write_bytes(b"not a zip")
    with pytest.raises(OperationalError, match="Unable to inspect wheel"):
        validate_distribution_artifact(corrupt, kind="wheel")


class _FailingRunner:
    def run(self, request: CommandRequest) -> ProcessResult:
        raise CommandExecutionError("exit 1", returncode=1, stdout="", stderr="boom")


def test_gate_runtime_wraps_step_failures_with_their_label(tmp_path: Path) -> None:
    runtime = GateRuntime(
        git=tmp_path / "git",
        uv=tmp_path / "uv",
        pythons={},
        environment={"PATH": "/usr/bin"},
        runner=_FailingRunner(),  # type: ignore[arg-type]
    )

    with pytest.raises(OperationalError, match="failed during lint: exit 1"):
        runtime.run("lint", (str(tmp_path / "ruff"), "check"))


def test_source_gates_check_the_generated_inventories(
    tmp_path: Path,
) -> None:
    class RecordingRuntime:
        def __init__(self) -> None:
            self.uv = tmp_path / "uv"
            self.pythons = {
                "3.12": tmp_path / "python3.12",
                "3.13": tmp_path / "python3.13",
                "3.14": tmp_path / "python3.14",
            }
            self.calls: list[tuple[str, tuple[str, ...]]] = []

        def run(
            self,
            label: str,
            argv: tuple[str, ...],
            **values: object,
        ) -> ProcessResult:
            del values
            self.calls.append((label, argv))
            return ProcessResult(argv, 0, "", "", 0.0, 0, False, False)

    recorder = RecordingRuntime()

    release_check_module._run_source_gates(cast(GateRuntime, recorder), tmp_path)

    assert (
        "check guide-option support inventory",
        (
            str(recorder.uv),
            "run",
            "--frozen",
            "python",
            "-m",
            "conclear.guide_options",
            "--check",
        ),
    ) in recorder.calls
    assert (
        "check internal compatibility inventory",
        (
            str(recorder.uv),
            "run",
            "--frozen",
            "python",
            "-m",
            "conclear.compatibility_inventory",
            "--check",
        ),
    ) in recorder.calls
    assert (
        "check implementation matrix",
        (
            str(recorder.uv),
            "run",
            "--frozen",
            "python",
            "-m",
            "conclear.implementation",
            "--check",
        ),
    ) in recorder.calls
    assert (
        "check supported-tools table",
        (
            str(recorder.uv),
            "run",
            "--frozen",
            "python",
            "-m",
            "conclear.tool_matrix",
            "--check",
        ),
    ) in recorder.calls
    assert (
        "check Markdown",
        (
            str(recorder.uv),
            "run",
            "--frozen",
            "rumdl",
            "check",
            *release_check_module.MARKDOWN_RULE_ARGUMENTS,
            "--no-cache",
            ".",
        ),
    ) in recorder.calls


def test_gate_helpers_reject_missing_executables_and_ambiguous_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(OperationalError, match="requires executable"):
        release_check_module._executable("uv")

    with pytest.raises(OperationalError, match="exactly one release artifact"):
        release_check_module._one_artifact(tmp_path, "*.whl")

    for name in (".venv", "htmlcov"):
        (tmp_path / name).mkdir()
    (tmp_path / ".coverage").write_bytes(b"")
    release_check_module._clear_generated_files(tmp_path)
    assert not (tmp_path / ".venv").exists()
    assert not (tmp_path / ".coverage").exists()
    release_check_module._clear_generated_files(tmp_path)


def test_module_entry_point_reports_gate_failures(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing(*, output_directory: Path | None) -> None:
        raise OperationalError("Release check requires a clean checkout")

    monkeypatch.setattr(release_check_module, "run_release_check", failing)
    assert main([]) == 1
    assert "clean checkout" in capsys.readouterr().err

    seen: list[Path | None] = []

    def passing(*, output_directory: Path | None) -> None:
        seen.append(output_directory)

    monkeypatch.setattr(release_check_module, "run_release_check", passing)
    assert main(["--output-directory", "/tmp/x"]) == 0
    assert seen == [Path("/tmp/x")]


def test_development_guide_delegates_the_markdown_policy() -> None:
    text = Path("DEVELOPMENT.md").read_text(encoding="utf-8")
    start = text.index("### Code formatting and linting")
    end = text.index("### Commit messages and scopes", start)
    section = text[start:end]
    normalized = " ".join(section.split())

    assert (
        "https://github.com/foundata/guidelines/blob/main/"
        "markdown-style-guide.md#linting-and-automatic-formatting"
    ) in section
    assert "arguments are deliberately not duplicated here" in normalized
    assert "uv run rumdl" not in section


def test_whitespace_check_diffs_the_empty_tree_against_the_revision(
    tmp_path: Path,
) -> None:
    class RecordingRuntime:
        def __init__(self) -> None:
            self.git = tmp_path / "git"
            self.calls: list[tuple[str, tuple[str, ...]]] = []

        def run(
            self,
            label: str,
            argv: tuple[str, ...],
            **values: object,
        ) -> ProcessResult:
            del values
            self.calls.append((label, argv))
            stdout = (
                "4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"
                if "hash-object" in argv
                else ""
            )
            return ProcessResult(argv, 0, stdout, "", 0.0, 0, False, False)

    recorder = RecordingRuntime()

    release_check_module._require_clean_whitespace(
        cast(GateRuntime, recorder), tmp_path, "c" * 40
    )

    assert recorder.calls == [
        (
            "hash the empty tree",
            (str(recorder.git), "hash-object", "-t", "tree", os.devnull),
        ),
        (
            "check whitespace",
            (
                str(recorder.git),
                "-C",
                str(tmp_path),
                "diff",
                "--check",
                "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
                "c" * 40,
            ),
        ),
    ]
