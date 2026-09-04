import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

import conclear.commands.maintenance as maintenance
import conclear.pin_updates as pin_updates_module
from conclear.adapters.git import SourceObservation
from conclear.cli import main, root
from conclear.identity import ApplicationIdentity
from conclear.records import ToolIdentity
from conclear.tools import ToolName
from conclear.values import Digest, OCIReference

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64


class FakeGit:
    def __init__(self, revision: str = "1" * 40) -> None:
        self.revision = revision
        self.calls: list[str] = []

    def observe(self, repository: Path, selector: str) -> SourceObservation:
        assert selector == "HEAD"
        assert repository.is_dir()
        self.calls.append("observe")
        return SourceObservation(
            self.revision,
            "https://github.com/example/app.git",
            datetime(2026, 1, 1, tzinfo=UTC),
        )

    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"Git operation {name} is not permitted for pins commands")


class FakeSkopeo:
    def __init__(self, digest: str = NEW) -> None:
        self.digest = digest
        self.calls: list[str] = []

    def resolve_digest(
        self, reference: OCIReference, *, auth_file: Path | None = None
    ) -> Digest:
        assert auth_file is None
        assert reference.digest is None
        self.calls.append(str(reference))
        return Digest(self.digest)


class FakeTool:
    def record_identity(self) -> ToolIdentity:
        return ToolIdentity("skopeo", "1.22.2", executable_digest="sha256:" + "e" * 64)


class FakeRuntime:
    def __init__(self, git: FakeGit, skopeo: FakeSkopeo) -> None:
        self._git = git
        self._skopeo = skopeo
        self.tools = {ToolName.SKOPEO: FakeTool(), ToolName.GIT: FakeTool()}

    def git(self) -> FakeGit:
        return self._git

    def skopeo(self) -> FakeSkopeo:
        return self._skopeo

    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"Adapter {name} is not permitted for pins commands")


@pytest.fixture
def harness(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[FakeGit, FakeSkopeo, list[tuple[ToolName, ...]]]:
    git = FakeGit()
    skopeo = FakeSkopeo()
    requested: list[tuple[ToolName, ...]] = []

    @contextmanager
    def fake_runtime(names: tuple[ToolName, ...]) -> Iterator[FakeRuntime]:
        requested.append(names)
        yield FakeRuntime(git, skopeo)

    monkeypatch.setattr(maintenance, "command_runtime", fake_runtime)
    monkeypatch.setattr(
        pin_updates_module, "IDENTITY", ApplicationIdentity(source_revision="c" * 40)
    )
    return git, skopeo, requested


@dataclass(frozen=True, slots=True)
class Invocation:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


@pytest.fixture
def invoke(capsys: pytest.CaptureFixture[str]) -> Callable[[list[str]], Invocation]:
    def run(arguments: list[str]) -> Invocation:
        capsys.readouterr()
        exit_code = main(arguments)
        captured = capsys.readouterr()
        return Invocation(exit_code, captured.out, captured.err)

    return run


def test_pins_help_lists_propose_and_apply() -> None:
    runner = CliRunner()
    result = runner.invoke(root, ["pins", "--help"])
    assert result.exit_code == 0
    assert "propose" in result.stdout
    assert "apply" in result.stdout
    for command in ("propose", "apply"):
        detail = runner.invoke(root, ["pins", command, "--help"])
        assert detail.exit_code == 0
        assert detail.stderr == ""
    assert "--output" in runner.invoke(root, ["pins", "propose", "--help"]).stdout
    assert "--proposal" in runner.invoke(root, ["pins", "apply", "--help"]).stdout


def test_propose_writes_one_proposal_and_reports_review_in_json(
    repository_factory: Callable[..., Path],
    invoke: Callable[[list[str]], Invocation],
    harness: tuple[FakeGit, FakeSkopeo, list[tuple[ToolName, ...]]],
    tmp_path: Path,
) -> None:
    git, skopeo, requested = harness
    root_path = repository_factory()
    output = tmp_path / "proposal.json"
    before = (root_path / "Containerfile").read_bytes()

    result = invoke(
        [
            "pins",
            "propose",
            "--config",
            str(root_path / "conclear.toml"),
            "--output",
            str(output),
            "--format",
            "json",
        ]
    )

    assert result.exit_code == 0, result.output
    assert result.stdout.count("\n") == 1
    value = json.loads(result.stdout)
    assert value["status"] == "success"
    assert value["data"]["changed"] is True
    assert value["data"]["reviewRequired"] is True
    assert value["data"]["files"] == ["Containerfile", "conclear.toml"]
    assert value["findings"][0]["checkId"] == "CC0205"
    assert value["data"]["proposalDigest"].startswith("sha256:")
    stored = json.loads(output.read_text(encoding="utf-8"))
    assert stored["recordType"] == "pinUpdateProposal"
    assert stored["source"] == {
        "repository": "https://github.com/example/app",
        "revision": "1" * 40,
    }
    assert (root_path / "Containerfile").read_bytes() == before
    assert requested == [(ToolName.GIT, ToolName.SKOPEO)]
    assert git.calls == ["observe"]
    assert skopeo.calls == ["quay.io/example/base:1"]


def test_propose_refuses_to_overwrite_an_existing_output(
    repository_factory: Callable[..., Path],
    invoke: Callable[[list[str]], Invocation],
    harness: tuple[FakeGit, FakeSkopeo, list[tuple[ToolName, ...]]],
    tmp_path: Path,
) -> None:
    root_path = repository_factory()
    output = tmp_path / "proposal.json"
    output.write_text("keep me", encoding="utf-8")

    result = invoke(
        [
            "pins",
            "propose",
            "--config",
            str(root_path / "conclear.toml"),
            "--output",
            str(output),
            "--format",
            "json",
        ]
    )

    assert result.exit_code == 64
    assert json.loads(result.stdout)["status"] == "invalidInvocation"
    assert output.read_text(encoding="utf-8") == "keep me"


def test_propose_rejects_an_unknown_image_selection(
    repository_factory: Callable[..., Path],
    invoke: Callable[[list[str]], Invocation],
    harness: tuple[FakeGit, FakeSkopeo, list[tuple[ToolName, ...]]],
    tmp_path: Path,
) -> None:
    root_path = repository_factory()

    result = invoke(
        [
            "pins",
            "propose",
            "--config",
            str(root_path / "conclear.toml"),
            "--image",
            "missing",
            "--output",
            str(tmp_path / "proposal.json"),
        ]
    )

    assert result.exit_code == 64
    assert not (tmp_path / "proposal.json").exists()


def test_apply_names_paths_digests_and_follow_up_in_human_output(
    repository_factory: Callable[..., Path],
    invoke: Callable[[list[str]], Invocation],
    harness: tuple[FakeGit, FakeSkopeo, list[tuple[ToolName, ...]]],
    tmp_path: Path,
) -> None:
    git, _, requested = harness
    root_path = repository_factory()
    output = tmp_path / "proposal.json"
    config = str(root_path / "conclear.toml")
    assert (
        invoke(
            ["pins", "propose", "--config", config, "--output", str(output)]
        ).exit_code
        == 0
    )
    requested.clear()

    result = invoke(["pins", "apply", "--proposal", str(output), "--config", config])

    assert result.exit_code == 0, result.output
    assert "Applied the pin update proposal to 2 file(s)" in result.stdout
    assert "changed: Containerfile" in result.stdout
    assert "changed: conclear.toml" in result.stdout
    assert f"{OLD} -> {NEW}" in result.stdout
    assert f"next: conclear pins check --config {config} --image app" in result.stdout
    assert "CC0205 warning" in result.stdout
    assert NEW in (root_path / "Containerfile").read_text(encoding="utf-8")
    assert NEW in (root_path / "conclear.toml").read_text(encoding="utf-8")
    assert requested == [(ToolName.GIT,)]
    assert git.calls == ["observe", "observe"]


def test_apply_json_is_one_object_and_repeats_are_already_applied(
    repository_factory: Callable[..., Path],
    invoke: Callable[[list[str]], Invocation],
    harness: tuple[FakeGit, FakeSkopeo, list[tuple[ToolName, ...]]],
    tmp_path: Path,
) -> None:
    root_path = repository_factory()
    output = tmp_path / "proposal.json"
    config = str(root_path / "conclear.toml")
    assert (
        invoke(
            ["pins", "propose", "--config", config, "--output", str(output)]
        ).exit_code
        == 0
    )

    first = invoke(
        [
            "pins",
            "apply",
            "--proposal",
            str(output),
            "--config",
            config,
            "--format",
            "json",
        ]
    )
    second = invoke(
        [
            "pins",
            "apply",
            "--proposal",
            str(output),
            "--config",
            config,
            "--format",
            "json",
        ]
    )

    assert first.exit_code == 0
    assert first.stdout.count("\n") == 1
    assert json.loads(first.stdout)["data"]["status"] == "applied"
    assert json.loads(first.stdout)["data"]["changedPaths"] == [
        "Containerfile",
        "conclear.toml",
    ]
    assert second.exit_code == 0
    assert json.loads(second.stdout)["data"]["status"] == "already-applied"


def test_apply_rejects_a_changed_revision_without_writing(
    repository_factory: Callable[..., Path],
    invoke: Callable[[list[str]], Invocation],
    harness: tuple[FakeGit, FakeSkopeo, list[tuple[ToolName, ...]]],
    tmp_path: Path,
) -> None:
    git, _, _ = harness
    root_path = repository_factory()
    output = tmp_path / "proposal.json"
    config = str(root_path / "conclear.toml")
    assert (
        invoke(
            ["pins", "propose", "--config", config, "--output", str(output)]
        ).exit_code
        == 0
    )
    git.revision = "2" * 40
    before = (root_path / "Containerfile").read_bytes()

    result = invoke(
        [
            "pins",
            "apply",
            "--proposal",
            str(output),
            "--config",
            config,
            "--format",
            "json",
        ]
    )

    assert result.exit_code == 64
    value = json.loads(result.stdout)
    assert value["status"] == "invalidInvocation"
    assert value["findings"][0]["checkId"] == "CC0207"
    assert (root_path / "Containerfile").read_bytes() == before


def test_apply_rejects_a_malformed_proposal_before_touching_tools(
    repository_factory: Callable[..., Path],
    invoke: Callable[[list[str]], Invocation],
    harness: tuple[FakeGit, FakeSkopeo, list[tuple[ToolName, ...]]],
    tmp_path: Path,
) -> None:
    _, _, requested = harness
    root_path = repository_factory()
    proposal = tmp_path / "proposal.json"
    proposal.write_text('{"schemaVersion": 1}', encoding="utf-8")

    result = invoke(
        [
            "pins",
            "apply",
            "--proposal",
            str(proposal),
            "--config",
            str(root_path / "conclear.toml"),
        ]
    )

    assert result.exit_code == 64
    assert requested == []


def test_pins_commands_require_the_canonical_configuration_name(
    repository_factory: Callable[..., Path],
    invoke: Callable[[list[str]], Invocation],
    harness: tuple[FakeGit, FakeSkopeo, list[tuple[ToolName, ...]]],
    tmp_path: Path,
) -> None:
    root_path = repository_factory()
    other = root_path / "other.toml"
    other.write_bytes((root_path / "conclear.toml").read_bytes())

    result = invoke(
        [
            "pins",
            "propose",
            "--config",
            str(other),
            "--output",
            str(tmp_path / "p.json"),
        ]
    )

    assert result.exit_code == 64
    assert "conclear.toml" in result.output
