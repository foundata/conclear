"""`conclear adopt` observes, suggests and defers decisions without writing state."""

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import conclear.commands.adopt as adopt_commands
from conclear.adapters.git import SourceObservation
from conclear.cli import main
from conclear.config import load_repository_config
from conclear.errors import ExitStatus, InvalidInvocationError, OperationalError
from conclear.services.adoption import (
    PinQuality,
    UserKind,
    assess_repository,
    discover_containerfiles,
)

PINNED = "docker.io/library/debian:13-slim@sha256:" + "a" * 64
REVISION = "b" * 40


class FakeGit:
    def __init__(
        self, remote: str | None = "git@github.com:foundata/example.git"
    ) -> None:
        self.remote = remote

    def observe(self, repository: Path, selector: str) -> SourceObservation:
        assert selector == "HEAD"
        if self.remote is None:
            raise OperationalError("not a git repository")
        return SourceObservation(
            REVISION, self.remote, datetime(2026, 1, 1, tzinfo=UTC)
        )


def _containerfile(
    *,
    base: str = PINNED,
    user: str | None = "USER 1001:1001",
    volumes: tuple[str, ...] = (),
    stop_signal: str | None = None,
    entrypoint: str | None = 'ENTRYPOINT ["/usr/local/bin/app"]',
    extra: tuple[str, ...] = (),
) -> str:
    lines = [
        f"FROM {base} AS runtime",
        'LABEL org.opencontainers.image.source="https://github.com/foundata/example"',
        'LABEL org.opencontainers.image.title="Example" maintainer="ops"',
        *extra,
    ]
    lines.extend(f"VOLUME {volume}" for volume in volumes)
    if stop_signal is not None:
        lines.append(f"STOPSIGNAL {stop_signal}")
    if user is not None:
        lines.append(user)
    if entrypoint is not None:
        lines.append(entrypoint)
    return "\n".join(lines) + "\n"


def _repository(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "example"
    root.mkdir()
    for name, content in files.items():
        (root / name).write_text(content, encoding="utf-8")
    return root


def _assess(root: Path, *containerfiles: str, git: FakeGit | None = None) -> Any:
    return assess_repository(
        root, containerfiles=containerfiles, git=FakeGit() if git is None else git
    )


def _notes(notes: tuple[Any, ...], field: str) -> list[str]:
    return [note.text for note in notes if note.field == field]


def test_single_containerfile_observations_suggestions_and_decisions(
    tmp_path: Path,
) -> None:
    root = _repository(
        tmp_path,
        {"Containerfile": _containerfile(volumes=("/data",), stop_signal="SIGTERM")},
    )

    assessment = _assess(root)

    [image] = assessment.images
    assert image.image_id == "example"
    assert image.containerfile == "Containerfile"
    [reference] = image.external_references
    assert (reference.registry, reference.repository, reference.tag) == (
        "docker.io",
        "library/debian",
        "13-slim",
    )
    assert reference.quality is PinQuality.PINNED
    assert (image.user.kind, image.user.uid) == (UserKind.NUMERIC, 1001)
    assert image.volumes == ("/data",)
    assert image.stop_signal == "SIGTERM"
    assert dict(image.labels)["org.opencontainers.image.title"] == "Example"
    assert dict(image.labels)["maintainer"] == "ops"
    assert image.entrypoint.command == ("/usr/local/bin/app",)
    assert not image.entrypoint.systemd
    assert assessment.project.source == "https://github.com/foundata/example"
    assert assessment.project.revision == REVISION
    assert assessment.findings == ()
    assert _notes(assessment.suggestions, "runtime.user") == [
        "Keep the numeric UID 1001 from the final USER instruction."
    ]
    assert _notes(assessment.suggestions, "runtime.writable_mounts") == [
        "Declare the VOLUME destinations as writable mounts: /data."
    ]
    decided = {note.field for note in assessment.decisions}
    assert {
        "repository",
        "platforms",
        "pins.tag_intent",
        "runtime.health_command",
        "test",
    } <= decided
    assert "runtime.user" not in decided
    assert "user = 1001" in assessment.draft
    assert 'writable_mounts = ["/data"]' in assessment.draft
    assert "[[images.pins]]" in assessment.draft
    assert 'source = "https://github.com/foundata/example"' in assessment.draft


def test_multiple_containerfiles_get_ids_from_their_names(tmp_path: Path) -> None:
    root = _repository(
        tmp_path,
        {
            "Containerfile": _containerfile(),
            "Containerfile.generator": _containerfile(user="USER 1001"),
            "Containerfile.Tool_X": _containerfile(),
        },
    )

    assessment = _assess(root)

    assert [image.image_id for image in assessment.images] == [
        "example",
        "tool_x",
        "generator",
    ]
    assert [image.containerfile for image in assessment.images] == [
        "Containerfile",
        "Containerfile.Tool_X",
        "Containerfile.generator",
    ]
    assert assessment.draft.count("[[images]]") == 3
    assert 'containerfile = "Containerfile.generator"' in assessment.draft
    assert 'containerfile = "Containerfile"\n' not in assessment.draft


def test_discovery_is_ambiguous_across_families_and_empty_without_any(
    tmp_path: Path,
) -> None:
    root = _repository(
        tmp_path, {"Containerfile": _containerfile(), "Dockerfile": _containerfile()}
    )
    with pytest.raises(InvalidInvocationError, match="ambiguous"):
        discover_containerfiles(root)
    assert [image.containerfile for image in _assess(root, "Dockerfile").images] == [
        "Dockerfile"
    ]
    (root / "Dockerfile").unlink()
    (root / "Containerfile").unlink()
    (root / "notes.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="No conventional Containerfile"):
        _assess(root)


def test_explicit_paths_are_confined_below_the_root(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"Containerfile": _containerfile()})
    (tmp_path / "outside").write_text(_containerfile(), encoding="utf-8")
    (root / "Containerfile.link").symlink_to(tmp_path / "outside")
    (root / "build").mkdir()

    for value in ("../outside", str(tmp_path / "outside"), "build/../Containerfile"):
        with pytest.raises(InvalidInvocationError, match=r"source root|unsafe"):
            _assess(root, value)
    with pytest.raises(InvalidInvocationError, match="escapes"):
        _assess(root, "Containerfile.link")
    with pytest.raises(InvalidInvocationError, match="not a regular file"):
        _assess(root, "build")
    with pytest.raises(InvalidInvocationError, match="named twice"):
        _assess(root, "Containerfile", "Containerfile")
    assert [image.containerfile for image in _assess(root).images] == ["Containerfile"]


def test_pin_quality_is_classified_and_unpinned_inputs_become_decisions(
    tmp_path: Path,
) -> None:
    content = "\n".join(
        (
            "FROM debian:13 AS unqualified",
            "FROM docker.io/library/debian:13 AS tagged",
            f"FROM docker.io/library/debian@sha256:{'c' * 64} AS digested",
            "FROM docker.io/library/debian AS untagged",
            f"FROM {PINNED} AS runtime",
            "COPY --from=$BUILDER /x /y",
            "USER 1001",
            'ENTRYPOINT ["/app"]',
            "",
        )
    )
    root = _repository(tmp_path, {"Containerfile": content})

    assessment = _assess(root)

    [image] = assessment.images
    qualities = {
        item.reference: item.quality.value for item in image.external_references
    }
    assert qualities == {
        "$BUILDER": "build-argument",
        "debian:13": "unqualified",
        "docker.io/library/debian:13": "tag-only",
        f"docker.io/library/debian@sha256:{'c' * 64}": "digest-only",
        "docker.io/library/debian": "untagged",
        PINNED: "pinned",
    }
    pin_decisions = _notes(assessment.decisions, "pins")
    assert len(pin_decisions) == 5
    assert all("cannot be declared until then" in text for text in pin_decisions)
    assert assessment.draft.count("[[images.pins]]") == 1
    assert {finding.check_id for finding in assessment.findings} == {
        "CC0105",
        "CC0106",
    }
    assert all(finding.image == "example" for finding in assessment.findings)


@pytest.mark.parametrize(
    ("user", "kind", "uid", "draft_user", "decision"),
    [
        ("USER 1001:1001", UserKind.NUMERIC, 1001, "user = 1001", None),
        (
            "USER app",
            UserKind.NAMED,
            None,
            "DECIDE: numeric non-root UID",
            "numeric UID",
        ),
        (None, UserKind.MISSING, None, "DECIDE: numeric non-root UID", "runs as root"),
        ("USER 0", UserKind.ROOT, 0, "user = 0", "Justify UID 0"),
        ("USER root", UserKind.ROOT, 0, "user = 0", "Justify UID 0"),
    ],
)
def test_user_variants(
    tmp_path: Path,
    user: str | None,
    kind: UserKind,
    uid: int | None,
    draft_user: str,
    decision: str | None,
) -> None:
    root = _repository(tmp_path, {"Containerfile": _containerfile(user=user)})

    assessment = _assess(root)

    [image] = assessment.images
    assert (image.user.kind, image.user.uid) == (kind, uid)
    assert draft_user in assessment.draft
    user_decisions = _notes(assessment.decisions, "runtime.user") + _notes(
        assessment.decisions, "runtime.root_requirement"
    )
    if decision is None:
        assert user_decisions == []
        assert "[images.runtime.root_requirement]" not in assessment.draft
    else:
        assert any(decision in text for text in user_decisions)
    if kind is UserKind.ROOT:
        assert "[images.runtime.root_requirement]" in assessment.draft
        assert 'rationale = "DECIDE:' in assessment.draft


@pytest.mark.parametrize("stop_signal", [None, "SIGRTMIN+3", "RTMIN+3"])
def test_systemd_candidate_gets_the_systemd_profile_and_its_decisions(
    tmp_path: Path, stop_signal: str | None
) -> None:
    root = _repository(
        tmp_path,
        {
            "Containerfile": _containerfile(
                user=None,
                volumes=('["/run", "/run/lock", "/tmp", "/var/lib/journal"]',),
                stop_signal=stop_signal,
                entrypoint='CMD ["/lib/systemd/systemd"]',
            )
        },
    )

    assessment = _assess(root)

    [image] = assessment.images
    assert image.entrypoint.systemd and image.entrypoint.instruction == "CMD"
    assert image.volumes == ("/run", "/run/lock", "/tmp", "/var/lib/journal")
    assert 'profile = "systemd"' in assessment.draft
    assert "user = 0" in assessment.draft
    assert 'writable_mounts = ["/var/lib/journal"]' in assessment.draft
    assert "[images.runtime.systemd]" in assessment.draft
    assert "[images.runtime.root_requirement]" in assessment.draft
    fields = {note.field for note in assessment.decisions}
    assert {"runtime.systemd.required_units", "runtime.root_requirement"} <= fields
    assert ("STOPSIGNAL" in fields) == (stop_signal is None)
    assert "runtime.health_command" not in fields
    assert _notes(assessment.suggestions, "runtime.profile") == [
        "The entrypoint starts systemd, so the systemd profile applies."
    ]


@pytest.mark.parametrize(
    ("git", "source", "status"),
    [
        (
            FakeGit("https://github.com/foundata/example.git"),
            "https://github.com/foundata/example",
            "observed",
        ),
        (
            FakeGit("ssh://git@github.com/foundata/example.git"),
            "https://github.com/foundata/example",
            "observed",
        ),
        (FakeGit("ssh://alice@github.com/foundata/example.git"), None, "unsupported"),
        (
            FakeGit("https://alice:token123@github.com/foundata/example.git"),
            None,
            "unsupported",
        ),
        (FakeGit(None), None, "unavailable"),
        (None, None, "unavailable"),
    ],
)
def test_source_identity_is_observed_only_in_supported_credential_free_forms(
    tmp_path: Path, git: FakeGit | None, source: str | None, status: str
) -> None:
    root = _repository(tmp_path, {"Containerfile": _containerfile()})

    assessment = assess_repository(root, containerfiles=(), git=git)

    assert assessment.project.source == source
    assert assessment.project.status.value == status
    rendered = json.dumps(assessment.to_dict()) + assessment.draft
    assert "token123" not in rendered and "alice" not in rendered
    assert ("project.source" in {note.field for note in assessment.decisions}) == (
        source is None
    )
    if source is None:
        assert 'source = "DECIDE:' in assessment.draft


def test_draft_is_invalid_until_every_decision_is_resolved(tmp_path: Path) -> None:
    root = _repository(tmp_path, {"Containerfile": _containerfile()})
    assessment = _assess(root)
    draft_path = root / "conclear.toml"
    draft_path.write_text(assessment.draft, encoding="utf-8")

    with pytest.raises(InvalidInvocationError):
        load_repository_config(draft_path)

    resolved = re.sub(
        r'"DECIDE: fully qualified[^"]*"', '"quay.io/example/app"', assessment.draft
    )
    resolved = re.sub(r'\["DECIDE: linux/amd64[^"]*"\]', '["linux/amd64"]', resolved)
    resolved = re.sub(
        r'"DECIDE: immutable-version[^"]*"', '"immutable-version"', resolved
    )
    body = resolved.split("[adopt]")[0]
    assert not [
        line
        for line in body.splitlines()
        if "DECIDE" in line and not line.startswith("#")
    ]
    draft_path.write_text(resolved, encoding="utf-8")
    with pytest.raises(InvalidInvocationError, match="adopt"):
        load_repository_config(draft_path)

    draft_path.write_text(resolved.split("\n[adopt]")[0] + "\n", encoding="utf-8")
    config = load_repository_config(draft_path)
    image = config.release_image("example")
    assert image.runtime.user == 1001 and image.runtime.profile == "service"
    assert image.release.moving_tags == ("stable",)
    assert [str(pin.reference) for pin in image.pins] == [PINNED]


@contextmanager
def _runtime(git: FakeGit) -> Iterator[Any]:
    yield SimpleNamespace(git=lambda: git)


def _invoke(
    capsys: pytest.CaptureFixture[str], arguments: list[str]
) -> tuple[int, str]:
    capsys.readouterr()
    code = main(arguments)
    return code, capsys.readouterr().out


def test_adopt_command_reports_json_and_writes_only_a_new_draft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repository(tmp_path, {"Containerfile": _containerfile()})
    monkeypatch.setattr(
        adopt_commands, "command_runtime", lambda names: _runtime(FakeGit())
    )
    draft = tmp_path / "draft.toml"

    code, out = _invoke(
        capsys,
        ["adopt", "--source", str(root), "--output", str(draft), "--format", "json"],
    )

    assert code == 0
    value = json.loads(out)
    assert (value["command"], value["status"]) == ("adopt", "success")
    assert set(value["data"]) == {
        "root",
        "observations",
        "suggestions",
        "requiredDecisions",
        "draftToml",
        "draftPath",
    }
    assert value["data"]["draftPath"] == str(draft)
    assert draft.read_text(encoding="utf-8") == value["data"]["draftToml"]
    assert sorted(item.name for item in tmp_path.iterdir()) == ["draft.toml", "example"]
    assert sorted(item.name for item in root.iterdir()) == ["Containerfile"]

    code, out = _invoke(
        capsys,
        ["adopt", "--source", str(root), "--output", str(draft), "--format", "json"],
    )
    assert code == int(ExitStatus.INVALID_INVOCATION)
    assert json.loads(out)["status"] == "invalidInvocation"
    assert draft.read_text(encoding="utf-8") == value["data"]["draftToml"]
    assert sorted(item.name for item in tmp_path.iterdir()) == ["draft.toml", "example"]


def test_adopt_command_prints_a_concise_human_assessment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repository(tmp_path, {"Containerfile": _containerfile(user="USER app")})
    monkeypatch.setattr(
        adopt_commands, "command_runtime", lambda names: _runtime(FakeGit())
    )

    code, out = _invoke(capsys, ["adopt", "--source", str(root)])

    assert code == 0
    assert out.startswith("Assessed 1 image(s)")
    assert (
        "Image example (Containerfile): 1 external input(s), 1 pinned; USER named app"
        in out
    )
    assert "Decide example.runtime.user:" in out
    assert "DECIDE" not in out
    assert not (root / "conclear.toml").exists()


def test_adopt_command_refuses_ambiguous_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repository(
        tmp_path, {"Containerfile": _containerfile(), "Dockerfile": _containerfile()}
    )
    monkeypatch.setattr(
        adopt_commands, "command_runtime", lambda names: _runtime(FakeGit())
    )

    code, out = _invoke(capsys, ["adopt", "--source", str(root), "--format", "json"])

    assert code == int(ExitStatus.INVALID_INVOCATION)
    assert "ambiguous" in json.loads(out)["message"]
