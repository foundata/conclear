import json
import os
import stat
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import conclear.pin_updates as pin_updates_module
from conclear.config import PinIntent, load_repository_config
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import canonical_json_bytes, sha256_bytes
from conclear.pin_application import (
    ApplicationOutcome,
    ApplicationStatus,
    WritePhase,
    apply_pin_proposal,
)
from conclear.pin_updates import (
    MAX_PROPOSAL_BYTES,
    PinUpdateProposal,
    load_proposal,
    parse_proposal,
    propose_pin_updates,
)
from conclear.records import SourceIdentity, ToolIdentity
from conclear.values import Digest, OCIReference

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64
TAG = "docker.io/library/debian:13-slim"
OLD_REFERENCE = f"{TAG}@{OLD}"
NEW_REFERENCE = f"{TAG}@{NEW}"
TOOL_TAG = "quay.io/example/tool:2.1.0"
TOOL_OLD = "sha256:" + "c" * 64
TOOL_NEW = "sha256:" + "d" * 64
SOURCE = SourceIdentity("https://github.com/example/app", "1" * 40)
TOOLS = (ToolIdentity("skopeo", "1.22.2", executable_digest="sha256:" + "e" * 64),)
CLOCK = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)

RUNTIME_CONTAINERFILE = (
    f"FROM {OLD_REFERENCE} AS runtime\n"
    "# Comments and unrelated lines are preserved byte for byte.\n"
    'LABEL org.opencontainers.image.source="https://github.com/example/app"\n'
    "\tRUN set -eu; apt-get update  \n"
    "USER 1001:1001\n"
    'ENTRYPOINT ["/usr/sbin/slapd"]\n'
)
GENERATOR_CONTAINERFILE = (
    f"FROM {TOOL_TAG}@{TOOL_OLD} AS build\n"
    f"FROM {OLD_REFERENCE} AS runtime\n"
    f"COPY --from={TOOL_TAG}@{TOOL_OLD} /tool /usr/local/bin/tool\n"
    "USER 1001:1001\n"
    'ENTRYPOINT ["/usr/local/bin/generator"]\n'
)
CONFIGURATION = f"""schema_version = 1

[project]
name = "example"
source = "https://github.com/example/app"

[[images]]
id = "runtime"
repository = "quay.io/example/runtime"
platforms = ["linux/amd64"]

[images.release]
immutable_tags = ["{{version}}"]
moving_tags = ["stable"]

[images.runtime]
profile = "service"
user = 1001
memory = "256MiB"
cpus = 1.0
pids = 128
nofile = 1024
health_command = ["/usr/local/bin/healthcheck"]

[[images.pins]]
reference\t=   "{OLD_REFERENCE}"   # shared base image
tag_intent = "moving-release-line"

[[images]]
id = "generator"
containerfile = "Containerfile.generator"
repository = "quay.io/example/generator"
platforms = ["linux/amd64"]

[[images.pins]]
reference = "{OLD_REFERENCE}"
tag_intent = "moving-release-line"

[[images.pins]]
reference = '{TOOL_TAG}@{TOOL_OLD}'
tag_intent = "immutable-version"

[images.release]
immutable_tags = ["{{version}}"]
moving_tags = ["stable"]

[images.runtime]
profile = "one-shot"
user = 1001
memory = "256MiB"
cpus = 1.0
pids = 64
nofile = 512
"""


@pytest.fixture(autouse=True)
def embedded_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pin_updates_module,
        "IDENTITY",
        ApplicationIdentity(source_revision="c" * 40),
    )


class CountingResolver:
    def __init__(self, mapping: dict[str, str] | None = None) -> None:
        self.mapping = mapping or {TAG: NEW, TOOL_TAG: TOOL_NEW}
        self.calls: list[str] = []

    def resolve_digest(self, reference: OCIReference) -> Digest:
        assert reference.digest is None
        assert reference.tag is not None
        self.calls.append(str(reference))
        return Digest(self.mapping[str(reference)])


def repository(
    tmp_path: Path,
    *,
    configuration: str = CONFIGURATION,
    runtime: str = RUNTIME_CONTAINERFILE,
    generator: str = GENERATOR_CONTAINERFILE,
) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "conclear.toml").write_text(configuration, encoding="utf-8")
    (root / "Containerfile").write_text(runtime, encoding="utf-8")
    (root / "Containerfile.generator").write_text(generator, encoding="utf-8")
    (root / ".containerignore").write_text(
        "**/.git/\n**/.env*\n**/*.key\n**/*.pem\n**/.venv/\n**/venv/\n",
        encoding="utf-8",
    )
    return root


def propose(
    root: Path,
    *,
    resolver: CountingResolver | None = None,
    image_ids: tuple[str, ...] | None = None,
    now: datetime = CLOCK,
) -> PinUpdateProposal:
    return propose_pin_updates(
        load_repository_config(root / "conclear.toml"),
        source=SOURCE,
        resolver=resolver or CountingResolver(),
        tools=TOOLS,
        now=lambda: now,
        image_ids=image_ids,
    )


def apply(
    proposal: PinUpdateProposal,
    root: Path,
    *,
    source: SourceIdentity = SOURCE,
    now: datetime = CLOCK + timedelta(minutes=5),
    fault_hook: Callable[[WritePhase, Path], None] | None = None,
) -> ApplicationOutcome:
    return apply_pin_proposal(
        proposal,
        repository_root=root,
        source=source,
        now=now,
        fault_hook=fault_hook,
    )


def snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        name: ((root / name).read_bytes(), stat.S_IMODE((root / name).stat().st_mode))
        for name in ("conclear.toml", "Containerfile", "Containerfile.generator")
    }


def expected_after_apply(root: Path) -> dict[str, bytes]:
    return {
        "conclear.toml": CONFIGURATION.replace(OLD, NEW)
        .replace(TOOL_OLD, TOOL_NEW)
        .encode("utf-8"),
        "Containerfile": RUNTIME_CONTAINERFILE.replace(OLD, NEW).encode("utf-8"),
        "Containerfile.generator": GENERATOR_CONTAINERFILE.replace(OLD, NEW)
        .replace(TOOL_OLD, TOOL_NEW)
        .encode("utf-8"),
    }


def test_shared_pin_is_resolved_once_and_bound_to_every_occurrence(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    resolver = CountingResolver({TAG: NEW, TOOL_TAG: TOOL_OLD})
    before = snapshot(root)

    proposal = propose(root, resolver=resolver)

    assert resolver.calls == [TAG, TOOL_TAG]
    assert snapshot(root) == before
    shared = [
        item
        for item in proposal.lookups
        if str(item.original_reference) == OLD_REFERENCE
    ]
    assert len(shared) == 1
    assert shared[0].image_ids == ("generator", "runtime")
    assert shared[0].tag_intent is PinIntent.MOVING_RELEASE_LINE
    assert str(shared[0].resolved_reference) == NEW_REFERENCE
    assert shared[0].resolved_at == CLOCK
    edits = [
        (item.path, edit.old_text, edit.new_text)
        for item in proposal.files
        for edit in item.edits
    ]
    assert edits == [
        ("Containerfile", OLD_REFERENCE, NEW_REFERENCE),
        ("Containerfile.generator", OLD_REFERENCE, NEW_REFERENCE),
        ("conclear.toml", OLD_REFERENCE, NEW_REFERENCE),
        ("conclear.toml", OLD_REFERENCE, NEW_REFERENCE),
    ]
    unchanged = next(
        item
        for item in proposal.lookups
        if str(item.original_reference).startswith(TOOL_TAG)
    )
    assert not unchanged.changed
    assert proposal.changed
    assert not proposal.review_required


def test_spans_address_exact_bytes_and_preserve_spelling(tmp_path: Path) -> None:
    root = repository(tmp_path)

    proposal = propose(root)

    for item in proposal.files:
        content = (root / item.path).read_bytes()
        assert item.sha256 == sha256_bytes(content)
        for edit in item.edits:
            assert content[edit.start : edit.end] == edit.old_text.encode("utf-8")
            assert edit.new_text.rsplit("@", 1)[0] == edit.old_text.rsplit("@", 1)[0]


def test_application_rewrites_only_proposed_spans_and_preserves_modes(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    (root / "Containerfile").chmod(0o640)
    (root / "conclear.toml").chmod(0o600)
    proposal = propose(root)

    outcome = apply(proposal, root)

    assert outcome.status is ApplicationStatus.APPLIED
    assert outcome.changed_paths == (
        "Containerfile",
        "Containerfile.generator",
        "conclear.toml",
    )
    after = snapshot(root)
    assert {name: content for name, (content, _) in after.items()} == (
        expected_after_apply(root)
    )
    assert after["Containerfile"][1] == 0o640
    assert after["conclear.toml"][1] == 0o600
    assert not [path for path in root.iterdir() if ".tmp" in path.name]
    for item in proposal.files:
        assert sha256_bytes((root / item.path).read_bytes()) == item.result_sha256


def test_proposal_serialization_is_deterministic_and_schema_valid(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    first = propose(root)
    second = propose(root)

    assert first.content_bytes() == second.content_bytes()
    assert first.content_bytes() == canonical_json_bytes(first.to_dict())
    assert first.digest() == sha256_bytes(first.content_bytes())
    value = first.to_dict()
    assert value["schemaVersion"] == 1
    assert value["recordType"] == "pinUpdateProposal"
    assert value["repositoryConfiguration"] == {
        "path": "conclear.toml",
        "sha256": sha256_bytes((root / "conclear.toml").read_bytes()),
    }
    assert value["source"] == {
        "repository": "https://github.com/example/app",
        "revision": "1" * 40,
    }
    assert value["imageIds"] == ["generator", "runtime"]
    assert parse_proposal(json.loads(first.content_bytes())) == first
    text = first.content_bytes().decode("utf-8")
    assert "auth" not in text.lower()
    assert "token" not in text.lower()


def test_proposal_output_is_written_once_and_never_overwritten(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    output = tmp_path / "proposal.json"
    proposal = propose(root)

    digest = proposal.write(output)

    assert output.read_bytes() == proposal.content_bytes()
    assert digest == proposal.digest()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(InvalidInvocationError, match="already exists"):
        proposal.write(output)
    assert load_proposal(output) == proposal


def test_current_repository_yields_explicit_no_change_and_untouched_apply(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    before = snapshot(root)
    stats = {name: (root / name).stat() for name in before}

    proposal = propose(root, resolver=CountingResolver({TAG: OLD, TOOL_TAG: TOOL_OLD}))
    outcome = apply(proposal, root)

    assert not proposal.changed
    assert proposal.files == ()
    assert len(proposal.lookups) == 2
    assert outcome.status is ApplicationStatus.NO_CHANGE
    assert outcome.changed_paths == ()
    assert snapshot(root) == before
    assert {name: (root / name).stat().st_mtime_ns for name in before} == {
        name: value.st_mtime_ns for name, value in stats.items()
    }


def test_applying_the_same_proposal_twice_is_idempotent(tmp_path: Path) -> None:
    root = repository(tmp_path)
    proposal = propose(root)
    apply(proposal, root)
    after_first = snapshot(root)

    outcome = apply(proposal, root)

    assert outcome.status is ApplicationStatus.ALREADY_APPLIED
    assert outcome.changed_paths == ()
    assert snapshot(root) == after_first


def test_immutable_version_change_records_review_requirement(tmp_path: Path) -> None:
    root = repository(tmp_path)

    proposal = propose(root)

    tool = next(
        item
        for item in proposal.lookups
        if str(item.original_reference).startswith(TOOL_TAG)
    )
    shared = next(
        item
        for item in proposal.lookups
        if str(item.original_reference) == OLD_REFERENCE
    )
    assert tool.tag_intent is PinIntent.IMMUTABLE_VERSION
    assert tool.review_required
    assert not shared.review_required
    assert proposal.review_required
    assert proposal.to_dict()["reviewRequired"] is True
    assert [finding.check_id for finding in proposal.findings] == ["CC0205"]
    assert "supply-chain review" in proposal.findings[0].message


def test_divergent_tag_intents_for_one_dependency_are_rejected(tmp_path: Path) -> None:
    configuration = CONFIGURATION.replace(
        f'reference = "{OLD_REFERENCE}"\ntag_intent = "moving-release-line"',
        f'reference = "{OLD_REFERENCE}"\ntag_intent = "immutable-version"',
    )
    root = repository(tmp_path, configuration=configuration)

    with pytest.raises(InvalidInvocationError, match="tag intent") as caught:
        propose(root)
    assert caught.value.code == "CC0206"


def test_missing_containerfile_occurrence_is_a_declaration_mismatch(
    tmp_path: Path,
) -> None:
    root = repository(
        tmp_path,
        runtime=RUNTIME_CONTAINERFILE.replace(OLD_REFERENCE, f"{TOOL_TAG}@{TOOL_OLD}"),
    )

    with pytest.raises(RuleRejectionError) as caught:
        propose(root)
    assert caught.value.code == "CC0203"


def test_reference_in_a_comment_is_an_extra_occurrence(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        runtime=RUNTIME_CONTAINERFILE + f"# previously {OLD_REFERENCE}\n",
    )

    with pytest.raises(InvalidInvocationError, match="occurrence") as caught:
        propose(root)
    assert caught.value.code == "CC0206"


def test_reference_in_an_unrelated_configuration_value_is_rejected(
    tmp_path: Path,
) -> None:
    configuration = CONFIGURATION.replace(
        'name = "example"', f'name = "example {OLD_REFERENCE}"'
    )
    root = repository(tmp_path, configuration=configuration)

    with pytest.raises(InvalidInvocationError, match="occurrence") as caught:
        propose(root)
    assert caught.value.code == "CC0206"


def test_multi_stage_repeated_reference_binds_every_instruction(tmp_path: Path) -> None:
    generator = GENERATOR_CONTAINERFILE.replace(
        f"FROM {TOOL_TAG}@{TOOL_OLD} AS build\n",
        f"FROM {TOOL_TAG}@{TOOL_OLD} AS build\n"
        f"RUN --mount=type=bind,from={TOOL_TAG}@{TOOL_OLD},target=/mnt true\n",
    )
    root = repository(tmp_path, generator=generator)

    proposal = propose(root)

    generator_file = next(
        item for item in proposal.files if item.path == "Containerfile.generator"
    )
    assert [edit.old_text for edit in generator_file.edits] == [
        f"{TOOL_TAG}@{TOOL_OLD}",
        f"{TOOL_TAG}@{TOOL_OLD}",
        OLD_REFERENCE,
        f"{TOOL_TAG}@{TOOL_OLD}",
    ]
    apply(proposal, root)
    assert (root / "Containerfile.generator").read_text(encoding="utf-8") == (
        generator.replace(OLD, NEW).replace(TOOL_OLD, TOOL_NEW)
    )


def test_selection_omitting_an_image_sharing_the_dependency_is_rejected(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    with pytest.raises(InvalidInvocationError, match="generator"):
        propose(root, image_ids=("runtime",))
    with pytest.raises(InvalidInvocationError, match="unknown"):
        propose(root, image_ids=("missing",))


def test_closed_selection_limits_the_proposal_to_selected_images(
    tmp_path: Path,
) -> None:
    configuration = CONFIGURATION.replace(
        f'[[images.pins]]\nreference\t=   "{OLD_REFERENCE}"   # shared base image\n'
        'tag_intent = "moving-release-line"\n',
        f'[[images.pins]]\nreference = "quay.io/example/other:1@{OLD}"\n'
        'tag_intent = "moving-release-line"\n',
    )
    runtime = RUNTIME_CONTAINERFILE.replace(
        OLD_REFERENCE, f"quay.io/example/other:1@{OLD}"
    )
    root = repository(tmp_path, configuration=configuration, runtime=runtime)
    resolver = CountingResolver(
        {"quay.io/example/other:1": NEW, TAG: NEW, TOOL_TAG: TOOL_NEW}
    )

    proposal = propose(root, resolver=resolver, image_ids=("runtime",))

    assert resolver.calls == ["quay.io/example/other:1"]
    assert proposal.image_ids == ("runtime",)
    assert [item.path for item in proposal.files] == ["Containerfile", "conclear.toml"]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda root: (root / "Containerfile").write_bytes(b"FROM scratch\n"),
            "digest",
        ),
        (
            lambda root: (root / "conclear.toml").write_text(
                CONFIGURATION.replace('name = "example"', 'name = "renamed"'),
                encoding="utf-8",
            ),
            "configuration",
        ),
    ],
)
def test_changed_repository_state_is_rejected_before_any_write(
    tmp_path: Path,
    mutate: Callable[[Path], None],
    message: str,
) -> None:
    root = repository(tmp_path)
    proposal = propose(root)
    mutate(root)
    before = snapshot(root)

    with pytest.raises(InvalidInvocationError, match=message) as caught:
        apply(proposal, root)
    assert caught.value.code == "CC0207"
    assert snapshot(root) == before


def test_changed_git_revision_or_repository_is_rejected(tmp_path: Path) -> None:
    root = repository(tmp_path)
    proposal = propose(root)
    before = snapshot(root)

    with pytest.raises(InvalidInvocationError, match="revision") as caught:
        apply(proposal, root, source=SourceIdentity(SOURCE.repository, "2" * 40))
    assert caught.value.code == "CC0207"
    with pytest.raises(InvalidInvocationError, match="repository"):
        apply(
            proposal,
            root,
            source=SourceIdentity("https://github.com/example/other", SOURCE.revision),
        )
    assert snapshot(root) == before


def test_stale_resolution_is_rejected_without_resolving_again(tmp_path: Path) -> None:
    root = repository(tmp_path)
    proposal = propose(root)
    before = snapshot(root)

    with pytest.raises(OperationalError, match="stale"):
        apply(proposal, root, now=CLOCK + timedelta(hours=24, seconds=1))
    assert snapshot(root) == before
    apply(proposal, root, now=CLOCK + timedelta(hours=24))
    assert snapshot(root) != before


def test_narrowed_freshness_limit_applies_to_stale_proposals(tmp_path: Path) -> None:
    configuration = CONFIGURATION.replace(
        "[images.release]",
        '[images.limits]\npin_freshness = "1h"\n\n[images.release]',
        1,
    )
    root = repository(tmp_path, configuration=configuration)
    proposal = propose(root)

    with pytest.raises(OperationalError, match="stale"):
        apply(proposal, root, now=CLOCK + timedelta(hours=2))


def _mutated(proposal: PinUpdateProposal, **changes: object) -> dict[str, object]:
    return {**proposal.to_dict(), **changes}


def test_malformed_oversized_and_unsupported_proposals_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = repository(tmp_path)
    proposal = propose(root)
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not json", encoding="utf-8")
    with pytest.raises(InvalidInvocationError):
        load_proposal(malformed)

    with pytest.raises(InvalidInvocationError, match="Invalid pin update proposal"):
        parse_proposal(_mutated(proposal, unexpected=True))
    with pytest.raises(InvalidInvocationError, match="Invalid pin update proposal"):
        parse_proposal(_mutated(proposal, schemaVersion=2))
    with pytest.raises(InvalidInvocationError, match="Invalid pin update proposal"):
        parse_proposal(_mutated(proposal, recordType="releaseCandidate"))
    with pytest.raises(InvalidInvocationError):
        parse_proposal([])

    valid = tmp_path / "valid.json"
    proposal.write(valid)
    monkeypatch.setattr("conclear.pin_updates.MAX_PROPOSAL_BYTES", 64)
    with pytest.raises(InvalidInvocationError, match="size limit"):
        load_proposal(valid)
    assert MAX_PROPOSAL_BYTES > 64


def _with_file(
    proposal: PinUpdateProposal, index: int, **changes: object
) -> dict[str, object]:
    value = proposal.to_dict()
    files = list(value["files"])  # type: ignore[call-overload]
    files[index] = {**files[index], **changes}
    return {**value, "files": files}


def _with_edit(
    proposal: PinUpdateProposal, file_index: int, edit_index: int, **changes: object
) -> dict[str, object]:
    value = proposal.to_dict()
    files = list(value["files"])  # type: ignore[call-overload]
    edits = list(files[file_index]["edits"])
    edits[edit_index] = {**edits[edit_index], **changes}
    files[file_index] = {**files[file_index], "edits": edits}
    return {**value, "files": files}


def _with_lookup(
    proposal: PinUpdateProposal, index: int, **changes: object
) -> dict[str, object]:
    value = proposal.to_dict()
    lookups = list(value["lookups"])  # type: ignore[call-overload]
    lookups[index] = {**lookups[index], **changes}
    return {**value, "lookups": lookups}


def test_semantic_proposal_invariants_are_enforced(tmp_path: Path) -> None:
    root = repository(tmp_path)
    proposal = propose(root)
    first_edit = proposal.files[0].edits[0]

    with pytest.raises(InvalidInvocationError, match="overlap"):
        parse_proposal(
            _with_file(
                proposal,
                2,
                edits=[
                    *proposal.to_dict()["files"][2]["edits"],  # type: ignore[index]
                    {
                        "start": proposal.files[2].edits[0].start + 1,
                        "end": proposal.files[2].edits[0].end + 1,
                        "oldBytes": OLD_REFERENCE,
                        "newBytes": NEW_REFERENCE,
                    },
                ],
            )
        )
    with pytest.raises(InvalidInvocationError, match="span"):
        parse_proposal(_with_edit(proposal, 0, 0, end=first_edit.end + 1))
    with pytest.raises(InvalidInvocationError, match="spelling"):
        parse_proposal(
            _with_edit(
                proposal, 0, 0, newBytes=NEW_REFERENCE.replace("debian", "ubuntu")
            )
        )
    with pytest.raises(InvalidInvocationError, match="digest"):
        parse_proposal(_with_lookup(proposal, 0, newDigest="sha256:" + "f" * 64))
    with pytest.raises(InvalidInvocationError, match="lookup"):
        parse_proposal(
            _with_edit(proposal, 0, 0, newBytes=OLD_REFERENCE.replace(OLD, TOOL_NEW))
        )
    with pytest.raises(InvalidInvocationError, match=r"non-unique|duplicate"):
        parse_proposal(
            _mutated(proposal, files=proposal.to_dict()["files"] * 2)  # type: ignore[operator]
        )
    with pytest.raises(InvalidInvocationError, match="image"):
        parse_proposal(_with_lookup(proposal, 0, imageIds=["stranger"]))


@pytest.mark.parametrize(
    ("path", "prepare"),
    [
        ("/etc/passwd", lambda root: None),
        ("../outside", lambda root: (root.parent / "outside").write_bytes(b"x")),
        (
            "link",
            lambda root: (root / "link").symlink_to(root / "Containerfile"),
        ),
        ("fifo", lambda root: os.mkfifo(root / "fifo")),
        ("missing", lambda root: None),
    ],
)
def test_unsafe_target_paths_are_rejected_before_any_write(
    tmp_path: Path, path: str, prepare: Callable[[Path], None]
) -> None:
    root = repository(tmp_path)
    proposal = propose(root)
    prepare(root)
    before = snapshot(root)
    value = proposal.to_dict()
    files = list(value["files"])  # type: ignore[call-overload]
    files[0] = {**files[0], "path": path}

    with pytest.raises(InvalidInvocationError):
        apply(parse_proposal({**value, "files": files}), root)
    assert snapshot(root) == before


def test_changed_old_bytes_are_rejected_before_any_write(tmp_path: Path) -> None:
    root = repository(tmp_path)
    proposal = propose(root)
    other = OLD_REFERENCE.replace("a" * 64, "9" * 64)
    (root / "Containerfile").write_text(
        RUNTIME_CONTAINERFILE.replace(OLD_REFERENCE, other), encoding="utf-8"
    )
    tampered = _with_file(
        proposal,
        0,
        sha256=sha256_bytes((root / "Containerfile").read_bytes()),
    )
    before = snapshot(root)

    with pytest.raises(InvalidInvocationError, match="old bytes") as caught:
        apply(parse_proposal(tampered), root)
    assert caught.value.code == "CC0207"
    assert snapshot(root) == before


@pytest.mark.parametrize(
    "phase", [WritePhase.WRITE, WritePhase.FLUSH, WritePhase.REPLACE, WritePhase.VERIFY]
)
def test_injected_failures_during_application_restore_every_target(
    tmp_path: Path, phase: WritePhase
) -> None:
    root = repository(tmp_path)
    (root / "Containerfile").chmod(0o640)
    proposal = propose(root)
    before = snapshot(root)
    seen: list[tuple[WritePhase, str]] = []

    def hook(current: WritePhase, path: Path) -> None:
        seen.append((current, path.name))
        if current is phase and path.name == "Containerfile.generator":
            raise OSError("injected failure")

    with pytest.raises(OperationalError, match=r"injected failure|restored"):
        apply(proposal, root, fault_hook=hook)

    assert snapshot(root) == before
    assert (WritePhase.REPLACE, "Containerfile") in seen
    assert not [path for path in root.iterdir() if ".tmp" in path.name]


def test_failure_before_the_first_write_changes_nothing(tmp_path: Path) -> None:
    root = repository(tmp_path)
    proposal = propose(root)
    before = snapshot(root)

    def hook(current: WritePhase, path: Path) -> None:
        del path
        if current is WritePhase.PREPARE:
            raise OSError("no space")

    with pytest.raises(OperationalError):
        apply(proposal, root, fault_hook=hook)
    assert snapshot(root) == before


def test_development_source_tree_cannot_emit_proposals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = repository(tmp_path)
    proposal = propose(root)
    monkeypatch.setattr(
        pin_updates_module,
        "IDENTITY",
        ApplicationIdentity(source_revision="development-source-tree"),
    )

    with pytest.raises(OperationalError, match="staged build"):
        proposal.to_dict()
