"""Command dispatch, JSON result shapes and exit statuses for every command.

Services are replaced by typed fakes at the command boundary so each command's
argument handling, state transitions, result object and exit status are
exercised without container tools, registries or credentials.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import conclear.commands.local as local_commands
import conclear.commands.maintenance as maintenance_commands
import conclear.commands.remote as remote_commands
import conclear.commands.transport as transport_commands
import conclear.services.preflight as preflight_module
import conclear.services.release as release_module
from conclear.cli import main
from conclear.config import load_repository_config
from conclear.dependencies import (
    command_dependencies,
    command_tools,
    scope_dependencies,
)
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.freshness import QualificationWindow
from conclear.presentation import Finding
from conclear.records import SourceIdentity, Verdict
from conclear.release_profile import (
    BuilderConfig,
    CIContextPolicy,
    QuayRegistryConfig,
    RegistryProvider,
    ReleaseProfile,
)
from conclear.runtime import ToolProblem
from conclear.services.doctor import DoctorScope
from conclear.tools import ToolName
from conclear.values import Digest
from conclear.workspace import RunState, RunWorkspace
from tests.unit.test_config import _image_text

BUILDER_ID = "https://foundata.com/en/projects/conclear/builder/simple-v1/"
DIGEST = "sha256:" + "a" * 64
RUN_ID = "01arz3ndektsv4rrffq69g5fav"


class FixedIdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def release_profile(
    tmp_path: Path,
    *,
    key: str | None = "cosign.key",
    auth: str | None = "auth.json",
    token: str | None = None,
) -> ReleaseProfile:
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public\n", encoding="utf-8")
    return ReleaseProfile(
        name="production",
        ci_context=CIContextPolicy.OMIT,
        builder=BuilderConfig(BUILDER_ID),
        auth_file=None if auth is None else tmp_path / auth,
        registry=QuayRegistryConfig(
            RegistryProvider.QUAY,
            "quay.io",
            "https://quay.io/api/v1",
            None if token is None else tmp_path / token,
        ),
        cosign_private_key=None if key is None else str(tmp_path / key),
        cosign_public_key=public_key,
        passphrase_file=None,
        configuration_digest="sha256:" + "b" * 64,
        public_key_digest="sha256:" + "c" * 64,
    )


class FakeSourceRun:
    def __init__(
        self,
        root: Path,
        tmp_path: Path,
        *,
        state: RunState = RunState.CREATED,
        profile: ReleaseProfile | None = None,
        version: str | None = "1.2.3",
    ) -> None:
        self.repository = load_repository_config(root / "conclear.toml")
        inputs = {
            "sourceRoot": str(root.resolve()),
            "sourceRevision": "b" * 40,
            "sourceRepository": self.repository.project.source,
            "configurationDigest": DIGEST,
            "image": "app",
            "version": version or "",
            "profile": "none" if profile is None else profile.name,
        }
        if profile is not None:
            inputs.update(
                {
                    "builderId": profile.builder.id,
                    "profileConfigurationDigest": profile.configuration_digest,
                    "profilePublicKeyDigest": profile.public_key_digest,
                }
            )
        self.workspace = RunWorkspace.create(
            state_home=tmp_path / "state",
            immutable_inputs=inputs,
            id_factory=FixedIdFactory(),
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
        for next_state in (
            RunState.QUALIFIED,
            RunState.ASSEMBLED,
            RunState.PUBLISHED,
            RunState.ATTESTED,
            RunState.VERIFIED,
        ):
            if self.workspace.load().state is state:
                break
            self.workspace.transition(next_state)
        self.source = SourceIdentity(self.repository.project.source, "b" * 40)
        self.source_time = datetime(2026, 1, 1, tzinfo=UTC)
        self.runtime = SimpleNamespace(
            git=lambda: object(),
            buildah=lambda: object(),
            podman=lambda: object(),
            trivy=lambda: object(),
            hadolint=lambda: object(),
            skopeo=lambda: object(),
            cosign=lambda **kwargs: object(),
            identities=(),
            runner=object(),
            environment={"PATH": "/usr/bin"},
        )


@pytest.fixture
def invoke(
    capsys: pytest.CaptureFixture[str],
) -> Callable[[list[str]], tuple[int, Any, str]]:
    def run(arguments: list[str]) -> tuple[int, Any, str]:
        capsys.readouterr()
        exit_code = main([*arguments, "--format", "json"])
        captured = capsys.readouterr()
        assert captured.out.count("\n") == 1, captured.out
        return exit_code, json.loads(captured.out), captured.err

    return run


def graph(digest: str = DIGEST) -> SimpleNamespace:
    return SimpleNamespace(digest=Digest(digest))


def build_evidence(findings: tuple[Finding, ...] = ()) -> SimpleNamespace:
    return SimpleNamespace(
        observation=SimpleNamespace(layout_path=Path("/layout"), graph=graph()),
        findings=findings,
    )


ERROR = Finding("CC0113", "error", "label mismatch")


def _local(monkeypatch: pytest.MonkeyPatch, run: FakeSourceRun, **fakes: Any) -> None:
    monkeypatch.setattr(
        local_commands, "state_home", lambda: run.workspace.root.parents[2]
    )
    monkeypatch.setattr(
        local_commands, "cache_home", lambda: run.workspace.root / "cache"
    )
    monkeypatch.setattr(local_commands, "create_source_run", lambda **_kwargs: run)
    monkeypatch.setattr(local_commands, "open_source_run", lambda **_kwargs: run)
    for name, value in fakes.items():
        monkeypatch.setattr(local_commands, name, value)


@pytest.mark.parametrize(
    ("findings", "exit_code", "status", "state"),
    [
        ((), 0, "success", RunState.CREATED),
        ((ERROR,), 2, "ruleRejection", RunState.REJECTED),
    ],
)
def test_build_reports_layout_identity_and_rejects_on_metadata_errors(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    findings: tuple[Finding, ...],
    exit_code: int,
    status: str,
    state: RunState,
) -> None:
    run = FakeSourceRun(repository_factory(), tmp_path)
    _local(
        monkeypatch,
        run,
        build_platform=lambda inputs, builder: build_evidence(findings),
        write_build_evidence=lambda inputs, build: Path("/evidence/build.json"),
        build_test_dependencies=lambda inputs, builder: (),
    )

    code, value, _ = invoke(
        ["build", "--revision", "v1", "--image", "app", "--platform", "linux/amd64"]
    )

    assert (code, value["status"]) == (exit_code, status)
    assert value["data"]["digest"] == DIGEST
    assert value["data"]["runId"] == run.workspace.run_id
    assert run.workspace.load().state is state


def test_build_rejects_platform_that_the_image_does_not_declare(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    run = FakeSourceRun(repository_factory(), tmp_path)
    _local(monkeypatch, run)

    code, value, stderr = invoke(
        ["build", "--revision", "v1", "--image", "app", "--platform", "linux/arm64"]
    )

    assert code == 64
    assert value["status"] == "invalidInvocation"
    assert "not configured" in value["message"]
    assert value["data"] == {"runId": run.workspace.run_id}
    assert f"conclear cleanup {run.workspace.run_id}" in stderr
    assert run.workspace.load().state is RunState.INCOMPLETE


@pytest.mark.parametrize(
    ("command", "fake"),
    [("build", "build_platform"), ("qualify", "preflight_image_closure")],
)
def test_run_creating_commands_name_their_run_when_a_phase_fails(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    command: str,
    fake: str,
) -> None:
    run = FakeSourceRun(repository_factory(), tmp_path)

    def fail(*args: Any, **kwargs: Any) -> None:
        raise OperationalError("tool failed")

    _local(monkeypatch, run, **{fake: fail})

    code, value, stderr = invoke(
        [command, "--revision", "v1", "--image", "app", "--platform", "linux/amd64"]
    )

    assert (code, value["status"]) == (1, "operationalFailure")
    assert value["message"] == "tool failed"
    assert value["data"] == {"runId": run.workspace.run_id}
    assert f"conclear cleanup {run.workspace.run_id}" in stderr
    assert run.workspace.load().state is RunState.INCOMPLETE


@pytest.mark.parametrize(
    ("incomplete", "findings", "exit_code", "status", "state"),
    [
        (False, (), 0, "success", RunState.CREATED),
        (False, (ERROR,), 2, "ruleRejection", RunState.REJECTED),
        (True, (), 1, "operationalFailure", RunState.INCOMPLETE),
    ],
)
def test_test_command_distinguishes_pass_rejection_and_incompleteness(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    incomplete: bool,
    findings: tuple[Finding, ...],
    exit_code: int,
    status: str,
    state: RunState,
) -> None:
    run = FakeSourceRun(repository_factory(), tmp_path)
    _local(
        monkeypatch,
        run,
        load_build_evidence=lambda inputs: build_evidence(),
        test_platform=lambda *args, **kwargs: SimpleNamespace(
            incomplete=incomplete, findings=findings, test_report_digest=DIGEST
        ),
    )

    code, value, _ = invoke(["test", run.workspace.run_id, "--platform", "linux/amd64"])

    assert (code, value["status"]) == (exit_code, status)
    assert value["data"] == {"reportDigest": DIGEST}
    assert run.workspace.load().state is state


class _PinStore:
    def __init__(self, *, accepted: bool) -> None:
        self.accepted = accepted

    def check(self, pin: object, **kwargs: Any) -> SimpleNamespace:
        findings = () if self.accepted else (Finding("CC0204", "error", "diverged"),)
        return SimpleNamespace(accepted=self.accepted, findings=findings)


@pytest.mark.parametrize(
    ("preflight_accepted", "pins_accepted", "verdict", "exit_code", "status", "state"),
    [
        (True, True, Verdict.ACCEPTED, 0, "success", RunState.QUALIFIED),
        (True, True, Verdict.REJECTED, 2, "ruleRejection", RunState.REJECTED),
        (True, True, Verdict.INCOMPLETE, 1, "operationalFailure", RunState.INCOMPLETE),
        (False, True, None, 2, "ruleRejection", RunState.REJECTED),
        (True, False, None, 2, "ruleRejection", RunState.REJECTED),
    ],
)
@pytest.mark.parametrize("shared_start", [False, True])
def test_qualify_command_transitions_state_from_preflight_and_verdict(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    preflight_accepted: bool,
    pins_accepted: bool,
    verdict: Verdict | None,
    exit_code: int,
    status: str,
    state: RunState,
    shared_start: bool,
) -> None:
    run = FakeSourceRun(repository_factory(), tmp_path)
    selected_databases: list[str] = []
    started_at = datetime(2026, 1, 1, tzinfo=UTC) if shared_start else None

    def qualify(*args: Any, **kwargs: Any) -> SimpleNamespace:
        assert verdict is not None, "qualification ran after a rejected preflight"
        assert kwargs["qualification_started_at"] == started_at
        assert callable(kwargs["record_clock"])
        return SimpleNamespace(
            verdict=verdict,
            findings=() if verdict is Verdict.ACCEPTED else (ERROR,),
            record_path=Path("/record.json"),
            record_digest=DIGEST,
            layout_path=Path("/layout"),
            qualification_window=QualificationWindow.start(
                datetime(2026, 1, 1, tzinfo=UTC)
            ),
        )

    def by_digest(
        *args: Any, expected_digest: Digest, **kwargs: Any
    ) -> SimpleNamespace:
        selected_databases.append(str(expected_digest))
        assert kwargs["qualification_started_at"] == started_at
        return SimpleNamespace(digest=str(expected_digest))

    monkeypatch.setattr(
        preflight_module,
        "check_image",
        lambda image, hadolint: SimpleNamespace(
            accepted=preflight_accepted,
            findings=() if preflight_accepted else (ERROR,),
        ),
    )
    _local(
        monkeypatch,
        run,
        PinStore=lambda home: _PinStore(accepted=pins_accepted),
        AuthenticatedPinResolver=lambda runtime, auth_file: object(),
        select_database_by_digest=by_digest,
        select_fresh_database=lambda *args, **kwargs: SimpleNamespace(digest=DIGEST),
        hook_runner=lambda *args, **kwargs: object(),
        qualify_platform=qualify,
    )

    code, value, _ = invoke(
        [
            "qualify",
            "--revision",
            "v1",
            "--image",
            "app",
            "--platform",
            "linux/amd64",
            "--database-digest",
            DIGEST,
            *(
                ["--qualification-started-at", "2026-01-01T00:00:00Z"]
                if shared_start
                else []
            ),
        ]
    )

    assert (code, value["status"]) == (exit_code, status)
    assert value["data"]["runId"] == run.workspace.run_id
    assert run.workspace.load().state is state
    assert selected_databases == ([DIGEST] if verdict is not None else [])
    if verdict is not None:
        assert value["data"]["qualificationWindow"] == {
            "startedAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2026-01-02T00:00:00Z",
        }


@pytest.mark.parametrize(
    ("start", "digest_args", "message"),
    [
        ("2026-01-01T00:00:00Z", [], "requires --database-digest"),
        ("not-a-time", ["--database-digest", DIGEST], "qualification start"),
        ("2026-01-01T00:00:00", ["--database-digest", DIGEST], "qualification start"),
    ],
)
def test_qualify_rejects_invalid_shared_start_before_creating_a_run(
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    monkeypatch: pytest.MonkeyPatch,
    start: str,
    digest_args: list[str],
    message: str,
) -> None:
    monkeypatch.setattr(
        local_commands,
        "create_source_run",
        lambda **kwargs: pytest.fail("Invalid arguments must not create a run"),
    )
    code, value, _ = invoke(
        [
            "qualify",
            "--revision",
            "v1",
            "--image",
            "app",
            "--platform",
            "linux/amd64",
            "--qualification-started-at",
            start,
            *digest_args,
        ]
    )
    assert code == 64
    assert value["status"] == "invalidInvocation"
    assert message in value["message"]


def test_assemble_command_imports_transports_into_a_new_coordinator_run(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    run = FakeSourceRun(repository_factory(), tmp_path)
    imports: list[tuple[Path, str]] = []
    versions: list[str | None] = []
    worker = "01arz3ndektsv4rrffq69g5faw"

    def import_transport(
        path: Path,
        *,
        expected_digest: str,
        workspace: Any,
        image: Any,
        repository: Any,
        source_time: Any,
    ) -> SimpleNamespace:
        imports.append((path, expected_digest))
        return SimpleNamespace(
            transport=SimpleNamespace(record_path=path),
            source=path,
            kind=SimpleNamespace(value="archive"),
            platform="linux/amd64",
            worker_run_id=worker,
            transport_digest=expected_digest,
            manifest_digest=DIGEST,
            record_digest=DIGEST,
        )

    def assemble(
        transports: tuple[Any, ...], *, version: str | None, **kwargs: Any
    ) -> SimpleNamespace:
        versions.append(version)
        assert [item.record_path for item in transports] == [Path("/a.tar")]
        return SimpleNamespace(
            record_path=Path("/candidate.json"),
            record_digest=DIGEST,
            observation=SimpleNamespace(
                path=Path("/candidate"),
                graph=graph(),
                platform_manifests=(("linux/amd64", Digest(DIGEST)),),
            ),
            candidate_tag="1.2.3-candidate.01arz3ndektsv4rrffq69g5fav.gbbbbbbbb",
        )

    _local(
        monkeypatch,
        run,
        import_transport=import_transport,
        assemble_candidate=assemble,
    )

    code, value, _ = invoke(
        [
            "assemble",
            "--revision",
            "v1",
            "--image",
            "app",
            "--version",
            "1.2.3",
            "--transport",
            "/a.tar",
            DIGEST,
        ]
    )

    assert code == 0
    assert value["data"]["runId"] == run.workspace.run_id
    assert value["data"]["subjectDigest"] == DIGEST
    assert value["data"]["platformManifests"] == {"linux/amd64": DIGEST}
    assert value["data"]["transports"] == [
        {
            "platform": "linux/amd64",
            "workerRunId": worker,
            "transport": "/a.tar",
            "kind": "archive",
            "transportDigest": DIGEST,
            "manifestDigest": DIGEST,
            "recordDigest": DIGEST,
        }
    ]
    assert imports == [(Path("/a.tar"), DIGEST)]
    assert versions == ["1.2.3"]
    assert run.workspace.load().state is RunState.QUALIFIED


@pytest.mark.parametrize(
    ("failure", "exit_code", "status", "state"),
    [
        (
            RuleRejectionError("Transport digest mismatch", code="CC0306"),
            2,
            "ruleRejection",
            RunState.REJECTED,
        ),
        (
            OperationalError("Unable to copy transport member"),
            1,
            "operationalFailure",
            RunState.INCOMPLETE,
        ),
    ],
)
def test_assemble_command_records_a_failed_import_on_the_coordinator_run(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    failure: Exception,
    exit_code: int,
    status: str,
    state: RunState,
) -> None:
    run = FakeSourceRun(repository_factory(), tmp_path)

    def import_transport(*args: Any, **kwargs: Any) -> SimpleNamespace:
        raise failure

    _local(
        monkeypatch,
        run,
        import_transport=import_transport,
        assemble_candidate=lambda *args, **kwargs: pytest.fail("assembled"),
    )

    code, value, stderr = invoke(
        [
            "assemble",
            "--revision",
            "v1",
            "--image",
            "app",
            "--transport",
            "/a.tar",
            DIGEST,
        ]
    )

    assert (code, value["status"]) == (exit_code, status)
    assert value["data"] == {"runId": run.workspace.run_id}
    assert f"conclear cleanup {run.workspace.run_id}" in stderr
    assert run.workspace.load().state is state


def test_assemble_command_requires_at_least_one_transport(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    run = FakeSourceRun(repository_factory(), tmp_path)
    _local(monkeypatch, run)

    code, value, _ = invoke(["assemble", "--revision", "v1", "--image", "app"])

    assert code == 64
    assert value["status"] == "invalidInvocation"
    assert "--transport" in value["message"]


def test_transport_export_reports_every_digest_a_worker_must_publish(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    run = FakeSourceRun(repository_factory(), tmp_path, state=RunState.QUALIFIED)
    calls: list[dict[str, Any]] = []

    def export_transport(
        workspace: Any,
        image: Any,
        platform: Any,
        *,
        destination: Path,
        kind: Any,
        now: Any,
    ) -> SimpleNamespace:
        calls.append(
            {"platform": str(platform), "destination": destination, "kind": kind}
        )
        return SimpleNamespace(
            path=destination,
            kind=kind,
            worker_run_id=run.workspace.run_id,
            transport_digest=DIGEST,
            manifest_digest="sha256:" + "1" * 64,
            record_digest="sha256:" + "2" * 64,
            layout_digest="sha256:" + "3" * 64,
            platform_manifest_digest="sha256:" + "3" * 64,
            payload_digests=("sha256:" + "4" * 64,),
            members=(object(),) * 9,
            total_bytes=1234,
        )

    monkeypatch.setattr(
        transport_commands, "state_home", lambda: run.workspace.root.parents[2]
    )
    monkeypatch.setattr(transport_commands, "open_source_run", lambda **_kwargs: run)
    monkeypatch.setattr(transport_commands, "export_transport", export_transport)

    code, value, _ = invoke(
        [
            "transport",
            "export",
            run.workspace.run_id,
            "--platform",
            "linux/amd64",
            "--output",
            str(tmp_path / "app-linux-amd64.tar"),
        ]
    )

    assert code == 0
    assert value["command"] == "transport export"
    assert value["data"] == {
        "runId": run.workspace.run_id,
        "platform": "linux/amd64",
        "transport": str(tmp_path / "app-linux-amd64.tar"),
        "kind": "archive",
        "transportDigest": DIGEST,
        "manifestDigest": "sha256:" + "1" * 64,
        "recordDigest": "sha256:" + "2" * 64,
        "layoutDigest": "sha256:" + "3" * 64,
        "platformManifestDigest": "sha256:" + "3" * 64,
        "payloadDigests": ["sha256:" + "4" * 64],
        "members": 9,
        "totalBytes": 1234,
    }
    assert calls[0]["kind"].value == "archive"

    code, value, _ = invoke(
        [
            "transport",
            "export",
            run.workspace.run_id,
            "--platform",
            "linux/arm64",
            "--output",
            str(tmp_path / "other"),
            "--kind",
            "directory",
        ]
    )
    assert code == 64
    assert "not configured" in value["message"]
    assert len(calls) == 1


def _remote(
    monkeypatch: pytest.MonkeyPatch,
    run: FakeSourceRun,
    profile: ReleaseProfile,
    **fakes: Any,
) -> None:
    monkeypatch.setattr(
        remote_commands, "state_home", lambda: run.workspace.root.parents[2]
    )
    monkeypatch.setattr(
        remote_commands, "cache_home", lambda: run.workspace.root / "cache"
    )
    monkeypatch.setattr(remote_commands, "open_source_run", lambda **_kwargs: run)
    monkeypatch.setattr(remote_commands, "profile", lambda name: profile)
    monkeypatch.setattr(
        remote_commands, "signing_passphrase", lambda *args, **kwargs: "secret"
    )
    monkeypatch.setattr(remote_commands, "ci_context", lambda selected: None)
    monkeypatch.setattr(
        remote_commands,
        "create_registry_control",
        lambda *args, **kwargs: SimpleNamespace(close=lambda: None),
    )
    for name, value in fakes.items():
        monkeypatch.setattr(remote_commands, name, value)


def _candidate() -> SimpleNamespace:
    return SimpleNamespace(
        observation=SimpleNamespace(
            graph=graph(), platform_manifests=(), path=Path("/candidate")
        ),
        candidate_tag="1.2.3-candidate.01arz3ndektsv4rrffq69g5fav.gbbbbbbbb",
        record_digest=DIGEST,
        qualification_digests=(DIGEST,),
    )


def _published(run: FakeSourceRun) -> SimpleNamespace:
    return SimpleNamespace(
        reference=run.repository.release_image("app").repository.with_tag("candidate"),
        immutable_reference=run.repository.release_image("app").repository.with_digest(
            Digest(DIGEST)
        ),
        graph=graph(),
        expiration=datetime(2026, 1, 8, tzinfo=UTC),
        immutability_enabled=True,
    )


def test_provenance_command_requires_assembled_state_and_a_profile_bound_run(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    profile = release_profile(tmp_path)
    root = repository_factory()
    created = FakeSourceRun(root, tmp_path / "created", profile=profile)
    _remote(monkeypatch, created, profile)
    code, value, _ = invoke(["provenance", created.workspace.run_id])
    assert code == 64
    assert "assembled state" in value["message"]

    unbound = FakeSourceRun(root, tmp_path / "unbound", state=RunState.ASSEMBLED)
    _remote(monkeypatch, unbound, profile)
    code, value, _ = invoke(["provenance", unbound.workspace.run_id])
    assert code == 64
    assert "release profile" in value["message"]

    run = FakeSourceRun(
        root, tmp_path / "run", state=RunState.ASSEMBLED, profile=profile
    )
    generated: list[Path] = []

    def generate(workspace: Any, repository: Any, image: Any, **kwargs: Any) -> str:
        assert workspace.load().immutable_inputs["builderId"] == BUILDER_ID
        assert image.image_id == "app"
        path = workspace.root / "records" / "provenance.json"
        generated.append(path)
        path.write_text("{}\n", encoding="utf-8")
        return DIGEST

    _remote(
        monkeypatch,
        run,
        profile,
        load_release_evidence=lambda workspace, image: SimpleNamespace(
            provenance_digest="sha256:" + "e" * 64
        ),
        generate_release_provenance=generate,
    )
    code, value, _ = invoke(["provenance", run.workspace.run_id])
    assert code == 0
    assert value["data"]["digest"] == DIGEST
    assert generated == [run.workspace.root / "records" / "provenance.json"]

    code, value, _ = invoke(["provenance", run.workspace.run_id])
    assert code == 0
    assert value["data"]["digest"] == "sha256:" + "e" * 64
    assert len(generated) == 1


def test_remote_commands_refuse_a_profile_that_differs_from_the_run(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    profile = release_profile(tmp_path)
    run = FakeSourceRun(repository_factory(), tmp_path, state=RunState.ASSEMBLED)
    _remote(monkeypatch, run, profile)

    for arguments in (
        ["publish", run.workspace.run_id, "--profile", "production"],
        ["attest", run.workspace.run_id, "--profile", "production"],
        ["verify", run.workspace.run_id, "--profile", "production"],
        ["promote", run.workspace.run_id, "--profile", "production"],
    ):
        code, value, _ = invoke(arguments)
        assert code == 64, arguments
        assert "differs from recorded" in value["message"]


def test_remote_commands_refuse_a_changed_trust_profile(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    profile = release_profile(tmp_path)
    run = FakeSourceRun(
        repository_factory(), tmp_path, state=RunState.ASSEMBLED, profile=profile
    )
    changed = ReleaseProfile(
        **{
            **{field: getattr(profile, field) for field in profile.__slots__},
            "public_key_digest": "sha256:" + "9" * 64,
        }
    )
    _remote(monkeypatch, run, changed)

    code, value, _ = invoke(
        ["publish", run.workspace.run_id, "--profile", "production"]
    )

    assert code == 64
    assert "trust profile differs" in value["message"]


def test_publish_attest_verify_and_promote_report_their_observations(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    profile = release_profile(tmp_path)
    run = FakeSourceRun(
        repository_factory(), tmp_path, state=RunState.ASSEMBLED, profile=profile
    )
    published = _published(run)
    calls: list[str] = []

    def record(name: str, result: Any) -> Callable[..., Any]:
        def call(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            return result

        return call

    _remote(
        monkeypatch,
        run,
        profile,
        load_candidate=lambda workspace, image: _candidate(),
        load_release_evidence=lambda workspace, image: SimpleNamespace(
            source=run.source
        ),
        load_published=lambda workspace, candidate, image: published,
        load_verification=lambda workspace, image, subject: SimpleNamespace(
            record_path=Path("/verification.json"), record_digest=DIGEST
        ),
        publish_candidate=record(
            "publish",
            SimpleNamespace(
                reference=published.reference,
                graph=graph(),
                expiration=published.expiration,
                immutability_enabled=True,
            ),
        ),
        attest_candidate=record("attest", None),
        signer_identity=lambda selected, signer: ("managed-key", "sha256:" + "d" * 64),
        resolve_ci_context=lambda *args, **kwargs: None,
        verify_candidate=record(
            "verify",
            SimpleNamespace(
                record_path=Path("/verification.json"), record_digest=DIGEST
            ),
        ),
        promote_candidate=record(
            "promote",
            SimpleNamespace(
                tags=(("1.2.3", Digest(DIGEST)), ("stable", Digest(DIGEST))),
                candidate_deleted=False,
                findings=(Finding("CC0605", "warning", "candidate remained"),),
                immutability_enabled=False,
            ),
        ),
    )
    run_id = run.workspace.run_id

    code, value, _ = invoke(["publish", run_id, "--profile", "production"])
    assert code == 0
    assert value["data"]["immutabilityEnabled"] is True
    assert value["data"]["expiration"] == "2026-01-08T00:00:00Z"

    code, value, _ = invoke(["attest", run_id, "--profile", "production"])
    assert code == 0
    assert value["data"]["subject"].endswith("@" + DIGEST)

    code, value, _ = invoke(["verify", run_id, "--profile", "production"])
    assert code == 0
    assert value["data"] == {"record": "/verification.json", "digest": DIGEST}

    code, value, _ = invoke(
        ["promote", run_id, "--profile", "production", "--version", "9.9.9"]
    )
    assert code == 64

    code, value, _ = invoke(["promote", run_id, "--profile", "production"])
    assert code == 0
    assert value["message"].endswith("candidate cleanup failed")
    assert value["data"]["candidateDeleted"] is False
    assert value["data"]["immutabilityEnabled"] is False
    assert value["findings"][0]["checkId"] == "CC0605"
    assert [tag["tag"] for tag in value["data"]["tags"]] == ["1.2.3", "stable"]
    assert calls == ["publish", "attest", "verify", "promote"]


def test_attest_and_release_require_a_signing_key(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    profile = release_profile(tmp_path, key=None)
    run = FakeSourceRun(
        repository_factory(), tmp_path, state=RunState.PUBLISHED, profile=profile
    )
    _remote(monkeypatch, run, profile)

    for arguments in (
        ["attest", run.workspace.run_id, "--profile", "production"],
        ["release", "--revision", "v1", "--image", "app", "--profile", "production"],
    ):
        code, value, _ = invoke(arguments)
        assert code == 64, arguments
        assert "no Cosign signing key" in value["message"]


def test_release_command_validates_selection_and_reports_promotion(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    profile = release_profile(tmp_path)
    run = FakeSourceRun(repository_factory(), tmp_path, profile=profile)
    result = SimpleNamespace(
        run_id=run.workspace.run_id,
        workspace=run.workspace.root,
        subject="quay.io/example/app@" + DIGEST,
        tags=(("1.2.3", DIGEST),),
        candidate_deleted=True,
        findings=(),
        immutability_enabled=True,
    )
    executed: list[Any] = []
    resumed: list[str] = []

    def execute(request: Any) -> SimpleNamespace:
        executed.append(request)
        return result

    def resume(run_id: str, **kwargs: Any) -> SimpleNamespace:
        resumed.append(run_id)
        return result

    _remote(monkeypatch, run, profile, execute_release=execute, resume_release=resume)

    code, value, _ = invoke(["release", "--profile", "production"])
    assert code == 64
    assert "--revision is required" in value["message"]

    code, value, _ = invoke(
        [
            "release",
            "--profile",
            "production",
            "--resume",
            run.workspace.run_id,
            "--image",
            "app",
        ]
    )
    assert code == 64
    assert "recorded revision" in value["message"]
    assert executed == [] and resumed == []

    code, value, _ = invoke(
        ["release", "--profile", "production", "--revision", "v1", "--image", "app"]
    )
    assert code == 0
    assert value["message"].startswith("Release completed")
    assert value["data"]["subject"] == result.subject
    assert executed[0].revision == "v1"
    assert executed[0].passphrase == "secret"

    code, value, _ = invoke(
        ["release", "--profile", "production", "--resume", run.workspace.run_id]
    )
    assert code == 0
    assert resumed == [run.workspace.run_id]


def test_doctor_reports_environment_observations(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    root = repository_factory()
    profile = release_profile(tmp_path)
    closed: list[bool] = []
    control = SimpleNamespace(close=lambda: closed.append(True))
    monkeypatch.setattr(maintenance_commands, "profile", lambda name: profile)
    monkeypatch.setattr(
        maintenance_commands, "create_registry_control", lambda *a, **k: control
    )
    requested: list[tuple[ToolName, ...]] = []
    monkeypatch.setattr(
        maintenance_commands, "diagnostic_runtime", _recording_runtime(requested)
    )
    monkeypatch.setattr(
        maintenance_commands,
        "diagnose_environment",
        lambda *args, **kwargs: SimpleNamespace(
            tools=({"name": "git", "version": "2.55.0"},),
            native_architecture="amd64",
            emulated_architectures=(),
            registry_provider="quay",
            registry_access=True,
            sigstore_access=True,
        ),
    )
    monkeypatch.setattr(maintenance_commands, "ci_context", lambda selected: None)

    code, value, _ = invoke(
        ["doctor", "--config", str(root / "conclear.toml"), "--profile", "production"]
    )

    assert code == 0
    assert value["message"] == "Environment is ready for release"
    assert value["data"]["scope"] == "release"
    assert value["data"]["profile"] == "production"
    assert value["data"]["registryProvider"] == "quay"
    assert value["data"]["ciContextObserved"] is False
    assert closed == [True]
    assert requested == [scope_dependencies("release").tools]


def test_doctor_qualify_scope_needs_no_profile_registry_or_signing(
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    root = repository_factory()
    monkeypatch.setattr(
        maintenance_commands,
        "profile",
        lambda name: pytest.fail("qualify scope must not load a profile"),
    )
    monkeypatch.setattr(
        maintenance_commands,
        "create_registry_control",
        lambda *a, **k: pytest.fail("qualify scope must not create a registry control"),
    )
    requested: list[tuple[ToolName, ...]] = []
    monkeypatch.setattr(
        maintenance_commands, "diagnostic_runtime", _recording_runtime(requested)
    )
    seen: dict[str, Any] = {}

    def diagnose(*args: Any, **kwargs: Any) -> SimpleNamespace:
        seen.update(kwargs)
        return SimpleNamespace(
            tools=({"name": "buildah", "version": "1.43.2"},),
            native_architecture="amd64",
            emulated_architectures=("arm64",),
            registry_provider=None,
            registry_access=False,
            sigstore_access=False,
        )

    monkeypatch.setattr(maintenance_commands, "diagnose_environment", diagnose)

    code, value, _ = invoke(
        ["doctor", "--config", str(root / "conclear.toml"), "--scope", "qualify"]
    )

    assert code == 0
    assert value["message"] == "Environment is ready for qualify"
    assert value["data"] == {
        "scope": "qualify",
        "tools": [{"name": "buildah", "version": "1.43.2"}],
        "nativeArchitecture": "amd64",
        "emulatedArchitectures": ["arm64"],
    }
    assert seen["scope"] is DoctorScope.QUALIFY
    assert seen["profile"] is None and seen["registry_control"] is None
    assert requested == [scope_dependencies("qualify").tools]
    assert ToolName.COSIGN not in requested[0]


def test_doctor_release_scope_requires_a_profile(
    repository_factory: Callable[..., Path],
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    root = repository_factory()

    code, value, _ = invoke(["doctor", "--config", str(root / "conclear.toml")])

    assert code == 64
    assert "--profile is required for --scope release" in value["message"]
    assert "--scope qualify" in value["message"]


@pytest.mark.parametrize(
    ("problems", "exit_code"),
    [
        (
            (
                ToolProblem(
                    ToolName.TRIVY,
                    RuleRejectionError(
                        "Unsupported trivy version 0.1.0; supported: 0.69.3",
                        code="CC0301",
                    ),
                ),
                ToolProblem(
                    ToolName.COSIGN,
                    OperationalError("Required tool is unavailable: cosign"),
                ),
            ),
            1,
        ),
        (
            (
                ToolProblem(
                    ToolName.TRIVY,
                    RuleRejectionError(
                        "Unsupported trivy version 0.1.0; supported: 0.69.3",
                        code="CC0301",
                    ),
                ),
            ),
            2,
        ),
    ],
)
def test_doctor_reports_every_unresolved_tool_at_once(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    problems: tuple[ToolProblem, ...],
    exit_code: int,
) -> None:
    root = repository_factory()
    profile = release_profile(tmp_path)
    monkeypatch.setattr(maintenance_commands, "profile", lambda name: profile)
    monkeypatch.setattr(
        maintenance_commands,
        "create_registry_control",
        lambda *a, **k: SimpleNamespace(close=lambda: None),
    )
    monkeypatch.setattr(
        maintenance_commands,
        "diagnostic_runtime",
        lambda names: _Context((SimpleNamespace(), problems)),
    )
    monkeypatch.setattr(
        maintenance_commands,
        "diagnose_environment",
        lambda *a, **k: pytest.fail("diagnosis must stop on unresolved tools"),
    )

    code, value, _ = invoke(
        ["doctor", "--config", str(root / "conclear.toml"), "--profile", "production"]
    )

    assert code == exit_code
    assert value["message"].startswith("Environment is not ready for release: ")
    for problem in problems:
        assert problem.message in value["message"]


def test_cleanup_command_refuses_a_foreign_profile_and_reports_ownership(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    profile = release_profile(tmp_path)
    run = FakeSourceRun(repository_factory(), tmp_path, profile=profile)
    state_home = run.workspace.root.parents[2]
    monkeypatch.setattr(maintenance_commands, "state_home", lambda: state_home)
    monkeypatch.setattr(
        maintenance_commands,
        "ApplicationRuntime",
        SimpleNamespace(create=lambda root, names: run.runtime),
    )
    monkeypatch.setattr(
        maintenance_commands,
        "cleanup_run",
        lambda *args, **kwargs: SimpleNamespace(removed=("a",), retained=("b",)),
    )
    monkeypatch.setattr(
        maintenance_commands,
        "create_registry_control",
        lambda *a, **k: SimpleNamespace(close=lambda: None),
    )
    other = ReleaseProfile(
        **{
            **{field: getattr(profile, field) for field in profile.__slots__},
            "name": "other",
        }
    )
    monkeypatch.setattr(maintenance_commands, "profile", lambda name: other)
    code, value, _ = invoke(["cleanup", run.workspace.run_id, "--profile", "other"])
    assert code == 64
    assert "profile differs" in value["message"]

    changed = ReleaseProfile(
        **{
            **{field: getattr(profile, field) for field in profile.__slots__},
            "configuration_digest": "sha256:" + "9" * 64,
        }
    )
    monkeypatch.setattr(maintenance_commands, "profile", lambda name: changed)
    code, value, _ = invoke(
        ["cleanup", run.workspace.run_id, "--profile", "production"]
    )
    assert code == 64
    assert "trust profile changed" in value["message"]

    monkeypatch.setattr(maintenance_commands, "profile", lambda name: profile)
    code, value, err = invoke(
        ["cleanup", run.workspace.run_id, "--profile", "production"]
    )
    assert code == 0, err
    assert value["data"] == {"removed": ["a"], "retained": ["b"]}

    code, value, err = invoke(["cleanup", run.workspace.run_id])
    assert code == 0, err


def test_pins_check_reports_observations_and_rejections(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    root = repository_factory()
    monkeypatch.setattr(
        maintenance_commands,
        "command_runtime",
        lambda names: _Context(SimpleNamespace(skopeo=lambda: object())),
    )
    monkeypatch.setattr(
        maintenance_commands, "AuthenticatedPinResolver", lambda runtime, auth: object()
    )
    monkeypatch.setattr(maintenance_commands, "state_home", lambda: tmp_path / "state")

    class Store:
        def __init__(self, home: Path) -> None:
            self.accepted = True

        def check(self, pin: Any, **kwargs: Any) -> SimpleNamespace:
            return SimpleNamespace(
                accepted=Store.outcome,
                findings=() if Store.outcome else (Finding("CC0204", "error", "old"),),
                to_dict=lambda: {
                    "reference": str(pin.reference),
                    "pinnedDigest": DIGEST,
                    "observedDigest": DIGEST,
                    "checkedAt": "2026-01-01T00:00:00Z",
                    "divergenceSince": None,
                    "historyInitialized": True,
                    "findings": [],
                },
            )

        outcome = True

    monkeypatch.setattr(maintenance_commands, "PinStore", Store)
    code, value, _ = invoke(
        ["pins", "check", "--config", str(root / "conclear.toml"), "--image", "app"]
    )
    assert code == 0
    assert value["data"]["observations"][0]["reference"].startswith("quay.io/")

    Store.outcome = False
    code, value, _ = invoke(
        ["pins", "check", "--config", str(root / "conclear.toml"), "--image", "app"]
    )
    assert code == 2
    assert value["findings"][0]["checkId"] == "CC0204"


def test_rescan_command_validates_subject_profile_and_configuration(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    root = repository_factory()
    config = str(root / "conclear.toml")
    profile = release_profile(tmp_path, key=None)
    monkeypatch.setattr(maintenance_commands, "profile", lambda name: profile)
    subject = "quay.io/example/app@" + DIGEST

    code, value, _ = invoke(
        [
            "rescan",
            "--subject",
            "quay.io/example/app:1@" + DIGEST,
            "--config",
            config,
            "--image",
            "app",
            "--profile",
            "production",
        ]
    )
    assert code == 64
    assert "cannot include a tag" in value["message"]

    code, value, _ = invoke(
        [
            "rescan",
            "--subject",
            "quay.io/example/other@" + DIGEST,
            "--config",
            config,
            "--image",
            "app",
            "--profile",
            "production",
        ]
    )
    assert code == 64
    assert "differs from the selected image" in value["message"]

    code, value, _ = invoke(
        [
            "rescan",
            "--subject",
            subject,
            "--config",
            config,
            "--image",
            "app",
            "--profile",
            "production",
            "--authoritative",
        ]
    )
    assert code == 64
    assert "no Cosign signing key" in value["message"]


@pytest.mark.parametrize(
    ("profile_arguments", "expected"),
    [
        ({"auth": None}, "has no auth_file for registry writes"),
        ({"key": None}, "has no Cosign signing key"),
    ],
)
def test_authoritative_rescan_refuses_a_profile_that_cannot_write_or_sign(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    profile_arguments: dict[str, Any],
    expected: str,
) -> None:
    """An authoritative rescan attaches a signed result, so it is a write."""
    root = repository_factory()
    profile = release_profile(tmp_path, **profile_arguments)
    monkeypatch.setattr(maintenance_commands, "profile", lambda name: profile)
    monkeypatch.setattr(maintenance_commands, "state_home", lambda: tmp_path / "state")
    monkeypatch.setattr(
        maintenance_commands,
        "signing_passphrase",
        lambda *a, **k: pytest.fail("no passphrase was read before the profile check"),
    )
    monkeypatch.setattr(
        maintenance_commands,
        "RunWorkspace",
        SimpleNamespace(
            create=lambda **k: pytest.fail("no workspace before the profile check")
        ),
    )

    code, value, _ = invoke(
        [
            "rescan",
            "--subject",
            "quay.io/example/app@" + DIGEST,
            "--config",
            str(root / "conclear.toml"),
            "--image",
            "app",
            "--profile",
            "production",
            "--authoritative",
        ]
    )

    assert code == 64
    assert expected in value["message"]
    assert not (tmp_path / "state").exists()


def test_rescan_refuses_a_test_only_image(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    root = repository_factory()
    path = root / "conclear.toml"
    content = path.read_text(encoding="utf-8").replace(
        "[images.release]",
        '[images.test]\ndependencies = ["helper"]\n\n[images.release]',
    )
    path.write_text(content + _image_text("helper", releasable=False), encoding="utf-8")
    profile = release_profile(tmp_path)
    monkeypatch.setattr(maintenance_commands, "profile", lambda name: profile)
    monkeypatch.setattr(
        maintenance_commands,
        "RunWorkspace",
        SimpleNamespace(
            create=lambda **k: pytest.fail("no workspace for a test-only image")
        ),
    )

    code, value, _ = invoke(
        [
            "rescan",
            "--subject",
            "quay.io/example/helper@" + DIGEST,
            "--config",
            str(path),
            "--image",
            "helper",
            "--profile",
            "production",
        ]
    )

    assert code == 64
    assert "helper is test-only" in value["message"]


def test_diagnostic_rescan_accepts_a_read_only_profile(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    root = repository_factory()
    profile = release_profile(tmp_path, key=None, auth=None)
    recorded: list[tuple[ToolName, ...]] = []
    monkeypatch.setattr(maintenance_commands, "profile", lambda name: profile)
    monkeypatch.setattr(maintenance_commands, "state_home", lambda: tmp_path / "state")
    monkeypatch.setattr(
        maintenance_commands,
        "ApplicationRuntime",
        SimpleNamespace(
            create=lambda root, names: _stopping_run(recorded)(names=names)
        ),
    )

    code, value, _ = invoke(
        [
            "rescan",
            "--subject",
            "quay.io/example/app@" + DIGEST,
            "--config",
            str(root / "conclear.toml"),
            "--image",
            "app",
            "--profile",
            "production",
        ]
    )

    assert code == 64
    assert "stopped after resolving tools" in value["message"]
    assert recorded == [command_tools("rescan")]


class _Context:
    def __init__(self, value: Any) -> None:
        self.value = value

    def __enter__(self) -> Any:
        return self.value

    def __exit__(self, *exc: object) -> None:
        return None


def _recording_runtime(
    recorded: list[tuple[ToolName, ...]], problems: tuple[ToolProblem, ...] = ()
) -> Callable[[tuple[ToolName, ...]], Any]:
    def create(names: tuple[ToolName, ...]) -> Any:
        recorded.append(names)
        return _Context((SimpleNamespace(), problems))

    return create


def _stopping_run(recorded: list[tuple[ToolName, ...]]) -> Callable[..., Any]:
    def create(*args: Any, **kwargs: Any) -> Any:
        recorded.append(kwargs["names"])
        raise InvalidInvocationError("stopped after resolving tools")

    return create


class _StopOnEnter:
    def __enter__(self) -> Any:
        raise InvalidInvocationError("stopped after resolving tools")

    def __exit__(self, *exc: object) -> None:
        return None


def _stopping_runtime(recorded: list[tuple[ToolName, ...]]) -> Callable[..., Any]:
    def create(names: tuple[ToolName, ...]) -> _StopOnEnter:
        recorded.append(names)
        return _StopOnEnter()

    return create


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (["check", "--image", "app"], command_tools("check")),
        (["pins", "check", "--image", "app"], command_tools("pins check")),
        (
            ["pins", "propose", "--output", "{tmp}/proposal.json"],
            command_tools("pins propose"),
        ),
        (
            ["pins", "apply", "--proposal", "{tmp}/proposal.json"],
            command_tools("pins apply"),
        ),
        (
            [
                "build",
                "--source",
                "{root}",
                "--revision",
                "v1",
                "--image",
                "app",
                "--platform",
                "linux/amd64",
            ],
            command_tools("build"),
        ),
        (["test", RUN_ID, "--platform", "linux/amd64"], command_tools("test")),
        (
            [
                "qualify",
                "--source",
                "{root}",
                "--revision",
                "v1",
                "--image",
                "app",
                "--platform",
                "linux/amd64",
            ],
            command_tools("qualify"),
        ),
        (
            [
                "assemble",
                "--source",
                "{root}",
                "--revision",
                "v1",
                "--image",
                "app",
                "--transport",
                "{tmp}/t",
                DIGEST,
            ],
            command_tools("assemble"),
        ),
        (
            [
                "transport",
                "export",
                RUN_ID,
                "--platform",
                "linux/amd64",
                "--output",
                "{tmp}/out",
            ],
            command_tools("transport export"),
        ),
        (["provenance", RUN_ID], command_tools("provenance")),
        (["publish", RUN_ID, "--profile", "production"], command_tools("publish")),
        (["attest", RUN_ID, "--profile", "production"], command_tools("attest")),
        (["verify", RUN_ID, "--profile", "production"], command_tools("verify")),
        (["promote", RUN_ID, "--profile", "production"], command_tools("promote")),
        (
            [
                "release",
                "--source",
                "{root}",
                "--revision",
                "v1",
                "--image",
                "app",
                "--profile",
                "production",
            ],
            command_tools("release"),
        ),
        (
            [
                "rescan",
                "--subject",
                "{subject}",
                "--image",
                "app",
                "--profile",
                "production",
            ],
            command_tools("rescan"),
        ),
        pytest.param(
            [
                "rescan",
                "--subject",
                "{subject}",
                "--image",
                "app",
                "--profile",
                "production",
                "--authoritative",
            ],
            command_dependencies("rescan", "--authoritative").tools,
            id="rescan app production --authoritative",
        ),
        (["cleanup", RUN_ID], command_tools("cleanup")),
        (["doctor", "--scope", "check"], scope_dependencies("check").tools),
        (["doctor", "--scope", "qualify"], scope_dependencies("qualify").tools),
        (
            ["doctor", "--scope", "release", "--profile", "production"],
            scope_dependencies("release").tools,
        ),
    ],
    ids=lambda value: (
        " ".join(
            item
            for item in value
            if not item.startswith(("-", "{", "sha256:", "01arz", "v1", "linux/"))
        )
        if isinstance(value, list)
        else ""
    ),
)
def test_every_command_resolves_exactly_its_declared_tools(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    arguments: list[str],
    expected: tuple[ToolName, ...],
) -> None:
    """Production call paths request only the declared tools before anything else runs."""
    root = repository_factory()
    profile = release_profile(tmp_path)
    run = FakeSourceRun(root, tmp_path)
    image = run.repository.release_image("app")
    substitutions = {
        "{root}": str(root),
        "{tmp}": str(tmp_path),
        "{subject}": f"{image.repository}@{DIGEST}",
    }
    recorded: list[tuple[ToolName, ...]] = []
    stop_run = _stopping_run(recorded)
    stop_runtime = _stopping_runtime(recorded)
    for module in (
        local_commands,
        remote_commands,
        transport_commands,
        maintenance_commands,
        release_module,
    ):
        for name in ("create_source_run", "open_source_run"):
            if hasattr(module, name):
                monkeypatch.setattr(module, name, stop_run)
        for name in ("command_runtime", "diagnostic_runtime"):
            if hasattr(module, name):
                monkeypatch.setattr(module, name, stop_runtime)
        for name, value in (
            ("profile", lambda name: profile),
            ("state_home", lambda: tmp_path / "state"),
            ("signing_passphrase", lambda *a, **k: "secret"),
            ("ci_context", lambda selected: None),
            (
                "create_registry_control",
                lambda *a, **k: SimpleNamespace(close=lambda: None),
            ),
        ):
            if hasattr(module, name):
                monkeypatch.setattr(module, name, value)
    monkeypatch.setattr(
        maintenance_commands,
        "ApplicationRuntime",
        SimpleNamespace(create=lambda root, names: stop_run(names=names)),
    )
    monkeypatch.setattr(
        maintenance_commands, "load_proposal", lambda path: SimpleNamespace()
    )
    resolved = [substitutions.get(item, item) for item in arguments]
    if "--config" not in resolved and resolved[0] in {
        "check",
        "pins",
        "rescan",
        "doctor",
    }:
        resolved += ["--config", str(root / "conclear.toml")]

    code, value, _ = invoke(resolved)

    assert code == 64, value
    assert "stopped after resolving tools" in value["message"]
    assert recorded == [expected]


@pytest.mark.parametrize(
    ("profile_arguments", "expected"),
    [
        ({"auth": None}, "has no auth_file for registry writes"),
        ({"key": None}, "has no Cosign signing key"),
        ({"token": None}, "requires an API token"),
    ],
)
def test_doctor_release_scope_refuses_a_profile_that_cannot_write_or_sign(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    profile_arguments: dict[str, Any],
    expected: str,
) -> None:
    """Readiness is never reported without write authentication, token and key."""
    root = repository_factory()
    arguments: dict[str, Any] = {"token": "quay.token", **profile_arguments}
    profile = release_profile(tmp_path, **arguments)
    monkeypatch.setattr(maintenance_commands, "profile", lambda name: profile)
    monkeypatch.setattr(
        maintenance_commands,
        "diagnostic_runtime",
        lambda names: pytest.fail("no tool was resolved before the profile check"),
    )

    code, value, _ = invoke(
        ["doctor", "--config", str(root / "conclear.toml"), "--profile", "production"]
    )

    assert code == 64
    assert expected in value["message"]


def test_doctor_qualify_scope_accepts_a_read_only_profile(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
) -> None:
    root = repository_factory()
    profile = release_profile(tmp_path, key=None, auth=None)
    monkeypatch.setattr(maintenance_commands, "profile", lambda name: profile)
    monkeypatch.setattr(
        maintenance_commands, "diagnostic_runtime", _recording_runtime([])
    )
    monkeypatch.setattr(
        maintenance_commands,
        "diagnose_environment",
        lambda *a, **k: SimpleNamespace(
            tools=(),
            native_architecture="amd64",
            emulated_architectures=(),
            registry_provider=None,
            registry_access=False,
            sigstore_access=False,
        ),
    )
    monkeypatch.setattr(maintenance_commands, "ci_context", lambda selected: None)

    code, value, _ = invoke(
        [
            "doctor",
            "--config",
            str(root / "conclear.toml"),
            "--scope",
            "qualify",
            "--profile",
            "production",
        ]
    )

    assert code == 0
    assert value["data"]["profile"] == "production"
    assert "registryProvider" not in value["data"]


@pytest.mark.parametrize(
    ("command", "profile_arguments", "expected"),
    [
        ("publish", {"auth": None}, "has no auth_file for registry writes"),
        ("attest", {"auth": None}, "has no auth_file for registry writes"),
        ("attest", {"key": None}, "has no Cosign signing key"),
        ("verify", {"key": None}, "has no Cosign signing key"),
        ("release", {"auth": None}, "has no auth_file for registry writes"),
    ],
)
def test_remote_commands_refuse_an_incapable_profile_before_touching_the_run(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[list[str]], tuple[int, Any, str]],
    command: str,
    profile_arguments: dict[str, Any],
    expected: str,
) -> None:
    root = repository_factory()
    profile = release_profile(tmp_path, **profile_arguments)
    monkeypatch.setattr(remote_commands, "profile", lambda name: profile)
    monkeypatch.setattr(
        remote_commands,
        "open_source_run",
        lambda **kwargs: pytest.fail("the run must not be opened"),
    )
    monkeypatch.setattr(
        release_module,
        "create_source_run",
        lambda **kwargs: pytest.fail("no run must be created"),
    )
    arguments = (
        ["release", "--source", str(root), "--revision", "v1", "--image", "app"]
        if command == "release"
        else [command, RUN_ID]
    )

    code, value, _ = invoke([*arguments, "--profile", "production"])

    assert code == 64
    assert expected in value["message"]
