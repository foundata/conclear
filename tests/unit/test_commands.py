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
from conclear.cli import main
from conclear.config import load_repository_config
from conclear.errors import OperationalError, RuleRejectionError
from conclear.presentation import Finding
from conclear.records import SourceIdentity, Verdict
from conclear.release_profile import (
    BuilderConfig,
    CIContextPolicy,
    QuayRegistryConfig,
    RegistryProvider,
    ReleaseProfile,
)
from conclear.values import Digest
from conclear.workspace import RunState, RunWorkspace

BUILDER_ID = "https://foundata.com/en/projects/conclear/builder/simple-v1/"
DIGEST = "sha256:" + "a" * 64


class FixedIdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def release_profile(
    tmp_path: Path, *, key: str | None = "cosign.key"
) -> ReleaseProfile:
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("public\n", encoding="utf-8")
    return ReleaseProfile(
        name="production",
        ci_context=CIContextPolicy.OMIT,
        builder=BuilderConfig(BUILDER_ID),
        auth_file=None,
        registry=QuayRegistryConfig(
            RegistryProvider.QUAY, "quay.io", "https://quay.io/api/v1", None
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
    [("build", "build_platform"), ("qualify", "check_image")],
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
) -> None:
    run = FakeSourceRun(repository_factory(), tmp_path)
    selected_databases: list[str] = []

    def qualify(*args: Any, **kwargs: Any) -> SimpleNamespace:
        assert verdict is not None, "qualification ran after a rejected preflight"
        return SimpleNamespace(
            verdict=verdict,
            findings=() if verdict is Verdict.ACCEPTED else (ERROR,),
            record_path=Path("/record.json"),
            record_digest=DIGEST,
            layout_path=Path("/layout"),
        )

    def by_digest(
        *args: Any, expected_digest: Digest, **kwargs: Any
    ) -> SimpleNamespace:
        selected_databases.append(str(expected_digest))
        return SimpleNamespace(digest=str(expected_digest))

    _local(
        monkeypatch,
        run,
        check_image=lambda image, hadolint: SimpleNamespace(
            accepted=preflight_accepted,
            findings=() if preflight_accepted else (ERROR,),
        ),
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
        ]
    )

    assert (code, value["status"]) == (exit_code, status)
    assert value["data"]["runId"] == run.workspace.run_id
    assert run.workspace.load().state is state
    assert selected_databases == ([DIGEST] if verdict is not None else [])


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
        path: Path, *, expected_digest: str, workspace: Any, image: Any
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
        reference=run.repository.image("app").repository.with_tag("candidate"),
        immutable_reference=run.repository.image("app").repository.with_digest(
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
    assert "--revision and --image" in value["message"]

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
    monkeypatch.setattr(
        maintenance_commands,
        "command_runtime",
        lambda names: _Context(SimpleNamespace()),
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
    assert value["data"]["registryProvider"] == "quay"
    assert value["data"]["ciContextObserved"] is False
    assert closed == [True]


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
    assert "requires a signing key" in value["message"]


class _Context:
    def __init__(self, value: Any) -> None:
        self.value = value

    def __enter__(self) -> Any:
        return self.value

    def __exit__(self, *exc: object) -> None:
        return None
