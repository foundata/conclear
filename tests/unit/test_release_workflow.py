"""Release orchestration failure paths on a fully fake-backed release run."""

import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import conclear.provenance as provenance_module
import conclear.records as records_module
import conclear.services.assembly as assembly_module
import conclear.services.publication as publication_module
from conclear.artifacts import (
    load_candidate,
    load_published,
    load_release_evidence,
    load_verification,
    qualification_transport,
)
from conclear.config import RepositoryConfig, load_repository_config
from conclear.errors import (
    InvalidInvocationError,
    OperationalError,
    RuleRejectionError,
)
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import sha256_bytes
from conclear.presentation import Finding
from conclear.records import SourceIdentity, Verdict
from conclear.release_profile import (
    BuilderConfig,
    CIContextPolicy,
    QuayRegistryConfig,
    RegistryProvider,
    ReleaseProfile,
)
from conclear.services import release
from conclear.services.release import ReleaseRequest, ReleaseResult
from conclear.values import Platform
from conclear.workspace import ResourceKind, ResourceStatus, RunState, RunWorkspace
from tests.release_fakes import FakeRuntime

BUILDER_ID = "https://foundata.com/en/projects/conclear/builder/simple-v1/"
NOW = datetime(2026, 1, 1, tzinfo=UTC)


class FixedIdFactory:
    def create(self) -> str:
        return "01arz3ndektsv4rrffq69g5fav"


def profile(tmp_path: Path) -> ReleaseProfile:
    public_key = tmp_path / "cosign.pub"
    public_key.write_text("test public key\n", encoding="utf-8")
    public_key.chmod(0o600)
    return ReleaseProfile(
        name="production",
        ci_context=CIContextPolicy.OMIT,
        builder=BuilderConfig(BUILDER_ID),
        auth_file=None,
        registry=QuayRegistryConfig(
            RegistryProvider.QUAY, "quay.io", "https://quay.io/api/v1", None
        ),
        cosign_private_key=str(tmp_path / "cosign.key"),
        cosign_public_key=public_key,
        passphrase_file=None,
        configuration_digest="sha256:" + "a" * 64,
        public_key_digest="sha256:" + "b" * 64,
    )


class Harness:
    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        repository_factory: Callable[..., Path],
    ) -> None:
        identity = ApplicationIdentity(source_revision="c" * 40)
        for module in (
            records_module,
            provenance_module,
            assembly_module,
            publication_module,
        ):
            monkeypatch.setattr(module, "IDENTITY", identity)
        self.tmp_path = tmp_path
        self.monkeypatch = monkeypatch
        self.source_root = repository_factory()
        self.repository: RepositoryConfig = load_repository_config(
            self.source_root / "conclear.toml"
        )
        self.profile = profile(tmp_path)
        self.workspace = RunWorkspace.create(
            state_home=tmp_path / "state",
            immutable_inputs={
                "sourceRoot": str(self.source_root.resolve()),
                "sourceRevision": "b" * 40,
                "sourceRepository": self.repository.project.source,
                "configurationDigest": sha256_bytes(self.repository.raw_bytes),
                "image": "app",
                "version": "1.2.3",
                "profile": self.profile.name,
                "profileConfigurationDigest": self.profile.configuration_digest,
                "profilePublicKeyDigest": self.profile.public_key_digest,
                "builderId": self.profile.builder.id,
            },
            id_factory=FixedIdFactory(),
            now=NOW,
        )
        pin_digest = self.repository.image("app").pins[0].reference.digest
        assert pin_digest is not None
        self.runtime = FakeRuntime(pin_digest)
        self.source_run = SimpleNamespace(
            workspace=self.workspace,
            repository=self.repository,
            runtime=self.runtime,
            source=SourceIdentity(self.repository.project.source, "b" * 40),
            source_time=NOW,
        )
        monkeypatch.setattr(
            release, "create_source_run", lambda **_kwargs: self.source_run
        )
        monkeypatch.setattr(
            release, "open_source_run", lambda **_kwargs: self.source_run
        )
        monkeypatch.setattr(
            release,
            "create_registry_control",
            lambda _profile, *, destinations: self.runtime.registry_control,
        )

    @property
    def image(self) -> Any:
        return self.repository.image("app")

    def request(self, **overrides: Any) -> ReleaseRequest:
        values: dict[str, Any] = {
            "repository": self.source_root,
            "revision": "b" * 40,
            "image_id": "app",
            "version": "1.2.3",
            "profile": self.profile,
            "state_home": self.tmp_path / "state",
            "cache_home": self.tmp_path / "cache",
            "passphrase": None,
            "ci_context": None,
        }
        values.update(overrides)
        return ReleaseRequest(**values)

    def complete(self) -> ReleaseResult:
        return release.execute_release(self.request(), now_factory=lambda: NOW)

    def resume(self, **overrides: Any) -> ReleaseResult:
        values: dict[str, Any] = {
            "repository": self.source_root,
            "profile": self.profile,
            "state_home": self.tmp_path / "state",
            "cache_home": self.tmp_path / "cache",
            "passphrase": None,
            "ci_context": None,
            "now_factory": lambda: NOW,
        }
        values.update(overrides)
        return release.resume_release(self.workspace.run_id, **values)


@pytest.fixture
def harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_factory: Callable[..., Path],
) -> Harness:
    return Harness(tmp_path, monkeypatch, repository_factory)


def _rewrite(path: Path, mutate: Callable[[dict[str, Any]], None]) -> bytes:
    original = path.read_bytes()
    value = json.loads(original)
    mutate(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    return original


def test_candidate_loader_rejects_every_identity_substitution(harness: Harness) -> None:
    harness.complete()
    workspace, image = harness.workspace, harness.image
    record = workspace.root / "records" / "release-candidate.json"

    def expect(mutate: Callable[[dict[str, Any]], None], message: str) -> None:
        original = _rewrite(record, mutate)
        try:
            with pytest.raises(
                (InvalidInvocationError, RuleRejectionError), match=message
            ):
                load_candidate(workspace, image)
        finally:
            record.write_bytes(original)

    expect(lambda value: value.update(verdict="rejected"), "not accepted")
    expect(
        lambda value: value.update(runId="01arz3ndektsv4rrffq69g5faw"), "another run"
    )
    expect(lambda value: value["payload"].update(imageId="other"), "another image")
    expect(
        lambda value: value["payload"].update(repository="quay.io/example/other"),
        "another repository",
    )
    expect(
        lambda value: value["payload"].update(requiredPlatforms=["linux/arm64"]),
        "required platform set changed",
    )
    expect(
        lambda value: value["payload"].update(acceptedPlatforms=[]),
        "accepted platform set changed",
    )
    expect(lambda value: value.update(recordType="rescanResult"), "Invalid")
    assert load_candidate(workspace, image).candidate_tag.startswith("1.2.3-candidate.")


def test_published_and_verification_loaders_require_exact_journal_ownership(
    harness: Harness,
) -> None:
    def interrupted_promotion(*args: Any, **kwargs: Any) -> None:
        raise OperationalError("registry unavailable before promotion")

    harness.monkeypatch.setattr(release, "promote_candidate", interrupted_promotion)
    with pytest.raises(OperationalError, match="before promotion"):
        harness.complete()
    workspace, image = harness.workspace, harness.image
    assert workspace.load().state is RunState.INCOMPLETE
    candidate = load_candidate(workspace, image)
    published = load_published(workspace, candidate, image)
    subject = published.immutable_reference
    assert subject.digest == candidate.observation.graph.digest

    workspace.journal.update(
        "candidate", ResourceStatus.CREATED, metadata={"immutabilityEnabled": "yes"}
    )
    with pytest.raises(InvalidInvocationError, match="immutability observation"):
        load_published(workspace, candidate, image)
    workspace.journal.update(
        "candidate", ResourceStatus.CREATED, metadata={"immutabilityEnabled": True}
    )

    verification = load_verification(workspace, image, subject)
    assert verification.subject == subject
    with pytest.raises(InvalidInvocationError, match="not immutable"):
        load_verification(workspace, image, image.repository.with_tag("stable"))

    statement = workspace.root / "records" / "release-verification-statement.json"
    original = _rewrite(statement, lambda value: value.update(predicateType="other"))
    with pytest.raises(InvalidInvocationError, match="predicate type"):
        load_verification(workspace, image, subject)
    statement.write_bytes(original)
    original = _rewrite(
        statement,
        lambda value: value.update(subject=[{"name": "quay.io/example/other"}]),
    )
    with pytest.raises(RuleRejectionError, match="subject differs") as caught:
        load_verification(workspace, image, subject)
    assert caught.value.code == "CC0703"
    statement.write_bytes(original)

    record = workspace.root / "records" / "release-verification.json"
    original = _rewrite(record, lambda value: value.update(verdict="rejected"))
    with pytest.raises(InvalidInvocationError, match="not accepted"):
        load_verification(workspace, image, subject)
    record.write_bytes(original)

    workspace.journal.update(
        "release-verification",
        ResourceStatus.CREATED,
        metadata={"payloadDigest": "sha256:" + "0" * 64},
    )
    with pytest.raises(InvalidInvocationError, match="ownership is not established"):
        load_verification(workspace, image, subject)


def test_evidence_loaders_reject_changed_qualification_payloads(
    harness: Harness,
) -> None:
    harness.complete()
    workspace, image = harness.workspace, harness.image
    platform = Platform.parse("linux/amd64")
    evidence = load_release_evidence(workspace, image)
    assert evidence.sboms[0][0] == platform

    sbom = workspace.root / "exports" / "sbom" / "linux-amd64.spdx.json"
    original_sbom = sbom.read_bytes()
    sbom.write_bytes(original_sbom + b"\n")
    with pytest.raises(RuleRejectionError, match="SBOM changed") as caught:
        load_release_evidence(workspace, image)
    assert caught.value.code == "CC0504"
    with pytest.raises(
        RuleRejectionError, match="payload files are incomplete"
    ) as caught:
        qualification_transport(workspace, image, platform)
    assert caught.value.code == "CC0703"
    sbom.write_bytes(original_sbom)

    scan = workspace.root / "reports" / "app" / "linux-amd64" / "image-scan.json"
    original_scan = scan.read_bytes()
    scan.write_bytes(original_scan + b"\n")
    with pytest.raises(RuleRejectionError, match="Scan report changed") as caught:
        load_release_evidence(workspace, image)
    assert caught.value.code == "CC0501"
    scan.write_bytes(original_scan)

    record = workspace.root / "records" / "platform-qualification-linux-amd64.json"
    original_record = _rewrite(
        record, lambda value: value["payload"].update(platform="linux/arm64")
    )
    with pytest.raises(InvalidInvocationError, match="another platform"):
        qualification_transport(workspace, image, platform)
    record.write_bytes(original_record)
    original_record = _rewrite(record, lambda value: value.update(verdict="rejected"))
    with pytest.raises(InvalidInvocationError, match="not accepted"):
        qualification_transport(workspace, image, platform)
    record.write_bytes(original_record)
    original_record = _rewrite(
        record,
        lambda value: value["payload"].update(manifestDigest="sha256:" + "0" * 64),
    )
    with pytest.raises(RuleRejectionError, match="manifest digest changed") as caught:
        qualification_transport(workspace, image, platform)
    assert caught.value.code == "CC0302"
    record.write_bytes(original_record)

    layout_index = workspace.root / "layouts" / "app" / "linux-amd64" / "index.json"
    original_index = layout_index.read_bytes()
    index_value = json.loads(original_index)
    index_value["manifests"][0]["platform"]["architecture"] = "arm64"
    layout_index.write_text(json.dumps(index_value), encoding="utf-8")
    with pytest.raises((RuleRejectionError, InvalidInvocationError)):
        qualification_transport(workspace, image, platform)
    layout_index.write_bytes(original_index)
    assert qualification_transport(workspace, image, platform).record_path == record


def test_continuation_requires_a_signing_key_after_loading_evidence(
    harness: Harness,
) -> None:
    harness.complete()

    with pytest.raises(InvalidInvocationError, match="no Cosign signing key"):
        release._continue_release(
            harness.request(profile=replace(harness.profile, cosign_private_key=None)),
            repository=harness.repository,
            workspace=harness.workspace,
            runtime=cast(Any, harness.runtime),
            source=harness.source_run.source,
            source_time=NOW,
            started_at=NOW,
            now_factory=lambda: NOW,
        )


def test_resume_revalidates_source_root_profile_and_inputs(harness: Harness) -> None:
    harness.complete()
    with pytest.raises(InvalidInvocationError, match="terminal state"):
        harness.resume()

    workspace = harness.workspace
    other_root = harness.tmp_path / "elsewhere"
    other_root.mkdir()
    workspace_snapshot = json.loads((workspace.root / "run.json").read_text("utf-8"))
    workspace_snapshot["state"] = "incomplete"
    workspace_snapshot["resumeState"] = "attested"
    (workspace.root / "run.json").write_text(
        json.dumps(workspace_snapshot), encoding="utf-8"
    )

    with pytest.raises(InvalidInvocationError, match="source repository differs"):
        harness.resume(repository=other_root)
    with pytest.raises(InvalidInvocationError, match="profile differs"):
        harness.resume(profile=replace(harness.profile, name="staging"))
    with pytest.raises(InvalidInvocationError, match="trust profile changed"):
        harness.resume(
            profile=replace(harness.profile, public_key_digest="sha256:" + "9" * 64)
        )

    continued: list[RunState] = []

    def continue_release(*args: Any, **kwargs: Any) -> ReleaseResult:
        continued.append(kwargs["workspace"].load().state)
        return ReleaseResult("run", workspace.root, "subject", (), True)

    harness.monkeypatch.setattr(release, "_continue_release", continue_release)
    cleaned: list[dict[str, Any]] = []

    def cleanup(target: RunWorkspace, **kwargs: Any) -> Any:
        cleaned.append(kwargs)
        return SimpleNamespace(removed=(), retained=())

    harness.monkeypatch.setattr(release, "cleanup_run", cleanup)
    harness.resume()

    assert continued == [RunState.ATTESTED]
    assert cleaned[0]["excluded_kinds"] == frozenset({ResourceKind.CANDIDATE_REFERENCE})
    assert "source-worktree" in cleaned[0]["excluded_resource_ids"]
    assert "layout-app-linux-amd64" in cleaned[0]["excluded_resource_ids"]
    assert harness.runtime.registry_control.closed


def test_failed_continuation_records_a_safe_summary_and_reraises(
    harness: Harness,
) -> None:
    def failing(*args: Any, **kwargs: Any) -> ReleaseResult:
        raise RuleRejectionError("pins rejected", code="CC0204")

    harness.monkeypatch.setattr(release, "_continue_release", failing)

    with pytest.raises(RuleRejectionError, match="pins rejected"):
        harness.complete()

    assert harness.workspace.load().state is RunState.REJECTED
    summary = json.loads((harness.workspace.root / "summary.json").read_text("utf-8"))
    assert summary["failure"] == {
        "type": "ruleRejection",
        "message": "pins rejected",
        "checkId": "CC0204",
    }

    snapshot = json.loads((harness.workspace.root / "run.json").read_text("utf-8"))
    snapshot["state"] = "incomplete"
    snapshot["resumeState"] = "created"
    (harness.workspace.root / "run.json").write_text(json.dumps(snapshot), "utf-8")
    harness.monkeypatch.setattr(
        release, "cleanup_run", lambda *a, **k: SimpleNamespace(removed=(), retained=())
    )
    with pytest.raises(RuleRejectionError, match="pins rejected"):
        harness.resume()
    assert harness.workspace.load().state is RunState.REJECTED


def test_qualification_phase_rejects_before_later_state_changes(
    harness: Harness,
) -> None:
    calls: list[str] = []
    accepted_preflight = SimpleNamespace(accepted=True, findings=())
    rejected_preflight = SimpleNamespace(
        accepted=False, findings=(Finding("CC0113", "error", "labels"),)
    )
    state: dict[str, Any] = {
        "preflight": rejected_preflight,
        "pin_findings": (),
        "verdict": Verdict.ACCEPTED,
    }

    class Store:
        def __init__(self, home: Path) -> None:
            pass

        def check(self, pin: Any, **kwargs: Any) -> SimpleNamespace:
            calls.append("pins")
            findings = state["pin_findings"]
            return SimpleNamespace(
                accepted=not any(item.severity == "error" for item in findings),
                findings=findings,
            )

    def qualify(*args: Any, **kwargs: Any) -> SimpleNamespace:
        calls.append("qualify")
        return SimpleNamespace(
            verdict=state["verdict"],
            findings=(
                ()
                if state["verdict"] is Verdict.ACCEPTED
                else (Finding("CC0403", "error", "runtime"),)
            ),
        )

    monkeypatch = harness.monkeypatch
    monkeypatch.setattr(release, "check_image", lambda *a, **k: state["preflight"])
    monkeypatch.setattr(release, "PinStore", Store)
    monkeypatch.setattr(release, "select_fresh_database", lambda *a, **k: object())
    monkeypatch.setattr(release, "HookRunner", lambda **k: object())
    monkeypatch.setattr(release, "qualify_platform", qualify)
    monkeypatch.setattr(
        release, "qualification_transport", lambda *a: calls.append("transport")
    )

    def run() -> None:
        release._qualify_release(
            harness.request(),
            repository=harness.repository,
            workspace=harness.workspace,
            runtime=cast(Any, harness.runtime),
            source=harness.source_run.source,
            source_time=NOW,
            now_factory=lambda: NOW,
        )

    with pytest.raises(RuleRejectionError, match="Static image checks") as caught:
        run()
    assert caught.value.code == "CC0113"
    assert calls == []

    state["preflight"] = accepted_preflight
    state["pin_findings"] = (Finding("CC0204", "error", "diverged"),)
    with pytest.raises(RuleRejectionError, match="pin checks") as caught:
        run()
    assert caught.value.code == "CC0204"
    assert calls == ["pins"]

    calls.clear()
    state["pin_findings"] = ()
    state["verdict"] = Verdict.REJECTED
    with pytest.raises(RuleRejectionError, match="rejected linux/amd64") as caught:
        run()
    assert caught.value.code == "CC0403"
    assert calls == ["pins", "qualify"]

    calls.clear()
    state["verdict"] = Verdict.INCOMPLETE
    with pytest.raises(OperationalError, match="incomplete"):
        run()
    assert harness.workspace.load().state is RunState.CREATED

    calls.clear()
    state["verdict"] = Verdict.ACCEPTED
    record = (
        harness.workspace.root / "records" / "platform-qualification-linux-amd64.json"
    )
    record.write_text("{}", encoding="utf-8")
    run()
    assert calls == ["pins", "transport"]
    assert harness.workspace.load().state is RunState.QUALIFIED


def test_signer_modes_timestamps_and_failure_summaries(
    harness: Harness, tmp_path: Path
) -> None:
    hsm = replace(harness.profile, cosign_private_key="pkcs11:token=release")
    kms = replace(harness.profile, cosign_private_key="awskms:///alias/release")
    assert release.signer_identity(hsm, harness.runtime.cosign()) == (
        "hsm",
        "pkcs11:token=release",
    )
    assert release.signer_identity(kms, harness.runtime.cosign()) == (
        "kms",
        "awskms:///alias/release",
    )
    with pytest.raises(InvalidInvocationError, match="malformed"):
        release._parse_timestamp("not a time")
    with pytest.raises(InvalidInvocationError, match="lacks a timezone"):
        release._parse_timestamp("2026-01-01T00:00:00")
    assert release._parse_timestamp("2026-01-01T00:00:00Z") == NOW
    release._finish_failure(harness.workspace, OperationalError("late"), NOW)
    assert harness.workspace.load().state is RunState.INCOMPLETE
    release._finish_failure(harness.workspace, KeyboardInterrupt(), NOW)
    assert harness.workspace.load().state is RunState.INCOMPLETE
