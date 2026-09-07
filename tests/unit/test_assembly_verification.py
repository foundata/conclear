"""Assembly refuses qualification records that do not exactly match the run."""

import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import conclear.records as records_module
import conclear.services.assembly as assembly_service_module
from conclear.artifacts import qualification_materials
from conclear.config import load_repository_config
from conclear.errors import InvalidInvocationError
from conclear.identity import ApplicationIdentity
from conclear.jsonutil import sha256_bytes, sha256_file
from conclear.oci import validate_layout
from conclear.records import RecordEnvelope, SourceIdentity, ToolIdentity, Verdict
from conclear.services.assembly import QualificationTransport, assemble_candidate
from conclear.values import OCIReference, Platform
from conclear.workspace import RunState, RunWorkspace
from tests.unit.test_assembly import IdFactory, platform_layout
from tests.unit.test_config import _image_text

DIGEST = "sha256:" + "d" * 64
NOW = datetime(2026, 1, 1, tzinfo=UTC)
BUILD_ARGUMENTS = {
    "IMAGE_REVISION": "b" * 40,
    "IMAGE_CREATED": "2026-01-01T00:00:00Z",
    "SOURCE_DATE_EPOCH": str(int(NOW.timestamp())),
    "IMAGE_VERSION": "1.2.3",
}


class Scenario:
    def __init__(
        self,
        tmp_path: Path,
        repository_factory: Callable[..., Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        identity = ApplicationIdentity(source_revision="c" * 40)
        monkeypatch.setattr(records_module, "IDENTITY", identity)
        monkeypatch.setattr(assembly_service_module, "IDENTITY", identity)
        self.tmp_path = tmp_path
        self.repository = load_repository_config(repository_factory() / "conclear.toml")
        self.image = self.repository.release_image("app")
        self.workspace = RunWorkspace.create(
            state_home=tmp_path / "state",
            immutable_inputs={
                "sourceRevision": "b" * 40,
                "sourceRepository": self.repository.project.source,
                "configurationDigest": sha256_bytes(self.repository.raw_bytes),
                "image": "app",
                "version": "1.2.3",
            },
            id_factory=IdFactory(),
            now=NOW,
        )
        self.workspace.transition(RunState.QUALIFIED)
        self.layout = platform_layout(tmp_path / "qualified", "amd64")
        self.graph = validate_layout(self.layout, reference="qualified")
        self.payload_file = tmp_path / "scan.json"
        self.payload_file.write_text("{}\n", encoding="utf-8")
        self.payload_digest = sha256_file(self.payload_file)
        self.tool = ToolIdentity("buildah", "1.43.2", executable_digest=DIGEST)
        self.counter = 0

    def payload(self, **overrides: Any) -> dict[str, Any]:
        pin = self.image.pins[0].reference
        value: dict[str, Any] = {
            "imageId": "app",
            "platform": "linux/amd64",
            "layoutDescriptor": self.graph.root.to_dict(),
            "manifestDigest": str(self.graph.manifests[0].descriptor.digest),
            "containerfileDigest": DIGEST,
            "contextDigest": DIGEST,
            "buildArguments": dict(BUILD_ARGUMENTS),
            "externalImages": [str(pin)],
            "pinObservations": [
                {
                    "reference": str(pin),
                    "pinnedDigest": str(pin.digest),
                    "observedDigest": str(pin.digest),
                    "checkedAt": "2026-01-01T00:00:00Z",
                    "divergenceSince": None,
                    "historyInitialized": True,
                    "findings": [],
                }
            ],
            "effectiveLimits": {
                "pinFreshnessSeconds": 86400,
                "pinDivergenceSeconds": 604800,
            },
            "buildExecution": {
                "targetPlatform": "linux/amd64",
                "hostArchitecture": "x86_64",
                "executionArchitecture": "amd64",
                "mechanism": "native",
            },
            "testExecution": {
                "targetPlatform": "linux/amd64",
                "hostArchitecture": "x86_64",
                "executionArchitecture": "amd64",
                "mechanism": "native",
            },
            "runtimeConstraints": {
                "profile": "service",
                "user": 10001,
                "readOnly": True,
                "writableMounts": [],
                "memory": "512MiB",
                "cpus": 1.0,
                "pids": 128,
                "nofile": 1024,
                "capabilities": [],
            },
            "testInputs": {
                "fixtures": [],
                "outputs": [],
                "preparations": [],
                "launch": {
                    "argumentsDigest": DIGEST,
                    "environmentDigest": DIGEST,
                    "mounts": [],
                    "expectedExitStatus": 0,
                },
            },
            "testImageDependencies": [],
            "testResults": [],
            "sbom": {"digest": self.payload_digest, "spdxVersion": "SPDX-2.3"},
            "scans": [],
            "appliedExceptions": [],
            "payloadDigests": [self.payload_digest],
            "databaseDigest": DIGEST,
            "databaseMetadata": {
                name: {
                    "schemaVersion": version,
                    "updatedAt": "2026-01-01T00:00:00Z",
                    "nextUpdate": "2026-01-02T00:00:00Z",
                    "downloadedAt": "2026-01-01T00:01:00Z",
                }
                for name, version in (("vulnerability", 2), ("java", 1))
            },
            "findings": [],
        }
        value.update(overrides)
        return value

    def transport(
        self,
        payload: dict[str, Any] | None = None,
        *,
        source: SourceIdentity | None = None,
        configuration_digest: str | None = None,
        tools: tuple[ToolIdentity, ...] | None = None,
        verdict: Verdict = Verdict.ACCEPTED,
        created_at: datetime = NOW,
        mutate_record: Callable[[dict[str, Any]], None] | None = None,
        run_id: str | None = None,
    ) -> QualificationTransport:
        record = RecordEnvelope(
            record_type="platformQualification",
            created_at=created_at,
            run_id=run_id or self.workspace.run_id,
            source=source or SourceIdentity("https://github.com/example/app", "b" * 40),
            configuration_digest=configuration_digest
            or sha256_bytes(self.repository.raw_bytes),
            tools=tools or (self.tool,),
            verdict=verdict,
            payload=payload or self.payload(),
        )
        self.counter += 1
        record_path = self.tmp_path / f"qualification-{self.counter}.json"
        value = record.to_dict()
        if mutate_record is not None:
            mutate_record(value)
        record_path.write_text(json.dumps(value), encoding="utf-8")
        return QualificationTransport(
            record_path, self.layout, "qualified", (self.payload_file,)
        )

    def assemble(
        self,
        *transports: QualificationTransport,
        version: str | None = "1.2.3",
        image: Any = None,
        workspace: RunWorkspace | None = None,
    ) -> Any:
        return assemble_candidate(
            transports or (self.transport(),),
            repository=self.repository,
            image=image or self.image,
            workspace=workspace or self.workspace,
            version=version,
            tools=(self.tool,),
            now=NOW + timedelta(minutes=1),
        )


@pytest.fixture
def scenario(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> Scenario:
    return Scenario(tmp_path, repository_factory, monkeypatch)


def test_assembly_requires_the_recorded_version_and_exact_platform_coverage(
    scenario: Scenario,
) -> None:
    with pytest.raises(InvalidInvocationError, match="version differs"):
        scenario.assemble(version="9.9.9")

    arm64 = replace(
        scenario.image,
        platforms=(Platform.parse("linux/amd64"), Platform.parse("linux/arm64")),
    )
    with pytest.raises(InvalidInvocationError, match=r"missing=\['linux/arm64'\]"):
        scenario.assemble(image=arm64)

    with pytest.raises(InvalidInvocationError, match=r"coverage mismatch|duplicate"):
        scenario.assemble(scenario.transport(), scenario.transport())
    assert scenario.workspace.load().state is RunState.QUALIFIED


def test_assembly_rejects_records_bound_to_another_run_image_or_pin_set(
    scenario: Scenario,
) -> None:
    with pytest.raises(InvalidInvocationError, match="another release run"):
        scenario.assemble(scenario.transport(run_id="01arz3ndektsv4rrffq69g5faw"))

    other_image = replace(scenario.image, image_id="other")
    other_workspace = RunWorkspace.create(
        state_home=scenario.tmp_path / "other-state",
        immutable_inputs={
            "sourceRevision": "b" * 40,
            "image": "other",
            "version": "1.2.3",
        },
        id_factory=IdFactory(),
    )
    other_workspace.transition(RunState.QUALIFIED)
    with pytest.raises(InvalidInvocationError, match="selected image"):
        scenario.assemble(image=other_image, workspace=other_workspace)

    unpinned = replace(scenario.image, pins=())
    with pytest.raises(InvalidInvocationError, match="external image pins"):
        scenario.assemble(image=unpinned)

    narrowed = replace(
        scenario.image,
        pin_limits=replace(scenario.image.pin_limits, pin_freshness=timedelta(hours=1)),
    )
    with pytest.raises(InvalidInvocationError, match="effective pin limits"):
        scenario.assemble(image=narrowed)


def test_assembly_rejects_source_configuration_and_ruleset_drift(
    scenario: Scenario,
) -> None:
    with pytest.raises(InvalidInvocationError, match="source repository"):
        scenario.assemble(
            scenario.transport(
                source=SourceIdentity("https://github.com/example/other", "b" * 40)
            )
        )
    with pytest.raises(InvalidInvocationError, match="source revision"):
        scenario.assemble(
            scenario.transport(
                source=SourceIdentity("https://github.com/example/app", "e" * 40)
            )
        )
    with pytest.raises(InvalidInvocationError, match="repository configuration"):
        scenario.assemble(scenario.transport(configuration_digest="sha256:" + "5" * 64))

    def other_build(value: dict[str, Any]) -> None:
        value["ruleset"]["conclearRevision"] = "f" * 40

    with pytest.raises(InvalidInvocationError, match="not produced by this ConClear"):
        scenario.assemble(scenario.transport(mutate_record=other_build))

    def duplicate_tools(value: dict[str, Any]) -> None:
        value["tools"] = value["tools"] * 2

    with pytest.raises(InvalidInvocationError, match="duplicate tool identities"):
        scenario.assemble(scenario.transport(mutate_record=duplicate_tools))

    with pytest.raises(InvalidInvocationError, match="not accepted"):
        scenario.assemble(scenario.transport(verdict=Verdict.REJECTED))


def test_assembly_rejects_inconsistent_pin_observations(scenario: Scenario) -> None:
    observation = scenario.payload()["pinObservations"][0]

    def with_observation(**changes: Any) -> dict[str, Any]:
        return scenario.payload(pinObservations=[{**observation, **changes}])

    foreign = OCIReference.parse(
        "quay.io/example/other:1@sha256:" + "1" * 64,
        require_tag=True,
        require_digest=True,
    )
    with pytest.raises(InvalidInvocationError, match="undeclared external image"):
        scenario.assemble(
            scenario.transport(
                with_observation(
                    reference=str(foreign), pinnedDigest=str(foreign.digest)
                )
            )
        )
    with pytest.raises(InvalidInvocationError, match="another pinned digest"):
        scenario.assemble(
            scenario.transport(with_observation(pinnedDigest="sha256:" + "2" * 64))
        )
    with pytest.raises(InvalidInvocationError, match="freshness limit"):
        scenario.assemble(
            scenario.transport(with_observation(checkedAt="2025-12-30T00:00:00Z"))
        )
    with pytest.raises(InvalidInvocationError, match="divergence timestamp"):
        scenario.assemble(
            scenario.transport(with_observation(divergenceSince="2025-12-31T00:00:00Z"))
        )
    with pytest.raises(InvalidInvocationError, match="divergence exceeds"):
        scenario.assemble(
            scenario.transport(
                with_observation(
                    observedDigest="sha256:" + "3" * 64,
                    divergenceSince="2025-12-20T00:00:00Z",
                )
            )
        )
    with pytest.raises(InvalidInvocationError, match="rejecting pin finding"):
        scenario.assemble(
            scenario.transport(
                with_observation(
                    findings=[
                        {"checkId": "CC0204", "severity": "error", "message": "old"}
                    ]
                )
            )
        )
    with pytest.raises(InvalidInvocationError, match="exactly cover"):
        scenario.assemble(scenario.transport(scenario.payload(pinObservations=[])))
    with pytest.raises(InvalidInvocationError, match="rejecting finding"):
        scenario.assemble(
            scenario.transport(
                scenario.payload(
                    findings=[
                        {"checkId": "CC0403", "severity": "error", "message": "bad"}
                    ]
                )
            )
        )


def test_assembly_rejects_false_execution_observations(scenario: Scenario) -> None:
    emulated = {
        "targetPlatform": "linux/amd64",
        "hostArchitecture": "x86_64",
        "executionArchitecture": "amd64",
        "mechanism": "qemu-user",
    }
    with pytest.raises(InvalidInvocationError, match="claims qemu-user"):
        scenario.assemble(scenario.transport(scenario.payload(testExecution=emulated)))

    native_foreign = {
        "targetPlatform": "linux/amd64",
        "hostArchitecture": "aarch64",
        "executionArchitecture": "amd64",
        "mechanism": "native",
    }
    with pytest.raises(InvalidInvocationError, match="claims native"):
        scenario.assemble(
            scenario.transport(scenario.payload(buildExecution=native_foreign))
        )

    candidate = scenario.assemble()
    assert candidate.observation.graph.digest == scenario.graph.digest
    assert scenario.workspace.load().state is RunState.ASSEMBLED


def test_assembly_rejects_transported_layout_and_payload_drift(
    scenario: Scenario,
) -> None:
    with pytest.raises(
        InvalidInvocationError, match=r"non-unique|duplicate payload digests"
    ):
        scenario.assemble(
            scenario.transport(
                scenario.payload(
                    payloadDigests=[scenario.payload_digest, scenario.payload_digest]
                )
            )
        )
    with pytest.raises(InvalidInvocationError, match="manifest differs"):
        scenario.assemble(
            scenario.transport(scenario.payload(manifestDigest="sha256:" + "4" * 64))
        )
    descriptor = {**scenario.graph.root.to_dict(), "digest": "sha256:" + "4" * 64}
    with pytest.raises(InvalidInvocationError, match="layout root differs"):
        scenario.assemble(
            scenario.transport(scenario.payload(layoutDescriptor=descriptor))
        )
    with pytest.raises(InvalidInvocationError, match="repeats an external image"):
        scenario.assemble(
            scenario.transport(
                scenario.payload(
                    externalImages=[str(scenario.image.pins[0].reference)] * 2
                )
            )
        )
    scenario.payload_file.unlink()
    with pytest.raises(InvalidInvocationError, match="unavailable"):
        scenario.assemble()


def test_assembly_requires_identical_records_across_platforms(
    scenario: Scenario, tmp_path: Path
) -> None:
    arm64_layout = platform_layout(tmp_path / "qualified-arm64", "arm64")
    arm64_graph = validate_layout(arm64_layout, reference="qualified")
    image = replace(
        scenario.image,
        platforms=(Platform.parse("linux/amd64"), Platform.parse("linux/arm64")),
    )
    arm64_payload = scenario.payload(
        platform="linux/arm64",
        layoutDescriptor=arm64_graph.root.to_dict(),
        manifestDigest=str(arm64_graph.manifests[0].descriptor.digest),
        databaseDigest="sha256:" + "6" * 64,
        buildExecution={
            "targetPlatform": "linux/arm64",
            "hostArchitecture": "x86_64",
            "executionArchitecture": "arm64",
            "mechanism": "qemu-user",
        },
        testExecution={
            "targetPlatform": "linux/arm64",
            "hostArchitecture": "x86_64",
            "executionArchitecture": "arm64",
            "mechanism": "qemu-user",
        },
    )
    arm64_transport = scenario.transport(arm64_payload)
    arm64_transport = QualificationTransport(
        arm64_transport.record_path, arm64_layout, "qualified", (scenario.payload_file,)
    )

    with pytest.raises(InvalidInvocationError, match="database snapshots") as caught:
        scenario.assemble(scenario.transport(), arm64_transport, image=image)
    assert caught.value.code == "CC0505"

    arm64_payload["databaseDigest"] = DIGEST
    arm64_record = scenario.transport(
        arm64_payload,
        tools=(ToolIdentity("buildah", "1.43.3", executable_digest=DIGEST),),
    )
    arm64_transport = QualificationTransport(
        arm64_record.record_path, arm64_layout, "qualified", (scenario.payload_file,)
    )
    with pytest.raises(InvalidInvocationError, match="different normalized tool"):
        scenario.assemble(scenario.transport(), arm64_transport, image=image)


def _with_helper(repository_factory: Callable[..., Path]) -> Callable[..., Path]:
    def create(**kwargs: Any) -> Path:
        root = repository_factory(**kwargs)
        path = root / "conclear.toml"
        pin = "quay.io/example/base:1@sha256:" + "a" * 64
        content = path.read_text(encoding="utf-8").replace(
            "[images.release]",
            '[images.test]\ndependencies = ["helper"]\n\n[images.release]',
        )
        path.write_text(
            content
            + _image_text(
                "helper",
                releasable=False,
                tables=(
                    f'\n[[images.pins]]\nreference = "{pin}"\n'
                    'tag_intent = "immutable-version"\n'
                ),
            ),
            encoding="utf-8",
        )
        return root

    return create


def _dependency_entry(scenario: Scenario, **overrides: Any) -> dict[str, Any]:
    base = scenario.payload()
    entry: dict[str, Any] = {
        "imageId": "helper",
        "platform": "linux/amd64",
        "manifestDigest": base["manifestDigest"],
        "layoutDescriptor": base["layoutDescriptor"],
        "sourceRevision": "b" * 40,
        "containerfileDigest": "sha256:" + "5" * 64,
        "contextDigest": DIGEST,
        "buildArguments": dict(BUILD_ARGUMENTS),
        "externalImages": base["externalImages"],
        "pinObservations": base["pinObservations"],
        "effectiveLimits": base["effectiveLimits"],
        "testResultDigest": scenario.payload_digest,
    }
    entry.update(overrides)
    return entry


@pytest.fixture
def dependency_scenario(
    tmp_path: Path,
    repository_factory: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> Scenario:
    return Scenario(tmp_path, _with_helper(repository_factory), monkeypatch)


def test_assembly_verifies_test_dependency_evidence_against_configuration(
    dependency_scenario: Scenario,
) -> None:
    scenario = dependency_scenario

    def rejects(message: str, **overrides: Any) -> None:
        payload = scenario.payload(
            testImageDependencies=[_dependency_entry(scenario, **overrides)]
        )
        with pytest.raises(InvalidInvocationError, match=message):
            scenario.assemble(scenario.transport(payload))

    with pytest.raises(InvalidInvocationError, match="configured test dependencies"):
        scenario.assemble(scenario.transport(scenario.payload()))
    rejects(
        "configured external image pins of helper",
        externalImages=[],
        pinObservations=[],
    )
    rejects(
        "effective pin limits of helper",
        effectiveLimits={"pinFreshnessSeconds": 3600, "pinDivergenceSeconds": 604800},
    )
    observation = dict(scenario.payload()["pinObservations"][0])
    observation["findings"] = [
        {"checkId": "CC0204", "severity": "error", "message": "diverged"}
    ]
    rejects("rejecting pin finding", pinObservations=[observation])
    rejects(
        "Test dependency helper observes an undeclared",
        pinObservations=[
            {
                **scenario.payload()["pinObservations"][0],
                "reference": "quay.io/example/other:1@sha256:" + "9" * 64,
                "pinnedDigest": "sha256:" + "9" * 64,
                "observedDigest": "sha256:" + "9" * 64,
            }
        ],
    )
    rejects("another source revision", sourceRevision="c" * 40)
    rejects("another platform", platform="linux/arm64")
    rejects("not a bound payload", testResultDigest="sha256:" + "8" * 64)

    result = scenario.assemble(
        scenario.transport(
            scenario.payload(testImageDependencies=[_dependency_entry(scenario)])
        )
    )
    assert result.record_path.is_file()


def test_assembly_requires_identical_dependency_inputs_across_platforms(
    dependency_scenario: Scenario, tmp_path: Path
) -> None:
    scenario = dependency_scenario
    arm64_layout = platform_layout(tmp_path / "qualified-arm64", "arm64")
    arm64_graph = validate_layout(arm64_layout, reference="qualified")
    image = replace(
        scenario.image,
        platforms=(Platform.parse("linux/amd64"), Platform.parse("linux/arm64")),
    )
    helper = scenario.repository.image("helper")
    repository = replace(
        scenario.repository,
        images=tuple(
            image
            if item.image_id == "app"
            else replace(item, platforms=image.platforms)
            for item in scenario.repository.images
        ),
    )
    assert helper.image_id == "helper"
    execution = {
        "targetPlatform": "linux/arm64",
        "hostArchitecture": "x86_64",
        "executionArchitecture": "arm64",
        "mechanism": "qemu-user",
    }
    amd64_transport = scenario.transport(
        scenario.payload(testImageDependencies=[_dependency_entry(scenario)])
    )
    arm64_payload = scenario.payload(
        platform="linux/arm64",
        layoutDescriptor=arm64_graph.root.to_dict(),
        manifestDigest=str(arm64_graph.manifests[0].descriptor.digest),
        buildExecution=execution,
        testExecution=execution,
        testImageDependencies=[
            _dependency_entry(
                scenario,
                platform="linux/arm64",
                manifestDigest=str(arm64_graph.manifests[0].descriptor.digest),
                layoutDescriptor=arm64_graph.root.to_dict(),
                containerfileDigest="sha256:" + "7" * 64,
            )
        ],
    )
    arm64_record = scenario.transport(arm64_payload)
    arm64_transport = QualificationTransport(
        arm64_record.record_path, arm64_layout, "qualified", (scenario.payload_file,)
    )

    with pytest.raises(
        InvalidInvocationError, match="different test dependency inputs"
    ):
        assemble_candidate(
            (amd64_transport, arm64_transport),
            repository=repository,
            image=image,
            workspace=scenario.workspace,
            version="1.2.3",
            tools=(scenario.tool,),
            now=NOW + timedelta(minutes=1),
        )


def test_qualification_materials_name_every_test_dependency_input(
    dependency_scenario: Scenario,
) -> None:
    scenario = dependency_scenario
    entry = _dependency_entry(scenario)
    payload = scenario.payload(testImageDependencies=[entry])
    pin = str(scenario.image.pins[0].reference)

    materials = dict(
        qualification_materials(
            payload, image_id="app", platform=Platform.parse("linux/amd64")
        )
    )

    assert materials == {
        "conclear:containerfile/app/linux/amd64": DIGEST,
        "conclear:context/app/linux/amd64": DIGEST,
        f"docker://{pin}": str(scenario.image.pins[0].reference.digest),
        "conclear:containerfile/helper/linux/amd64": "sha256:" + "5" * 64,
        "conclear:context/helper/linux/amd64": DIGEST,
        "conclear:test-image/helper/linux/amd64": entry["manifestDigest"],
    }


def test_assembly_verifies_build_arguments_of_the_image_and_its_dependencies(
    dependency_scenario: Scenario,
) -> None:
    scenario = dependency_scenario

    def rejects(message: str, **overrides: Any) -> None:
        payload = scenario.payload(
            testImageDependencies=[_dependency_entry(scenario, **overrides)]
        )
        with pytest.raises(InvalidInvocationError, match=message):
            scenario.assemble(scenario.transport(payload))

    rejects(
        "other build arguments than the qualified image",
        buildArguments={**BUILD_ARGUMENTS, "EXTRA": "1"},
    )
    rejects(
        "Test dependency helper build arguments name another source revision",
        buildArguments={**BUILD_ARGUMENTS, "IMAGE_REVISION": "c" * 40},
    )
    rejects(
        "IMAGE_CREATED does not match SOURCE_DATE_EPOCH",
        buildArguments={**BUILD_ARGUMENTS, "IMAGE_CREATED": "2026-01-02T00:00:00Z"},
    )
    rejects(
        "no valid SOURCE_DATE_EPOCH",
        buildArguments={
            key: value
            for key, value in BUILD_ARGUMENTS.items()
            if key != "SOURCE_DATE_EPOCH"
        },
    )
    for arguments, message in (
        (
            {**BUILD_ARGUMENTS, "IMAGE_REVISION": "c" * 40},
            "Qualification build arguments name another source revision",
        ),
        (
            {**BUILD_ARGUMENTS, "SOURCE_DATE_EPOCH": "1767225601"},
            "IMAGE_CREATED does not match",
        ),
    ):
        with pytest.raises(InvalidInvocationError, match=message):
            scenario.assemble(
                scenario.transport(
                    scenario.payload(
                        buildArguments=arguments,
                        testImageDependencies=[_dependency_entry(scenario)],
                    )
                )
            )


def test_assembly_requires_identical_build_arguments_across_platforms(
    scenario: Scenario, tmp_path: Path
) -> None:
    arm64_layout = platform_layout(tmp_path / "qualified-arm64", "arm64")
    arm64_graph = validate_layout(arm64_layout, reference="qualified")
    image = replace(
        scenario.image,
        platforms=(Platform.parse("linux/amd64"), Platform.parse("linux/arm64")),
    )
    execution = {
        "targetPlatform": "linux/arm64",
        "hostArchitecture": "x86_64",
        "executionArchitecture": "arm64",
        "mechanism": "qemu-user",
    }
    later = NOW + timedelta(seconds=60)
    arm64_payload = scenario.payload(
        platform="linux/arm64",
        layoutDescriptor=arm64_graph.root.to_dict(),
        manifestDigest=str(arm64_graph.manifests[0].descriptor.digest),
        buildExecution=execution,
        testExecution=execution,
        buildArguments={
            **BUILD_ARGUMENTS,
            "IMAGE_CREATED": "2026-01-01T00:01:00Z",
            "SOURCE_DATE_EPOCH": str(int(later.timestamp())),
        },
    )
    arm64_record = scenario.transport(arm64_payload)
    arm64_transport = QualificationTransport(
        arm64_record.record_path, arm64_layout, "qualified", (scenario.payload_file,)
    )

    with pytest.raises(InvalidInvocationError, match="different build arguments"):
        scenario.assemble(scenario.transport(), arm64_transport, image=image)
