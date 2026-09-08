import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, override

import pytest

import conclear.records as records_module
from conclear.adapters.podman import (
    ExecObservation,
    PodmanAdapter,
    RuntimeControlObservation,
)
from conclear.adapters.trivy import DatabaseObservation
from conclear.checks import analyze_containerfile
from conclear.config import load_repository_config
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.identity import ApplicationIdentity
from conclear.presentation import Finding
from conclear.records import Verdict, validate_record
from conclear.scan_policy import evaluate_trivy_report
from conclear.services.privilege_tests import test_privileges as run_privilege_tests
from conclear.services.qualification import qualify_platform
from conclear.services.runtime_controls import control_findings
from conclear.tools import ToolName
from conclear.workspace import ResourceStatus
from tests.unit.test_adapters import FakeRunner, adapter_arguments, result
from tests.unit.test_qualification import (
    DATABASE_METADATA,
    Builder,
    Runtime,
    Scanner,
    closure_preflight,
    hook_runner,
    inputs,
)

SUDO_REQUIREMENT = """
[images.runtime.sudo_requirement]
rationale = "Exercise Ansible become in a disposable target."
owner = "platform@example.com"
review_trigger = "Changes to test purpose or authorization."
mode = "escalation"
scope = "Account 10001 may administer the test OS; nobody may not."
"""
SUDO_TEST = """
[images.test.sudo]
user = 10001
denied_user = 65534
command = ["/usr/bin/id", "-u"]
expected_stdout = "0\\n"
"""
ROOT_REQUIREMENT = """
[images.runtime.root_requirement]
rationale = "Run the system manager."
owner = "platform@example.com"
review_trigger = "Lifecycle change."
"""


def configure_sudo(
    root: Path, *, mode: str = "escalation", root_user: bool = False
) -> Path:
    path = root / "conclear.toml"
    text = path.read_text(encoding="utf-8")
    if root_user:
        text = text.replace("user = 10001", "user = 0") + ROOT_REQUIREMENT
    text += SUDO_REQUIREMENT.replace('mode = "escalation"', f'mode = "{mode}"')
    if mode == "escalation":
        text += SUDO_TEST
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("root_user", [False, True])
@pytest.mark.parametrize("mode", ["presence-only", "escalation"])
def test_sudo_permission_is_independent_of_startup_root(
    repository_factory: Callable[..., Path], root_user: bool, mode: str
) -> None:
    path = configure_sudo(repository_factory(), mode=mode, root_user=root_user)
    image = load_repository_config(path).release_image("app")
    assert (image.runtime.root_requirement is not None) is root_user
    assert image.runtime.sudo_requirement is not None
    assert image.runtime.no_new_privileges is (mode == "presence-only")
    assert image.runtime.read_only
    assert image.runtime.capabilities == ()
    assert image.runtime.setid_paths == ("/usr/bin/sudo",)
    assert (image.test.sudo is not None) is (mode == "escalation")


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('owner = "platform@example.com"', 'owner = "   "'),
        ('mode = "escalation"', 'mode = "allow-all"'),
        (
            'scope = "Account 10001 may administer the test OS; nobody may not."',
            'scope = " "',
        ),
        ("user = 10001\ndenied_user", "user = 0\ndenied_user"),
        ("denied_user = 65534", "denied_user = 10001"),
        ('command = ["/usr/bin/id", "-u"]', 'command = ["id", "-u"]'),
        ('mode = "escalation"', 'mode = "presence-only"'),
        (SUDO_TEST, ""),
    ],
)
def test_sudo_contract_rejects_missing_or_inconsistent_decisions(
    repository_factory: Callable[..., Path], old: str, new: str
) -> None:
    path = configure_sudo(repository_factory())
    path.write_text(
        path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8"
    )
    with pytest.raises(InvalidInvocationError):
        load_repository_config(path)


def test_writable_root_needs_its_own_requirement(
    repository_factory: Callable[..., Path],
) -> None:
    path = configure_sudo(repository_factory())
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text
        + ROOT_REQUIREMENT.replace("root_requirement", "writable_root_requirement"),
        encoding="utf-8",
    )
    runtime = load_repository_config(path).release_image("app").runtime
    assert not runtime.read_only
    assert runtime.writable_root_requirement is not None
    assert runtime.root_requirement is None


@pytest.mark.parametrize("mode", ["4755", "u+s"])
def test_setid_chmod_exception_matches_only_exact_declared_paths(
    tmp_path: Path, mode: str
) -> None:
    path = tmp_path / "Containerfile"
    path.write_text(
        f'FROM scratch\nRUN chmod {mode} /usr/bin/sudo\nUSER 10001\nCMD ["/app"]\n',
        encoding="utf-8",
    )
    assert any(
        item.check_id == "CC0109" for item in analyze_containerfile(path).findings
    )
    assert not any(
        item.check_id == "CC0109"
        for item in analyze_containerfile(
            path, allowed_setid_paths=("/usr/bin/sudo",)
        ).findings
    )
    assert any(
        item.check_id == "CC0109"
        for item in analyze_containerfile(
            path, allowed_setid_paths=("/usr/bin/other",)
        ).findings
    )
    path.write_text(
        path.read_text(encoding="utf-8").replace(mode, "4777"), encoding="utf-8"
    )
    assert any(
        item.check_id == "CC0109"
        for item in analyze_containerfile(
            path, allowed_setid_paths=("/usr/bin/sudo",)
        ).findings
    )


def test_reviewed_root_applies_only_to_the_nonroot_scanner_rule(
    repository_factory: Callable[..., Path],
) -> None:
    path = configure_sudo(repository_factory(), root_user=True)
    runtime = load_repository_config(path).release_image("app").runtime
    report = {
        "Results": [
            {
                "Misconfigurations": [
                    {"ID": "DS-0002", "Status": "FAIL"},
                    {"ID": "OTHER", "Status": "FAIL"},
                ]
            }
        ]
    }
    result = evaluate_trivy_report(
        report, image_id="app", exceptions=(), today=date(2026, 9, 8), runtime=runtime
    )
    assert [item.message for item in result.findings] == ["Configuration finding OTHER"]
    assert result.applied_runtime_requirements[0]["owner"] == "platform@example.com"
    assert not evaluate_trivy_report(
        report,
        image_id="app",
        exceptions=(),
        today=date(2026, 9, 8),
        runtime=replace(runtime, root_requirement=None),
    ).accepted


class PrivilegeRuntime(Runtime):
    def __init__(self, *, defect: str = "") -> None:
        super().__init__()
        self.defect = defect
        self.probe_commands: list[tuple[int, tuple[str, ...]]] = []

    @override
    def inspect_controls(self, **values: Any) -> RuntimeControlObservation:
        observed = super().inspect_controls(**values)
        runtime = self.runtimes[str(values["name"])]
        return replace(
            observed,
            read_only=runtime.read_only,
            security_options=("no-new-privileges",)
            if runtime.no_new_privileges
            else (),
            bounding_capabilities=runtime.capabilities,
            effective_capabilities=runtime.capabilities,
        )

    @override
    def exec_observe(self, **values: Any) -> ExecObservation:
        if not str(values["name"]).endswith(("-functional", "-restrictive")):
            return super().exec_observe(**values)
        command = tuple(values["command"])
        user = int(values.get("user", 0))
        self.probe_commands.append((user, command))
        runtime = self.runtimes[str(values["name"])]
        if self.defect == "execution-error":
            raise OperationalError("injected probe failure")
        output = ""
        status = 0
        if command[0] == "readlink":
            output = command[-1] + "\n"
            if self.defect == "invalid-path":
                output = "relative\n"
        elif command[0] == "stat":
            mode = (
                0o104755
                if command[-1] == "/usr/bin/sudo"
                else 0o100440
                if command[-1].startswith("/etc/sudoers")
                else 0o40755
            )
            owner = 10001 if self.defect == "unsafe-file" else 0
            if self.defect == "nonsetid-sudo" and command[-1] == "/usr/bin/sudo":
                mode = 0o100755
            if self.defect == "unsafe-parent" and command[-1] == "/usr/bin":
                mode = 0o40777
            if self.defect == "unsafe-policy" and command[-1] == "/etc/sudoers":
                mode = 0o100666
            output = f"{owner}:{mode:x}\n"
            if self.defect == "invalid-metadata":
                output = "not-metadata\n"
        elif command[0] == "/bin/sh":
            output = "/usr/bin/sudo\n"
        elif command[0] == "env":
            output = "/etc/sudoers: parsed OK\n/etc/sudoers.d/test: parsed OK\n"
            if self.defect == "invalid-policy":
                status = 1
            if self.defect == "missing-policy-files":
                output = ""
        elif command[:2] == ("cat", "/proc/self/status"):
            enabled = runtime.no_new_privileges and self.defect != "wrong-nnp"
            output = f"NoNewPrivs:\t{int(enabled)}\n"
        elif command[0] == "cat":
            output = "test ALL=(root) NOPASSWD: ALL\n"
        elif command == ("id", "-u"):
            output = f"{0 if self.defect == 'root-caller' else user}\n"
        elif command == ("id", "-un"):
            output = f"user{user}\n"
        elif command[0] == "sudo":
            succeeds = user == 10001 and not runtime.no_new_privileges
            if self.defect == "unauthorized-allowed" and user == 65534:
                succeeds = True
            if self.defect == "restriction-bypassed" and runtime.no_new_privileges:
                succeeds = True
            if self.defect == "permitted-denied":
                succeeds = False
            status = 0 if succeeds else 1
            output = "0\n" if succeeds else ""
        else:
            raise AssertionError(f"Unexpected probe command: {command}")
        return ExecObservation(status, output, "")


@pytest.mark.parametrize("mode", ["presence-only", "escalation"])
def test_privilege_probes_record_policy_identities_and_both_modes(
    repository_factory: Callable[..., Path], tmp_path: Path, mode: str
) -> None:
    root = repository_factory()
    configure_sudo(root, mode=mode)
    value = inputs(root, tmp_path)
    runtime = PrivilegeRuntime()
    findings, results = run_privilege_tests(
        value,
        runtime,
        storage_root=tmp_path / "store",
        runroot=tmp_path / "run",
        image_name="localhost/test:qualified",
        mounts=(),
    )
    assert findings == []
    assert len(results) == (2 if mode == "escalation" else 1)
    assert results[0]["sudoPolicy"] == {
        "/etc/sudoers": "test ALL=(root) NOPASSWD: ALL\n",
        "/etc/sudoers.d/test": "test ALL=(root) NOPASSWD: ALL\n",
    }
    callers = [user for user, command in runtime.probe_commands if command[0] == "sudo"]
    assert callers == ([65534, 65534, 10001, 10001] if mode == "escalation" else [])
    assert all(
        item.status is ResourceStatus.REMOVED
        for item in value.workspace.journal.entries()
    )
    assert len(runtime.created) == len(results)
    if mode == "escalation":
        restrictive = runtime.created[1]["runtime"]
        assert restrictive.read_only and restrictive.no_new_privileges
        assert restrictive.capabilities == ()
    observation = runtime.inspect_controls(name=runtime.created[0]["name"])
    assert control_findings(value.image, observation) == ()


@pytest.mark.parametrize(
    "defect", ["unauthorized-allowed", "restriction-bypassed", "permitted-denied"]
)
def test_incorrect_sudo_outcomes_reject_the_gate(
    repository_factory: Callable[..., Path], tmp_path: Path, defect: str
) -> None:
    root = repository_factory()
    configure_sudo(root)
    value = inputs(root, tmp_path)
    findings, _ = run_privilege_tests(
        value,
        PrivilegeRuntime(defect=defect),
        storage_root=tmp_path / "store",
        runroot=tmp_path / "run",
        image_name="localhost/test:qualified",
        mounts=(),
    )
    assert findings and all(item.check_id == "CC0405" for item in findings)
    assert all(
        item.status is ResourceStatus.REMOVED
        for item in value.workspace.journal.entries()
    )


@pytest.mark.parametrize(
    "defect",
    [
        "unsafe-file",
        "invalid-policy",
        "root-caller",
        "wrong-nnp",
        "execution-error",
        "invalid-path",
        "unsafe-parent",
        "unsafe-policy",
        "invalid-metadata",
        "missing-policy-files",
    ],
)
def test_probe_failures_never_pass_and_clean_owned_containers(
    repository_factory: Callable[..., Path], tmp_path: Path, defect: str
) -> None:
    root = repository_factory()
    configure_sudo(root)
    value = inputs(root, tmp_path)
    with pytest.raises(OperationalError):
        run_privilege_tests(
            value,
            PrivilegeRuntime(defect=defect),
            storage_root=tmp_path / "store",
            runroot=tmp_path / "run",
            image_name="localhost/test:qualified",
            mounts=(),
        )
    assert all(
        item.status is ResourceStatus.REMOVED
        for item in value.workspace.journal.entries()
    )


@pytest.mark.parametrize("mode", ["presence-only", "escalation"])
def test_sudo_qualification_binds_permission_contract_and_test_report(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    monkeypatch.setattr(
        records_module, "IDENTITY", ApplicationIdentity(source_revision="c" * 40)
    )
    root = repository_factory()
    path = configure_sudo(root, mode=mode)
    path.write_text(
        path.read_text(encoding="utf-8")
        + ROOT_REQUIREMENT.replace("root_requirement", "writable_root_requirement"),
        encoding="utf-8",
    )
    value = inputs(root, tmp_path)
    database = tmp_path / "database"
    database.mkdir()
    outcome = qualify_platform(
        value,
        builder=Builder(),
        runtime=PrivilegeRuntime(),
        hooks=hook_runner(value),
        scanner=Scanner(),
        database=DatabaseObservation(database, "sha256:" + "e" * 64, DATABASE_METADATA),
        preflight=closure_preflight(value),
        now=datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    )
    assert outcome.verdict is Verdict.ACCEPTED
    record = json.loads(outcome.record_path.read_text(encoding="utf-8"))
    validate_record(record)
    constraints = record["payload"]["runtimeConstraints"]
    assert constraints["sudoRequirement"]["mode"] == mode
    assert constraints["sudoRequirement"]["setidPaths"] == ["/usr/bin/sudo"]
    assert constraints["noNewPrivileges"] is (mode == "presence-only")
    assert not constraints["readOnly"]
    assert constraints["writableRootRequirement"]["owner"] == "platform@example.com"
    report = json.loads(
        (value.workspace.root / "reports/app/linux-amd64/tests.json").read_text(
            encoding="utf-8"
        )
    )
    assert [item["name"] for item in report["results"][:2]] == [
        "functionalPrivileges",
        "restrictivePrivileges",
    ]
    assert all(item["status"] == "passed" for item in report["results"][:2])
    for invalid_field, invalid_value in (
        ("noNewPrivileges", mode == "escalation"),
        ("readOnly", True),
    ):
        changed = deepcopy(record)
        changed["payload"]["runtimeConstraints"][invalid_field] = invalid_value
        with pytest.raises(InvalidInvocationError):
            validate_record(changed)


@pytest.mark.parametrize("mode", ["presence-only", "escalation"])
def test_empty_sudo_setid_paths_only_support_presence(
    repository_factory: Callable[..., Path],
    mode: str,
) -> None:
    path = configure_sudo(repository_factory(), mode=mode)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            f'mode = "{mode}"', f'mode = "{mode}"\nsetid_paths = []'
        ),
        encoding="utf-8",
    )
    if mode == "escalation":
        with pytest.raises(InvalidInvocationError, match="requires a declared set-ID"):
            load_repository_config(path)
    else:
        assert (
            load_repository_config(path).release_image("app").runtime.setid_paths == ()
        )


@pytest.mark.parametrize("path_name", ["/usr/bin/sudo", "/usr/bin/other"])
def test_additional_setid_requirements_must_not_duplicate_sudo_paths(
    repository_factory: Callable[..., Path],
    path_name: str,
) -> None:
    path = configure_sudo(repository_factory())
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n[[images.runtime.setid_requirements]]\n"
        + f'path = "{path_name}"\n'
        + 'rationale = "Declared helper."\nowner = "platform"\nreview_trigger = "Helper changes."\n',
        encoding="utf-8",
    )
    if path_name == "/usr/bin/sudo":
        with pytest.raises(InvalidInvocationError, match="distinct paths"):
            load_repository_config(path)
    else:
        runtime = load_repository_config(path).release_image("app").runtime
        assert runtime.setid_paths == ("/usr/bin/other", "/usr/bin/sudo")
        assert runtime.setid_requirements[0].review.owner == "platform"


@pytest.mark.parametrize("truncated", [False, True])
def test_podman_exec_uses_explicit_caller_and_rejects_truncated_evidence(
    tmp_path: Path,
    truncated: bool,
) -> None:
    runner = FakeRunner(replace(result("10001\n"), stdout_truncated=truncated))
    adapter = adapter_arguments(tmp_path, ToolName.PODMAN, runner).create(PodmanAdapter)

    def observe() -> ExecObservation:
        return adapter.exec_observe(
            root=tmp_path / "store",
            runroot=tmp_path / "run",
            name="probe",
            command=("id", "-u"),
            timeout_seconds=10,
            user=10001,
        )

    if truncated:
        with pytest.raises(OperationalError, match="observation limit"):
            observe()
    else:
        assert observe().stdout == "10001\n"
    assert runner.requests[0].argv[-6:] == (
        "exec",
        "--user",
        "10001",
        "probe",
        "id",
        "-u",
    )


@pytest.mark.parametrize("has_setid", [False, True])
def test_presence_only_cannot_omit_an_installed_setid_sudo(
    repository_factory: Callable[..., Path],
    tmp_path: Path,
    has_setid: bool,
) -> None:
    root = repository_factory()
    path = configure_sudo(root, mode="presence-only")
    path.write_text(
        path.read_text(encoding="utf-8") + "\nsetid_paths = []\n", encoding="utf-8"
    )
    value = inputs(root, tmp_path)
    runtime = PrivilegeRuntime(defect="" if has_setid else "nonsetid-sudo")

    def probe() -> tuple[list[Finding], list[dict[str, object]]]:
        return run_privilege_tests(
            value,
            runtime,
            storage_root=tmp_path / "store",
            runroot=tmp_path / "run",
            image_name="localhost/test:qualified",
            mounts=(),
        )

    if has_setid:
        with pytest.raises(OperationalError, match="not declared"):
            probe()
    else:
        findings, results = probe()
        assert not findings and results[0]["status"] == "passed"
