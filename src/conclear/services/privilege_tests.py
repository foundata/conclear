"""Owned functional and restrictive probes for reviewed runtime permissions."""

import logging
import stat
from dataclasses import replace
from pathlib import Path, PurePosixPath

from conclear.adapters.podman import BindMount, ExecObservation
from conclear.config import SudoRequirement, SudoTestConfig
from conclear.emulation import detect_execution_mode
from conclear.errors import OperationalError
from conclear.jsonutil import canonical_json_bytes, sha256_bytes
from conclear.presentation import Finding
from conclear.services.qualification_inputs import QualificationInputs
from conclear.services.runtime_controls import control_findings, controls_dict
from conclear.services.runtime_lifecycle import RuntimeAdapter
from conclear.workspace import ResourceKind, ResourceStatus

LOGGER = logging.getLogger(__name__)
_KEEPALIVE = ("/bin/sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done")


class PrivilegeContractError(OperationalError):
    """An image fact that breaks a declared privilege contract.

    Raised by the probe for a declared executable's mode, ownership or parent
    directories. For declared set-ID paths it becomes a `CC0406` rejection; on
    the sudo path it stays an operational failure, because the functional
    tests cannot proceed without a usable executable.
    """


def require_emulated_escalation_support(inputs: QualificationInputs) -> None:
    """Refuse escalation tests under an emulation handler without credentials.

    A `binfmt_misc` handler registered without the `C` flag runs a set-user-ID
    binary with the caller's credentials, so `sudo` cannot become root under
    user-mode emulation and every escalation test would fail for a reason the
    image cannot fix. Naming the host cause beats a misleading rejection.
    """
    mode = detect_execution_mode(
        inputs.host_architecture, inputs.platform, binfmt_root=inputs.binfmt_root
    )
    if mode.handler is not None and "C" not in mode.handler.flags:
        raise OperationalError(
            f"Set-ID escalation cannot be tested under user-mode emulation: the "
            f"binfmt handler {mode.handler.name} for {inputs.platform} has flags "
            f"'{mode.handler.flags}' without C (credentials); register it with "
            f"C or test {inputs.platform} natively"
        )


def test_privileges(
    inputs: QualificationInputs,
    runtime: RuntimeAdapter,
    *,
    storage_root: Path,
    runroot: Path,
    image_name: str,
    mounts: tuple[BindMount, ...],
) -> tuple[list[Finding], list[dict[str, object]]]:
    """Test declared permissions without changing the primary lifecycle container."""
    configured = inputs.image.runtime
    needs_inspection = configured.sudo_requirement is not None or bool(
        configured.setid_paths
    )
    if (
        configured.sudo_requirement is not None
        and configured.sudo_requirement.mode == "escalation"
    ):
        require_emulated_escalation_support(inputs)
    modes = (["functional"] if needs_inspection else []) + (
        ["restrictive"] if configured.requires_restrictive_test else []
    )
    findings: list[Finding] = []
    results: list[dict[str, object]] = []
    for mode in modes:
        restricted = mode == "restrictive"
        controls = replace(configured, systemd=None, profile="one-shot")
        if restricted:
            controls = replace(
                controls,
                read_only=True,
                capabilities=(),
                sudo_requirement=None,
                writable_root_requirement=None,
            )
        probe_image = replace(inputs.image, runtime=controls)
        name = f"cc-{inputs.workspace.run_id}-{inputs.platform.key}-{mode}"
        resource_id = (
            f"podman-privilege-{inputs.image.image_id}-{inputs.platform.key}-{mode}"
        )
        inputs.workspace.journal.plan(
            resource_id=resource_id,
            kind=ResourceKind.PODMAN_IMPORT,
            identifier=name,
            ephemeral=True,
            metadata={
                "imageName": image_name,
                "storageRoot": str(storage_root),
                "resetStorage": False,
            },
        )
        try:
            runtime.create_container(
                root=storage_root,
                runroot=runroot,
                name=name,
                image_name=image_name,
                runtime=controls,
                platform=inputs.platform,
                entrypoint=_KEEPALIVE if needs_inspection else (),
                arguments=()
                if needs_inspection
                else inputs.image.test.launch.arguments,
                environment=inputs.image.test.launch.environment,
                mounts=mounts,
            )
            inputs.workspace.journal.update(resource_id, ResourceStatus.CREATED)
            observation = runtime.inspect_controls(
                root=storage_root, runroot=runroot, name=name
            )
            mismatches = list(control_findings(probe_image, observation))
            result: dict[str, object] = {
                "name": f"{mode}Privileges",
                "observed": controls_dict(observation),
            }
            if not mismatches and needs_inspection:
                probe = _Probe(runtime, storage_root, runroot, name)
                if not restricted:
                    executables: list[dict[str, object]] = []
                    for path in configured.setid_paths:
                        try:
                            executables.append(probe.setid(path))
                        except PrivilegeContractError as exc:
                            findings.append(
                                Finding("CC0406", "error", str(exc), location=path)
                            )
                    result["setidExecutables"] = executables
                    if configured.sudo_requirement is not None:
                        sudo_path, policy = probe.sudo_policy(
                            configured.sudo_requirement
                        )
                        result["sudoPolicy"] = policy
                        result["sudoPolicyDigest"] = sha256_bytes(
                            canonical_json_bytes(policy)
                        )
                        result["sudoExecutable"] = sudo_path
                if inputs.image.test.sudo is not None:
                    checks, outcomes = probe.sudo_tests(
                        inputs.image.test.sudo, restrictive=restricted
                    )
                    mismatches.extend(checks)
                    result["sudoTests"] = outcomes
            findings.extend(mismatches)
            result["status"] = "failed" if mismatches else "passed"
            results.append(result)
        except BaseException:
            inputs.workspace.journal.mark_failed(resource_id)
            try:
                runtime.remove(
                    root=storage_root, runroot=runroot, name=name, force=True
                )
                inputs.workspace.journal.update(resource_id, ResourceStatus.REMOVED)
            except Exception:
                LOGGER.debug(
                    "Unable to remove failed privilege probe %s", name, exc_info=True
                )
            raise
        try:
            runtime.remove(root=storage_root, runroot=runroot, name=name, force=True)
            inputs.workspace.journal.update(resource_id, ResourceStatus.REMOVED)
        except BaseException:
            inputs.workspace.journal.mark_failed(resource_id)
            raise
    return findings, results


class _Probe:
    """Bounded commands in one disposable image-specific probe container."""

    def __init__(
        self, runtime: RuntimeAdapter, root: Path, runroot: Path, name: str
    ) -> None:
        self.runtime = runtime
        self.root = root
        self.runroot = runroot
        self.name = name

    def observe(
        self, command: tuple[str, ...], *, user: int = 0, timeout: int = 30
    ) -> ExecObservation:
        return self.runtime.exec_observe(
            root=self.root,
            runroot=self.runroot,
            name=self.name,
            command=command,
            user=user,
            timeout_seconds=timeout,
        )

    def require(self, command: tuple[str, ...], *, user: int = 0) -> str:
        observation = self.observe(command, user=user)
        if observation.exit_status != 0:
            raise OperationalError(f"Privilege probe command failed: {command[0]}")
        return observation.stdout

    def resolve(self, path: str) -> str:
        resolved = self.require(("readlink", "-f", "--", path)).strip()
        if not resolved.startswith("/") or "\n" in resolved:
            raise OperationalError(
                "Privilege probe returned an invalid executable path"
            )
        return resolved

    def setid(self, path: str) -> dict[str, object]:
        resolved = self.resolve(path)
        owner, mode = self._mode(resolved)
        if (
            owner != 0
            or not stat.S_ISREG(mode)
            or not mode & 0o111
            or not mode & (stat.S_ISUID | stat.S_ISGID)
            or mode & 0o022
        ):
            raise PrivilegeContractError(
                f"Declared set-ID executable has unsafe ownership or mode: {path}"
            )
        self._protected_parents(path, resolved)
        return {
            "path": path,
            "resolvedPath": resolved,
            "owner": owner,
            "mode": oct(stat.S_IMODE(mode)),
        }

    def _protected_parents(self, path: str, resolved: str) -> None:
        for parent in sorted(
            {*PurePosixPath(path).parents, *PurePosixPath(resolved).parents}
        ):
            owner, mode = self._mode(str(parent))
            if owner != 0 or mode & 0o022:
                raise PrivilegeContractError(
                    f"Privileged file has an unsafe parent directory: {parent}"
                )

    def _mode(self, path: str) -> tuple[int, int]:
        value = (
            self.require(("stat", "-L", "-c", "%u:%f", "--", path)).strip().split(":")
        )
        try:
            if len(value) != 2:
                raise ValueError("expected owner and mode")
            return int(value[0]), int(value[1], 16)
        except ValueError as exc:
            raise OperationalError(
                "Privilege probe returned malformed file metadata"
            ) from exc

    def sudo_policy(
        self, requirement: SudoRequirement
    ) -> tuple[str, dict[str, object]]:
        path = self.require(("/bin/sh", "-ec", "command -v sudo")).strip()
        resolved = self.resolve(path)
        owner, mode = self._mode(resolved)
        if owner != 0 or not stat.S_ISREG(mode) or not mode & 0o111 or mode & 0o022:
            raise OperationalError("Sudo executable has unsafe ownership or mode")
        self._protected_parents(path, resolved)
        approved = {self.resolve(path) for path in requirement.setid_paths}
        if (
            requirement.mode == "escalation" or mode & (stat.S_ISUID | stat.S_ISGID)
        ) and resolved not in approved:
            raise OperationalError(
                "Resolved sudo executable is not declared in sudo_requirement.setid_paths"
            )
        output = self.require(("env", "LC_ALL=C", "visudo", "-c"))
        paths = [
            line.removesuffix(": parsed OK")
            for line in output.splitlines()
            if line.endswith(": parsed OK")
        ]
        if not paths or any(not path.startswith("/") for path in paths):
            raise OperationalError("visudo did not identify the validated policy files")
        files: dict[str, object] = {}
        for policy_path in paths:
            owner, mode = self._mode(policy_path)
            if owner != 0 or mode & 0o022:
                raise OperationalError(
                    f"Unsafe sudo policy ownership or permissions: {policy_path}"
                )
            self._protected_parents(policy_path, self.resolve(policy_path))
            files[policy_path] = self.require(("cat", "--", policy_path))
        return resolved, files

    def sudo_tests(
        self, test: SudoTestConfig, *, restrictive: bool
    ) -> tuple[list[Finding], list[dict[str, object]]]:
        findings: list[Finding] = []
        results: list[dict[str, object]] = []
        callers = (test.user,) if restrictive else (test.denied_user, test.user)
        for user in callers:
            identity = self.require(("id", "-u"), user=user).strip()
            caller_name = self.require(("id", "-un"), user=user).strip()
            if not caller_name or "\n" in caller_name:
                raise OperationalError("Sudo caller's account name is malformed")
            if identity != str(user) or user == 0:
                raise OperationalError(
                    "Sudo probe did not run as its declared non-root caller"
                )
            status = self.require(("cat", "/proc/self/status"), user=user)
            flags = [
                line.partition(":")[2].strip()
                for line in status.splitlines()
                if line.startswith("NoNewPrivs:")
            ]
            if flags != (["1"] if restrictive else ["0"]):
                raise OperationalError(
                    "Sudo caller's effective no-new-privileges flag differs from the probe"
                )
            command = ("sudo", "-n", "-u", f"#{test.target_user}", "--", *test.command)
            if not restrictive and user == test.denied_user:
                authorization_command = (
                    "sudo",
                    "-n",
                    "-l",
                    "-U",
                    caller_name,
                    "-u",
                    f"#{test.target_user}",
                    "--",
                    *test.command,
                )
                authorization = self.observe(
                    authorization_command,
                    user=0,
                    timeout=test.timeout_seconds,
                )
                if authorization.exit_status != 1:
                    findings.append(
                        Finding(
                            "CC0405",
                            "error",
                            "Sudo authorizes the declared denied caller",
                        )
                    )
                results.append(
                    {
                        "name": "sudoAuthorization",
                        "user": 0,
                        "policyUser": user,
                        "targetUser": test.target_user,
                        "command": list(authorization_command),
                        "expected": "denied",
                        "noNewPrivileges": False,
                        "exitStatus": authorization.exit_status,
                        "stdout": authorization.stdout,
                        "stderr": authorization.stderr,
                        "status": "passed"
                        if authorization.exit_status == 1
                        else "failed",
                    }
                )
            observation = self.observe(command, user=user, timeout=test.timeout_seconds)
            should_succeed = not restrictive and user == test.user
            accepted = (
                observation.exit_status == 0
                and observation.stdout == test.expected_stdout
                if should_succeed
                else observation.exit_status == 1
            )
            if not accepted:
                findings.append(
                    Finding(
                        "CC0405",
                        "error",
                        f"Sudo {'permitted' if should_succeed else 'denied'} operation did not match its contract for UID {user}",
                    )
                )
            results.append(
                {
                    "user": user,
                    "targetUser": test.target_user,
                    "command": list(command),
                    "expected": "success" if should_succeed else "denied",
                    "status": "passed" if accepted else "failed",
                    "exitStatus": observation.exit_status,
                    "stdout": observation.stdout,
                    "stderr": observation.stderr,
                    "noNewPrivileges": restrictive,
                }
            )
        return findings, results
