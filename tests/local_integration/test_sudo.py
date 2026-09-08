"""Real sudo tests using an explicitly supplied, run-owned OCI fixture layout."""

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from conclear.jsonutil import atomic_write_json
from conclear.oci import validate_layout
from conclear.runtime import ApplicationRuntime
from conclear.services.privilege_tests import test_privileges as run_privilege_tests
from conclear.tools import ToolName
from conclear.workspace import ResourceStatus
from tests.local_integration.fixtures import tool_resolver
from tests.unit.test_privilege_contracts import configure_sudo
from tests.unit.test_qualification import inputs

pytestmark = pytest.mark.local_integration


@pytest.mark.parametrize("mode", ["presence-only", "escalation"])
def test_real_sudo_permissions_and_restrictive_controls(
    tmp_path: Path, repository_factory: Callable[..., Path], mode: str
) -> None:
    selected = os.environ.get("CONCLEAR_TEST_SUDO_LAYOUT")
    if selected is None:
        pytest.skip("Requires a manifest-owned CONCLEAR_TEST_SUDO_LAYOUT")
    layout = Path(selected)
    if not layout.is_absolute():
        pytest.skip("CONCLEAR_TEST_SUDO_LAYOUT must be absolute")
    graph = validate_layout(layout, reference="sudo-fixture")
    repository = repository_factory()
    path = configure_sudo(repository, mode=mode)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "[images.runtime]\n",
            '[images.runtime]\ncapabilities = ["CAP_SETUID", "CAP_SETGID"]\nwritable_mounts = ["/run", "/tmp"]\n',
        ),
        encoding="utf-8",
    )
    value = inputs(repository, tmp_path)
    application = ApplicationRuntime.create(
        value.workspace.root / "environment",
        names=(ToolName.PODMAN,),
        resolver=tool_resolver(),
    )
    adapter = application.podman()
    root = value.workspace.root / "podman" / "root"
    runroot = value.workspace.root / "podman" / "runroot"
    image_name = f"localhost/conclear-sudo-{value.workspace.run_id}:fixture"
    try:
        imported = adapter.import_layout(
            root=root,
            runroot=runroot,
            layout_path=layout,
            layout_reference="sudo-fixture",
            image_name=image_name,
            expected_digest=graph.digest,
        )
        assert imported.digest == graph.digest
        findings, results = run_privilege_tests(
            value,
            adapter,
            storage_root=root,
            runroot=runroot,
            image_name=image_name,
            mounts=(),
        )
        atomic_write_json(
            tmp_path / "sudo-results.json",
            {"findings": [item.to_dict() for item in findings], "results": results},
        )
        assert not findings
        assert all(item["status"] == "passed" for item in results)
        if mode == "escalation":
            tests = results[0]["sudoTests"]
            assert isinstance(tests, list)
            assert tests[0]["user"] == 0 and tests[0]["policyUser"] == 65534
            assert "a password is required" not in tests[0]["stderr"]
            assert "unknown user" not in tests[0]["stderr"]
            assert tests[0]["command"][tests[0]["command"].index("-U") + 1] == "nobody"
        assert all(
            item.status is ResourceStatus.REMOVED
            for item in value.workspace.journal.entries()
        )
    finally:
        adapter.remove_storage(root=root, runroot=runroot)
