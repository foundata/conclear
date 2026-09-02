"""Validation and deterministic identity for container runtime test inputs."""

import logging
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from conclear.config import (
    TestConfig,
    TestLaunchConfig,
    TestMountConfig,
    TestPreparationConfig,
)
from conclear.errors import OperationalError
from conclear.jsonutil import canonical_json_bytes, sha256_bytes, sha256_file

MAX_TEST_INPUT_ENTRIES = 100_000
MAX_TEST_INPUT_BYTES = 1024 * 1024 * 1024
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TreeObservation:
    """One validated file tree without exposing its content."""

    digest: str | None
    files: int
    bytes: int

    def to_dict(self, *, name: str, secret: bool) -> dict[str, object]:
        """Return the non-secret public observation."""
        value: dict[str, object] = {
            "name": name,
            "secret": secret,
            "files": self.files,
            "bytes": self.bytes,
        }
        if self.digest is not None:
            value["digest"] = self.digest
        return value


@dataclass(frozen=True, slots=True)
class MaterializedTestInputs:
    """Run-owned output paths and validated repository fixture observations."""

    root: Path
    fixtures: dict[str, Path]
    outputs: dict[str, Path]
    fixture_observations: dict[str, TreeObservation]
    secret_outputs: frozenset[str]

    def path_for(self, mount: TestMountConfig) -> Path:
        """Resolve a previously validated mount handle."""
        paths = self.fixtures if mount.source.value == "fixture" else self.outputs
        try:
            return paths[mount.name]
        except KeyError as exc:
            raise OperationalError("Test mount refers to an unavailable input") from exc

    def is_secret(self, mount: TestMountConfig) -> bool:
        """Return whether a mount source is secret test material."""
        return mount.source.value == "output" and mount.name in self.secret_outputs


def materialize_test_inputs(
    root: Path, *, run_id: str, test: TestConfig
) -> MaterializedTestInputs:
    """Create one private run-owned test-input tree after ownership is journaled."""
    created_root = False
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        created_root = True
        marker = root / ".conclear-owner"
        descriptor = os.open(
            marker,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(descriptor, (run_id + "\n").encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        output_root = root / "outputs"
        output_root.mkdir(mode=0o700)
        outputs: dict[str, Path] = {}
        for output in test.outputs:
            path = output_root / output.name
            path.mkdir(mode=0o700)
            outputs[output.name] = path
    except OSError as exc:
        if created_root:
            try:
                root_value = root.lstat()
                if (
                    stat.S_ISDIR(root_value.st_mode)
                    and not stat.S_ISLNK(root_value.st_mode)
                    and root_value.st_uid == os.getuid()
                ):
                    shutil.rmtree(root)
            except OSError:
                LOGGER.debug(
                    "Failed to remove partially materialized test inputs %s",
                    root,
                    exc_info=True,
                )
        raise OperationalError(
            f"Unable to create run-owned test inputs {root}"
        ) from exc
    fixtures = {fixture.name: fixture.path for fixture in test.fixtures}
    observations = {
        name: observe_test_tree(path, secret=False) for name, path in fixtures.items()
    }
    return MaterializedTestInputs(
        root=root,
        fixtures=fixtures,
        outputs=outputs,
        fixture_observations=observations,
        secret_outputs=frozenset(
            output.name for output in test.outputs if output.secret
        ),
    )


def remove_materialized_test_inputs(root: Path, *, run_id: str) -> None:
    """Remove only a test-input tree carrying this run's ownership marker."""
    marker = root / ".conclear-owner"
    try:
        root_value = root.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise OperationalError(
            f"Unable to inspect run-owned test inputs {root}"
        ) from exc
    try:
        value = marker.lstat()
        if (
            stat.S_ISLNK(value.st_mode)
            or not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) & 0o077
            or marker.read_text(encoding="ascii") != run_id + "\n"
        ):
            raise OperationalError("Test-input ownership marker is invalid")
        if (
            stat.S_ISLNK(root_value.st_mode)
            or not stat.S_ISDIR(root_value.st_mode)
            or root_value.st_uid != os.getuid()
            or stat.S_IMODE(root_value.st_mode) & 0o077
        ):
            raise OperationalError("Test-input directory ownership is invalid")
        shutil.rmtree(root)
    except FileNotFoundError as exc:
        raise OperationalError("Test-input ownership marker is missing") from exc
    except OSError as exc:
        raise OperationalError(
            f"Unable to remove run-owned test inputs {root}"
        ) from exc


def destroy_secret_test_outputs(value: MaterializedTestInputs) -> None:
    """Destroy validated secret output directories before repository hooks run."""
    for name in sorted(value.secret_outputs):
        path = value.outputs[name]
        observe_test_tree(path, secret=True)
        try:
            shutil.rmtree(path)
        except OSError as exc:
            raise OperationalError("Unable to destroy secret test output") from exc


def observe_test_tree(path: Path, *, secret: bool) -> TreeObservation:
    """Validate one fixture or output tree and return a bounded identity."""
    entries: list[dict[str, object]] = []
    files = 0
    total_bytes = 0

    def observe(current: Path, relative: PurePosixPath) -> None:
        nonlocal files, total_bytes
        try:
            value = current.lstat()
        except OSError as exc:
            raise OperationalError(f"Unable to inspect test input {path}") from exc
        if stat.S_ISLNK(value.st_mode):
            raise OperationalError(f"Test input contains a symbolic link: {current}")
        if value.st_uid != os.getuid():
            raise OperationalError(
                f"Test input is not owned by the current user: {current}"
            )
        unsafe_mode = 0o077 if secret else 0o022
        if stat.S_IMODE(value.st_mode) & unsafe_mode:
            raise OperationalError(f"Test input has unsafe permissions: {current}")
        if stat.S_ISDIR(value.st_mode):
            try:
                children = sorted(
                    current.iterdir(), key=lambda item: os.fsencode(item.name)
                )
            except OSError as exc:
                raise OperationalError(
                    f"Unable to enumerate test input {current}"
                ) from exc
            for child in children:
                child_relative = (
                    PurePosixPath(child.name)
                    if not relative.parts
                    else relative / child.name
                )
                observe(child, child_relative)
            return
        if not stat.S_ISREG(value.st_mode):
            raise OperationalError(f"Test input is not a regular file: {current}")
        files += 1
        total_bytes += value.st_size
        if files > MAX_TEST_INPUT_ENTRIES:
            raise OperationalError("Test input exceeds the file-count limit")
        if total_bytes > MAX_TEST_INPUT_BYTES:
            raise OperationalError("Test input exceeds the content-size limit")
        entry: dict[str, object] = {
            "path": relative.as_posix(),
            "mode": stat.S_IMODE(value.st_mode),
            "size": value.st_size,
        }
        if not secret:
            entry["digest"] = sha256_file(current)
        entries.append(entry)

    observe(path, PurePosixPath())
    digest = None if secret else sha256_bytes(canonical_json_bytes(entries))
    return TreeObservation(digest=digest, files=files, bytes=total_bytes)


def preparation_declaration(value: TestPreparationConfig) -> dict[str, object]:
    """Return the public, path-independent identity of one preparation."""
    return {
        "name": value.name,
        "imageId": value.image,
        "commandDigest": sha256_bytes(canonical_json_bytes(list(value.command))),
        "environmentDigest": sha256_bytes(
            canonical_json_bytes(dict(value.environment))
        ),
        "mounts": [_mount_declaration(item) for item in value.mounts],
        "timeoutSeconds": value.timeout_seconds,
        "expectedExitStatus": value.expected_exit_status,
    }


def launch_declaration(value: TestLaunchConfig) -> dict[str, object]:
    """Return the public, path-independent identity of launch inputs."""
    return {
        "argumentsDigest": sha256_bytes(canonical_json_bytes(list(value.arguments))),
        "environmentDigest": sha256_bytes(
            canonical_json_bytes(dict(value.environment))
        ),
        "mounts": [_mount_declaration(item) for item in value.mounts],
        "expectedExitStatus": value.expected_exit_status,
    }


def empty_test_input_observation(value: TestConfig) -> dict[str, object]:
    """Return the declaration identity before runtime paths are materialized."""
    return {
        "fixtures": [],
        "outputs": [],
        "preparations": [preparation_declaration(item) for item in value.preparations],
        "launch": launch_declaration(value.launch),
    }


def _mount_declaration(value: TestMountConfig) -> dict[str, object]:
    return {
        "source": value.source.value,
        "name": value.name,
        "target": value.target,
        "readOnly": value.read_only,
    }
