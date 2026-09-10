"""Retain explicitly non-secret test outputs as a qualification payload."""

import os
import stat
import tarfile
import tempfile
from pathlib import Path

from conclear.archive import member_path
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.parsing import Narrower
from conclear.path_safety import extract_tar_safely
from conclear.test_inputs import observe_test_tree

_narrow = Narrower(InvalidInvocationError)
OUTPUT_ARCHIVE = "test-outputs.tar"


def retain_test_outputs(
    report_root: Path, observation: dict[str, object]
) -> Path | None:
    """Pack public output bytes and verify them against their runtime observations."""
    outputs = tuple(
        _narrow.object_value(raw, "test output")
        for raw in _narrow.array_value(observation.get("outputs", []), "test outputs")
        if _narrow.object_value(raw, "test output").get("secret") is False
    )
    if not outputs:
        return None
    roots: dict[str, Path] = {}
    for item in outputs:
        name = _narrow.string_value(item.get("name"), "output name")
        if len(member_path(name).parts) != 1 or name in roots:
            raise InvalidInvocationError("Invalid or repeated public test output name")
        path = report_root / "test-inputs/outputs" / name
        if observe_test_tree(path, secret=False).digest != item.get("digest"):
            raise InvalidInvocationError("Public test output changed after its test")
        roots[name] = path
    try:
        with tempfile.TemporaryDirectory(
            prefix=".output-archive-", dir=report_root
        ) as temporary:
            staging = Path(temporary)
            path = staging / OUTPUT_ARCHIVE
            with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
                for name, root in sorted(roots.items()):
                    header = tarfile.TarInfo(name)
                    header.type = tarfile.DIRTYPE
                    header.mode = 0o700
                    archive.addfile(header)
                    for source in sorted(root.rglob("*")):
                        info = source.lstat()
                        header = tarfile.TarInfo(
                            f"{name}/{source.relative_to(root).as_posix()}"
                        )
                        header.mode = stat.S_IMODE(info.st_mode)
                        if stat.S_ISDIR(info.st_mode):
                            header.type = tarfile.DIRTYPE
                            archive.addfile(header)
                        elif stat.S_ISREG(info.st_mode):
                            descriptor = os.open(
                                source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                            )
                            with os.fdopen(descriptor, "rb") as stream:
                                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                                    raise InvalidInvocationError(
                                        "Test output changed while archiving"
                                    )
                                header.size = info.st_size
                                archive.addfile(header, stream)
                        else:
                            raise InvalidInvocationError(
                                "Test output is not a regular file"
                            )
            path.chmod(0o600)
            extracted = staging / "checked"
            extract_tar_safely(path, extracted)
            for item in outputs:
                if (
                    observe_test_tree(
                        extracted / str(item["name"]), secret=False
                    ).digest
                    != item["digest"]
                ):
                    raise InvalidInvocationError(
                        "Archived test output differs from the observed bytes"
                    )
            destination = report_root / OUTPUT_ARCHIVE
            path.replace(destination)
            return destination
    except (OSError, tarfile.TarError) as exc:
        raise OperationalError("Unable to retain non-secret test outputs") from exc
