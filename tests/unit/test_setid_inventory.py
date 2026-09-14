import gzip
import io
import json
import stat
import tarfile
from pathlib import Path

import pytest

from conclear.errors import OperationalError
from conclear.jsonutil import sha256_bytes
from conclear.oci import Descriptor
from conclear.setid_inventory import (
    OCI_LAYER_GZIP,
    OCI_LAYER_TAR,
    OCI_LAYER_ZSTD,
    inventory_setid,
    setid_findings,
)
from conclear.values import Digest

SETUID_ROOT = 0o4755
SETGID = 0o2755


def _member(
    name: str,
    *,
    kind: str = "file",
    mode: int = 0o755,
    uid: int = 0,
    gid: int = 0,
    target: str = "",
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.uid = uid
    info.gid = gid
    if kind == "dir":
        info.type = tarfile.DIRTYPE
    elif kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = target
    elif kind == "hardlink":
        info.type = tarfile.LNKTYPE
        info.linkname = target
    else:
        info.type = tarfile.REGTYPE
        info.size = 4
    return info


def _layer(
    layout: Path, members: list[tarfile.TarInfo], *, compressed: bool = True
) -> Descriptor:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for member in members:
            archive.addfile(
                member, io.BytesIO(b"exec") if member.type == tarfile.REGTYPE else None
            )
    content = gzip.compress(buffer.getvalue()) if compressed else buffer.getvalue()
    digest = sha256_bytes(content)
    blob = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(content)
    return Descriptor(
        OCI_LAYER_GZIP if compressed else OCI_LAYER_TAR, Digest(digest), len(content)
    )


def test_inherited_setid_executables_are_inventoried_and_undeclared_ones_reported(
    tmp_path: Path,
) -> None:
    base = _layer(
        tmp_path,
        [
            _member("usr", kind="dir"),
            _member("usr/bin", kind="dir"),
            _member("./usr/bin/su", mode=SETUID_ROOT),
            _member("usr/bin/passwd", mode=SETUID_ROOT),
            _member("usr/bin/wall", mode=SETGID, gid=5),
            _member("usr/bin/plain", mode=0o755),
            _member("var/local", kind="dir", mode=SETGID),
            _member("bin", kind="symlink", target="usr/bin"),
        ],
        compressed=False,
    )

    inventory = inventory_setid(tmp_path, [base])

    assert [item.path for item in inventory.executables] == [
        "/usr/bin/passwd",
        "/usr/bin/su",
        "/usr/bin/wall",
    ]
    assert inventory.setgid_directories == ("/var/local",)
    assert inventory.executables[1].to_dict() == {
        "path": "/usr/bin/su",
        "mode": "04755",
        "uid": 0,
        "gid": 0,
        "aliases": [],
    }
    json.dumps(inventory.to_dict())

    findings = setid_findings(inventory, ["/bin/su"])

    assert [finding.location for finding in findings] == [
        "/usr/bin/passwd",
        "/usr/bin/wall",
    ]
    assert all(finding.check_id == "CC0406" for finding in findings)
    assert all(finding.severity == "error" for finding in findings)
    assert "Undeclared set-ID executable /usr/bin/passwd" in findings[0].message


def test_whiteouts_mode_changes_and_replacements_follow_the_layer_order(
    tmp_path: Path,
) -> None:
    base = _layer(
        tmp_path,
        [
            _member("usr/bin", kind="dir"),
            _member("usr/bin/su", mode=SETUID_ROOT),
            _member("usr/bin/mount", mode=SETUID_ROOT),
            _member("usr/bin/chsh", mode=SETUID_ROOT),
            _member("opt/helpers", kind="dir"),
            _member("opt/helpers/old", mode=SETUID_ROOT),
            _member("opt/helpers/kept-lower", mode=SETUID_ROOT),
            _member("srv/dir", kind="dir"),
            _member("srv/dir/child", mode=SETUID_ROOT),
        ],
    )
    upper = _layer(
        tmp_path,
        [
            _member("usr/bin/.wh.su"),
            _member("usr/bin/mount", mode=0o755),
            _member("opt/helpers/.wh..wh..opq"),
            _member("opt/helpers/new", mode=SETUID_ROOT),
            _member("srv/dir", mode=0o644),
        ],
    )
    restoring = _layer(tmp_path, [_member("usr/bin/mount", mode=SETUID_ROOT)])

    two = inventory_setid(tmp_path, [base, upper])
    three = inventory_setid(tmp_path, [base, upper, restoring])

    assert [item.path for item in two.executables] == [
        "/opt/helpers/new",
        "/usr/bin/chsh",
    ]
    assert [item.path for item in three.executables] == [
        "/opt/helpers/new",
        "/usr/bin/chsh",
        "/usr/bin/mount",
    ]


def test_hard_link_aliases_share_one_entry_and_one_declaration(tmp_path: Path) -> None:
    layer = _layer(
        tmp_path,
        [
            _member("usr/bin", kind="dir"),
            _member("usr/bin/sudo", mode=SETUID_ROOT),
            _member("usr/bin/sudoedit", kind="hardlink", target="usr/bin/sudo"),
            _member("usr/bin/sudo-link", kind="symlink", target="sudo"),
        ],
    )

    inventory = inventory_setid(tmp_path, [layer])

    [executable] = inventory.executables
    assert executable.path == "/usr/bin/sudo"
    assert executable.aliases == ("/usr/bin/sudoedit",)
    assert setid_findings(inventory, ["/usr/bin/sudoedit"]) == ()
    assert setid_findings(inventory, ["/usr/bin/sudo-link"]) == ()
    assert setid_findings(inventory, ["/usr/bin/sudo"]) == ()


def test_stale_declarations_are_reported(tmp_path: Path) -> None:
    layer = _layer(
        tmp_path,
        [_member("usr/bin", kind="dir"), _member("usr/bin/tool", mode=0o755)],
    )

    inventory = inventory_setid(tmp_path, [layer])
    findings = setid_findings(inventory, ["/usr/bin/tool", "/usr/bin/absent"])

    assert [finding.location for finding in findings] == [
        "/usr/bin/tool",
        "/usr/bin/absent",
    ]
    assert "stale declaration" in findings[0].message


def test_malformed_layers_are_operational_errors(tmp_path: Path) -> None:
    escaping = _layer(tmp_path, [_member("../etc/passwd", mode=SETUID_ROOT)])
    with pytest.raises(OperationalError, match="escapes the filesystem root"):
        inventory_setid(tmp_path, [escaping])

    dangling = _layer(
        tmp_path, [_member("usr/bin/alias", kind="hardlink", target="usr/bin/none")]
    )
    with pytest.raises(OperationalError, match="hard-links"):
        inventory_setid(tmp_path, [dangling])

    zstd = Descriptor(OCI_LAYER_ZSTD, Digest("sha256:" + "a" * 64), 1)
    with pytest.raises(OperationalError, match="unsupported media type"):
        inventory_setid(tmp_path, [zstd])

    corrupt = Descriptor(OCI_LAYER_GZIP, Digest("sha256:" + "b" * 64), 1)
    (tmp_path / "blobs" / "sha256" / ("b" * 64)).write_bytes(b"not gzip")
    with pytest.raises(OperationalError, match="Unable to read layer"):
        inventory_setid(tmp_path, [corrupt])


def test_setgid_directories_and_symbolic_links_are_never_executables(
    tmp_path: Path,
) -> None:
    layer = _layer(
        tmp_path,
        [
            _member("srv", kind="dir", mode=SETGID),
            _member("srv/link-to-nothing", kind="symlink", target="/usr/bin/su"),
            _member("srv/setgid-non-executable", mode=0o2644),
        ],
    )

    inventory = inventory_setid(tmp_path, [layer])

    assert inventory.executables == ()
    assert inventory.setgid_directories == ("/srv",)
    assert stat.S_ISGID & 0o2755
