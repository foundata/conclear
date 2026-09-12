import json
from pathlib import Path

from conclear.build_identity import write_embedded_identity
from conclear.identity import (
    GUIDE_REVISION,
    IDENTITY,
    SOURCE_REVISION,
    human_version,
    is_release_build,
)


def test_identity_exposes_selected_guide_revision() -> None:
    assert GUIDE_REVISION == "9902755d7775d8679e09c35f7b639e9f573b0530"
    assert IDENTITY.to_public_dict() == {
        "name": "conclear",
        "version": "1.0.0",
        "sourceRevision": SOURCE_REVISION,
        "guide": {
            "title": "OCI container image build and release guide",
            "repository": "https://github.com/foundata/guidelines",
            "path": "oci-container-image-guide.md",
            "revision": "9902755d7775d8679e09c35f7b639e9f573b0530",
        },
    }


def test_identity_object_is_json_serializable() -> None:
    assert (
        json.loads(json.dumps(IDENTITY.to_public_dict()))["guide"]["revision"]
        == GUIDE_REVISION
    )


def test_human_identity_matches_normative_shape() -> None:
    assert human_version().splitlines() == [
        f"ConClear 1.0.0 (commit {SOURCE_REVISION})",
        'Implements the automatable rules of foundata "OCI container image build and release guide", oci-container-image-guide.md at commit 9902755d7775d8679e09c35f7b639e9f573b0530',
    ]


def test_staged_build_identity_uses_external_full_revision(tmp_path: Path) -> None:
    revision = "a" * 40
    target = write_embedded_identity(tmp_path, revision)
    assert target.read_text(encoding="utf-8").endswith(
        f'SOURCE_REVISION = "{revision}"\n'
    )
    assert is_release_build() is (
        len(SOURCE_REVISION) in {40, 64}
        and all(character in "0123456789abcdef" for character in SOURCE_REVISION)
    )
