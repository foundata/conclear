"""Archives preserve release evidence without retaining run environments."""

import io
import json
import os
import shutil
import tarfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner

import conclear.commands.archive as archive_commands
import conclear.commands.maintenance as maintenance_commands
import conclear.services.archive_rescan as archive_rescan_service
import conclear.services.release as release_service
from conclear.adapters.cosign import VerificationObservation
from conclear.adapters.skopeo import RegistryCopyObservation
from conclear.archive import OpenArchive, open_archive, prepare_archive_directory
from conclear.archive_source import collect_source, restore_source
from conclear.attestations import RESCAN_TYPE
from conclear.cli import root
from conclear.commands.common import resolve_archive_directory
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.jsonutil import canonical_json_bytes, load_json, sha256_bytes, sha256_file
from conclear.oci import validate_layout, validate_layout_metadata
from conclear.services.archive_rescan import archived_rescan_input
from conclear.services.archives import (
    ArchiveSigner,
    create_run_archive,
    verify_archive_signatures,
)
from conclear.services.qualification_inputs import QualificationInputs
from conclear.source_integrity import source_tree_digest
from conclear.tools import ToolName
from conclear.values import OCIReference
from conclear.workspace import RunState
from tests.release_fakes import FakeBuilder
from tests.unit.test_commands import release_profile
from tests.unit.test_qualification import _register_arm64_handler
from tests.unit.test_release_workflow import NOW, Harness


@pytest.fixture
def released(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_factory: Callable[..., Path],
) -> Harness:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    harness.complete()
    shutil.copytree(harness.source_root, harness.workspace.root / "source")
    return harness


def _create(harness: Harness, *, layers: bool = False) -> Path:
    directory = harness.tmp_path / "archives"
    directory.mkdir(exist_ok=True)
    return create_run_archive(
        harness.workspace,
        directory=directory,
        signer=harness.runtime.signer,
        public_key=harness.profile.cosign_public_key,
        include_image_layers=layers,
    ).path


def test_release_archive_retains_source_metadata_reports_and_signed_material(
    released: Harness,
) -> None:
    private = released.workspace.root / "environment"
    private.mkdir(exist_ok=True)
    (private / "cosign.key").write_bytes(b"private signing key")
    (private / "auth.json").write_bytes(b"registry credentials")
    (released.workspace.root / "logs/raw.log").write_bytes(b"private raw log")
    archive_path = _create(released)
    assert archive_path.name.startswith("release-")
    assert archive_path.suffixes[-2:] == [".tar", ".gz"]
    assert archive_path.stat().st_mode & 0o777 == 0o600
    with open_archive(archive_path) as archive:
        verify_archive_signatures(
            archive,
            signer=released.runtime.signer,
            public_key=released.profile.cosign_public_key,
        )
        assert archive.manifest["imageLayers"] is False
        assert archive.manifest["source"] is True
        assert "releaseArchiveName" not in archive.manifest
        assert (archive.root / "source/conclear.toml").is_file()
        assert (archive.root / "source/Containerfile").is_file()
        assert (archive.root / "image/index.json").is_file()
        assert (archive.root / "exports/sbom/linux-amd64.spdx.json").is_file()
        assert list((archive.root / "signatures").glob("*.sigstore.json"))
        content = b"".join(
            path.read_bytes() for path in archive.root.rglob("*") if path.is_file()
        )
        for secret in (
            b"private signing key",
            b"registry credentials",
            b"private raw log",
        ):
            assert secret not in content
    assert _create(released) == archive_path
    assert len(list(archive_path.parent.glob("*.tar.gz"))) == 1


def test_archive_restores_source_after_original_workspace_and_checkout_are_lost(
    released: Harness,
) -> None:
    expected = source_tree_digest(released.source_root)
    archive = _create(released)
    shutil.rmtree(released.source_root)
    shutil.rmtree(released.workspace.root)
    with archived_rescan_input(
        archive,
        signer=released.runtime.signer,
        public_key=released.profile.cosign_public_key,
    ) as restored:
        assert source_tree_digest(restored.configuration.parent) == expected
        assert restored.image_id == "app"
        assert restored.history_checkpoint is None
        path = restored.configuration
    assert not path.exists()


def test_archive_creation_rejects_changed_source_before_writing(
    released: Harness,
) -> None:
    source = released.workspace.root / "source/Containerfile"
    source.write_bytes(source.read_bytes() + b"\n# Changed after release\n")
    with pytest.raises(InvalidInvocationError, match="source content changed"):
        _create(released)
    assert not list((released.tmp_path / "archives").iterdir())


def test_archive_does_not_accept_unauthenticated_downloaded_payloads(
    released: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = released.runtime.signer.download_attestations

    def unrelated(**kwargs: Any) -> tuple[object, ...]:
        values = original(**kwargs)
        first = values[0]
        assert isinstance(first, dict)
        return ({**first, "payload": "e30="},)

    monkeypatch.setattr(released.runtime.signer, "download_attestations", unrelated)
    with pytest.raises(OperationalError, match="matches the verified"):
        _create(released)


def _rewrite_archive(path: Path, update: Callable[[dict[str, bytes]], None]) -> Path:
    contents: dict[str, bytes] = {}
    with tarfile.open(path) as source:
        for entry in source:
            stream = source.extractfile(entry)
            assert stream is not None
            contents[entry.name] = stream.read()
    update(contents)
    destination = path.with_name("tampered.tar.gz")
    with tarfile.open(destination, "w:gz") as archive:
        for name, content in contents.items():
            header = tarfile.TarInfo(name)
            header.size = len(content)
            archive.addfile(header, io.BytesIO(content))
    return destination


def _rewrite_archive_manifest(
    path: Path, update: Callable[[dict[str, Any]], None]
) -> Path:
    def update_members(members: dict[str, bytes]) -> None:
        manifest = json.loads(members["archive.json"])
        update(manifest)
        members["archive.json"] = canonical_json_bytes(manifest)

    return _rewrite_archive(path, update_members)


@pytest.mark.parametrize("change", ["bytes", "extra", "missing", "source"])
def test_archive_rejects_tampering(released: Harness, change: str) -> None:
    original = _create(released)

    def change_members(members: dict[str, bytes]) -> None:
        if change == "extra":
            members["environment/key"] = b"secret"
        elif change == "missing":
            del members["source/conclear.toml"]
        else:
            members["source/conclear.toml"] += b"\n# Changed\n"
            if change == "source":
                manifest = json.loads(members["archive.json"])
                for member in manifest["members"]:
                    if member["path"] == "source/conclear.toml":
                        member.update(
                            size=len(members[member["path"]]),
                            digest=sha256_bytes(members[member["path"]]),
                        )
                members["archive.json"] = json.dumps(manifest).encode()

    changed = _rewrite_archive(original, change_members)
    with pytest.raises(InvalidInvocationError):
        with open_archive(changed) as archive:
            verify_archive_signatures(
                archive,
                signer=released.runtime.signer,
                public_key=released.profile.cosign_public_key,
            )


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_archive_rejects_links_and_special_files(tmp_path: Path, kind: bytes) -> None:
    path = tmp_path / "bad.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        header = tarfile.TarInfo("escape")
        header.type = kind
        header.linkname = "/tmp/escape"
        archive.addfile(header)
    with pytest.raises(InvalidInvocationError):
        with open_archive(path):
            pytest.fail("Unsafe tar was accepted")


def test_source_snapshot_preserves_executable_modes_and_contained_links(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "bin").mkdir()
    (source / "bin/app").write_bytes(b"#!/bin/sh\nexit 0\n")
    (source / "bin/app").chmod(0o755)
    (source / "app").symlink_to("bin/app")
    staging = tmp_path / "staging"
    staging.mkdir()
    for name, value in collect_source(source).items():
        path = staging / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.read_bytes())
    destination = tmp_path / "restored"
    restore_source(staging, destination)
    assert source_tree_digest(source) == source_tree_digest(destination)


def test_archival_output_is_mandatory(tmp_path: Path) -> None:
    profile = release_profile(tmp_path)
    option = tmp_path / "option-archives"
    default = tmp_path / "profile-archives"

    with pytest.raises(InvalidInvocationError, match="--archive-dir is required"):
        resolve_archive_directory(None, profile)
    assert resolve_archive_directory(option, profile) == option
    with_default = replace(profile, archive_dir=default)
    assert resolve_archive_directory(None, with_default) == default
    assert resolve_archive_directory(option, with_default) == option


def test_archive_directory_must_be_outside_working_data(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    output = work / "archives"
    output.mkdir()
    with pytest.raises(InvalidInvocationError, match="outside"):
        prepare_archive_directory(output, excluded=(work,))


@pytest.mark.parametrize("include_layers", [False, True])
def test_layer_retention_is_optional_and_metadata_always_remains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_factory: Callable[..., Path],
    include_layers: bool,
) -> None:
    harness = Harness(tmp_path, monkeypatch, repository_factory)
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w") as layer:
        header = tarfile.TarInfo("fixture.txt")
        header.size = 7
        layer.addfile(header, io.BytesIO(b"fixture"))
    harness.runtime.builder = FakeBuilder(layer=content.getvalue())
    harness.complete()
    shutil.copytree(harness.source_root, harness.workspace.root / "source")
    with open_archive(_create(harness, layers=include_layers)) as archive:
        layout = archive.root / "image"
        graph = validate_layout_metadata(layout)
        assert len(graph.manifests[0].layers) == 1
        digest = graph.manifests[0].layers[0].digest
        blob = layout / "blobs/sha256" / digest.encoded
        assert blob.exists() is include_layers
        if include_layers:
            assert blob.read_bytes() == content.getvalue()
            assert validate_layout(layout).digest == graph.digest
        else:
            with pytest.raises(OperationalError):
                validate_layout(layout)


def test_multiplatform_release_archive_retains_all_qualifications(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_factory: Callable[..., Path],
) -> None:
    def repository() -> Path:
        path = repository_factory()
        config = path / "conclear.toml"
        config.write_text(
            config.read_text().replace(
                'platforms = ["linux/amd64"]',
                'platforms = ["linux/amd64", "linux/arm64"]',
            )
        )
        return path

    binfmt = _register_arm64_handler(tmp_path / "binfmt")
    monkeypatch.setattr(
        release_service,
        "QualificationInputs",
        lambda **kwargs: QualificationInputs(**{**kwargs, "binfmt_root": binfmt}),
    )
    harness = Harness(tmp_path, monkeypatch, repository)
    harness.complete()
    shutil.copytree(harness.source_root, harness.workspace.root / "source")
    with open_archive(_create(harness)) as archive:
        graph = validate_layout_metadata(archive.root / "image")
        # Buildah records arm64 with its implicit variant; the archive keeps
        # the published spelling.
        assert {str(platform) for platform in graph.platforms} == {
            "linux/amd64",
            "linux/arm64/v8",
        }
        for key in ("linux-amd64", "linux-arm64"):
            assert (
                archive.root / f"records/platform-qualification-{key}.json"
            ).is_file()
            assert (archive.root / f"exports/sbom/{key}.spdx.json").is_file()


def test_rehashed_source_cannot_replace_signed_source(released: Harness) -> None:
    original = _create(released)

    def update(members: dict[str, bytes]) -> None:
        members["source/Containerfile"] += b"\n# Unapproved source\n"
        inventory = json.loads(members["source-tree.json"])
        for entry in inventory:
            if entry["path"] == "Containerfile":
                entry["digest"] = sha256_bytes(members["source/Containerfile"])
        members["source-tree.json"] = canonical_json_bytes(inventory)
        manifest = json.loads(members["archive.json"])
        for item in manifest["members"]:
            item.update(
                digest=sha256_bytes(members[item["path"]]),
                size=len(members[item["path"]]),
            )
        members["archive.json"] = canonical_json_bytes(manifest)

    with open_archive(_rewrite_archive(original, update)) as archive:
        with pytest.raises(InvalidInvocationError, match="signed qualification"):
            verify_archive_signatures(
                archive,
                signer=released.runtime.signer,
                public_key=released.profile.cosign_public_key,
            )


def test_failed_archive_write_is_retryable_without_republishing(
    released: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    tags = dict(released.runtime.registry.tags)
    original = os.link

    def fail(*args: Any, **kwargs: Any) -> None:
        raise OSError("storage unavailable")

    monkeypatch.setattr(os, "link", fail)
    with pytest.raises(OperationalError):
        _create(released)
    assert released.workspace.load().state is RunState.PROMOTED
    assert not list((released.tmp_path / "archives").iterdir())
    monkeypatch.setattr(os, "link", original)
    assert _create(released).is_file()
    assert released.runtime.registry.tags == tags


def _rescan_cli(
    released: Harness, monkeypatch: pytest.MonkeyPatch
) -> Callable[[Path], dict[str, Any]]:
    state = released.tmp_path / "restored-state"
    cache = released.tmp_path / "restored-cache"
    released.profile = replace(
        released.profile, auth_file=released.tmp_path / "auth.json"
    )
    for module in (maintenance_commands, archive_commands):
        monkeypatch.setattr(module, "profile", lambda name: released.profile)
        monkeypatch.setattr(module, "state_home", lambda: state)
        monkeypatch.setattr(module, "cache_home", lambda: cache)
        monkeypatch.setattr(
            module, "command_runtime", lambda names: nullcontext(released.runtime)
        )
    monkeypatch.setattr(
        released.runtime,
        "tools",
        {
            ToolName.COSIGN: SimpleNamespace(
                name=ToolName.COSIGN,
                version="3.1.3",
                executable_digest="sha256:" + "a" * 64,
                binding_digest="sha256:" + "a" * 64,
            ),
        },
        raising=False,
    )
    monkeypatch.setattr(
        maintenance_commands,
        "ApplicationRuntime",
        SimpleNamespace(create=lambda *args, **kwargs: released.runtime),
    )
    monkeypatch.setattr(
        maintenance_commands, "signing_passphrase", lambda *args, **kwargs: None
    )
    registry_layout = released.tmp_path / "registry-layout"
    shutil.copytree(released.workspace.root / "layouts/app/candidate", registry_layout)

    def copy(
        *,
        source: OCIReference,
        layout_path: Path,
        layout_reference: str,
        auth_file: Path | None,
    ) -> RegistryCopyObservation:
        del auth_file
        shutil.copytree(registry_layout, layout_path, dirs_exist_ok=True)
        index = json.loads((layout_path / "index.json").read_bytes())
        index["manifests"][0]["annotations"]["org.opencontainers.image.ref.name"] = (
            layout_reference
        )
        (layout_path / "index.json").write_bytes(canonical_json_bytes(index))
        return RegistryCopyObservation(
            source,
            layout_path,
            validate_layout(layout_path, reference=layout_reference),
        )

    monkeypatch.setattr(released.runtime.registry, "copy_registry_to_layout", copy)
    monkeypatch.setattr(
        released.runtime.trivy_adapter,
        "scan_sbom",
        released.runtime.trivy_adapter.scan_layout,
        raising=False,
    )
    timestamp = NOW

    def invoke(bundle: Path) -> dict[str, Any]:
        nonlocal timestamp
        timestamp += timedelta(seconds=1)
        monkeypatch.setattr(maintenance_commands, "utc_now", lambda: timestamp)
        result = CliRunner().invoke(
            root,
            [
                "rescan",
                "--archive",
                str(bundle),
                "--archive-dir",
                str(bundle.parent),
                "--profile",
                "production",
                "--authoritative",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0, f"{result.output}\n{result.exception}"
        value = json.loads(result.output)
        return dict(value["data"])

    return invoke


def test_archived_rescans_continue_after_source_and_local_state_loss(
    released: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _create(released)
    invoke = _rescan_cli(released, monkeypatch)
    shutil.rmtree(released.source_root)
    shutil.rmtree(released.workspace.root)
    first = invoke(bundle)
    first_archive = Path(first["archive"]["path"])
    with open_archive(first_archive) as archive:
        assert archive.manifest["source"] is False
        assert archive.manifest["releaseArchiveName"] == bundle.name
        assert not (archive.root / "source").exists()
        first_record = load_json(archive.root / "records/rescan-result.json")
        assert "releaseArchiveName" not in first_record["payload"]
    shutil.rmtree(released.tmp_path / "restored-state")
    second = invoke(first_archive)
    with open_archive(Path(second["archive"]["path"])) as archive:
        assert archive.manifest["releaseArchiveName"] == bundle.name
        record = load_json(archive.root / "records/rescan-result.json")
        assert isinstance(record, dict) and isinstance(first_record, dict)
        assert record["payload"]["previousResultDigest"] == first["recordDigest"]
        assert (
            record["payload"]["releaseRecordDigest"]
            == first_record["payload"]["releaseRecordDigest"]
        )
    with archived_rescan_input(
        first_archive,
        signer=released.runtime.signer,
        public_key=released.profile.cosign_public_key,
    ) as restored:
        assert restored.history_checkpoint == first["recordDigest"]
    for key in list(released.runtime.signer.statements):
        if key[1] == RESCAN_TYPE:
            del released.runtime.signer.statements[key]
    # Verify archived signatures independently of simulated registry disappearance.
    monkeypatch.setattr(
        released.runtime.signer,
        "verify_attestation_bundle",
        lambda **kwargs: VerificationObservation(
            kwargs["subject"], (load_json(kwargs["bundle"]),)
        ),
    )
    result = CliRunner().invoke(
        root,
        [
            "rescan",
            "--archive",
            str(first_archive),
            "--archive-dir",
            str(first_archive.parent),
            "--profile",
            "production",
            "--authoritative",
        ],
    )
    assert result.exit_code != 0
    assert "missing the archived checkpoint" in str(result.exception)


@pytest.fixture
def rescan_archives(
    released: Harness, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    source = _create(released)
    result = _rescan_cli(released, monkeypatch)(source)
    return source, Path(result["archive"]["path"])


def test_source_archive_hint_avoids_directory_search(
    released: Harness,
    rescan_archives: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, rescan = rescan_archives
    (source.parent / "000-unrelated.tar.gz").write_bytes(b"unrelated archive")
    monkeypatch.setattr(archive_rescan_service, "MAX_SOURCE_ARCHIVE_LOOKUP_FILES", 0)
    observed: list[Path] = []
    original_glob = Path.glob

    def glob(path: Path, *arguments: Any, **options: Any) -> Iterator[Path]:
        assert path != source.parent, "A valid hint must not list the archive directory"
        return original_glob(path, *arguments, **options)

    def digest(path: Path) -> str:
        if path.parent == source.parent:
            observed.append(path)
        return sha256_file(path)

    monkeypatch.setattr(Path, "glob", glob)
    monkeypatch.setattr(archive_rescan_service, "sha256_file", digest)
    with archived_rescan_input(
        rescan,
        signer=released.runtime.signer,
        public_key=released.profile.cosign_public_key,
    ) as restored:
        assert restored.release_archive_name == source.name
        assert restored.release_archive_digest == sha256_file(source)
    assert observed == [source]


def test_source_archive_fallback_keeps_its_lookup_limit(
    released: Harness,
    rescan_archives: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, rescan = rescan_archives
    (source.parent / "000-unrelated.tar.gz").write_bytes(b"unrelated archive")
    changed = _rewrite_archive_manifest(
        rescan, lambda manifest: manifest.pop("releaseArchiveName")
    )
    monkeypatch.setattr(archive_rescan_service, "MAX_SOURCE_ARCHIVE_LOOKUP_FILES", 1)
    with pytest.raises(InvalidInvocationError, match="lookup limit"):
        with archived_rescan_input(
            changed,
            signer=released.runtime.signer,
            public_key=released.profile.cosign_public_key,
        ):
            pytest.fail("The source archive search exceeded its bound")


@pytest.mark.parametrize(
    "hint_state", ["missing", "wrong-digest", "symlink", "directory", "absent"]
)
def test_source_archive_hint_falls_back_and_retains_the_found_name(
    released: Harness,
    rescan_archives: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    hint_state: str,
) -> None:
    source, rescan = rescan_archives
    renamed = source.rename(source.with_name("renamed-source.tar.gz"))
    if hint_state == "wrong-digest":
        source.write_bytes(b"unrelated archive")
    elif hint_state == "symlink":
        source.symlink_to(renamed)
    elif hint_state == "directory":
        source.mkdir()
    elif hint_state == "absent":
        rescan = _rewrite_archive_manifest(
            rescan, lambda manifest: manifest.pop("releaseArchiveName")
        )
    observed: list[Path] = []

    def digest(path: Path) -> str:
        if path.parent == source.parent:
            observed.append(path)
        return sha256_file(path)

    monkeypatch.setattr(archive_rescan_service, "sha256_file", digest)
    with archived_rescan_input(
        rescan,
        signer=released.runtime.signer,
        public_key=released.profile.cosign_public_key,
    ) as restored:
        assert restored.release_archive_name == renamed.name
        assert restored.release_archive_digest == sha256_file(renamed)
    assert observed.count(source) == (1 if hint_state == "wrong-digest" else 0)


def test_rescan_updates_stale_source_archive_hint(
    released: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _create(released)
    invoke = _rescan_cli(released, monkeypatch)
    first = invoke(source)
    renamed = source.rename(source.with_name("renamed-source.tar.gz"))
    second = invoke(Path(first["archive"]["path"]))
    with open_archive(Path(second["archive"]["path"])) as archive:
        assert archive.manifest["releaseArchiveName"] == renamed.name
        assert archive.manifest["releaseArchiveDigest"] == sha256_file(renamed)


@pytest.mark.parametrize(
    "hint",
    [
        "../outside.tar.gz",
        "/outside.tar.gz",
        "nested/source.tar.gz",
        "nested\\source.tar.gz",
        ".",
        "..",
        "",
        "bad\x00name",
        None,
        42,
    ],
)
def test_archive_rejects_unsafe_or_malformed_source_archive_hints(
    rescan_archives: tuple[Path, Path], hint: object
) -> None:
    _source, rescan = rescan_archives
    changed = _rewrite_archive_manifest(
        rescan, lambda manifest: manifest.update(releaseArchiveName=hint)
    )
    with pytest.raises(InvalidInvocationError):
        with open_archive(changed):
            pytest.fail("Unsafe source archive filename hint was accepted")


def test_source_inclusive_archive_cannot_declare_a_reference_hint(
    released: Harness,
) -> None:
    source = _create(released)
    changed = _rewrite_archive_manifest(
        source, lambda manifest: manifest.update(releaseArchiveName="other.tar.gz")
    )
    with pytest.raises(InvalidInvocationError, match="referenced archive"):
        with open_archive(changed):
            pytest.fail("Source-inclusive archive accepted a reference hint")


def test_source_archive_hint_does_not_replace_the_expected_digest(
    released: Harness, rescan_archives: tuple[Path, Path]
) -> None:
    source, rescan = rescan_archives
    repacked = _rewrite_archive(source, lambda members: None).rename(
        source.with_name("repacked.tar.gz")
    )
    assert sha256_file(repacked) != sha256_file(source)
    with open_archive(repacked) as archive:
        verify_archive_signatures(
            archive,
            signer=released.runtime.signer,
            public_key=released.profile.cosign_public_key,
        )
    source.rename(released.tmp_path / "retained-original.tar.gz")
    changed = _rewrite_archive_manifest(
        rescan, lambda manifest: manifest.update(releaseArchiveName=repacked.name)
    )
    with pytest.raises(InvalidInvocationError, match="Keep the referenced"):
        with archived_rescan_input(
            changed,
            signer=released.runtime.signer,
            public_key=released.profile.cosign_public_key,
        ):
            pytest.fail("A hint substituted different bytes for the signed digest")


def test_source_archive_hint_still_requires_signature_verification(
    released: Harness,
    rescan_archives: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, rescan = rescan_archives
    verified: list[Path] = []

    def verify(
        archive: OpenArchive, *, signer: ArchiveSigner, public_key: Path
    ) -> None:
        verified.append(archive.result.path)
        if archive.result.path == source:
            raise OperationalError("Source signature verification failed")
        verify_archive_signatures(archive, signer=signer, public_key=public_key)

    monkeypatch.setattr(archive_rescan_service, "verify_archive_signatures", verify)
    with pytest.raises(OperationalError, match="Source signature verification failed"):
        with archived_rescan_input(
            rescan,
            signer=released.runtime.signer,
            public_key=released.profile.cosign_public_key,
        ):
            pytest.fail("The source archive's signatures were not required")
    assert verified == [rescan, source]


def test_source_archive_changed_between_lookup_and_open_is_rejected(
    released: Harness,
    rescan_archives: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, rescan = rescan_archives
    repacked = _rewrite_archive(source, lambda members: None)
    assert sha256_file(repacked) != sha256_file(source)

    @contextmanager
    def changed_archive(path: Path) -> Iterator[OpenArchive]:
        if path == source:
            source.write_bytes(repacked.read_bytes())
        with open_archive(path) as archive:
            yield archive

    monkeypatch.setattr(archive_rescan_service, "open_archive", changed_archive)
    with pytest.raises(InvalidInvocationError, match="changed during lookup"):
        with archived_rescan_input(
            rescan,
            signer=released.runtime.signer,
            public_key=released.profile.cosign_public_key,
        ):
            pytest.fail("The opened archive differs from the matched digest")


def test_archive_commands_create_and_verify_completed_evidence(
    released: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = released.tmp_path / "archives"
    directory.mkdir()
    monkeypatch.setattr(archive_commands, "profile", lambda name: released.profile)
    monkeypatch.setattr(
        archive_commands, "state_home", lambda: released.tmp_path / "state"
    )
    monkeypatch.setattr(
        archive_commands, "cache_home", lambda: released.tmp_path / "cache"
    )
    monkeypatch.setattr(
        archive_commands, "command_runtime", lambda names: nullcontext(released.runtime)
    )
    created = CliRunner().invoke(
        root,
        [
            "archive",
            "create",
            released.workspace.run_id,
            "--profile",
            "production",
            "--archive-dir",
            str(directory),
            "--format",
            "json",
        ],
    )
    assert created.exit_code == 0, created.exception
    archive = json.loads(created.output)["data"]["archive"]
    verified = CliRunner().invoke(
        root,
        [
            "archive",
            "verify",
            archive["path"],
            "--profile",
            "production",
            "--format",
            "json",
        ],
    )
    assert verified.exit_code == 0, verified.exception
    assert json.loads(verified.output)["data"]["signedEvidenceVerified"] is True


@pytest.mark.parametrize("authoritative", [False, True])
def test_direct_rescan_archives_diagnostics_and_rejected_signed_results(
    released: Harness,
    monkeypatch: pytest.MonkeyPatch,
    authoritative: bool,
) -> None:
    bundle = _create(released)
    _rescan_cli(released, monkeypatch)
    monkeypatch.setattr(
        maintenance_commands, "utc_now", lambda: NOW + timedelta(seconds=1)
    )

    def rejected_scan(**kwargs: Any) -> object:
        return released.runtime.trivy_adapter._write(
            kwargs["report_path"],
            {
                "Results": [
                    {
                        "Target": "fixture",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-12345",
                                "PkgName": "fixture",
                                "InstalledVersion": "1",
                                "FixedVersion": "2",
                                "Severity": "CRITICAL",
                            }
                        ],
                    }
                ],
            },
        )

    monkeypatch.setattr(released.runtime.trivy_adapter, "scan_layout", rejected_scan)
    monkeypatch.setattr(
        released.runtime.trivy_adapter, "scan_sbom", rejected_scan, raising=False
    )
    with open_archive(bundle) as archive:
        subject = str(archive.subject)
    result = CliRunner().invoke(
        root,
        [
            "rescan",
            "--subject",
            subject,
            "--config",
            str(released.source_root / "conclear.toml"),
            "--profile",
            "production",
            "--archive-dir",
            str(bundle.parent),
            "--format",
            "json",
            *(["--authoritative"] if authoritative else []),
        ],
    )
    assert result.exit_code == 2, f"{result.output}\n{result.exception}"
    data = json.loads(result.output)["data"]
    assert data["authoritative"] is authoritative
    assert (data["verifiedAt"] is not None) is authoritative
    with open_archive(Path(data["archive"]["path"])) as archive:
        assert archive.manifest["source"] is True
        record = load_json(archive.root / "records/rescan-result.json")
        assert isinstance(record, dict) and record["verdict"] == "rejected"
        verify_archive_signatures(
            archive,
            signer=released.runtime.signer,
            public_key=released.profile.cosign_public_key,
        )
