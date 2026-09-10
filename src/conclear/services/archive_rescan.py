"""Restore archived rescan inputs without reviving completed run workspaces."""

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from conclear.archive import OpenArchive, open_archive
from conclear.archive_source import SOURCE_MANIFEST, restore_source
from conclear.errors import InvalidInvocationError
from conclear.jsonutil import load_json, sha256_file
from conclear.parsing import Narrower
from conclear.services.archives import ArchiveSigner, verify_archive_signatures
from conclear.values import OCIReference

_narrow = Narrower(InvalidInvocationError)
MAX_SOURCE_ARCHIVE_LOOKUP_FILES = 10_000


@dataclass(frozen=True, slots=True)
class ArchiveRescanInput:
    """Source, immutable subject and any retained authoritative history checkpoint."""

    configuration: Path
    subject: OCIReference
    image_id: str
    release_archive_digest: str
    release_archive_name: str
    history_checkpoint: str | None


@contextmanager
def archived_rescan_input(
    path: Path,
    *,
    signer: ArchiveSigner,
    public_key: Path,
) -> Iterator[ArchiveRescanInput]:
    """Verify a release/rescan archive and restore its exact source privately."""
    with open_archive(path) as archive:
        verify_archive_signatures(archive, signer=signer, public_key=public_key)
        checkpoint = None
        if archive.kind == "rescan":
            record = _narrow.object_value(
                load_json(archive.root / "records/rescan-result.json"), "rescan record"
            )
            payload = _narrow.object_value(record.get("payload"), "rescan payload")
            checkpoint = (
                sha256_file(archive.root / "records/rescan-result.json")
                if payload.get("authoritative") is True
                else payload.get("previousResultDigest")
            )
            if checkpoint is not None:
                checkpoint = _narrow.string_value(checkpoint, "history checkpoint")
        with _source_archive(
            archive, signer=signer, public_key=public_key
        ) as source_archive:
            with tempfile.TemporaryDirectory(
                prefix="conclear-archived-source-"
            ) as temporary:
                source = Path(temporary) / "source"
                restore_source(source_archive.root, source)
                yield ArchiveRescanInput(
                    configuration=source / "conclear.toml",
                    subject=archive.subject,
                    image_id=_narrow.string_value(
                        archive.manifest["imageId"], "archive image id"
                    ),
                    release_archive_digest=source_archive.result.digest,
                    release_archive_name=source_archive.result.path.name,
                    history_checkpoint=checkpoint,
                )


@contextmanager
def _source_archive(
    archive: OpenArchive, *, signer: ArchiveSigner, public_key: Path
) -> Iterator[OpenArchive]:
    if archive.manifest["source"]:
        yield archive
        return
    expected = archive.manifest["releaseArchiveDigest"]
    record = _narrow.object_value(
        load_json(archive.root / "records/rescan-result.json"), "rescan record"
    )
    payload = _narrow.object_value(record["payload"], "rescan payload")
    for path in _source_archive_candidates(archive):
        if path.is_symlink() or not path.is_file() or sha256_file(path) != expected:
            continue
        with open_archive(path) as source:
            if source.result.digest != expected:
                raise InvalidInvocationError(
                    "Referenced source archive changed during lookup"
                )
            verify_archive_signatures(source, signer=signer, public_key=public_key)
            if (
                not source.manifest["source"]
                or source.subject != archive.subject
                or source.manifest["imageId"] != archive.manifest["imageId"]
                or sha256_file(source.root / SOURCE_MANIFEST)
                != payload.get("sourceTreeDigest")
                or source.manifest["configurationDigest"]
                != archive.manifest["configurationDigest"]
            ):
                raise InvalidInvocationError(
                    "Referenced source archive does not match the rescan"
                )
            yield source
            return
    raise InvalidInvocationError(
        "Keep the referenced release archive beside this rescan archive"
    )


def _source_archive_candidates(archive: OpenArchive) -> Iterator[Path]:
    directory = archive.result.path.parent
    hint = archive.manifest.get("releaseArchiveName")
    hinted_path = (
        None
        if hint is None
        else directory / _narrow.string_value(hint, "source archive filename hint")
    )
    if hinted_path is not None:
        yield hinted_path
    for number, path in enumerate(sorted(directory.glob("*.tar.gz"))):
        if number >= MAX_SOURCE_ARCHIVE_LOOKUP_FILES:
            raise InvalidInvocationError("Archive directory exceeds the lookup limit")
        if path != hinted_path:
            yield path
