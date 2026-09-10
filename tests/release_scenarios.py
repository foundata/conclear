"""CLI-only lifecycle assertions reusable with a live or scripted command runner."""

from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from conclear.jsonutil import load_json, sha256_file


class ScenarioCli(Protocol):
    def run(self, *arguments: str, expect: int = 0) -> dict[str, Any]: ...


def repeat_release_and_rescan(
    cli: ScenarioCli,
    *,
    source_arguments: tuple[str, ...],
    config: Path,
    profile: str,
    observe_tags: Callable[[], dict[str, str | None]],
) -> str:
    """Keep one release/SBOM anchor across a same-digest release and two later rescans."""
    archive_directory = config.parent.parent / "archives"
    archive_directory.mkdir(exist_ok=True)
    archive_arguments = ("--archive-dir", str(archive_directory))
    first = cli.run(
        "release", *source_arguments, "--profile", profile, *archive_arguments
    )["data"]
    _promoted(first, observe_tags())
    subject = first["subject"]
    assert isinstance(subject, str)
    arguments = (
        "rescan",
        "--subject",
        subject,
        "--config",
        str(config),
        "--profile",
        profile,
        "--authoritative",
        *archive_arguments,
    )
    initial = cli.run(*arguments)["data"]
    anchor = _rescan_payload(initial)["releaseRecordDigest"]
    assert anchor == sha256_file(
        Path(first["workspace"]) / "records" / "release-verification.json"
    )
    second = cli.run(
        "release", *source_arguments, "--profile", profile, *archive_arguments
    )["data"]
    assert second["runId"] != first["runId"]
    assert second["subject"] == subject, "fixture must reproduce the same image digest"
    _promoted(second, observe_tags())
    previous = initial["recordDigest"]
    for _ in range(2):
        scan = cli.run(*arguments, "--previous-result", previous)["data"]
        payload = _rescan_payload(scan)
        assert payload["releaseRecordDigest"] == anchor
        assert payload["previousResultDigest"] == previous
        assert scan["recordDigest"] != previous
        previous = scan["recordDigest"]
    return subject


def resume_published_candidate(
    cli: ScenarioCli,
    *,
    source_arguments: tuple[str, ...],
    source: Path,
    profile: str,
    platforms: tuple[str, ...],
    directory: Path,
    expected_subject: str,
    observe_tags: Callable[[], dict[str, str | None]],
    observe_candidate: Callable[[str], str | None],
) -> None:
    """Stop at a durable publication boundary, then resume without extending authorization.

    This exercises process-to-process recovery, not a crash during a provider write.
    """
    transports: list[str] = []
    archive_directory = directory / "archives"
    archive_directory.mkdir(exist_ok=True)
    snapshot: tuple[str, ...] = ()
    for index, platform in enumerate(platforms):
        qualified = cli.run(
            "qualify",
            *source_arguments,
            "--profile",
            profile,
            "--platform",
            platform,
            *snapshot,
        )["data"]
        if not snapshot:
            snapshot = (
                "--database-digest",
                qualified["databaseDigest"],
                "--qualification-started-at",
                qualified["qualificationWindow"]["startedAt"],
            )
        path = directory / f"qualification-{index}.tar"
        exported = cli.run(
            "transport",
            "export",
            qualified["runId"],
            "--platform",
            platform,
            "--output",
            str(path),
        )["data"]
        assert sha256_file(path) == exported["transportDigest"]
        transports.extend(("--transport", str(path), exported["transportDigest"]))
    assembled = cli.run(
        "assemble",
        *source_arguments,
        "--profile",
        profile,
        *transports,
    )["data"]
    run_id = assembled["runId"]
    cli.run("provenance", run_id)
    before = observe_tags()
    published = cli.run("publish", run_id, "--profile", profile)["data"]
    assert observe_tags() == before, "publication must not move release tags"
    assert observe_candidate(published["reference"]) == published["digest"]
    resumed = cli.run(
        "release",
        "--source",
        str(source),
        "--resume",
        run_id,
        "--profile",
        profile,
        "--archive-dir",
        str(archive_directory),
    )["data"]
    assert resumed["runId"] == run_id
    assert resumed["subject"] == expected_subject
    _promoted(resumed, observe_tags())
    verification = load_json(
        Path(resumed["workspace"]) / "records" / "release-verification.json"
    )
    assert (
        verification["payload"]["candidateAuthorization"]["expiresAt"]
        == published["expiration"]
    )
    assert observe_candidate(published["reference"]) is None
    after = observe_tags()
    cli.run(
        "release",
        "--source",
        str(source),
        "--resume",
        run_id,
        "--profile",
        profile,
        "--archive-dir",
        str(archive_directory),
        expect=64,
    )
    assert observe_tags() == after, "terminal resume must not mutate tags"
    cli.run("cleanup", run_id, "--profile", profile)
    assert observe_tags() == after, "cleanup must not delete promoted tags"


def _promoted(data: dict[str, Any], observed: dict[str, str | None]) -> None:
    assert data["candidateDeleted"] is True
    expected = {item["tag"]: item["digest"] for item in data["tags"]}
    assert "latest" in expected
    assert observed == expected
    assert set(expected.values()) == {data["subject"].split("@", 1)[1]}


def _rescan_payload(data: dict[str, Any]) -> dict[str, Any]:
    assert data["authoritative"] is True and data["verifiedAt"]
    path = Path(data["record"])
    assert sha256_file(path) == data["recordDigest"]
    record = load_json(path)
    assert record["verdict"] == "accepted"
    return dict(record["payload"])
