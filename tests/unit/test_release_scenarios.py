"""Check the reusable live-drill assertions without containers or network access."""

from pathlib import Path
from typing import Any

import pytest

from conclear.jsonutil import atomic_write_json, sha256_file
from tests.release_scenarios import (
    repeat_release_and_rescan,
    resume_published_candidate,
)

DIGEST = "sha256:" + "a" * 64
SUBJECT = "quay.io/example/app@" + DIGEST
CANDIDATE = "quay.io/example/app:owned-candidate"
EXPIRATION = "2026-09-11T00:00:00Z"


class ScriptedCli:
    def __init__(self, root: Path, fault: str | None = None) -> None:
        self.root = root
        self.fault = fault
        self.calls: list[tuple[str, ...]] = []
        self.releases = 0
        self.scans = 0
        self.tags: dict[str, str | None] = {"1.2.3": None, "latest": None}
        self.candidate: str | None = None
        self.anchor = ""

    def run(self, *arguments: str, expect: int = 0) -> dict[str, Any]:
        self.calls.append(arguments)
        command = arguments[0]
        data: dict[str, Any] = {}
        if command == "release":
            if expect == 64:
                assert "--resume" in arguments
                return {"status": "invalidInvocation"}
            self.releases += 1
            self.tags = {"1.2.3": DIGEST, "latest": DIGEST}
            workspace = self.root / f"release-{self.releases}"
            run_id = "coordinator" if "--resume" in arguments else str(self.releases)
            digest = atomic_write_json(
                workspace / "records" / "release-verification.json",
                {
                    "runId": run_id,
                    "payload": {
                        "candidateAuthorization": {
                            "expiresAt": "changed"
                            if self.fault == "expiration"
                            else EXPIRATION
                        }
                    },
                },
            )
            if self.releases == 1:
                self.anchor = digest
            data = {
                "runId": run_id,
                "workspace": str(workspace),
                "subject": SUBJECT,
                "candidateDeleted": self.fault != "candidate",
                "tags": [{"tag": tag, "digest": DIGEST} for tag in self.tags],
            }
            self.candidate = None
            if self.fault == "digest" and self.releases == 2:
                data["subject"] = "quay.io/example/app@sha256:" + "b" * 64
            if self.fault == "tag":
                self.tags["latest"] = "sha256:" + "b" * 64
        elif command == "rescan":
            assert "--authoritative" in arguments
            self.scans += 1
            previous = (
                arguments[arguments.index("--previous-result") + 1]
                if "--previous-result" in arguments
                else None
            )
            path = self.root / f"rescan-{self.scans}.json"
            digest = atomic_write_json(
                path,
                {
                    "sequence": self.scans,
                    "verdict": "accepted",
                    "payload": {
                        "releaseRecordDigest": "wrong"
                        if self.fault == "anchor"
                        else self.anchor,
                        "previousResultDigest": "wrong"
                        if self.fault == "previous"
                        else previous,
                    },
                },
            )
            data = {
                "record": str(path),
                "recordDigest": digest,
                "authoritative": True,
                "verifiedAt": "2026-09-10T00:00:00Z",
            }
        elif command == "qualify":
            data = {
                "runId": "worker",
                "databaseDigest": DIGEST,
                "qualificationWindow": {"startedAt": "2026-09-10T00:00:00Z"},
            }
        elif command == "transport":
            path = Path(arguments[arguments.index("--output") + 1])
            path.write_bytes(b"transport")
            data = {"transportDigest": sha256_file(path)}
        elif command == "assemble":
            data = {"runId": "coordinator"}
        elif command == "publish":
            self.candidate = DIGEST
            data = {"reference": CANDIDATE, "digest": DIGEST, "expiration": EXPIRATION}
        elif command == "cleanup":
            if self.fault == "cleanup":
                self.tags["latest"] = None
        else:
            assert command == "provenance"
        return {"status": "success", "data": data}


def _repeat(cli: ScriptedCli) -> str:
    return repeat_release_and_rescan(
        cli,
        source_arguments=("--source", str(cli.root), "--version", "1.2.3"),
        config=cli.root / "conclear.toml",
        profile="test",
        observe_tags=lambda: dict(cli.tags),
    )


def _resume(cli: ScriptedCli) -> None:
    resume_published_candidate(
        cli,
        source_arguments=("--source", str(cli.root), "--version", "1.2.3"),
        source=cli.root,
        profile="test",
        platforms=("linux/amd64", "linux/arm64"),
        directory=cli.root,
        expected_subject=SUBJECT,
        observe_tags=lambda: dict(cli.tags),
        observe_candidate=lambda _reference: cli.candidate,
    )


def test_repeat_scenario_releases_twice_and_checks_three_authoritative_rescans(
    tmp_path: Path,
) -> None:
    cli = ScriptedCli(tmp_path)
    assert _repeat(cli) == SUBJECT
    assert [call[0] for call in cli.calls] == [
        "release",
        "rescan",
        "release",
        "rescan",
        "rescan",
    ]


@pytest.mark.parametrize("fault", ["digest", "tag", "anchor", "previous", "candidate"])
def test_repeat_scenario_detects_regressions(tmp_path: Path, fault: str) -> None:
    with pytest.raises(AssertionError):
        _repeat(ScriptedCli(tmp_path, fault))


def test_recovery_scenario_reuses_snapshot_and_observes_authorization(
    tmp_path: Path,
) -> None:
    cli = ScriptedCli(tmp_path)
    _resume(cli)
    assert [call[0] for call in cli.calls] == [
        "qualify",
        "transport",
        "qualify",
        "transport",
        "assemble",
        "provenance",
        "publish",
        "release",
        "release",
        "cleanup",
    ]
    assert cli.calls[2][-4:] == (
        "--database-digest",
        DIGEST,
        "--qualification-started-at",
        "2026-09-10T00:00:00Z",
    )


@pytest.mark.parametrize("fault", ["expiration", "candidate", "cleanup"])
def test_recovery_scenario_detects_regressions(tmp_path: Path, fault: str) -> None:
    with pytest.raises(AssertionError):
        _resume(ScriptedCli(tmp_path, fault))
