from pathlib import Path
from typing import Any, cast

import pytest

from conclear.config import VersionSourceConfig, load_repository_config
from conclear.errors import InvalidInvocationError, OperationalError
from conclear.pins import PinStore
from conclear.services.preflight import preflight_image_closure, revision_tags
from conclear.values import Digest, OCIReference
from conclear.version_sources import (
    observe_version_sources,
    version_source_findings,
)

CHANGELOG = """# Changelog

## [Unreleased]

- Nothing worth mentioning right now.

## [1.2.3] - 2026-09-14

### Added

- Everything.

## [1.2.2] - 2026-08-01
"""


def _observe(
    tmp_path: Path,
    *sources: VersionSourceConfig,
    version: str = "1.2.3",
    tags: tuple[str, ...] = (),
) -> Any:
    return observe_version_sources(
        sources, source_root=tmp_path, version=version, revision_tags=tags
    )


def test_changelog_source_uses_the_first_versioned_heading(tmp_path: Path) -> None:
    path = tmp_path / "CHANGELOG.md"
    path.write_text(CHANGELOG, encoding="utf-8")
    source = VersionSourceConfig("changelog", path, None)

    [good] = _observe(tmp_path, source)
    [bad] = _observe(tmp_path, source, version="1.3.0")

    assert good.to_dict() == {
        "kind": "changelog",
        "path": "CHANGELOG.md",
        "pattern": None,
        "observed": ["1.2.3"],
        "matched": True,
    }
    assert version_source_findings([good], "1.2.3") == ()
    [finding] = version_source_findings([bad], "1.3.0")
    assert finding.check_id == "CC0005" and finding.severity == "error"
    assert "states version 1.2.3 rather than 1.3.0" in finding.message
    assert finding.location == "CHANGELOG.md"

    path.write_text("# Changelog\n\n## [Unreleased]\n", encoding="utf-8")
    [empty] = _observe(tmp_path, source)
    assert empty.observed == () and not empty.matched
    assert "states no version" in version_source_findings([empty], "1.2.3")[0].message


def test_git_tag_source_requires_the_exact_tag_at_the_revision(tmp_path: Path) -> None:
    source = VersionSourceConfig("git-tag", None, "v{version}")

    [good] = _observe(tmp_path, source, tags=("v1.2.3", "latest-drill"))
    [bad] = _observe(tmp_path, source, tags=("v1.2.2", "v1.2.3-rc1"))
    [none] = _observe(tmp_path, source)

    assert good.matched and good.observed == ("1.2.3",)
    assert not bad.matched and bad.observed == ("1.2.2", "1.2.3-rc1")
    [finding] = version_source_findings([bad], "1.2.3")
    assert "No tag matching v{version} names version 1.2.3" in finding.message
    assert "stated by tags at the revision: 1.2.2, 1.2.3-rc1" in finding.message
    assert (
        "tags at the revision"
        not in version_source_findings([none], "1.2.3")[0].message
    )


def test_file_source_matches_exactly_and_reports_what_it_found(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text(
        '[project]\nname = "x"\nversion = "1.2.3"\n\n[tool]\nversion = "9"\n',
        encoding="utf-8",
    )
    source = VersionSourceConfig("file", path, '^version = "{version}"$')

    [good] = _observe(tmp_path, source)
    [bad] = _observe(tmp_path, source, version="1.2")

    assert good.matched and good.observed == ("1.2.3", "9")
    assert not bad.matched
    [finding] = version_source_findings([bad], "1.2")
    assert "states version 1.2.3, 9 rather than 1.2" in finding.message

    path.write_bytes(b"\xff\xfe")
    with pytest.raises(OperationalError, match="Unable to read version source"):
        _observe(tmp_path, source)


def _repository(root: Path, *, sources: str, changelog: str = CHANGELOG) -> Path:
    root.mkdir(exist_ok=True)
    (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    (root / "pyproject.toml").write_text('version = "1.2.3"\n', encoding="utf-8")
    (root / "Containerfile").write_text(
        "FROM quay.io/example/base:1@sha256:" + "a" * 64 + " AS runtime\n"
        "ARG IMAGE_CREATED\nARG IMAGE_REVISION\nARG IMAGE_VERSION\n"
        'LABEL org.opencontainers.image.source="https://foundata.com/en/projects/example/#source" \\\n'
        '      org.opencontainers.image.title="Example" \\\n'
        '      org.opencontainers.image.created="${IMAGE_CREATED}" \\\n'
        '      org.opencontainers.image.revision="${IMAGE_REVISION}" \\\n'
        '      org.opencontainers.image.version="${IMAGE_VERSION}"\n'
        'USER 10001:10001\nENTRYPOINT ["/app"]\n',
        encoding="utf-8",
    )
    (root / ".containerignore").write_text(
        "**/.git/\n**/.env*\n**/*.key\n**/*.pem\n**/.venv/\n**/venv/\n",
        encoding="utf-8",
    )
    (root / "conclear.toml").write_text(
        f"""schema_version = 1

[project]
name = "example"
source = "https://foundata.com/en/projects/example/#source"
{sources}
[[images]]
id = "app"
repository = "quay.io/example/app"
platforms = ["linux/amd64"]

[images.release]
version_tags = ["{{version}}"]
moving_tags = ["stable"]

[images.runtime]
profile = "service"
user = 10001
memory = "512MiB"
cpus = 1.0
pids = 128
nofile = 1024
health_command = ["/app", "health"]

[[images.pins]]
reference = "quay.io/example/base:1"
tag_intent = "immutable-version"
""",
        encoding="utf-8",
    )
    return root / "conclear.toml"


THREE_SOURCES = """
[[project.version_sources]]
kind = "changelog"
path = "CHANGELOG.md"

[[project.version_sources]]
kind = "git-tag"
pattern = "v{version}"

[[project.version_sources]]
kind = "file"
path = "pyproject.toml"
pattern = '^version = "{version}"$'
"""


def test_configuration_declares_version_sources_and_rejects_malformed_ones(
    tmp_path: Path,
) -> None:
    config = load_repository_config(_repository(tmp_path / "ok", sources=THREE_SOURCES))
    kinds = [item.kind for item in config.project.version_sources]
    assert kinds == ["changelog", "git-tag", "file"]
    assert (
        config.project.version_sources[0].path
        == (tmp_path / "ok" / "CHANGELOG.md").resolve()
    )
    assert (
        load_repository_config(
            _repository(tmp_path / "none", sources="")
        ).project.version_sources
        == ()
    )

    rejected = {
        '[[project.version_sources]]\nkind = "svn"\npath = "CHANGELOG.md"\n': "is not one of",
        '[[project.version_sources]]\nkind = "changelog"\npath = "CHANGELOG.md"\npattern = "x{version}"\n': "does not take a pattern",
        '[[project.version_sources]]\nkind = "git-tag"\n': "requires a pattern",
        '[[project.version_sources]]\nkind = "git-tag"\npattern = "release"\n': "contain {version} once",
        '[[project.version_sources]]\nkind = "file"\npath = "pyproject.toml"\npattern = "({version}"\n': "not a valid regular expression",
        '[[project.version_sources]]\nkind = "changelog"\npath = "missing.md"\n': "cannot be resolved",
        THREE_SOURCES
        + '\n[[project.version_sources]]\nkind = "git-tag"\npattern = "v{version}"\n': "unique",
    }
    for index, (text, message) in enumerate(rejected.items()):
        with pytest.raises(InvalidInvocationError, match=message):
            load_repository_config(_repository(tmp_path / f"bad{index}", sources=text))


class _Hadolint:
    def check(self, containerfile: Path, *, config_directory: Path) -> list[Any]:
        return []


class _Resolver:
    def __init__(self) -> None:
        self.requests: list[str] = []

    def resolve_digest(self, reference: OCIReference) -> Digest:
        self.requests.append(str(reference))
        return Digest("sha256:" + "a" * 64)


class _Git:
    def __init__(self, tags: tuple[str, ...]) -> None:
        self.tags = tags
        self.calls: list[tuple[Path, str]] = []

    def tags_at(self, repository: Path, revision: str) -> tuple[str, ...]:
        self.calls.append((repository, revision))
        return self.tags


def test_preflight_compares_declared_sources_before_resolving_pins(
    tmp_path: Path,
) -> None:
    from datetime import UTC, datetime

    config = load_repository_config(
        _repository(tmp_path / "repo", sources=THREE_SOURCES)
    )
    image = config.release_image("app")
    git = _Git(("v1.2.3",))
    tags = revision_tags(config, git, tmp_path / "repo", "b" * 40)
    assert git.calls == [(tmp_path / "repo", "b" * 40)]

    def run(version: str | None, tags: tuple[str, ...]) -> Any:
        resolver = _Resolver()
        result = preflight_image_closure(
            config,
            image,
            hadolint=cast(Any, _Hadolint()),
            store=PinStore(tmp_path / "state"),
            resolver=resolver,
            now=datetime(2026, 1, 1, tzinfo=UTC),
            version=version,
            revision_tags=tags,
        )
        return result, resolver

    accepted, resolver = run("1.2.3", tags)
    assert accepted.accepted
    assert [item.matched for item in accepted.version_sources] == [True, True, True]
    assert resolver.requests, "pins are resolved after the version sources agree"

    rejected, resolver = run("1.3.0", ())
    assert not rejected.accepted
    assert [f.check_id for f in rejected.findings] == ["CC0005", "CC0005", "CC0005"]
    assert resolver.requests == []

    unversioned, _ = run(None, ())
    assert unversioned.accepted and unversioned.version_sources == ()

    plain = load_repository_config(_repository(tmp_path / "plain", sources=""))
    assert revision_tags(plain, git, tmp_path / "plain", "b" * 40) == ()
    assert len(git.calls) == 1
