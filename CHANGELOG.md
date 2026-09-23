<!-- MD080 (heading anchor collisions) is disabled for this file: Keep a
Changelog repeats "Added", "Changed" and "Fixed" under every release heading by
design, so their anchors necessarily collide. The sections are distinguished by
their parent release, never linked by fragment. -->
<!-- rumdl-disable MD080 -->

# Changelog

All notable, user-facing changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added

- `CC0507` rejects Java artifacts assessed against an expired Trivy Java
  database, and `--accept-stale-java-database` on `qualify`, `release` and
  `rescan` accepts that risk for one invocation. Qualification,
  release-candidate and rescan records carry the verdict as `javaDatabase`
  beside the artifact count.

### Changed

- The Java database's freshness gates a qualification only when the SBOM
  inventories Java artifacts (`pkg:maven` package URLs). An expired Java
  database no longer blocks images that contain no Java. `CC0505` continues to
  require a fresh vulnerability database and now names it.
- A database refresh that cannot reach its publisher no longer fails a run whose
  installed snapshot already carries a fresh vulnerability database. The
  snapshot is kept and its Java component's age stays recorded. A refresh
  failure without such a snapshot still fails the run.


## [1.0.2] - 2026-09-20

### Changed

- `python -m conclear.release_check` writes `artifacts.json` in the shared
  `releasing` manifest format. It now names the version and the repository, and
  spells digests as bare hex the way a package index serves them.
  `conclearRevision` became `sourceRevision`; `guideRevision` stayed.


## [1.0.1] - 2026-09-20

### Fixed

- The package page on PyPI resolves its links. The description shipped with
  1.0.0 kept the README's repository-relative destinations, so all links and
  images on that page pointed nowhere. No functional or runtime code changes.


## [1.0.0] - 2026-09-15

### Added

- All functionality and files.

[unreleased]: https://github.com/foundata/conclear/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/foundata/conclear/releases/tag/v1.0.2
[1.0.1]: https://github.com/foundata/conclear/releases/tag/v1.0.1
[1.0.0]: https://github.com/foundata/conclear/releases/tag/v1.0.0
