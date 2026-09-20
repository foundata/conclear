# Changelog

All notable, user-facing changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

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

[unreleased]: https://github.com/foundata/conclear/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/foundata/conclear/releases/tag/v1.0.1
[1.0.0]: https://github.com/foundata/conclear/releases/tag/v1.0.0
