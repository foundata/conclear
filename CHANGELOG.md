# Changelog

All notable, user-facing changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Changed

- The release profile names the signing passphrase file `cosign_passphrase_file`
  instead of `passphrase_file`, and the option supplying it on the command line
  is `--cosign-passphrase-fd` instead of `--passphrase-fd`. Both now say which
  key they unlock, so a further passphrase can be added later without renaming
  this one.
- The release profile schema is version 2. Rename the key in
  `~/.config/conclear/<profile>.toml` and set `schema_version = 2`; a profile
  still declaring version 1 is rejected and names the edit it needs.


## [1.1.0] - 2026-09-24

### Added

- Trivy and Hadolint can run from their publishers' images instead of host
  executables: name them in `CONCLEAR_TOOL_IMAGES`. Each image is pinned by its
  index digest, Trivy's publisher signature is verified, and records name the
  pinned index and the platform manifest that ran. The supported-tools table and
  the compatibility inventory name each pinned image.
- Commands narrate what they do on stderr: the phase under way and every
  external command that ran, verb first, coloured only on a terminal. Stdout
  stays the result. `-q`/`--quiet` before the command drops the narration but
  never an error. `python -m conclear.release_check` announces its steps there
  too instead of on stdout, so its stdout is now empty.
- The compatibility inventory lists the root group as `conclear` with its own
  options, `--version` and `--quiet`, which it had left out.
- `CC0507` rejects Java artifacts assessed against an expired Trivy Java
  database, and `--accept-stale-java-database` on `qualify`, `release` and
  `rescan` accepts that risk for one invocation. Qualification,
  release-candidate and rescan records carry the verdict as `javaDatabase`
  beside the artifact count.
- `doctor --scope qualify` and `--scope release` report the installed Trivy
  database's freshness as `database` and warn with `CC0507` when the Java
  database has expired, before any image is built. The snapshot is only read,
  never refreshed.
- Rescan records name the Java artifacts of each platform as
  `scanResults[].javaArtifacts`, so a multi-platform image shows which platform
  the Java database verdict applies to.

### Fixed

- `rescan` reports the record's findings in its command result, located by
  platform. A rejected rescan previously returned the rejection status with an
  empty findings list, so the reason was only in the record.

### Changed

- The real-tool tested versions are Buildah 1.43.4, Podman 5.8.7 and Skopeo
  1.22.3, the versions this release's real-tool tier ran against. The accepted
  ranges are unchanged.
- The Java database's freshness gates a qualification only when the SBOM
  inventories Java artifacts (`pkg:maven` package URLs). An expired Java
  database no longer blocks images that contain no Java. `CC0505` continues to
  require a fresh vulnerability database and now names it.
- A database refresh that cannot reach its publisher no longer fails a run whose
  installed snapshot already carries a fresh vulnerability database. The
  snapshot is kept and its Java component's age stays recorded. A refresh
  failure without such a snapshot still fails the run.
- The release gate runs the Markdown style guide's current invocation and needs
  `rumdl` 0.2.72 or later, the version the guide documents. `MD090` and the
  front-matter key order are now enforced, and `MD080` anchor collisions are
  limited to heading levels 1 and 2.


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

[unreleased]: https://github.com/foundata/conclear/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/foundata/conclear/releases/tag/v1.1.0
[1.0.2]: https://github.com/foundata/conclear/releases/tag/v1.0.2
[1.0.1]: https://github.com/foundata/conclear/releases/tag/v1.0.1
[1.0.0]: https://github.com/foundata/conclear/releases/tag/v1.0.0
