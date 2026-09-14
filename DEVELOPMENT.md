# Development

This file provides information for maintainers and contributors to `conclear`.


## Table of contents<a id="toc"></a>

- [Prerequisites](#prerequisites)
- [Getting started](#getting-started)
- [Project structure](#project-structure)
- [Development standards](#development-standards)
  - [Code formatting and linting](#code-linting)
  - [Commit messages and scopes](#commit-scopes)
  - [Contract changes](#contract-changes)
  - [Compatibility](#compatibility)
- [Testing](#testing)
  - [Running tests](#running-tests)
  - [Test tiers and markers](#test-tiers)
  - [Test structure](#test-structure)
  - [Writing tests](#writing-tests)
  - [Local integration tests](#local-integration-tests)
  - [Network tests](#network-tests)
- [Generated conformance catalog](#conformance-catalog)
- [Generated guide-option support inventory](#guide-option-inventory)
- [Generated guide requirement inventory](#guide-requirement-inventory)
- [Generated compatibility inventory](#compatibility-inventory)
- [Generated supported-tools table](#supported-tools-table)
- [Generated implementation matrix](#implementation-matrix)
- [CI context observation](#ci-context-observation)
- [Recommended development workflow](#development-workflow)
  - [Before making changes](#before-making-changes)
  - [Making changes](#making-changes)
  - [Before committing](#before-committing)
- [Releases](#releases)
  - [Release procedure](#release-procedure)
- [Troubleshooting](#troubleshooting)
  - [Common issues](#common-issues)


## Prerequisites<a id="prerequisites"></a>

- **Python 3.12 or later** - Required for running the application.
- **Git** - For version control.
- **[`uv`](https://docs.astral.sh/uv/getting-started/installation/)** - Python
  package manager and build front end.
- **Python 3.12, 3.13 and 3.14 interpreters** - Required by the clean-checkout
  release gate, which runs the unit matrix on each of them.
- **Rootless [Buildah](https://buildah.io/), [Podman](https://podman.io/),
  [Skopeo](https://github.com/containers/skopeo),
  [Hadolint](https://github.com/hadolint/hadolint), [Trivy](https://trivy.dev/)
  and [Cosign](https://docs.sigstore.dev/cosign/)** - Only for the opt-in local
  integration tier and for real releases. The default unit suite does not need
  them. [`README.md`](./README.md#installation) lists the accepted ranges and
  exact real-tool tested versions.

Hermetic unit tests need no container tools, credentials or network access.


## Getting started<a id="getting-started"></a>

1. Clone the repository:

   ```sh
   git clone https://github.com/foundata/conclear.git
   cd conclear
   ```

2. Set up the development environment from the committed lock file:

   ```sh
   # Install all dependencies including development dependencies
   uv sync --frozen --all-groups
   ```

3. Test that the installation works:

   ```sh
   # Show the command hierarchy
   uv run conclear --help

   # Show the tool and implemented-guide identity
   uv run conclear version

   # Run the hermetic unit suite
   uv run pytest
   ```


## Project structure<a id="project-structure"></a>

```text
conclear/
├── ARCHITECTURE.md               # Normative behavioral contract
├── CHANGELOG.md
├── CONTRIBUTING.md
├── DEVELOPMENT.md                # This file
├── README.md
├── REUSE.toml
├── LICENSES/                     # License texts (SPDX)
├── docs/
│   ├── conformance.md            # Generated check catalog and guide options
│   ├── compatibility-inventory.json # Generated internal compatibility inventory
│   ├── implementation.md         # Generated implementation promise matrix
│   └── backup.md                 # Backup and archive retention
├── pyproject.toml                # Project configuration
├── uv.lock                       # Dependency lock file
├── src/conclear/                 # Main package
│   ├── cli.py                    # Click entry point and error-to-exit mapping
│   ├── identity.py               # Embedded tool and guide identity
│   ├── config.py                 # Repository-owned conclear.toml
│   ├── config_decisions.py       # Owner decisions and draft diagnostics
│   ├── release_profile.py        # Maintainer-controlled release profiles
│   ├── catalog.py                # CCnnnn check catalog loader
│   ├── checks.py                 # Static Containerfile and context checks
│   ├── containerfile.py          # Shared lexical model and source byte spans
│   ├── conformance.py            # docs/conformance.md generator
│   ├── guide_options.py          # Guide-option support inventory generator
│   ├── guide_requirements.py     # Guide requirement inventory, coverage and revision diffs
│   ├── compatibility_inventory.py # Internal compatibility inventory generator
│   ├── implementation.py         # Release-specific implementation matrix generator
│   ├── emulation.py              # binfmt handler detection and execution-mode facts
│   ├── records.py                # Record envelopes and digests
│   ├── parsing.py                # Typed narrowing of untrusted JSON and TOML values
│   ├── pins.py                   # Durable pin observations and divergence policy
│   ├── pin_occurrences.py        # Read-only pin occurrence discovery
│   ├── pin_updates.py            # Non-mutating pin-update proposals
│   ├── pin_application.py        # Verified all-or-nothing proposal application
│   ├── workspace.py              # Run state machine and ownership journal
│   ├── process.py                # Supervised execution and redaction
│   ├── oci.py                    # Layout, descriptor and graph validation
│   ├── registry_control.py       # Provider-neutral registry controls
│   ├── release_check.py          # Clean-checkout release gate
│   ├── transport.py              # Qualification transport export and verified import
│   ├── adapters/                 # Typed tool and registry boundaries
│   │   ├── buildah.py            # Build and layout export
│   │   ├── podman.py             # Import and runtime tests
│   │   ├── skopeo.py             # Registry inspection and transport
│   │   ├── hadolint.py           # Containerfile linting
│   │   ├── trivy.py              # Scanning, SBOMs, database snapshots
│   │   ├── cosign.py             # Signing, attestations, verification
│   │   ├── registry_backends.py  # Compiled backend selection
│   │   ├── quay.py               # Quay tag API
│   │   └── git.py                # Source selection and worktrees
│   ├── commands/                 # CLI surface, grouped by scope (transport.py: worker exports)
│   ├── services/                 # Workflow decisions (qualification, runtime
│   │                             # tests, assembly, publication, attestation,
│   │                             # verification, promotion, rescan, cleanup)
│   ├── schemas/                  # Shipped JSON Schemas
│   ├── data/checks.json          # Check catalog source of truth
│   ├── data/guide-options.json   # Guide-option support source of truth
│   ├── data/guide-requirements.json # Imported guide requirement inventory
│   ├── data/requirement-coverage.json # Status of every requirement no check covers
│   └── data/implementation.json  # Current promise-to-code-and-test mappings
└── tests/
    ├── conftest.py               # Marker auto-assignment and shared fixtures
    ├── release_fakes.py          # Stateful adapter fakes
    ├── unit/                     # Hermetic tests (default tier)
    ├── local_integration/        # Opt-in, real local tools; fixtures.py compiles the shared Go fixture
    └── network/                  # Opt-in, disposable external services
```


## Development standards<a id="development-standards"></a>

This project follows these coding standards and rules:

- **Python Style**: [PEP 8](https://peps.python.org/pep-0008/) compliance.
- **Type Hints**: Use [type](https://docs.python.org/3/library/typing.html)
  annotations everywhere. `mypy --strict` must pass for `src` and `tests`.
- **Docstrings**: Use the three-double-quote `"""` format (per
  [PEP 257](https://peps.python.org/pep-0257/)) for public functions, classes
  and modules.
- **Import organization**: Follow [isort](https://pycqa.github.io/isort/)
  standards.
- **Error handling**: Keep rule rejections and operational failures
  distinguishable. Never convert an unknown state into success.
- **Untrusted input**: Treat configuration, JSON, registry responses, OCI
  layouts, archives, paths and tool output as untrusted. Validate them at
  runtime before constructing typed domain values.
- **Encoding, line ending:** Use UTF-8 encoding with `LF` (Line Feed `\n`) line
  endings *without* [BOM](https://en.wikipedia.org/wiki/Byte_order_mark) for all
  files.

Keep each change focused and include its tests, schema changes, generated
conformance output and affected documentation. Avoid unrelated refactoring. A
new external dependency needs a concrete requirement that the standard library
or an existing dependency cannot meet.

The linting and formatting tool can take care of most of the style rules (see
next section).


### Code formatting and linting<a id="code-linting"></a>

```sh
# Format code
uv run ruff format .

# Check formatting without writing
uv run ruff format --check .

# Lint code
uv run ruff check .

# Fix auto-fixable linting issues
uv run ruff check --fix .

# Strict type checking
uv run mypy --strict src tests

```

Markdown follows the foundata Markdown style guide's canonical
[`fmt` and `check` invocations](https://github.com/foundata/guidelines/blob/main/markdown-style-guide.md#linting-and-automatic-formatting).
Run those commands from this repository. Their arguments are deliberately not
duplicated here; the release gate applies the same `check` policy together with
`git diff --check` over the committed tree.


### Commit messages and scopes<a id="commit-scopes"></a>

Commit messages follow the
[foundata guideline (`guidelines/git-commits.md`)](https://github.com/foundata/guidelines/blob/master/git-commits.md):
`<scope>: <description>`, imperative, lowercase description, body only for
context the diff cannot preserve. Choose the narrowest stable project area
affected by the commit. ConClear uses these recurring scopes:

|                                Scope                                 | Area |
| -------------------------------------------------------------------- | ---- |
| `architecture`                                                       | Changes to the contract in `ARCHITECTURE.md` |
| `adopt`                                                              | Read-only repository assessment and the draft configuration it renders |
| `catalog`                                                            | Stable `CCnnnn` definitions, conformance generation and generated conformance documentation |
| `checks`                                                             | Containerfile, context and lint finding checks |
| `ci`                                                                 | Optional CI context observation and checkout binding, excluding CI gate configuration |
| `cli`                                                                | Click command parsing, command composition, presentation and command-specific diagnostics |
| `config`                                                             | External configuration, release profiles and their schemas |
| `errors`                                                             | Shared error taxonomy, exit classification and diagnostic identifiers |
| `parsing`                                                            | Shared validation and resource bounds for untrusted structured input |
| `process`                                                            | Supervised child processes, sanitized environments, redaction and executable discovery |
| `records`                                                            | Public record envelopes, layouts, schemas and deterministic serialization |
| `workspace`                                                          | Run state, ownership journals, atomic local writes and persisted workspace validation |
| `qualification`                                                      | Source isolation, build-context checks, image builds, runtime tests and per-platform evidence |
| `pins`                                                               | Pin declarations, durable pin observations, pin-update proposals and their verified application |
| `assembly`                                                           | Verified multi-platform OCI assembly |
| `transport`                                                          | Qualification transport export, caller-verified import and coordinator assembly inputs |
| `scanner`                                                            | Scan policy, immutable database snapshots and scanner behavior shared by qualification and rescans |
| `release`                                                            | Release-run orchestration, resume behavior and terminal summaries |
| `publication`                                                        | Candidate publication, remote-graph verification and the ownership-journal retry rule shared by the later phases |
| `attestation`                                                        | SBOM and provenance attestation, image signing and the downloaded-statement matching later phases reuse |
| `verification`                                                       | Independent verification of the attested candidate and the signed release-verification result |
| `promotion`                                                          | Release-tag writes, tag protection and candidate removal for the verified digest |
| `registry`                                                           | Provider-neutral registry control contracts, backend selection and support policy |
| `rescan`                                                             | Post-release scanning, triage, remediation history and rescan cleanup |
| `adapters`                                                           | Shared adapter contracts or one change spanning several external tools |
| `buildah`, `cosign`, `hadolint`, `podman`, `quay`, `skopeo`, `trivy` | Behavior confined to one external tool adapter |
| `build`                                                              | Python packaging, distribution identity, the lock file, the clean-checkout release gate and CI gate configuration |
| `dependencies`                                                       | Dependency-only changes |
| `licensing`                                                          | License texts, SPDX metadata and REUSE configuration |
| `repository`                                                         | Repository-wide non-code concerns such as contributor documentation and ignore rules |
| `tests`                                                              | Cross-cutting test infrastructure or coverage not attributable to one subsystem |
| `project`                                                            | Initial establishment of the application when no narrower subsystem describes the change |

A new stable subsystem may introduce a scope when none of the documented scopes
fits; the table is a reference rather than a closed registry.

`docs` is not a scope: the foundata guideline lists it among the Conventional
Commits types a scope must not be written as. A commit that only changes
documentation still uses the scope of the subsystem it documents, or a
cross-cutting scope such as `repository` when the documentation is not about one
subsystem.

Do not prepare releases, create tags or push from local validation work.


### Contract changes<a id="contract-changes"></a>

[`ARCHITECTURE.md`](./ARCHITECTURE.md) is the current behavioral contract: every
promise in it must be implemented and tested in the same source tree. Put every
`ARCHITECTURE.md` edit in its own commit whose subject names it as a contract
change, such as
`architecture: require a new run after an ambiguous candidate write`, and never
fold one into a commit that also changes code. Give the reason in the commit
body when the diff does not carry it.

Keep planned behavior in a
[GitHub issue](https://github.com/foundata/conclear/issues) until its code,
tests and contract text can land together. Do not silently amend the contract to
normalize an implementation defect. Decide whether the implementation or the
promise is wrong, then either fix the code or make an explicit contract
correction whose rationale is reviewable.

Every contract change has to be reported. A summary that lists
implemented behavior but omits an edit to `ARCHITECTURE.md`, an `IPnnnn`
promise, a shipped schema, an exit status, a record layout or a `CCnnnn`
identifier is incomplete.

The guide that `ARCHITECTURE.md` implements is normative and lives outside this
repository. Each build embeds one exact guide revision together with that
revision's requirement inventory. Moving to a newer revision means reviewing
every added, removed or reworded requirement and updating the embedded identity,
inventory, catalog, coverage file, generated documents, schemas and tests
together (see
[Generated guide requirement inventory](#guide-requirement-inventory));
ConClear must not advertise a revision whose automatable rules it does not
implement.


### Compatibility<a id="compatibility"></a>

ConClear uses its SemVer product version for the aggregate public behavioral
contract. The Click hierarchy, command options, `--format json` objects, JSON
Schemas, record layouts, exit statuses, stable check identifiers and
implementation promises are compatibility surfaces. Change them deliberately and
document the effect. Durable public record formats keep independent integer
schema versions because records can outlive the ConClear release that created
them. The committed
[internal compatibility inventory](./docs/compatibility-inventory.json)
enumerates these surfaces; the unit suite and the release gate fail until a
changed surface is regenerated and reviewed (see
[Generated compatibility inventory](#compatibility-inventory)).

A `CCnnnn` identifier is never reused for a different rule. Removing a check
leaves a retired entry in the catalog so historical findings stay
understandable.


## Testing<a id="testing"></a>

The default suite is hermetic. Tests that need local tools or external services
use explicit opt-in tiers.

### Running tests<a id="running-tests"></a>

```sh
# Run the default hermetic unit suite
uv run pytest

# Run a specific test file
uv run pytest tests/unit/test_publication.py

# Run a specific test
uv run pytest tests/unit/test_pins.py -k divergence

# Run with branch coverage; the configured floor fails the run below 85 %
uv run pytest --cov=conclear --cov-branch --cov-report=term-missing

# Run the opt-in local integration tier (see below)
uv run pytest -m local_integration
```

Branch coverage of the hermetic unit suite must stay at or above the
`fail_under` floor in `pyproject.toml`. Raise the floor when coverage grows;
never lower it, exclude a module or add `pragma: no cover` to reach it.


### Test tiers and markers<a id="test-tiers"></a>

`addopts` selects the `unit` marker, so a bare `uv run pytest` is always
hermetic. `tests/conftest.py` assigns markers by directory, and pytest's
`strict = true` mode rejects an unregistered marker.

|       Marker        |          Location          | Requires |
| ------------------- | -------------------------- | -------- |
| `unit`              | `tests/unit/`              | Nothing. No container storage, credentials, network or wall-clock dependency. |
| `local_integration` | `tests/local_integration/` | Installed rootless tools at real-tool tested versions; the tier fails on a version the policy does not yet list as tested. |
| `emulation`         | `tests/local_integration/` | Non-native execution through an enabled arm64 binfmt handler. The tier skips, with the handler diagnostic, on a host without one; ConClear never installs emulators or registers handlers. |
| `network`           | `tests/network/`           | An explicitly authorized disposable Quay repository and test signing keys. |

The default suite must stay independent of the workstation's container storage,
configuration, credentials, network and clock. Inject clocks and identifier
factories rather than reading the current time.


### Test structure<a id="test-structure"></a>

- **Unit tests**: `tests/unit/` - Hermetic tests of one component or workflow
  through fakes.
- **Local integration tests**: `tests/local_integration/` - Exercise real
  installed tools against run-owned storage.
- **Network tests**: `tests/network/` - Exercise real external services. These
  cover the behavior that fakes cannot model, such as the predicate URI Cosign
  really writes and Quay's real tag-immutability semantics.
- **Adapter fakes**: `tests/release_fakes.py` - Stateful fakes used by workflow
  tests.


### Writing tests<a id="writing-tests"></a>

1. **Write the failing test first**. A fix without a test that failed before it
   is not finished.
2. **Cover the failure path**, not only the success path. This is a fail-closed
   tool; its error branches are its product.
3. **Use deterministic fakes at adapter boundaries** for operational failures
   and ambiguous remote writes. Do not mock ordinary policy or serialization
   logic.
4. **Make fakes behave like the real tool.** A fake that echoes its input back
   can hide a real defect; where behavior depends on an external format, assert
   against that format in the network tier.
5. **Keep tests isolated**: `tmp_path` only, no shared state, no ambient
   environment.

A new release-registry backend must implement the typed control contract in
`registry_control.py` and pass the shared publication, resume, promotion and
cleanup tests. Add it to the closed backend table only after opt-in network
tests establish exact tag observation, digest-preserving graph handling, Cosign
referrers, independently enforced candidate lifetime, selective tag protection,
exact tag assignment, deletion and ambiguous-write recovery. Provider-specific
request and response details stay in the adapter. Workflow services continue
deciding verdicts from typed observations.


### Local integration tests<a id="local-integration-tests"></a>

Read the local testing instructions before running opt-in tests. Use a unique
run ID, run-owned rootless storage and a resource manifest outside the
repository. Never reuse or clean up unrecorded Buildah, Podman, registry or
virtual-machine resources.

```sh
CONCLEAR_TEST_RUN_ID=<manifest-owned-run-id> uv run pytest -m local_integration
```

The native archive-signature test also requires
`CONCLEAR_TEST_PUBLIC_SIGSTORE=1`. It generates a disposable key, writes
synthetic non-secret statements to the public transparency log and verifies
saved bundles without registry access. The test removes its private key;
transparency entries are permanent.

The run ID becomes part of an OCI repository name, so it must be lowercase.

On SELinux hosts, label the manifest-owned parent of `--basetemp` as
`container_file_t` before creating test storage. Keep SELinux enforcing and use
the normal login runtime directory; do not put `XDG_RUNTIME_DIR` under the
checkout or a home-directory test workspace.

The sudo tests need a separate Linux amd64 fixture containing real sudo,
visudo, UID 10001 and the denied account `nobody`. After recording an absolute
`RUN` directory and its descendant storage, images and containers in the local
test manifest, build and export it with isolated rootless storage:

```sh
buildah --root "${RUN}/builder/root" --runroot "${RUN}/builder/runroot" \
  --storage-driver vfs bud --platform linux/amd64 --format oci \
  --tag localhost/conclear-sudo:fixture tests/local_integration/sudo_fixture
buildah --root "${RUN}/builder/root" --runroot "${RUN}/builder/runroot" \
  --storage-driver vfs push localhost/conclear-sudo:fixture "oci:${RUN}/layout:sudo-fixture"
CONCLEAR_TEST_SUDO_LAYOUT="${RUN}/layout" uv run pytest -m local_integration \
  tests/local_integration/test_sudo.py --basetemp "${RUN}/pytest"
buildah --root "${RUN}/builder/root" --runroot "${RUN}/builder/runroot" \
  --storage-driver vfs rmi --all
```

The fixture build downloads its pinned public Debian base and packages. The
tests make no registry writes, use fresh Podman storage below `--basetemp`,
retain `sudo-results.json` and reset only their own storage. They exercise
presence-only and escalation modes, permitted and denied callers, and blocked
escalation under restrictive controls. Without `CONCLEAR_TEST_SUDO_LAYOUT`
they skip. Use an unused `--basetemp` directory for each run and record cleanup
in the manifest, including after a failed build or test.

The local suite compiles network-free `scratch` fixtures with Go, uses isolated
Buildah and Podman storage, copies only between local OCI layouts with Skopeo
and creates disposable Cosign key material under the run workspace. Its manual
no-log Cosign check stays outside the production adapter and follows the guide's
no-service signing configuration, bundle and verification flags. Record the
workspace and all created resources in the external run manifest before invoking
it, then record the observed assertions and cleanup result.

The exact runtime-input integration case needs two additional manifest-owned
lowercase ULIDs because its service and one-shot parameterizations create
separate ConClear workspaces:

```sh
CONCLEAR_TEST_RUN_ID=<manifest-owned-run-id> \
CONCLEAR_TEST_SERVICE_ULID=<manifest-owned-lowercase-ulid> \
CONCLEAR_TEST_ONE_SHOT_ULID=<manifest-owned-lowercase-ulid> \
uv run pytest -m local_integration \
  tests/local_integration/test_tools.py::test_real_exact_image_preparation_and_launch_inputs \
  --basetemp <external-run-workspace>/tmp/pytest
```

Record the primary and preparation container names for both ULIDs before
invoking the test. A passing run proves exact sibling-layout import, private
output generation and destruction, read-only fixture and generated-output
mounts, non-secret launch environment, service health and TERM behavior,
one-shot exit behavior, and journal-owned cleanup without using the
workstation's existing container storage.

`tests/local_integration/test_transport_cli.py` runs the distributed workflow
through the public CLI only: two `qualify` worker runs, two `transport export`
invocations and one `assemble` coordinator run, followed by an inspection of the
assembled index with plain file reads and `cleanup` of every run. A development
checkout cannot emit public records, so the scenario needs `CONCLEAR_TEST_CLI`,
the absolute path of the `conclear` entry point of an installed wheel built from
the revision under test, plus the Trivy snapshot that the shared `trivy_cache`
fixture selects or provisions from `CONCLEAR_TEST_TRIVY_CACHE`. The
`local_integration` case uses `linux/amd64` and `linux/amd64/v3` so two real
workers and a two-descriptor index can be exercised on an x86-64 host without
emulation; the `emulation` case uses `linux/amd64` and `linux/arm64` and skips
without an enabled handler.

```sh
uv venv --python python3.12 <external-run-workspace>/conclear-venv
uv pip install --python <external-run-workspace>/conclear-venv/bin/python \
  "${HOME}/.local/share/conclear/distributions/<revision>"/*.whl
CONCLEAR_TEST_RUN_ID=<manifest-owned-run-id> \
CONCLEAR_TEST_CLI=<external-run-workspace>/conclear-venv/bin/conclear \
CONCLEAR_TEST_TRIVY_CACHE=<manifest-owned-cache> \
uv run pytest -m local_integration tests/local_integration/test_transport_cli.py \
  --basetemp <external-run-workspace>/tmp/pytest
```

The complete local tier, including the emulation case, is one invocation with
the same manifest-owned identifiers:

```sh
CONCLEAR_TEST_RUN_ID=<manifest-owned-run-id> \
CONCLEAR_TEST_SERVICE_ULID=<manifest-owned-lowercase-ulid> \
CONCLEAR_TEST_ONE_SHOT_ULID=<manifest-owned-lowercase-ulid> \
CONCLEAR_TEST_CLI=<identity-bearing-conclear-executable> \
CONCLEAR_TEST_TRIVY_CACHE=<manifest-owned-cache> \
uv run pytest -m "local_integration or emulation" \
  --basetemp <external-run-workspace>/tmp/pytest
```

`tests/local_integration/test_adapter_failures.py` drives the installed Git,
Buildah, Podman, Skopeo and Hadolint binaries into the failures that the adapter
fakes can only imitate: refused connections, missing objects, failed builds,
unrepresentable commit times, invalid output paths and Podman's real capability
reporting. Skopeo cases target the closed local port `localhost:1` only; nothing
listens, nothing is pulled and nothing is published. When a real tool
contradicts a fake, fix the adapter and the fake together and keep the real
case.

`tests/local_integration/test_trivy_database.py` exercises the real
vulnerability-database snapshot, layout scan, SPDX generation and SBOM rescan
paths, the filesystem secret and configuration scans, and a complete
two-platform qualification and assembly that shares one database snapshot by
digest. The session-scoped `trivy_cache` fixture in
`tests/local_integration/conftest.py` supplies the snapshot to this case and to
the CLI transport scenario, so one invocation of the complete tier provisions it
before any dependent case runs, whatever the collection order. The fixture needs
a manifest-owned cache directory in `CONCLEAR_TEST_TRIVY_CACHE`. When that cache
holds no fresh snapshot, every dependent case skips unless
`CONCLEAR_TEST_TRIVY_DOWNLOAD=1` is also set, in which case the production
adapter downloads the current Trivy and Java databases once (about 1.1 GB
compressed, several GB on disk). Later runs can reuse the pinned snapshot
offline while it is fresh enough to start qualification. Stale caches require
explicit download permission again. Record the cache directory and its snapshot
digest in the run manifest and remove it when the run ends.

The workstation's Trivy package may lag behind the accepted line.
`CONCLEAR_TEST_TRIVY` names the absolute path of a verified official Trivy
release build inside the run workspace; the tier then resolves Trivy from that
path instead of normal tool discovery and leaves the host installation
untouched. Download the release tarball, its checksums file and the checksums'
Sigstore bundle into the manifest-owned workspace, verify the tarball's SHA-256
against the checksums file, verify the checksums file with `cosign verify-blob
--bundle`, the GitHub Actions OIDC issuer and the `aquasecurity/trivy` workflow
identity, and record the executable path and digest in the manifest. The CLI
transport scenario needs an accepted Trivy available to the installed
`conclear` command; it does not use this test-only override.
`CONCLEAR_TEST_QUALIFICATION_ULID` supplies the
manifest-owned lowercase ULID of the workspace that the real-Trivy qualification
case creates.

The emulation case builds the shared `linux/arm64` fixture with Buildah, imports
it into run-owned Podman storage and runs its architecture self-check through
the host's enabled `qemu-aarch64` handler, then records the observed execution
mode below `--basetemp`. On a host without an enabled handler the case is
reported as skipped with the same diagnostic that `conclear build` and
`conclear test` raise for that platform; a skipped emulation case is not
evidence that arm64 qualification works.


### Network tests<a id="network-tests"></a>

Network tests need an explicitly authorized disposable Quay repository, narrow
credentials and dedicated test signing keys. Production release keys and shared
repositories are never test inputs. These tests write to a real registry and
create permanent public transparency-log entries, so they are opt-in by design.

They remain the only check on behavior that fakes cannot reproduce. Run them at
least once before trusting a production-signed release.

The baseline covers candidate read-back, selected expiration and owned deletion,
plus an SPDX attestation round trip. Select `CONCLEAR_TEST_TAG_PROTECTION`
(`required` or `not-enforced`) and `CONCLEAR_TEST_CANDIDATE_CLEANUP` (`manual`,
`tag-expiration` or `auto-prune`) to match the release profile. Optional tests
check selective repository/organization protection and auto-prune creation and
read-back. Selected controls fail if their APIs are unavailable; unselected
controls are skipped. Read-back does not prove overwrite rejection or eventual
pruning. Candidates remain mutable throughout the baseline.

With `CONCLEAR_TEST_NETWORK_AUTHORIZED=yes`, missing required inputs fail the
test. The external resource manifest must own the repository and every supplied
tag. `required` also needs the full tagged references
`CONCLEAR_TEST_QUAY_VERSION_TAG` and `CONCLEAR_TEST_QUAY_MOVING_TAG`; configure
a selective policy for them before testing. All credential paths must be
absolute and outside this checkout. Use the environment block in the release
procedure below for the baseline inputs.

#### Repeat release and recovery

`tests/network/test_release_lifecycle.py` exercises an installed wheel through
the public CLI. It releases the same source/version twice, checks `latest` by
registry read-back and runs three authoritative rescans across those releases.
It then qualifies and assembles another candidate, stops after publication and
resumes in a new process. The assertions cover unchanged authorization expiry,
candidate deletion, terminal-resume rejection and preservation of promoted tags
during cleanup. A stop between commands does not test crashes during writes or
lost provider acknowledgements.

The fixture is a committed repository with exactly one release image, the
manifest-owned Quay destination and `latest` as a moving tag; the
[drill project](https://github.com/foundata/oci-conclear-drill/blob/master/README.md)
creates one with `drill/lifecycle-fixture.sh`. Use an unused version and
repository. Put the installed wheel, the fixture, dedicated file-based signing
credentials and the XDG directories under the manifest's `workspace`. Keep the
same configuration bytes for rescans. The selected profile must include a
passphrase file and match the two policy-mode variables above.

Set `CONCLEAR_TEST_RELEASE_LIFECYCLE=yes` and
`CONCLEAR_TEST_RELEASE_SCENARIO` to an external JSON file containing:

```json
{
  "cli": "/absolute/run/wheel-env/bin/conclear",
  "conclear_revision": "<full revision embedded in the retained wheel>",
  "source": "/absolute/run/image",
  "revision": "<full committed fixture revision>",
  "version": "1.2.3",
  "profile": "test",
  "state_home": "/absolute/run/state",
  "cache_home": "/absolute/run/cache",
  "config_home": "/absolute/run/config"
}
```

Run `uv run pytest -m network tests/network/test_release_lifecycle.py -rs` with
the common authorization, manifest, repository and policy-mode variables. The
test creates `workspace/release-lifecycle` once, retains protected command
output there and records discovered ConClear run IDs in the resource manifest.
After reviewing evidence, clean those runs with their original state/profile,
then remove only manifest-owned registry resources. Interrupted commands may
leave additional journaled resources; reconcile the dedicated state directory
before declaring cleanup complete. No result report belongs in this checkout.

## Generated conformance catalog<a id="conformance-catalog"></a>

`docs/conformance.md` is generated from `src/conclear/data/checks.json`, the
guide requirement inventory, the requirement coverage file and the embedded
guide identity. Never edit it by hand. Every check names the `IGnnnn` guide
requirements it covers, and the document ends with the status of every
requirement of the embedded revision.

```sh
# Regenerate the catalog
uv run python -m conclear.conformance

# Verify the committed catalog is current
uv run python -m conclear.conformance --check

# Also verify every requirement and section anchor against the guide checkout
uv run python -m conclear.conformance --check \
  --guide ../guidelines/oci-container-image-guide.md
```

Commit a catalog change together with the check definition, implementation,
tests and affected documentation. Continuous integration verifies that
identifiers are unique and well formed, that every referenced requirement exists
in the inventory, that every requirement has exactly one status and that the
committed document matches the generator.


## Generated guide-option support inventory<a id="guide-option-inventory"></a>

The guide-option section of `docs/conformance.md` is generated from
`src/conclear/data/guide-options.json`. It records guide choices whose support
cannot be inferred from the check catalog, including supported exceptions and
deliberately unsupported or out-of-scope behavior. Every entry names the guide
requirements it concerns, its rationale, related checks and condition for
reconsideration. Both parts of the document are generated and verified together:

```sh
# Regenerate the conformance document, including the guide options
uv run python -m conclear.conformance

# Verify the committed document is current
uv run python -m conclear.conformance --check

# Verify anchors against the exact implemented guide checkout
uv run python -m conclear.conformance --check \
  --guide ../guidelines/oci-container-image-guide.md
```

Update an entry when implementation changes its status or when a guide revision
changes the option. The loader rejects stale product or guide versions,
malformed or duplicate identifiers, unknown check references and unsupported
status values. The release gate verifies the generated document and its
distribution contents.


## Generated guide requirement inventory<a id="guide-requirement-inventory"></a>

The implemented guide gives every normative statement a stable `IGnnnn`
identifier. `src/conclear/data/guide-requirements.json` is that inventory,
imported from the `--list` output of the guide repository's
`scripts/check-requirement-identifiers.py` for the embedded revision.
`src/conclear/data/checks.json` maps every check to the identifiers it covers,
and `src/conclear/data/requirement-coverage.json` gives every identifier no
check covers one status with a rationale: `automated`, `manual`, `external` or
`unsupported`. The generated conformance document renders the result. The check
fails while any requirement lacks a status, has both a check and a coverage
entry, or is referenced but unknown.

```sh
# Verify the shipped inventory, catalog mapping and coverage
uv run python -m conclear.guide_requirements --check

# Also verify every requirement and section anchor against the guide checkout
uv run python -m conclear.guide_requirements --check \
  --guide ../guidelines/oci-container-image-guide.md
```

Moving to a newer guide revision:

1. List the requirements of the new revision from its checkout:

   ```sh
   python3 ../guidelines/scripts/check-requirement-identifiers.py --list \
     > /tmp/guide-requirements.json
   ```

2. Review what changed and what it touches:

   ```sh
   uv run python -m conclear.guide_requirements --diff /tmp/guide-requirements.json
   ```

   The command prints the added, removed and reworded requirements together with
   the checks, guide options and coverage entries that reference each one.
3. Replace the embedded revision in `src/conclear/identity.py`, in the three
   data files and in the `guideRevision` constants of the record and proposal
   schemas.
4. Import the inventory:
   `uv run python -m conclear.guide_requirements --import /tmp/guide-requirements.json`.
5. Update the affected checks, guide options and coverage entries, regenerate
   the conformance document, then run the checklist under
   [Before committing](#before-committing) and the `--guide` verification above.


## Generated compatibility inventory<a id="compatibility-inventory"></a>

`docs/compatibility-inventory.json` is a repository-internal inventory generated
from the Click command hierarchy, the bundled JSON Schemas, the record and
command-result schema versions, the exit statuses, the check catalog and the
current implementation-promise identifiers. Its `productVersion` is the exact
ConClear SemVer whose public behavior it inventories. Its integer
`inventorySchemaVersion` describes only this internal file structure and
increments when repository tooling needs an incompatible layout change. The
inventory's JSON layout is not a supported external interface. Never edit it by
hand.

```sh
# Regenerate the inventory
uv run python -m conclear.compatibility_inventory

# Verify the committed inventory is current
uv run python -m conclear.compatibility_inventory --check
```

A diff in this file is a compatibility-review signal, not automatically a public
contract change. A diff that only changes internal inventory structure or
metadata is internal. A diff caused by a removed or renamed command, option,
schema identifier, record type, exit status or other inventoried surface changes
public behavior and needs a new major version. The unit suite and the release
gate fail while the committed inventory is stale.


## Generated supported-tools table<a id="supported-tools-table"></a>

The table under [Installation](README.md#installation) in the README is
rendered from the tool policies in `src/conclear/tools.py` between two HTML
comment markers. Never edit it by hand; change the policy and regenerate. An
accepted interval and its exclusions come from the flags and output fields the
adapters use and from published advisories; the tested column lists only the
versions the real-tool tier ran against, and that tier fails on a host whose
version is not listed, so a version is added there after the tier passed with
it.

```sh
# Regenerate the table
uv run python -m conclear.tool_matrix

# Verify the committed table is current
uv run python -m conclear.tool_matrix --check
```


## Generated implementation matrix<a id="implementation-matrix"></a>

`src/conclear/data/implementation.json` is the machine-readable source for
stable `IPnnnn` promises marked in `ARCHITECTURE.md`. Its integer
`schemaVersion` describes the internal matrix structure, while `productVersion`
identifies the exact ConClear SemVer. Each entry summarizes one current behavior
and links it to production modules and verification tests. The generated
`docs/implementation.md` makes those links reviewable for the ConClear version
it names in its heading. Never edit the generated Markdown by hand.

```sh
# Regenerate the matrix for the current package version
uv run python -m conclear.implementation

# Verify promise anchors, file links and generated output
uv run python -m conclear.implementation --check
```

Update the catalog when a promise, its implementation ownership or its
verification changes. A package-version change also updates the catalog's
`productVersion` and the version named in the generated heading. The unit suite
and release gate reject stale output, absent or unsafe paths, mismatched
versions, duplicate identifiers and architecture promises missing from either
side of the mapping.


## CI context observation<a id="ci-context-observation"></a>

The protected release profile chooses `omit`, `observe` or `require`. ConClear
has environment adapters for GitHub Actions, GitLab CI, Gitea Actions, Forgejo
Actions and Woodpecker CI. Provider-specific markers are required, and the Gitea
and Forgejo adapters take precedence over their GitHub-compatible variables.
Forgejo observation requires Forgejo Runner 7 or newer because earlier runners
expose only GitHub-compatible names and cannot be identified reliably.

|                                            Provider                                            |                       Marker                        |        Origin        |      Repository      |    Revision     | Run |
| ---------------------------------------------------------------------------------------------- | --------------------------------------------------- | -------------------- | -------------------- | --------------- | --- |
| [GitHub Actions](https://docs.github.com/en/actions/reference/workflows-and-actions/variables) | `GITHUB_ACTIONS` with the GitHub API URL convention | `GITHUB_SERVER_URL`  | `GITHUB_REPOSITORY`  | `GITHUB_SHA`    | `GITHUB_RUN_ID` |
| [GitLab CI](https://docs.gitlab.com/ci/variables/predefined_variables/)                        | `GITLAB_CI`                                         | `CI_SERVER_URL`      | `CI_PROJECT_PATH`    | `CI_COMMIT_SHA` | `CI_PIPELINE_ID` |
| [Gitea Actions](https://docs.gitea.com/usage/actions/actions-variables/)                       | `GITEA_ACTIONS`                                     | `GITHUB_SERVER_URL`  | `GITHUB_REPOSITORY`  | `GITHUB_SHA`    | `GITHUB_RUN_ID` |
| [Forgejo Actions](https://forgejo.org/docs/v15.0/user/actions/reference/)                      | `FORGEJO_ACTIONS`                                   | `FORGEJO_SERVER_URL` | `FORGEJO_REPOSITORY` | `FORGEJO_SHA`   | `FORGEJO_RUN_ID` |
| [Woodpecker CI](https://woodpecker-ci.org/docs/usage/environment)                              | `CI` or `CI_SYSTEM_NAME` equal to `woodpecker`      | `CI_FORGE_URL`       | `CI_REPO`            | `CI_COMMIT_SHA` | `CI_PIPELINE_NUMBER` |

Before observed context enters signed release evidence, ConClear requires its
repository and revision to match the canonical repository and commit from the
isolated checkout. The public shape contains only a normalized provider,
`provider-environment` source, repository, revision and provider run identifier.
Internal service origins remain in local diagnostics.

Provider environment variables are ordinary process inputs. They support audit
correlation but do not authenticate the runner or authorize a release. Tests and
code must not use CI context to replace the source checkout, builder identity,
signer identity, ConClear run identifier, artifact digest or release verdict.

ConClear does not acquire or accept OIDC tokens because the release profile
defines no issuer and audience trust root against which to authenticate those
claims.

The protected release profile supplies the SLSA builder identity independently
of CI observation. The identity names a documented trust domain and remains
stable across ConClear versions. Security-significant environment changes
require another builder URI, and consumers must approve the corresponding signer
and builder pair.

## Recommended development workflow<a id="development-workflow"></a>

Routine changes begin from a passing branch and keep behavior, tests and
affected documentation together.

### Before making changes<a id="before-making-changes"></a>

1. **Create a feature branch**:

   ```sh
   git checkout -b feature/your-feature-name
   ```

2. **Ensure the suite passes**:

   ```sh
   uv run pytest
   ```


### Making changes<a id="making-changes"></a>

1. **Follow the coding standards** mentioned above.
2. **Write or update tests** for your changes, failure paths first.
3. **Update documentation** in the same commit as the behavior it describes.
4. **Separate contract changes** into their own commits, as described in
   [Contract changes](#contract-changes).


### Before committing<a id="before-committing"></a>

Always run this checklist before committing:

```sh
# 1. Format code
uv run ruff format .

# 2. Fix linting issues (if any)
uv run ruff check --fix .

# 3. Strict type checking
uv run mypy --strict src tests

# 4. Run the unit suite
uv run pytest

# 5. Verify the generated conformance catalog and guide options are current
uv run python -m conclear.conformance --check

# 6. Verify the guide requirement inventory and coverage are complete
uv run python -m conclear.guide_requirements --check

# 7. Verify the generated compatibility inventory is current
uv run python -m conclear.compatibility_inventory --check

# 8. Verify the implementation promise matrix is current
uv run python -m conclear.implementation --check

# 9. Verify the supported-tools table is current
uv run python -m conclear.tool_matrix --check
```


## Releases<a id="releases"></a>

A ConClear release consists of one Semantic Versioning version, one annotated
`vX.Y.Z` Git tag, one GitHub release and the source distribution and wheel
published for that version. Release only a clean, committed revision. Test
results and retained artifacts belong to that exact revision and cannot be
carried over after another commit.

The source tree identifies itself as `development-source-tree` and cannot emit
release evidence. The release check creates a clean source archive and embeds
the selected full Git revision as `conclear/_embedded_identity.py` before it
builds the distributions. Runtime identity is never inferred from the consumer
repository.

The maintainer performing a release also needs `jq`, `sha256sum`, an
authenticated `gh` installation, an authorized PyPI publishing identity and the
Quay and Sigstore test inputs described below. Keep credentials, signing keys,
test workspaces and resource manifests outside the repository.


### Release procedure<a id="release-procedure"></a>

1. **Choose the release version.** Select the version according to
   [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The numbered
   steps below are the checklist; every step must produce its result before the
   next one starts. A skip is a missing result, not a pass.

   ```sh
   version="<major.minor.patch>"
   tag="v${version}"

   git status --short
   git tag --list "${tag}"
   ```

   Start from a clean branch and stop if the version or tag already exists.

2. **Prepare the versioned sources and changelog.** Move the accumulated entries
   under `Unreleased` in [`CHANGELOG.md`](./CHANGELOG.md) to a section named for
   the version and release date, then leave an `Unreleased` section containing
   `No unreleased changes.` above it. Add a link for the new release; after a
   previous release exists, also add or update the comparison links.

   Keep the version in `pyproject.toml`, `src/conclear/identity.py`,
   `src/conclear/data/implementation.json` and
   `src/conclear/data/guide-options.json` aligned. Review version-specific prose
   and links in `README.md`, `ARCHITECTURE.md`, `DEVELOPMENT.md` and `docs/`.
   Each released tag carries the generated documents of its own revision, so no
   earlier copy is kept in the working tree.

   Regenerate the lock file and every version-dependent document rather than
   editing generated output:

   ```sh
   uv lock
   uv run python -m conclear.implementation
   uv run python -m conclear.compatibility_inventory
   uv run python -m conclear.conformance
   uv run python -m conclear.tool_matrix
   ```

3. **Review and commit the release preparation.** Inspect every changed file,
   stage only the reviewed release changes and create one release commit.

   ```sh
   git diff --check
   git diff
   git add --all
   git diff --cached
   git commit -m "release: prepare ${version}"

   revision="$(git rev-parse --verify HEAD)"
   git status --short
   ```

   The final command must print nothing. Do not amend the release commit after
   its validation starts.

4. **Run the distribution gate and retain its exact artifacts.** The gate needs
   locally available Python 3.12, 3.13 and 3.14 interpreters. It checks clean
   whitespace, formatting, linting, Markdown, strict typing, all generated
   artifacts and the unit suite on every supported interpreter. It then builds
   the source distribution from a clean archive, builds the wheel from that
   source distribution, validates their contents, installs the wheel into a
   clean environment and smoke-tests its import, version and help output.

   ```sh
   install -d -m 0700 "${HOME}/.local/share/conclear/distributions"
   artifact_dir="${HOME}/.local/share/conclear/distributions/${revision}"

   uv run python -m conclear.release_check \
     --output-directory "${artifact_dir}"
   ```

   The destination must not exist before the command starts. A successful gate
   publishes it atomically. Verify the retained files against the generated
   manifest:

   ```sh
   (
     cd "${artifact_dir}"
     jq -r '.artifacts[] | "\(.sha256 | ltrimstr("sha256:"))  \(.filename)"' artifacts.json |
       sha256sum --check -
   )
   ```

5. **Run the complete local integration tier against the retained wheel.** Read
   [Local integration tests](#local-integration-tests) first. Create and record
   the external resource manifest, workspace, unique lowercase identifiers,
   container names and Trivy cache before running the tests. Install the wheel
   without rebuilding it and supply that executable to the CLI transport test.

   ```sh
   dogfood="<external-run-workspace>/conclear-venv"
   uv venv --python python3.12 "${dogfood}"
   uv pip install --python "${dogfood}/bin/python" \
     "${artifact_dir}"/*.whl

   CONCLEAR_TEST_RUN_ID=<manifest-owned-run-id> \
   CONCLEAR_TEST_SERVICE_ULID=<manifest-owned-lowercase-ulid> \
   CONCLEAR_TEST_ONE_SHOT_ULID=<manifest-owned-lowercase-ulid> \
   CONCLEAR_TEST_CLI="${dogfood}/bin/conclear" \
   CONCLEAR_TEST_TRIVY_CACHE=<manifest-owned-cache> \
   uv run pytest -m "local_integration or emulation" -rs \
     --basetemp <external-run-workspace>/tmp/pytest
   ```

   Supply `CONCLEAR_TEST_TRIVY_DOWNLOAD=1` only when the recorded cache needs a
   database snapshot. An emulation skip means the platform remains unverified.

6. **Verify the installed identity against the drill project.**
   The installed command must report the selected version, candidate revision
   and embedded guide revision. Its help hierarchy must agree with the
   compatibility inventory.

   ```sh
   "${dogfood}/bin/conclear" version --format json
   "${dogfood}/bin/conclear" --help
   ```

   From the retained wheel, run `conclear check` and `conclear pins check` for
   every image of the
   [drill project](https://github.com/foundata/oci-conclear-drill/blob/master/README.md).
   Record every `CCnnnn` finding verbatim and do not add an exception to obtain
   an accepted result. Also complete one `conclear qualify` of its `service`
   image with Cosign absent from the executable search path; qualification must
   not acquire a signing dependency.

7. **Exercise the external trust boundaries.** Follow
   [Network tests](#network-tests) with an explicitly authorized disposable Quay
   repository, dedicated test signing keys and an external resource manifest.

   ```sh
   CONCLEAR_TEST_NETWORK_AUTHORIZED=yes \
   CONCLEAR_TEST_RUN_ID=<manifest-owned-run-id> \
   CONCLEAR_TEST_RESOURCE_MANIFEST=<external-resource-manifest> \
   CONCLEAR_TEST_QUAY_REPOSITORY=quay.io/<organization>/<repository> \
   CONCLEAR_TEST_QUAY_CANDIDATE=quay.io/<organization>/<repository>:<candidate-tag> \
   CONCLEAR_TEST_QUAY_CANDIDATE_DIGEST=sha256:<candidate-digest> \
   CONCLEAR_TEST_QUAY_TOKEN_FILE=<quay-api-token-file> \
   CONCLEAR_TEST_TAG_PROTECTION=not-enforced \
   CONCLEAR_TEST_CANDIDATE_CLEANUP=tag-expiration \
   CONCLEAR_TEST_COSIGN_SUBJECT=quay.io/<organization>/<repository>@sha256:<subject-digest> \
   CONCLEAR_TEST_DOCKER_CONFIG=<registry-auth-file> \
   CONCLEAR_TEST_COSIGN_PRIVATE_KEY=<test-private-key> \
   CONCLEAR_TEST_COSIGN_PUBLIC_KEY=<test-public-key> \
   CONCLEAR_TEST_COSIGN_PASSPHRASE_FILE=<test-passphrase-file> \
   uv run pytest -m network -rs
   ```

   Then run the release drill of the
   [drill project](https://github.com/foundata/oci-conclear-drill/blob/master/README.md)
   against the retained wheel:

   ```sh
   drill/prepare.sh --wheel "${distribution}/conclear-${version}-py3-none-any.whl" --workspace "${workspace}"
   drill/run.sh --workspace "${workspace}"
   drill/verify.sh --workspace "${workspace}"
   ```

   Every stage must be `passed` in the drill's `manifest.json`. Keep that file
   with the candidate's evidence.

8. **Freeze the validated candidate.** Confirm that every result of steps 4 to 7
   belongs to the candidate revision named in `artifacts.json`. Do not continue
   when any mandatory result is absent. Any tracked-file change invalidates the
   retained artifacts and all results that depend on them: commit the change,
   choose a new revision-specific artifact directory and repeat validation from
   step 4.

9. **Create and push the release tag.** Tag the exact revision recorded by the
   gate, inspect it, then push the branch and that tag explicitly.

   ```sh
   test "$(git rev-parse --verify HEAD)" = "${revision}"
   git status --short

   git tag -a "${tag}" "${revision}" -m "version ${version}"
   git show "${tag}"

   git push origin main
   git push origin "refs/tags/${tag}"
   ```

   Stop if the status command prints anything or the tag does not point to the
   validated revision.

10. **Publish the retained distributions to PyPI without rebuilding.** Upload
    only the source distribution and wheel named in `artifacts.json`. Prefer the
    configured trusted-publishing environment. When a maintainer token is the
    configured mechanism, keep it out of shell history and process arguments:

    ```sh
    printf 'PyPI API token: '
    read -rs UV_PUBLISH_TOKEN
    printf '\n'
    export UV_PUBLISH_TOKEN

    uv publish \
      "${artifact_dir}/conclear-${version}.tar.gz" \
      "${artifact_dir}/conclear-${version}-py3-none-any.whl"

    unset UV_PUBLISH_TOKEN
    ```

    PyPI versions are immutable. Never rebuild and retry the same version with
    different bytes.

11. **Verify the public installation.** Install the exact version from PyPI in
    an isolated environment. Check both the product version and the embedded
    candidate revision rather than accepting version text alone.

    ```sh
    published_identity="$(
      uv run --isolated --no-project --with "conclear==${version}" -- \
        conclear version --format json
    )"
    printf '%s\n' "${published_identity}" | jq -e \
      --arg version "${version}" \
      --arg revision "${revision}" \
      '.version == $version and .sourceRevision == $revision'

    uv run --isolated --no-project --with "conclear==${version}" -- \
      conclear --help
    ```

12. **Create and verify the GitHub release.** Use the matching changelog section
    as the release notes. Attach `artifacts.json` and the exact distributions
    already published to PyPI.

    ```sh
    gh release create "${tag}" \
      "${artifact_dir}/artifacts.json" \
      "${artifact_dir}/conclear-${version}.tar.gz" \
      "${artifact_dir}/conclear-${version}-py3-none-any.whl" \
      --verify-tag \
      --title "${tag}" \
      --notes-file <release-notes-file>

    gh release view "${tag}"
    ```

    Confirm that GitHub reports the new release as latest and that the attached
    files match `artifacts.json`.

Before either PyPI or a GitHub release exposes an artifact, a bad tag may be
deleted and the procedure restarted. Once either service has published the
version, do not replace it or reuse its tag. Yank a defective PyPI release when
appropriate and publish the correction under a new patch version.

The release check itself never writes to a registry, signs content, creates
transparency-log entries, tags Git, pushes commits or publishes Python packages.
CI configuration should delegate checks to this command and verify the catalog
against the exact embedded guide revision instead of redefining the project
gates.


## Troubleshooting<a id="troubleshooting"></a>

Keep validation and test isolation intact when resolving the following failures.

### Common issues<a id="common-issues"></a>

- **Import errors**: Ensure the environment is installed with
  `uv sync --frozen --all-groups`.
- **`uv run conclear version` reports `development-source-tree`**: Expected in a
  source checkout. Only a distribution build embeds a real revision, and only
  such a build can emit records.
- **The retained distribution destination already exists**: Choose a new path.
  The release gate never merges with or overwrites prior output.
- **Conformance check fails after editing `docs/conformance.md`**: The file is
  generated. Change `src/conclear/data/checks.json` and regenerate.
- **Requirement coverage check reports requirements without a status**: The
  guide revision gained requirements no check covers. Map them in
  `src/conclear/data/checks.json` or classify them in
  `src/conclear/data/requirement-coverage.json`, then regenerate the
  conformance document.
- **Implementation-matrix check fails after a contract or version change**:
  Update `src/conclear/data/implementation.json`, the matching `IPnnnn` anchor
  or the versioned documentation link, then regenerate the matrix.
- **A local integration test fails on the run ID**: The identifier becomes part
  of an OCI repository name and must be lowercase.
- **Unit tests suddenly need the network or container storage**: A test landed
  in `tests/unit/` that belongs in `local_integration` or `network`. Move it
  rather than relaxing the tier.
