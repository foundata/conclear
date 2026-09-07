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
- [Generated implementation matrix](#implementation-matrix)
- [CI context observation](#ci-context-observation)
- [Recommended development workflow](#development-workflow)
  - [Before making changes](#before-making-changes)
  - [Making changes](#making-changes)
  - [Before committing](#before-committing)
- [Releases](#releases)
  - [Local 1.0-readiness checklist](#local-readiness)
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
  them. [`README.md`](./README.md#supported-tools) lists the exact supported
  versions.

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
├── CONTRIBUTING.md
├── ARCHITECTURE.md               # Normative behavioral contract
├── DEVELOPMENT.md                # This file
├── README.md
├── REUSE.toml
├── LICENSES/                     # License texts (SPDX)
├── docs/
│   ├── conformance.md            # Generated check catalog (do not edit by hand)
│   ├── guide-options-1.0.0.md    # Generated guide-option support inventory
│   ├── compatibility-inventory.json # Generated internal compatibility inventory
│   ├── implementation-1.0.0.md   # Generated release-specific promise matrix
│   └── quickstart.md             # Project adoption quick start
├── pyproject.toml                # Project configuration
├── uv.lock                       # Dependency lock file
├── .rumdl.toml                   # Markdown conventions checked by rumdl
├── src/conclear/                 # Main package
│   ├── cli.py                    # Click entry point and error-to-exit mapping
│   ├── identity.py               # Embedded tool and guide identity
│   ├── config.py                 # Repository-owned conclear.toml
│   ├── release_profile.py        # Maintainer-controlled release profiles
│   ├── catalog.py                # CCnnnn check catalog loader
│   ├── checks.py                 # Static Containerfile and context checks
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
│   ├── toml_spans.py             # Structural TOML string spans
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

# Check Markdown against the conventions in .rumdl.toml
uv run rumdl check .

# Apply the automatic Markdown fixes
uv run rumdl check --fix .
```


### Commit messages and scopes<a id="commit-scopes"></a>

Commit messages follow the
[foundata guideline (`guidelines/git-commits.md`)](https://github.com/foundata/guidelines/blob/master/git-commits.md):
`<scope>: <description>`, imperative, lowercase description, body only for
context the diff cannot preserve. Choose the narrowest stable project area
affected by the commit. ConClear uses these recurring scopes:

|                                Scope                                 | Area |
| -------------------------------------------------------------------- | ---- |
| `architecture`                                                       | Changes to the contract in `ARCHITECTURE.md` |
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

Report every contract change when reporting completed work. A summary that lists
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

Do not add a changelog before the first 1.0.0 release is published. Do not
prepare releases, create tags or push from local validation work.


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
| `local_integration` | `tests/local_integration/` | Installed rootless tools at supported versions. |
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

The run ID becomes part of an OCI repository name, so it must be lowercase.

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
paths. The session-scoped `trivy_cache` fixture in
`tests/local_integration/conftest.py` supplies the snapshot to this case and to
the CLI transport scenario, so one invocation of the complete tier provisions it
before any dependent case runs, whatever the collection order. The fixture needs
a manifest-owned cache directory in `CONCLEAR_TEST_TRIVY_CACHE`. When that cache
holds no snapshot, every dependent case skips unless
`CONCLEAR_TEST_TRIVY_DOWNLOAD=1` is also set, in which case the production
adapter downloads the current Trivy and Java databases once (about 1.1 GB
compressed, several GB on disk). Every later run is offline and reuses the
pinned snapshot, so record the cache directory and its snapshot digest in the
run manifest and remove it when the run ends.

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

`docs/guide-options-1.0.0.md` is generated from
`src/conclear/data/guide-options.json`. It records guide choices whose support
cannot be inferred from the check catalog, including supported exceptions and
deliberately unsupported or out-of-scope behavior. Every entry names the guide
requirements it concerns, its rationale, related checks and condition for
reconsideration.

```sh
# Regenerate the inventory
uv run python -m conclear.guide_options

# Verify the committed inventory is current
uv run python -m conclear.guide_options --check

# Verify anchors against the exact implemented guide checkout
uv run python -m conclear.guide_options --check \
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

   The command prints the added, removed and reworded requirements together
   with the checks, guide options and coverage entries that reference each one.
3. Replace the embedded revision in `src/conclear/identity.py`, in the three
   data files and in the `guideRevision` constants of the record and proposal
   schemas.
4. Import the inventory:
   `uv run python -m conclear.guide_requirements --import /tmp/guide-requirements.json`.
5. Update the affected checks, guide options and coverage entries, regenerate
   the conformance and guide-option documents, then run the checklist under
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
public behavior and needs a deliberate decision before the first 1.0.0 release;
after that release, an incompatible change needs a new major version. The unit
suite and the release gate fail while the committed inventory is stale.


## Generated implementation matrix<a id="implementation-matrix"></a>

`src/conclear/data/implementation.json` is the machine-readable source for
stable `IPnnnn` promises marked in `ARCHITECTURE.md`. Its integer
`schemaVersion` describes the internal matrix structure, while `productVersion`
identifies the exact ConClear SemVer. Each entry summarizes one current behavior
and links it to production modules and verification tests. The generated
`docs/implementation-<product-version>.md` makes those links reviewable for one
exact ConClear version. Never edit the generated Markdown by hand.

```sh
# Regenerate the matrix for the current package version
uv run python -m conclear.implementation

# Verify promise anchors, file links and generated output
uv run python -m conclear.implementation --check
```

Update the catalog when a promise, its implementation ownership or its
verification changes. A package-version change also updates the catalog's
`productVersion`, the versioned document path and links to it. The unit suite
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

# 5. Verify the generated conformance catalog is current
uv run python -m conclear.conformance --check

# 6. Verify the generated guide-option inventory is current
uv run python -m conclear.guide_options --check

# 7. Verify the guide requirement inventory and coverage are complete
uv run python -m conclear.guide_requirements --check

# 8. Verify the generated compatibility inventory is current
uv run python -m conclear.compatibility_inventory --check

# 9. Verify the release-specific implementation matrix is current
uv run python -m conclear.implementation --check
```


## Releases<a id="releases"></a>

The provider-independent release check requires a clean Git checkout and locally
available Python 3.12, 3.13 and 3.14 interpreters:

```sh
uv run python -m conclear.release_check
```

The command checks formatting, linting, the Markdown conventions in
`.rumdl.toml`, strict typing, the generated conformance documentation, the
guide-option support inventory, the guide requirement inventory and coverage,
the generated compatibility inventory, the release-specific implementation
matrix and the unit-test matrix on every supported interpreter, enforcing the
branch-coverage floor on the first interpreter. It then creates a temporary
clean source archive, embeds the committed source revision, builds a source
distribution, builds a wheel from that source distribution, inspects artifact
contents, installs the wheel into a clean environment and runs import,
`--version` and `--help` smoke tests.

To retain the exact source distribution and wheel that passed the complete gate,
create a private parent directory and select a new revision-specific output
directory:

```sh
install -d -m 0700 "${HOME}/.local/share/conclear/distributions"
revision=$(git rev-parse HEAD)
uv run python -m conclear.release_check \
  --output-directory "${HOME}/.local/share/conclear/distributions/${revision}"
```

The destination must not exist before the command starts. ConClear publishes the
directory only after all source, matrix, distribution-content, clean-install and
smoke checks pass. `artifacts.json` records the embedded ConClear and guide
revisions plus the SHA-256 digest of each retained file.

Install that retained wheel into a new environment without rebuilding it:

```sh
uv venv --python python3.12 /tmp/conclear-dogfood
uv pip install --python /tmp/conclear-dogfood/bin/python \
  "${HOME}/.local/share/conclear/distributions/${revision}"/*.whl
/tmp/conclear-dogfood/bin/conclear version --format json
```

The release check does not create a release, write to a registry, sign content,
create transparency-log entries, tag Git or push commits.


### Local 1.0-readiness checklist<a id="local-readiness"></a>

A revision is a locally validated 1.0 release candidate when all of the
following pass from a clean checkout of that revision, in this order, without
changing any gate, exception, coverage floor or configuration to obtain the
result:

1. The distribution gate on all supported interpreters, retaining its artifacts
   under a directory named for the full revision:

   ```sh
   uv run python -m conclear.release_check \
     --output-directory "${HOME}/.local/share/conclear/distributions/$(git rev-parse HEAD)"
   ```

2. The complete local tier from an external run manifest,
   `uv run pytest -m "local_integration or emulation"` with manifest-owned
   identifiers as described under
   [Local integration tests](#local-integration-tests), including the CLI
   transport scenario against the retained wheel, run with `-rs` so every skip
   is listed with its reason; record any skipped case as a missing result, not
   as a pass, and a skipped emulation case as a missing platform.
3. The retained wheel installed into a fresh environment, with
   `conclear version --format json` reporting the embedded ConClear and guide
   revisions and `conclear --help` listing the command hierarchy recorded in the
   compatibility inventory.
4. `conclear check` and `conclear pins check` run from that installed wheel
   against the current
   [OpenLDAP compatibility project](https://github.com/foundata/oci-openldap-declarative)
   checkout for every image it declares, with every `CCnnnn` finding recorded
   verbatim and no exception added to reach an accepted verdict.

Local readiness does not prove the release path. It cannot show that Quay's tag
immutability, candidate expiry and post-write observation behave as the typed
fakes assume, that Cosign writes the expected predicate and bundle to the public
transparency log, that Rekor inclusion verifies, that an ambiguous remote write
is recovered correctly, or that arm64 qualification works on a host that has no
enabled emulation handler. Those facts exist only on the external side of the
trust boundary.

Before tagging `1.0.0`, one complete external release drill is mandatory: the
opt-in [network tests](#network-tests) against an explicitly authorized
disposable Quay repository with dedicated test signing keys, followed by a
complete `conclear release` of the OpenLDAP compatibility project into a
disposable repository, including `publish`, `attest`, `verify`, `promote` and
candidate cleanup, and an arm64 qualification on a host with an enabled handler
or native hardware. The drill must also run the composable remote path once:
`qualify` and `transport export` per platform, then `assemble`, `provenance`,
`publish`, `attest`, `verify` and `promote` as separate invocations against the
same disposable repository, because a monolithic `release` never reopens a run
and cannot expose a defect in first-use tool binding. Record the observed
results in the release issue. A locally validated candidate without that drill
stays a candidate.

Two facts are proven only indirectly by the automated tiers and belong to the
same gate until they are automated: a complete `conclear qualify` from the
retained wheel on a host without Cosign installed, which the local tier cannot
stage because ConClear searches a fixed tool path, and the composable remote
path above.

CI configuration should delegate project checks to this command and verify the
catalog against the OCI guide at the exact embedded revision. The provider
configuration must not redefine formatting, typing, test or distribution-build
logic.

The source tree uses `development-source-tree` as its local identity.
Distribution builds generate `conclear/_embedded_identity.py` from an externally
observed full Git revision; identity is never derived from an application
repository at runtime. A build without an embedded revision cannot produce
release evidence.


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
