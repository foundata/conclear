# Development

ConClear requires Python 3.12 or newer and uses [uv](https://docs.astral.sh/uv/) for locked environments and builds.

## Setup

Create or update the development environment from the committed lock file:

```sh
uv sync --frozen --all-groups
```

The supported release tools are listed in [README.md](README.md). Hermetic unit tests do not require those tools, credentials or network access.

## Local checks

Run the normal source checks with:

```sh
uv run ruff format --check .
uv run ruff check .
uv run mypy --strict src tests
uv run pytest -m unit --strict-markers --strict-config
uv run pytest -m unit --strict-markers --strict-config --cov=conclear --cov-branch --cov-report=term-missing
uv run python -m conclear.conformance --check
```

Tests under `tests/unit/` receive the `unit` marker automatically. Tests that invoke installed rootless tools use `local_integration`; non-native execution also uses `emulation`; tests that access disposable external services use `network`. The default unit suite must remain independent of the workstation's container storage, configuration, credentials, network and clock.

Use deterministic fakes at adapter boundaries for operational failures and ambiguous remote writes. Do not mock ordinary policy or serialization logic.

## Generated conformance catalog

`docs/conformance.md` is generated from `src/conclear/data/checks.json` and the embedded guide identity. Update the catalog with:

```sh
uv run python -m conclear.conformance
```

Commit a catalog change with the check definition, implementation, tests and affected documentation.

## Release check

The provider-independent release check requires a clean Git checkout and locally available Python 3.12, 3.13 and 3.14 interpreters:

```sh
uv run python -m conclear.release_check
```

The command checks formatting, linting, strict typing, generated conformance documentation and the unit-test matrix. It creates a temporary clean source archive, embeds the committed source revision, builds a source distribution, builds a wheel from that source distribution, inspects artifact contents, installs the wheel into a clean environment and runs import, `--version` and `--help` smoke tests.

The release check does not create a release, write to a registry, sign content, create transparency-log entries, tag Git or push commits.

## Local integration tests

Read the local testing instructions before running opt-in tests. Use a unique run ID, run-owned rootless storage and a resource manifest outside the repository. Never reuse or clean up unrecorded Buildah, Podman, registry or virtual-machine resources.

Run read-only and run-owned local tool tests with:

```sh
CONCLEAR_TEST_RUN_ID=<manifest-owned-run-id> uv run pytest -m local_integration --strict-markers --strict-config
```

The local suite compiles network-free `scratch` fixtures with Go, uses isolated Buildah and Podman storage, copies only between local OCI layouts with Skopeo and creates disposable Cosign key material under the run workspace. Its manual no-log Cosign check stays outside the production adapter and follows the guide's no-service signing configuration, bundle and verification flags. Record the workspace and all created resources in the external run manifest before invoking it, then record the observed assertions and cleanup result.

Network tests need an explicitly authorized disposable Quay repository, narrow credentials and dedicated test signing keys. Production release keys and shared repositories are never test inputs.

## Source layout

Production code lives under `src/conclear/`. Click command modules parse inputs and call workflow services. Configuration, schemas, records, state, process supervision, OCI parsing, adapters, presentation and workflow decisions remain separate modules.

The source tree uses `development-source-tree` as its local identity. Distribution builds must generate `conclear/_embedded_identity.py` from an externally observed full Git revision; they must not derive identity from an application repository at runtime.
