# ConClear — container clearance before promotion

A tool implementing the technical parts of [foundata's OCI container image build and release guide](https://github.com/foundata/guidelines/blob/main/oci-container-image-guide.md):

`qualify` → `assemble` → `provenance` → `publish` → `attest` (sign) → `verify` → `promote`

ConClear takes a container image from a reviewed source commit to a signed, verified, and promoted digest. It lets you run the same qualify, sign, and verify steps whether you're on your laptop or in CI. It's designed to fail closed: if any check, signature, or verification step doesn't pass, nothing gets promoted, so what ends up published is always backed by evidence, not just trust.


## Table of contents<a id="toc"></a>

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Repository configuration](#usage-repository-configuration)
  - [Exact runtime test inputs](#usage-runtime-test-inputs)
  - [Release profiles](#usage-release-profiles)
  - [Running a release](#usage-release)
  - [Resuming an interrupted run](#usage-resume)
  - [Composable commands](#usage-commands)
  - [Updating pinned references](#usage-pin-updates)
  - [Distributed qualification](#usage-distributed)
  - [JSON output and exit codes](#usage-json-exit-codes)
  - [Rescan triage](#usage-rescan-triage)
- [Supported tools](#supported-tools)
- [Records and schemas](#records-schemas)
- [Conformance](#conformance)
- [Contributing](#contributing)
- [Licensing, copyright](#licensing-copyright)
  - [Trademarks](#trademarks)
- [Author information](#author-information)


## Features<a id="features"></a>

- **Digest-bound end to end.** Every test, scan, SBOM, signature and attestation names an immutable manifest or index digest. No rebuild happens between qualification and publication.
- **Rejecting gates stay local.** Linting, tests, scans and SBOM generation run against a local OCI layout, before anything becomes public.
- **Rootless and daemonless.** Buildah, Podman and Skopeo, with no Docker daemon anywhere in the workflow.
- **Signed, logged and verified.** Cosign signs the index and every platform manifest, always with public transparency-log inclusion, and verification checks that inclusion before promotion.
- **Promotion moves tags, never content.** Only the digest accepted by release verification is written, and every written tag is resolved again afterwards.
- **Machine-readable evidence.** Qualification, candidate, verification and rescan records are schema-validated JSON with stable digests, so a release decision can be reconstructed without treating logs as evidence.
- **Distinguishable failures.** A rule rejection and an operational failure never look alike, in human output, JSON output or exit status.


## Installation<a id="installation"></a>

ConClear requires Python 3.12 or newer and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/foundata/conclear.git
cd conclear
uv sync --frozen --all-groups
uv run conclear --help
```

Maintainers can build and retain a locally installable, identity-bearing wheel without PyPI or a CI service. The complete command and clean-environment installation procedure are documented in [`DEVELOPMENT.md`](./DEVELOPMENT.md#releases).

Container projects can follow the [ConClear quick start](./docs/quickstart.md) for the required repository files, runtime test inputs and release-profile setup.

Release workflows additionally need the rootless container toolchain listed under [Supported tools](#supported-tools). The hermetic unit suite needs none of it.


## Usage<a id="usage"></a>

The `release` command runs the complete workflow. The sections below cover its repository inputs, external trust profile, recovery, distributed work, result contract and rescan triage.


### Repository configuration<a id="usage-repository-configuration"></a>

Repository behavior is declared in a reviewed `conclear.toml` at the selected source revision. It holds project facts and the exceptions the guide permits, never credentials. Unknown keys are errors, so a misspelled security setting cannot be silently ignored.


### Exact runtime test inputs<a id="usage-runtime-test-inputs"></a>

An image can declare non-secret repository fixtures, run-owned generated outputs, ordered preparation commands, launch inputs and exact sibling image dependencies. ConClear builds every dependency from the same isolated source revision, timestamp, platform, version input and Buildah toolchain, then imports each validated layout by digest before preparation starts.

This example lets a one-shot sibling create a private key and a generated test artifact, then launches the primary image with only the non-secret artifact:

```toml
[images.test]
dependencies = ["generator"]

[[images.test.fixtures]]
name = "definition"
path = "tests/fixtures/definition"

[[images.test.outputs]]
name = "test-key"
secret = true

[[images.test.outputs]]
name = "generated"

[[images.test.preparations]]
name = "create-key"
image = "generator"
command = ["/usr/local/bin/generator", "keygen"]
mounts = [{ name = "test-key", target = "/output", read_only = false }]

[[images.test.preparations]]
name = "generate"
image = "generator"
command = ["/usr/local/bin/generator", "build", "--input", "/input", "--key", "/key", "--output", "/output"]
mounts = [
  { name = "definition", target = "/input" },
  { name = "test-key", target = "/key" },
  { name = "generated", target = "/output", read_only = false },
]

[images.test.launch]
arguments = ["--test-input", "/run/generated"]
environment = { SERVICE_SELECTOR = "test" }
expected_exit_status = 0
mounts = [{ name = "generated", target = "/run/generated" }]
```

The `generator` image must be another `[[images]]` entry in the same file, cover every tested platform and declare `/output` in its runtime `writable_mounts`. Preparation commands replace only that exact image's entrypoint; launch arguments retain the primary image's original entrypoint. Commands are arrays and are never interpreted by a shell.

A mount names a declared fixture or output and is read-only unless it sets `read_only = false`. Fixtures must be ordinary source-tree files or directories with no symbolic links or unsafe permissions, and are always mounted read-only. Writable outputs exist only below the run workspace and only at destinations already declared by the selected image's runtime contract. Output names marked `secret = true` have no path, value or content digest in public evidence, are unavailable to repository hooks and are destroyed before a hook runs.

ConClear continues to own layout validation, digest-preserving import, runtime controls, startup, health, signals, expected exit status and cleanup. A reviewed repository hook receives `CC_TEST_INPUT_MANIFEST`, which contains exact layout paths and digests plus non-secret fixture and output handles. Hooks add assertions but cannot mark a built-in gate as passed; ConClear records their command and result but does not sandbox a reviewed hook from invoking other host executables.


### Release profiles<a id="usage-release-profiles"></a>

Trust roots, signing keys and registry credentials stay outside the repository, in a named profile such as `$XDG_CONFIG_HOME/conclear/foundata.toml`:

```toml
ci_context = "observe"
auth_file = "/home/example/.config/containers/auth.json"
cosign_private_key = "/home/example/.config/conclear/cosign.key"
cosign_public_key = "/home/example/.config/conclear/cosign.pub"
passphrase_file = "/home/example/.config/conclear/cosign.passphrase"

[builder]
id = "https://foundata.com/en/projects/conclear/builder/simple-v1/"

[registry]
provider = "quay"
host = "quay.io"
api_url = "https://quay.io/api/v1"
token_file = "/home/example/.config/conclear/quay.token"
```

The profile and every secret file must be owned by the invoking user and carry private permissions. CI may supply the signing passphrase through `--passphrase-fd` instead of a file. Secret values are never accepted through project configuration, command-line literals or inherited environment variables.

`builder.id` names the complete build-platform trust domain and must be a public, credential-free HTTPS documentation URI. The simple v1 identity covers foundata's operator-controlled workstation workflow and claims SLSA Build L1 only. A different workstation policy or CI trust boundary needs a different builder identity. ConClear records its own version and source revision separately and verifies the configured signer and builder identities before promotion.

`ci_context` controls optional CI correlation metadata. `omit` does not inspect CI variables, `observe` records complete matching context when available, and `require` stops when recognized context is absent, malformed or inconsistent with the isolated checkout. ConClear recognizes GitHub Actions, GitLab CI, Gitea Actions, Forgejo Actions and Woodpecker CI. The normalized public record contains the provider, repository, full revision and provider run identifier. Provider environment variables are not authentication and never control the release verdict, source identity, signer identity or artifact digest.

Repository configuration may name any fully qualified OCI registry for local checks, qualification, assembly and provenance. The complete `publish` through `promote` workflow requires an explicitly selected registry control backend. A supported backend must provide exact tag observation, digest-preserving graph handling, Cosign referrers, an independently enforced candidate lifetime, selective tag protection, exact tag assignment, deletion and ambiguous-write recovery. Quay.io provides these controls and `quay` is currently the only implemented backend. A release profile that selects `quay` rejects a destination on another registry before qualification or remote mutation.


### Running a release<a id="usage-release"></a>

The normal interface resolves a reviewed Git selector, creates a detached checkout, qualifies `linux/amd64` before any additional platform, assembles the accepted layouts, publishes one registry-controlled candidate, signs and verifies every digest and attestation, and promotes only the verified digest:

```sh
uv run conclear release --image app --revision v1.2.3 --version 1.2.3 --profile foundata
```

The ordinary checkout may be dirty. Uncommitted and untracked files cannot enter the build context.
The project configuration records a credential-free canonical HTTPS source identity, while the local Git remote may use the equivalent HTTPS or Git SSH form. ConClear canonicalizes the observed transport before comparison and records only the HTTPS identity in evidence.


### Resuming an interrupted run<a id="usage-resume"></a>

An interrupted run resumes only when its source, configuration, tool identities, artifacts and remote observations still match:

```sh
uv run conclear release --resume 01arz3ndektsv4rrffq69g5fav --profile foundata
```

A candidate reference is never reused for a second publication attempt. If an ambiguous write cannot be resolved conclusively to the expected digest within its lifetime, the release restarts as a new run.


### Composable commands<a id="usage-commands"></a>

`release` is the normal interface. The composable commands support diagnosis, distributed platform work and recovery without defining an alternative workflow: `doctor`, `check`, `pins check`, `pins propose`, `pins apply`, `build`, `test`, `evidence`, `qualify`, `transport export`, `assemble`, `provenance`, `publish`, `attest`, `verify`, `promote`, `rescan` and `cleanup`. Run any of them with `--help` for its exact inputs.

No command offers an option that disables a gate, skips verification or affects transparency-log behavior.


### Updating pinned references<a id="usage-pin-updates"></a>

Pin maintenance does not require Renovate, another updater, CI, a branch or a pull request. `pins propose` resolves every declared readable tag exactly once, binds that digest to each `[[images.pins]]` declaration and each `FROM`, `COPY --from` and `RUN --mount=from` input that names the same reference, and writes one schema-validated proposal without touching the repository:

```sh
uv run conclear pins propose --output /tmp/pins.json --profile foundata
```

The proposal records the ConClear and guide identity, the canonical repository and its current commit, the configuration digest, one lookup per pinned reference with old and new digest and resolution time, and every file with its digest and the exact byte spans that would change. Only the digest of a reference changes; registry, repository and tag spelling stay as written. A change under an `immutable-version` tag is marked as requiring supply-chain review and reported as `CC0205`; ConClear offers no way to skip that review. An already-current repository yields a successful proposal that changes nothing.

`pins apply` reads the proposal, verifies the repository, commit, configuration digest, every target file digest, the reparsed dependency set and every old byte sequence, and only then replaces the proposed spans through same-directory temporary files. It never resolves a tag again and never commits, builds, publishes or signs. If anything fails, every target keeps its original bytes:

```sh
uv run conclear pins apply --proposal /tmp/pins.json
uv run conclear pins check --image app
uv run conclear check --image app
git diff --check
git diff
```

`pins apply` reports one follow-up `pins check` command for every affected image; run all of them, and run each image's repository checks before accepting the update. `pins check` remains the freshness and divergence gate and the only command that updates durable pin observations. Review the complete diff, commit it through the repository's normal process, and qualify that committed revision. This is the complete local workflow; qualification and release do not require an external updater either.

A pinned, self-hosted updater such as Renovate may schedule this workflow and place the resulting reviewed diff on an updater-owned branch or pull request. That is an optional delivery layer around ConClear's proposal and application operations, not a second pin resolver, a required writer or a release prerequisite.


### Distributed qualification<a id="usage-distributed"></a>

`release` qualifies every platform in one process. When platforms are qualified on separate workers, or when one workstation qualifies them in separate runs, each `qualify` produces its own worker run, and a coordinator assembles the accepted qualifications in a new run of its own. Nothing in this workflow needs a release profile, registry credentials, signing material or publication.

```sh
# Worker A (linux/amd64)
conclear qualify --source . --revision v1.2.3 --image app --version 1.2.3 \
  --platform linux/amd64 --format json
conclear transport export <worker-run-a> --platform linux/amd64 \
  --output ./app-linux-amd64.tar --format json

# Worker B (linux/arm64), pinned to the same vulnerability database snapshot
conclear qualify --source . --revision v1.2.3 --image app --version 1.2.3 \
  --platform linux/arm64 --database-digest sha256:<database-digest> --format json
conclear transport export <worker-run-b> --platform linux/arm64 \
  --output ./app-linux-arm64.tar --format json

# Coordinator (authorized release environment)
conclear assemble --source . --revision v1.2.3 --image app --version 1.2.3 \
  --transport ./app-linux-amd64.tar sha256:<transport-digest-a> \
  --transport ./app-linux-arm64.tar sha256:<transport-digest-b> \
  --format json
```

`transport export` writes a new archive, or a directory with `--kind directory`, containing only the immutable qualification record, its OCI layout and the evidence payloads the record names, plus a schema-validated `transport.json` manifest that binds every member by digest. It refuses an existing destination and never includes logs, tool environments, container storage, test inputs, secret outputs, private keys or authentication files. Its JSON result reports the identifiers a coordinator must receive through a channel other than the transport itself:

| Identifier | Meaning |
|---|---|
| worker run ID | The lowercase ULID of the `qualify` run that produced the qualification. It stays in the record and in the candidate. |
| coordinator run ID | The new lowercase ULID that `assemble` generates. It names the candidate reference and owns the assembled layout. |
| qualification-record digest | SHA-256 of the exact `platform-qualification.json` bytes (`recordDigest`). |
| transport digest | SHA-256 of the archive file, or of `transport.json` for a directory transport (`transportDigest`). `assemble` requires it as its second `--transport` value. |
| platform manifest digest | Digest of the platform's OCI image manifest (`platformManifestDigest`), which becomes one index entry. |
| assembled index digest | Digest of the assembled image index, or of the single manifest for a one-platform image (`subjectDigest`). |

`assemble` creates the coordinator run from the reviewed source revision, so the coordinator needs the repository checkout but no worker workspace. It compares each transport with the caller-supplied digest before trusting any member, extracts only regular files below a bounded, confined staging directory, verifies every member, the record digest, the layout graph, the platform descriptor and the evidence payloads, and then checks that all qualifications agree on image, source revision, configuration digest, guide and ConClear identity, tool versions, pin resolutions, effective limits, release version and vulnerability database. It rejects missing, duplicate and unexpected platforms and a qualification produced by another ConClear revision. The candidate record names the coordinator run and every worker run with its record and transport digests, and the assembled index carries exactly one verified manifest per required platform. `provenance`, `publish`, `attest`, `verify` and `promote` then continue on the coordinator run. Copying worker workspaces or records by hand is not a supported operation; assembly accepts only transports it can verify.

Every worker must scan against the same vulnerability database. The coordinator takes `data.databaseDigest` from the first `qualify --format json` result and distributes `$XDG_CACHE_HOME/conclear/trivy/snapshots/<digest-without-sha256-prefix>` unchanged to every later worker, which pins it with `--database-digest`. ConClear selects that directory directly, recomputes its content digest and fails before building if it differs.


### JSON output and exit codes<a id="usage-json-exit-codes"></a>

Every command that produces a result supports `--format json`. JSON mode writes exactly one schema-validated object to standard output and all diagnostics to standard error.

| Exit code | Meaning |
|---:|---|
| `0` | Success. |
| `1` | Operational failure: a required fact could not be established. |
| `2` | Rule rejection: observed content violates the guide or the effective configuration. |
| `64` | Invalid invocation or configuration. |


### Rescan triage<a id="usage-rescan-triage"></a>

`rescan` accepts externally owned vulnerability decisions through `--triage-file`. Each decision must name the exact immutable rescan subject and one platform in that subject; duplicate platform, component and advisory identities are rejected.

```json
{
  "schemaVersion": 1,
  "decisions": [
    {
      "subject": "quay.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "platform": "linux/amd64",
      "component": "openssl",
      "advisory": "CVE-2026-0001",
      "decision": "remediation-planned",
      "rationale": "The fixed base-image rebuild is scheduled.",
      "owner": "security@example.com",
      "decidedAt": "2026-08-31T12:34:56Z",
      "remediatingDigest": null
    }
  ]
}
```

An exact `not-applicable` decision suppresses only its matching platform, component and advisory finding. An exact `remediated` decision closes deadline tracking for its matching finding and must name the immutable remediating digest, but it does not erase the scanner observation. `affected` and `remediation-planned` findings remain active. Exact, unexpired vulnerability exceptions from the release configuration are evaluated separately, and every applied exception is included in the new linked rescan record.

An authoritative rescan reports and durably journals the successful post-attachment verification time that starts the remediation clock. The signed rescan attestations on the released digest are the authoritative history. Later rescans link the exact latest result, preserve the original start time while a finding remains active, and reject an active fixable finding at or beyond its configured deadline of at most 30 days.


## Supported tools<a id="supported-tools"></a>

The initial supported host-tool matrix is intentionally exact. ConClear resolves every executable at release start, records its version and digest, rejects an unsupported combination and rechecks the identities before later use, so a package upgrade during a run cannot silently change the toolchain.

| Tool | Version |
|---|---:|
| Git | 2.55.0 |
| Buildah | 1.43.2 |
| Podman | 5.8.4 |
| Skopeo | 1.22.2 |
| Hadolint | 2.14.0 |
| Trivy | 0.69.3 |
| Cosign | 3.1.3 |

Trivy is the only supported scanner stack. Production signing always uses Cosign 3 public Rekor logging and verifies log inclusion; there is no release option that disables upload or ignores the transparency log. Manual no-service signing experiments stay outside ConClear and use disposable keys, a no-service signing configuration, `--bundle` and `--insecure-ignore-tlog=true` as specified by the guide.


## Records and schemas<a id="records-schemas"></a>

Public qualification, transport, candidate, verification and rescan records each carry their own record schema version. Repository configuration, release profiles, provenance, rescan-triage input and command-result objects use their own independent schemas. Signed registry attestations are the authoritative retained evidence; workspace files are convenience copies.


## Conformance<a id="conformance"></a>

The generated [conformance catalog](./docs/conformance.md) maps stable `CCnnnn` identifiers to guide requirements, records which requirements need human review rather than a mechanical check, lists guide options that ConClear does not implement, and states the built-in limits that repository configuration may narrow but never disable.

[`ARCHITECTURE.md`](./ARCHITECTURE.md) is the behavioral contract behind those checks. The generated [contract inventory](./docs/contract-v1.json) lists the commands, options, schemas, record types, exit statuses and check identifiers that form the compatibility surface.


## Contributing<a id="contributing"></a>

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the contribution workflow and [`DEVELOPMENT.md`](./DEVELOPMENT.md) for the development environment, test tiers and the clean-checkout release gate.


## Licensing, copyright<a id="licensing-copyright"></a>

<!--REUSE-IgnoreStart-->
Copyright (c) 2026 [foundata GmbH](https://foundata.com/)

This project is licensed under the GNU General Public License v3.0 or later (SPDX-License-Identifier: `GPL-3.0-or-later`), see [`LICENSES/GPL-3.0-or-later.txt`](LICENSES/GPL-3.0-or-later.txt) for the full text.

The [`REUSE.toml`](REUSE.toml) file provides detailed licensing and copyright information in a human- and machine-readable format. This includes parts that may be subject to different licensing or usage terms, such as third-party components. The repository conforms to the [REUSE specification](https://reuse.software/spec/). You can use [`reuse spdx`](https://reuse.readthedocs.io/en/latest/readme.html#cli) to create a SPDX software bill of materials (SBOM).
<!--REUSE-IgnoreEnd-->

[![REUSE status](https://api.reuse.software/badge/github.com/foundata/conclear)](https://api.reuse.software/info/github.com/foundata/conclear)


### Trademarks<a id="trademarks"></a>

- Red Hat® and Quay® are trademarks of Red Hat, Inc., registered in the US and other countries
- Docker® is a trademark of Docker, Inc.
- Linux® is a registered trademark of Linus Torvalds

Their use here is purely descriptive and does not imply any affiliation with or endorsement by the trademark holders.


## Author information<a id="author-information"></a>

This project was created and is maintained by [foundata GmbH](https://foundata.com).
