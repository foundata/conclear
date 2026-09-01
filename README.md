# ConClear — container clearance before promotion

A tool implementing the technical parts of [foundata's OCI container image build and release guide](https://github.com/foundata/guidelines/blob/main/oci-container-image-guide.md):

`qualify` → `assemble` → `provenance` → `publish` → `attest` (sign) → `verify` → `promote`

ConClear takes a container image from a reviewed source commit to a signed, verified, and promoted digest. It lets you run the same qualify, sign, and verify steps whether you're on your laptop or in CI. It's designed to fail closed: if any check, signature, or verification step doesn't pass, nothing gets promoted, so what ends up published is always backed by evidence, not just trust.


## Table of contents<a id="toc"></a>

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Repository configuration](#usage-repository-configuration)
  - [Release profiles](#usage-release-profiles)
  - [Running a release](#usage-release)
  - [Resuming an interrupted run](#usage-resume)
  - [Composable commands](#usage-commands)
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

Release workflows additionally need the rootless container toolchain listed under [Supported tools](#supported-tools). The hermetic unit suite needs none of it.


## Usage<a id="usage"></a>

The `release` command runs the complete workflow. The sections below cover its repository inputs, external trust profile, recovery, distributed work, result contract and rescan triage.


### Repository configuration<a id="usage-repository-configuration"></a>

Repository behavior is declared in a reviewed `conclear.toml` at the selected source revision. It holds project facts and the exceptions the guide permits, never credentials. Unknown keys are errors, so a misspelled security setting cannot be silently ignored.


### Release profiles<a id="usage-release-profiles"></a>

Trust roots, signing keys and registry credentials stay outside the repository, in a named profile such as `$XDG_CONFIG_HOME/conclear/foundata.toml`:

```toml
mode = "local"
auth_file = "/home/example/.config/containers/auth.json"
quay_token_file = "/home/example/.config/conclear/quay.token"
cosign_private_key = "/home/example/.config/conclear/cosign.key"
cosign_public_key = "/home/example/.config/conclear/cosign.pub"
passphrase_file = "/home/example/.config/conclear/cosign.passphrase"
```

The profile and every secret file must be owned by the invoking user and carry private permissions. CI may supply the signing passphrase through `--passphrase-fd` instead of a file. Secret values are never accepted through project configuration, command-line literals or inherited environment variables.


### Running a release<a id="usage-release"></a>

The normal interface resolves a reviewed Git selector, creates a detached checkout, qualifies `linux/amd64` before any additional platform, assembles the accepted layouts, publishes one expiring Quay candidate, signs and verifies every digest and attestation, and promotes only the verified digest:

```sh
uv run conclear release --image app --revision v1.2.3 --version 1.2.3 --profile foundata
```

The ordinary checkout may be dirty. Uncommitted and untracked files cannot enter the build context.


### Resuming an interrupted run<a id="usage-resume"></a>

An interrupted run resumes only when its source, configuration, tool identities, artifacts and remote observations still match:

```sh
uv run conclear release --resume 01arz3ndektsv4rrffq69g5fav --profile foundata
```

A candidate reference is never reused for a second publication attempt. If an ambiguous write cannot be resolved conclusively to the expected digest within its lifetime, the release restarts as a new run.


### Composable commands<a id="usage-commands"></a>

`release` is the normal interface. The composable commands support diagnosis, distributed platform work and recovery without defining an alternative workflow: `doctor`, `check`, `pins check`, `build`, `test`, `evidence`, `qualify`, `assemble`, `provenance`, `publish`, `attest`, `verify`, `promote`, `rescan` and `cleanup`. Run any of them with `--help` for its exact inputs.

No command offers an option that disables a gate, skips verification or affects transparency-log behavior.


### Distributed qualification<a id="usage-distributed"></a>

The coordinator takes `data.databaseDigest` from the first `qualify --format json` result and distributes `$XDG_CACHE_HOME/conclear/trivy/snapshots/<digest-without-sha256-prefix>` unchanged to every later worker. Each later worker then pins that exact vulnerability database:

```sh
uv run conclear qualify --database-digest sha256:<digest> ...
```

ConClear selects that directory directly, recomputes its content digest and fails before building if it differs.


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

Public qualification, candidate, verification and rescan records each carry their own record schema version. Repository configuration, release profiles, provenance, rescan-triage input and command-result objects use their own independent schemas. Signed registry attestations are the authoritative retained evidence; workspace files are convenience copies.


## Conformance<a id="conformance"></a>

The generated [conformance catalog](./docs/conformance.md) maps stable `CCnnnn` identifiers to guide requirements, records which requirements need human review rather than a mechanical check, lists guide options that ConClear does not implement, and states the built-in limits that repository configuration may narrow but never disable.

[`ARCHITECTURE.md`](./ARCHITECTURE.md) is the behavioral contract behind those checks.


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
