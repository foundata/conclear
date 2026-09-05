# ConClear — container clearance before promotion

ConClear implements the technical parts of [foundata's OCI container image build and release guide](https://github.com/foundata/guidelines/blob/main/oci-container-image-guide.md). It takes a container image from a reviewed source commit to a signed, verified and promoted digest:

`qualify` → `assemble` → `provenance` → `publish` → `attest` (sign) → `verify` → `promote`

A container project adopts it by adding a repository configuration, making each Containerfile comply with the guide and declaring any runtime inputs its tests need.


## Table of contents<a id="toc"></a>

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Getting started](#usage-getting-started)
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

- **One command from reviewed commit to promoted digest:** `conclear release` builds, tests, scans, signs, verifies and promotes an image, and it implements the rules of a published guide instead of a homegrown checklist.
- **Same workflow on a laptop and in CI:** there is no separate CI mode, and a maintainer workstation can produce a fully verified release without special services.
- **Rootless and daemonless toolchain:** [Buildah](https://github.com/containers/buildah), [Podman](https://github.com/containers/podman) and [Skopeo](https://github.com/containers/skopeo), with no Docker daemon anywhere in the workflow.
- **Signed, logged and auditable:** [Cosign](https://docs.sigstore.dev/cosign/) signs every released digest and always records it in the public transparency log; there is no switch to turn that off. Each release decision is also kept as a schema-validated JSON record with a stable digest, so it can be reconstructed later without relying on logs.
- **Promotion moves tags, never content:** the exact digest that passed every gate is the one consumers receive.
- **Usable day to day:** multi-platform images can be qualified on separate machines and assembled into one verified index, base-image pins can be updated locally without a bot (verified and all-or-nothing), and a policy rejection never looks like an operational failure in human output, JSON output or exit status.


## Installation<a id="installation"></a>

ConClear is published on PyPI as [`conclear`](https://pypi.org/project/conclear/) and requires Python 3.12 or newer. Install it as a tool with [uv](https://docs.astral.sh/uv/):

```sh
uv tool install conclear
conclear version
```

`pipx install conclear`, or `pip install conclear` inside a virtual environment, works as well. Release workflows also need the rootless container toolchain listed under [Supported tools](#supported-tools).

Development happens in a source checkout as described in [`DEVELOPMENT.md`](./DEVELOPMENT.md). A checkout is enough to explore the commands and run the unit suite, but it cannot emit release evidence; only a built distribution such as the published package can.


## Usage<a id="usage"></a>

### Getting started<a id="usage-getting-started"></a>

The [quick start](./docs/quickstart.md) is the path from an empty container project to a first release: the repository files, a compliant Containerfile and build context, `conclear.toml`, runtime test inputs, the local checks, a first qualification and candidate, pin updates, the release profile and the release itself.

In short: repository behavior is declared in a reviewed `conclear.toml` at the selected source revision, which holds project facts and the exceptions the guide permits, never credentials. Images whose tests need fixtures, generated outputs or sibling images describe them in `[images.test]`. Trust roots, signing keys and registry credentials stay outside the repository in a named release profile.


### Running a release<a id="usage-release"></a>

`release` runs the complete workflow from a reviewed Git selector through promotion:

```sh
conclear release --image app --revision v1.2.3 --version 1.2.3 --profile foundata
```

The quick start explains what the command does at each stage under [Check and run the release environment](./docs/quickstart.md#11-check-and-run-the-release-environment).


### Resuming an interrupted run<a id="usage-resume"></a>

An interrupted run resumes only when its source, configuration, tool identities, artifacts and remote observations still match:

```sh
conclear release --resume 01arz3ndektsv4rrffq69g5fav --profile foundata
```

A candidate reference is never reused for a second publication attempt. If an ambiguous write cannot be resolved conclusively to the expected digest within its lifetime, the release restarts as a new run.


### Composable commands<a id="usage-commands"></a>

`release` is the normal interface. The composable commands support diagnosis, distributed platform work and recovery without defining an alternative workflow: `doctor`, `check`, `pins check`, `pins propose`, `pins apply`, `build`, `test`, `evidence`, `qualify`, `transport export`, `assemble`, `provenance`, `publish`, `attest`, `verify`, `promote`, `rescan` and `cleanup`. Run any of them with `--help` for its exact inputs.

No command offers an option that disables a gate, skips verification or affects transparency-log behavior.


### Distributed qualification<a id="usage-distributed"></a>

`release` qualifies every platform in one process. When platforms are qualified on separate workers, or when one workstation qualifies them in separate runs, each `qualify` produces its own worker run, and a coordinator assembles the accepted qualifications in a new run of its own. This workflow needs no release profile, registry credentials, signing material or publication.

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

`transport export` writes a new archive, or a directory with `--kind directory`, containing only the immutable qualification record, its OCI layout and the evidence payloads the record names, plus a schema-validated `transport.json` manifest that binds every member by digest. It refuses an existing destination and never includes logs, tool environments, container storage, test inputs, secret outputs, private keys or authentication files. Its JSON result reports the identifiers that a coordinator must receive through a channel other than the transport itself:

| Identifier | Meaning |
|---|---|
| worker run ID | The lowercase ULID of the `qualify` run that produced the qualification. It stays in the record and in the candidate. |
| coordinator run ID | The new lowercase ULID that `assemble` generates. It names the candidate reference and owns the assembled layout. |
| qualification-record digest | SHA-256 of the exact `platform-qualification.json` bytes (`recordDigest`). |
| transport digest | SHA-256 of the archive file, or of `transport.json` for a directory transport (`transportDigest`). `assemble` requires it as its second `--transport` value. |
| platform manifest digest | Digest of the platform's OCI image manifest (`platformManifestDigest`), which becomes one index entry. |
| assembled index digest | Digest of the assembled image index, or of the single manifest for a one-platform image (`subjectDigest`). |

`assemble` creates the coordinator run from the reviewed source revision, so the coordinator needs the repository checkout but no worker workspace. It compares each transport with the caller-supplied digest before trusting any member, extracts only regular files below a bounded, confined staging directory, verifies every member, the record digest, the layout graph, the platform descriptor and the evidence payloads, and then checks that all qualifications agree on image, source revision, configuration digest, guide and ConClear identity, tool versions, pin resolutions, effective limits, release version and vulnerability database. It rejects missing, duplicate and unexpected platforms and any qualification produced by another ConClear revision. The candidate record names the coordinator run and every worker run with its record and transport digests, and the assembled index carries exactly one verified manifest per required platform. `provenance`, `publish`, `attest`, `verify` and `promote` then continue on the coordinator run. Copying worker workspaces or records by hand is not a supported operation; assembly accepts only transports it can verify.

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
