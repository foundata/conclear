# ConClear — container clearance before promotion

ConClear is a command-line application for checking, building, testing, qualifying, publishing, signing, verifying and promoting OCI container images. It implements the automatable requirements of the foundata [OCI container image build and release guide](https://github.com/foundata/guidelines/blob/909794089dbabbf6c8d8e50fcf47bb2b6fd315b9/oci-container-image-guide.md) through one digest-bound workflow that runs on a maintainer workstation or in protected CI.

ConClear requires Python 3.12 or newer. Release workflows use rootless Buildah, Podman and Skopeo, with Hadolint for Containerfile linting, Trivy for scanning and SBOM generation, Cosign for signing and attestations, and Quay for public publication.

Install the locked development environment and inspect the command surface:

```sh
uv sync --dev
uv run conclear --help
```

Repository behavior is declared in `conclear.toml`. Trust roots, signing keys and registry credentials stay outside the repository in a named release profile under `$XDG_CONFIG_HOME/conclear/`.

The normal interface resolves a reviewed Git selector, creates a detached checkout, qualifies `linux/amd64` before any additional platforms, assembles the accepted layouts, publishes one expiring Quay candidate, signs and verifies every digest and attestation, and promotes only the verified digest:

```sh
uv run conclear release --image app --revision v1.2.3 --version 1.2.3 --profile foundata
```

An interrupted run can resume only when its source, configuration, tool identities, artifacts and remote observations still match:

```sh
uv run conclear release --resume 01arz3ndektsv4rrffq69g5fav --profile foundata
```

The composable commands are `doctor`, `check`, `pins check`, `build`, `test`, `evidence`, `qualify`, `assemble`, `provenance`, `publish`, `attest`, `verify`, `promote`, `release`, `rescan` and `cleanup`. Run any command with `--help` for its exact inputs.

For distributed qualification, the coordinator takes `data.databaseDigest` from the first `qualify --format json` result and distributes `$XDG_CACHE_HOME/conclear/trivy/snapshots/<digest-without-sha256-prefix>` unchanged to every later worker. Each later worker invokes `qualify --database-digest sha256:<digest>`; ConClear selects that directory directly, recomputes its content digest and fails before building if it differs.

Every command that produces a result supports `--format json`. JSON mode writes exactly one schema-validated object to standard output. Exit status `0` is success, `1` is operational failure, `2` is rule rejection and `64` is invalid invocation or configuration.

Public qualification, candidate, verification and rescan records use record schema version 6. Repository configuration, rescan-triage input and command-result objects use their independent version 1 schemas.

## Supported tools

The initial supported host-tool matrix is intentionally exact:

| Tool | Version |
|---|---:|
| Git | 2.55.0 |
| Buildah | 1.43.2 |
| Podman | 5.8.4 |
| Skopeo | 1.22.2 |
| Hadolint | 2.14.0 |
| Trivy | 0.69.3 |
| Cosign | 3.1.3 |

Production signing always uses Cosign 3 public Rekor logging and verifies log inclusion. ConClear exposes no release option that disables upload or ignores the transparency log. Manual no-service signing experiments stay outside ConClear and use disposable keys, a no-service signing configuration, `--bundle`, and `--insecure-ignore-tlog=true` as specified by the guide.

## Rescan triage

`rescan` accepts externally owned vulnerability decisions through `--triage-file`. Each decision must name the exact immutable rescan subject and one platform in that subject, and duplicate platform, component and advisory identities are rejected.

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

An exact `not-applicable` decision suppresses only its matching platform, component and advisory finding. An exact `remediated` decision closes deadline tracking for its matching finding and must name the immutable remediating digest, but it does not erase the scanner observation. `affected` and `remediation-planned` findings remain active. Exact, unexpired vulnerability exceptions from the release configuration are evaluated separately and every applied exception is included in the new linked rescan record.

An authoritative rescan reports and durably journals the successful post-attachment verification time that starts the remediation clock. Later authoritative and diagnostic rescans must link the exact latest result from protected state outside the checkout, preserve the original start time while a finding remains active and reject an active fixable finding at or beyond its configured deadline of at most 30 days.

## Release profiles

A release profile is a private file such as `$XDG_CONFIG_HOME/conclear/foundata.toml`:

```toml
mode = "local"
auth_file = "/home/example/.config/containers/auth.json"
quay_token_file = "/home/example/.config/conclear/quay.token"
cosign_private_key = "/home/example/.config/conclear/cosign.key"
cosign_public_key = "/home/example/.config/conclear/cosign.pub"
passphrase_file = "/home/example/.config/conclear/cosign.passphrase"
```

The profile and secret files must be owned by the invoking user and have private permissions. CI may supply the signing passphrase through `--passphrase-fd` instead of a file. Secret values are not accepted through ordinary project configuration or inherited environment variables.

## Conformance

The generated [conformance catalog](docs/conformance.md) maps stable `CCnnnn` identifiers to guide requirements and records the built-in limits that repository configuration may narrow but never disable.

Development setup, test markers and the clean-checkout release gate are documented in [DEVELOPMENT.md](DEVELOPMENT.md). See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change.

ConClear is licensed under GPL-3.0-or-later.
