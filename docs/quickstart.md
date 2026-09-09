# ConClear quick start

Run ConClear from a native Linux workstation or VM, without CI. This path covers
one image; publication requires a
[compatible Quay deployment](#5-prepare-release-access). Run repository commands
from the image project's root, as a normal user.

## 1. Install ConClear and host tools

Use Python 3.12 or newer and a verified ConClear wheel:

```sh
uv tool install /path/to/conclear-VERSION-py3-none-any.whl
conclear version --format json
```

Replace the wheel path with your reviewed distribution. A development checkout
identifies itself as `development-source-tree` and cannot emit release evidence.
See [development and packaging](../DEVELOPMENT.md#releases) for building a
wheel. Install the [supported host tools](./native-tool-installation.md),
including rootless Buildah and Podman. Host-tool discovery ignores your shell's
`PATH` and excludes `~/.local/bin`.

## 2. Add repository configuration

For an existing Containerfile, generate a draft:

```sh
conclear adopt --output conclear.toml
```

`adopt` refuses to overwrite an existing file. Resolve every `DECIDE` value;
validation reports unresolved decisions together. It observes source facts but
cannot choose measured resource limits, release roles or exception rationales.

For one service image, the configuration has this shape. Replace the example
identities and resource numbers with your project's facts and measurements:

```toml
schema_version = 1

[project]
name = "example"
source = "https://git.example.com/foundata/example"

[[images]]
id = "app"
repository = "quay.io/foundata/example"
platforms = ["linux/amd64"]

[images.release]
version_tags = ["{version}"]
moving_tags = ["latest"]

[images.runtime]
profile = "service"
user = 65532
writable_mounts = ["/tmp"]
memory = "512MiB"
cpus = 1.0
pids = 256
nofile = 1024
health_command = ["/usr/local/bin/app", "health"]

[[images.pins]]
reference = "quay.io/example/base:1"
tag_intent = "immutable-version"
```

`source` is the canonical, credential-free HTTPS Git URL; an equivalent SSH
origin is accepted. Keep credentials and signing identities out of this file.
`containerfile` defaults to `Containerfile`, and `context` to `.`. Platforms
stay explicit: include `linux/amd64`, optionally `linux/arm64`. Commands infer
`--image` only when there is exactly one release image.

Pin declarations contain the readable tag and intent only. The Containerfile
supplies its digest. Every external `FROM`, `COPY --from` and
`RUN --mount=from` image needs exactly one matching declaration; local stages
and `scratch` need none. Unused or ambiguous declarations are rejected.

Choose `one-shot` for a command that exits, or `systemd` for a system manager.
Starting as root, supporting sudo and making the root filesystem writable need
separate reviewed requirements with rationale, owner and review trigger. Sudo
escalation also needs permitted/denied caller tests and explicitly declared
capabilities; it never enables privileged containers. Review inherited set-ID
executables separately. See the
[configuration and runtime contract](../ARCHITECTURE.md#configuration-and-trust-inputs)
for these options and `[images.test]` fixtures, generated outputs and
dependencies. Omit optional tables you do not need.

## 3. Prepare the Containerfile and build context

The example below assumes an existing application with an `app health` command.
Replace the illustrative base reference and all-`a` digest with a reviewed,
real pin; use labels appropriate to your project:

```dockerfile
FROM quay.io/example/base:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

ARG IMAGE_CREATED
ARG IMAGE_REVISION
ARG IMAGE_VERSION
ARG SOURCE_DATE_EPOCH

COPY --chmod=0555 app /usr/local/bin/app

LABEL org.opencontainers.image.created="${IMAGE_CREATED}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.source="https://git.example.com/foundata/example" \
      org.opencontainers.image.title="Example" \
      org.opencontainers.image.version="${IMAGE_VERSION}"

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/app"]
```

ConClear supplies the build arguments. Match the numeric `USER` to the runtime
configuration, use JSON-array commands, and put health checks in
`conclear.toml`, not Docker-format `HEALTHCHECK` metadata. Declare all writable
destinations, including inherited `VOLUME` paths. Check the
[supported Containerfile syntax](../ARCHITECTURE.md#supported-containerfile-syntax)
when using builder extensions.

Add a default-deny `.containerignore`, allowing only required build inputs:

```gitignore
*
!Containerfile
!conclear.toml
!app
```

Expand this allowlist for your build without re-including `.git`, environment
files, private keys or local virtual environments.

## 4. Check locally

Choose the intended image version and inspect the effective configuration:

```sh
version=1.2.3
conclear config show --version "$version"
conclear check
conclear pins check
conclear doctor --scope qualify
```

`config show` displays defaults and decision reasons and validates rendered tags
without host tools or network access. `check` runs static checks and Hadolint;
`pins check` resolves tags and updates durable pin history. `doctor` checks
local tool and rootless-runtime readiness. Fix every rejection.

Commit the reviewed configuration, Containerfile, ignore file and test inputs
before qualification or release. ConClear builds an isolated committed revision;
uncommitted and untracked changes are excluded.

To qualify one platform without publication or release credentials:

```sh
conclear qualify --revision HEAD --version "$version" \
  --platform linux/amd64 --format json
```

This is optional before `release`, which performs fresh qualification itself.
For separate platform workers and manual assembly, use the
[distributed workflow](../README.md#usage-distributed).

## 5. Prepare release access

`quay` is the only implemented publication backend. Provision a destination
repository with writer access and Cosign-compatible referrers, a containers-auth
file and a separate Quay API token. Scope writers to the intended repositories.
The token needs repository access for tag observation, assignment and deletion;
required tag protection also needs repository and organization policy access.

Prefer selective protection for version tags, excluding `latest` and generated
candidates. Where it is unavailable, explicitly accept its absence with an
owner and rationale. The example below uses that choice and native tag
expiration.

Reuse one protected release profile for your organization's build trust domain.
With an encrypted Cosign keypair and the credential files provisioned, create
`${XDG_CONFIG_HOME:-$HOME/.config}/conclear/foundata.toml` outside the image
repository. Adjust these paths and identities:

```toml
schema_version = 1
ci_context = "observe"
auth_file = "~/.config/containers/auth.json"
cosign_private_key = "~/.config/conclear/cosign.key"
cosign_public_key = "~/.config/conclear/cosign.pub"

[builder]
id = "https://foundata.com/en/projects/conclear/builder/simple-v1/"

[registry]
provider = "quay"
host = "quay.io"
api_url = "https://quay.io/api/v1"
token_file = "~/.config/conclear/quay.token"

[registry.tag_protection]
mode = "not-enforced"
rationale = "Selective version-tag protection is unavailable on this deployment."
owner = "Release maintainer"

[registry.candidate_cleanup]
mode = "tag-expiration"
owner = "Release maintainer"
procedure = "Review abandoned runs daily; run conclear cleanup before discarding state."
```

Use `mode = "required"` without rationale or owner in `tag_protection` when
selective protection is available. ConClear verifies existing policies; it does
not create them. Cleanup can instead select `manual` or `auto-prune`; all modes
need an owner and procedure. Auto-prune establishes a candidate-only policy
before upload and also sets tag expiration. Chosen controls fail closed;
ConClear never downgrades after an API error. See the
[publication contract](../ARCHITECTURE.md#publication-and-promotion).

The rationale, owner and procedure are retained in public release evidence.
Use non-secret descriptions.

Keep the profile and secret files owned by the invoking user with mode `0600`.
ConClear prompts for the signing passphrase; automation can use a protected
`passphrase_file` or `--passphrase-fd`. Never supply secrets as command-line
values, repository configuration or ordinary environment variables.

`builder.id` must document your actual build trust domain. The example is
foundata's workstation policy, claiming SLSA Build L1; another organization or
materially different build environment needs its own identity. CI execution
alone does not raise that assurance level.

## 6. Release the committed revision

```sh
conclear doctor --profile foundata
conclear release --revision HEAD --version "$version" --profile foundata
```

Release-scope `doctor` checks tools, profile, registry tag access and Sigstore
initialization. It does not test policy enforcement or replace a complete
release drill. `release` qualifies all declared platforms, assembles the
candidate, publishes, signs, verifies and promotes only the verified digest.

For the example, `1.2.3` becomes a version tag and `latest` moves to the same
digest. Changed image bytes can reuse a requested version only while its final
tag is absent; an existing final tag must keep its digest. Without registry
protection, other writers can still change it; restrict their permissions. See
[resume](../README.md#usage-resume) for interrupted runs.

Finish within the reported qualification window; expiry requires new
qualification. Candidates also have a fixed authorization deadline recorded
before upload; cleanup settings and retries cannot extend it. Keep
durable pin history across releases and retain run evidence before cleanup.
See [limits](../ARCHITECTURE.md#built-in-limits) and
[evidence retention](./evidence-retention.md).

## 7. Maintain the image

Use the pin updater for new base-image digests:

```sh
conclear pins propose --output ../pins-proposal.json
conclear pins apply --proposal ../pins-proposal.json
conclear pins check
conclear check
git diff
```

Review the diff, run project tests and commit before releasing again. Pin
updates change only Containerfile digests; changes under immutable-version tags
require supply-chain review. See the
[pin-update contract](../ARCHITECTURE.md#pin-updates).

Retain non-secret reports and the exact release source/configuration before
cleanup. The [retention recipe](./evidence-retention.md) also shows historical
rescans with fresh vulnerability data. Assign owners for keys, registry writers,
candidate retention, supported-release inventory, scheduled rescans, triage and
rebuilds. Cron or a systemd timer can schedule work on a managed host with
preserved state and monitoring; CI may call the same CLI but is optional.

Reference: [architecture](../ARCHITECTURE.md),
[conformance checks](./conformance.md),
[implementation matrix](./implementation-1.0.0.md).
