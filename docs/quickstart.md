# ConClear quick start

ConClear takes a reviewed Git commit through local qualification, publication, signing, verification and tag promotion. A container project adopts it by adding a repository configuration, making each Containerfile comply with the guide and defining any runtime inputs that its tests need. Release credentials and trust policy stay outside the project repository.

This quick start covers the basic adoption path. See the [architecture](../ARCHITECTURE.md) for the complete behavioral contract and the [conformance catalog](./conformance.md) for the checks that ConClear applies.


## Contents

- [1. Install ConClear and its tools](#1-install-conclear-and-its-tools)
- [2. Prepare the repository](#2-prepare-the-repository)
- [3. Make the Containerfile qualify](#3-make-the-containerfile-qualify)
- [4. Define the build context](#4-define-the-build-context)
- [5. Add `conclear.toml`](#5-add-concleartoml)
- [6. Describe application test inputs when needed](#6-describe-application-test-inputs-when-needed)
- [7. Run the local checks](#7-run-the-local-checks)
- [8. Create a release profile](#8-create-a-release-profile)
- [9. Check and run the release environment](#9-check-and-run-the-release-environment)
- [10. Use the same commands in CI](#10-use-the-same-commands-in-ci)


## 1. Install ConClear and its tools

ConClear requires Python 3.12 or newer. Use an identity-bearing wheel for qualification or release work. A development checkout identifies itself as `development-source-tree` and cannot emit release evidence.

Install a retained wheel in a dedicated environment:

```sh
uv venv ~/.local/share/conclear/venv
uv pip install \
  --python ~/.local/share/conclear/venv/bin/python \
  /secure/path/conclear-0.1.0-py3-none-any.whl

~/.local/share/conclear/venv/bin/conclear version --format json
```

ConClear currently accepts these exact tool versions:

|   Tool   | Version |
| -------- | ------- |
| Git      | 2.55.0  |
| Buildah  | 1.43.2  |
| Podman   | 5.8.4   |
| Skopeo   | 1.22.2  |
| Hadolint | 2.14.0  |
| Trivy    | 0.69.3  |
| Cosign   | 3.1.3   |

Use rootless Buildah and Podman. ConClear creates isolated storage for each run and does not use the workstation's existing containers or images.


## 2. Prepare the repository

ConClear reads a committed Git revision through an isolated checkout. The configured source URL must match the checkout's observed Git remote. Uncommitted and untracked files do not enter a release build.

Add these files to the container project:

- `conclear.toml` describes images, platforms, runtime behavior, test inputs, release tags and pinned image inputs.
- `.containerignore` defines the effective build context.
- Each Containerfile supplies the required OCI metadata and follows the guide's build rules.
- Optional repository hooks add application assertions after ConClear's built-in runtime checks pass.

Do not store registry credentials, signing keys, builder identities or signer identities in the project repository.


## 3. Make the Containerfile qualify

Every external image in `FROM` or `COPY --from` must use a fully qualified tag and digest. Declare the same reference in `conclear.toml`; ConClear rejects undeclared and unused pins.

The final image must use a numeric, non-root user and JSON-array `ENTRYPOINT` or `CMD`. Do not add Docker-format `HEALTHCHECK` metadata. Declare the health command in `conclear.toml` so ConClear can run and record it itself.

ConClear supplies `IMAGE_REVISION`, `IMAGE_CREATED`, `IMAGE_VERSION` when a version was requested, and `SOURCE_DATE_EPOCH`. The built image must record the observed source and revision, plus non-empty title and license labels. When present, version and creation labels must match the supplied values.

A minimal pattern is:

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

Projects without release versions omit `IMAGE_VERSION` and the corresponding label.


## 4. Define the build context

`.containerignore` must effectively exclude source-control data, environment files, private keys and local environments. ConClear evaluates the ordered rules instead of requiring one particular spelling.

A default-deny allowlist is usually the shortest safe form:

```gitignore
*
!Containerfile
!conclear.toml
!app
```

Keep later negations narrow. A rule that re-includes `.git`, `.env`, a private-key extension or a virtual environment is rejected with `CC0202`, including nested variants.


## 5. Add `conclear.toml`

This example declares one `linux/amd64` service image:

```toml
schema_version = 1

[project]
name = "example"
source = "https://git.example.com/foundata/example"

[[images]]
id = "app"
repository = "quay.io/foundata/example"
platforms = ["linux/amd64"]
arm64_omission_reason = "The required runtime dependency is not available for arm64."
scanner = "trivy"

[images.release]
immutable_tags = ["{version}"]
moving_tags = ["stable"]

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
reference = "quay.io/example/base:1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
tag_intent = "immutable-version"
```

Every image must include `linux/amd64`. Add `linux/arm64` when the image supports it; otherwise record the reason in `arm64_omission_reason`. `containerfile` defaults to `Containerfile` and `context` to `.`, both relative to the repository root. `native_test_platforms` identifies platforms that must run without emulation and defaults to `["linux/amd64"]`. `scanner` is optional and currently accepts only `trivy`; it documents the gating scanner for the reader.

Use `profile = "one-shot"` for a command that should exit. The test launch contract may set its expected exit status. The root filesystem is always read-only, so runtime writable paths must be listed explicitly. Repository configuration can narrow ConClear's built-in time limits in `[images.limits]` but cannot extend or disable them.


## 6. Describe application test inputs when needed

An image that starts without extra input needs no `[images.test]` table. For an input-dependent service or one-shot tool, declare the inputs instead of hiding startup behind a hook.

The test model supports:

- Reviewed repository fixtures, always mounted read-only.
- Run-owned generated outputs at declared writable destinations.
- Secret outputs whose paths and content digests never enter public evidence.
- Ordered preparation commands executed inside the primary image or an exact sibling image.
- Launch arguments and non-secret environment values that preserve the image's original entrypoint.
- Sibling image dependencies built from the same source revision, timestamp, platform, version input and Buildah toolchain.

For example, a runtime image can depend on a generator image declared in the same file:

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
command = ["/usr/local/bin/generator", "--input", "/input", "--key", "/key", "--output", "/output"]
timeout_seconds = 300
expected_exit_status = 0
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

A mount names a declared fixture or output and is read-only unless it sets `read_only = false`. Every output must have a writable producer before it is consumed. In this example, the `generator` image must declare `/output` in its own `images.runtime.writable_mounts`.

ConClear still owns layout validation, digest-preserving import, container hardening, startup, health, signal and exit observation, journaling and cleanup. Hooks can add application assertions, but they cannot replace or mark those checks as passed.


## 7. Run the local checks

Run the static checks first:

```sh
conclear check --image app
```

Resolve the declared tags and update the durable pin history:

```sh
conclear pins check --image app
```

Qualify one platform from a reviewed commit:

```sh
conclear qualify \
  --source . \
  --revision HEAD \
  --image app \
  --version 1.2.3 \
  --platform linux/amd64 \
  --format json
```

ConClear writes run state below `$XDG_STATE_HOME/conclear/` and keeps Trivy database snapshots below `$XDG_CACHE_HOME/conclear/`. Preserve the protected pin history and distribute the exact selected Trivy database snapshot when qualification runs on more than one worker.


## 8. Create a release profile

The complete release needs a maintainer-controlled profile outside the application repository. For example, create `$XDG_CONFIG_HOME/conclear/foundata.toml`:

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

The profile and secret files must belong to the invoking user and have private permissions. `cosign_private_key` may instead name a supported KMS or HSM handle. Automation can provide the passphrase through `--passphrase-fd` rather than a file.

`builder.id` identifies the documented build environment, not ConClear itself. Use a different builder URI for a materially different workstation or CI trust boundary.

`ci_context = "observe"` adds provider correlation data when ConClear recognizes complete CI metadata that agrees with the isolated checkout. Use `omit` to ignore CI variables or `require` when the release must have recognized matching CI context. CI metadata never determines source, builder, signer, digest or verdict.


## 9. Check and run the release environment

`doctor` checks the project configuration, supported tools, target execution, registry access, signing configuration and public Sigstore services without publishing or signing:

```sh
conclear doctor --config conclear.toml --profile foundata
```

Run the complete workflow from a reviewed tag or commit:

```sh
conclear release \
  --source . \
  --revision v1.2.3 \
  --image app \
  --version 1.2.3 \
  --profile foundata
```

The workflow is `qualify`, `assemble`, `provenance`, `publish`, `attest`, `verify` and `promote`. A rejection or operational failure stops promotion.

Quay is currently the only registry backend for the complete publication workflow. Projects targeting another registry can use local qualification, assembly and provenance, but cannot use ConClear's `publish` through `promote` stages there yet.


## 10. Use the same commands in CI

ConClear has no separate CI execution mode. A CI job invokes the same CLI and supplies the protected profile, credentials, cache and state through its normal secret and artifact mechanisms.

Do not pass source identity, builder identity, signer identity, release verdicts or artifact digests through repository configuration or ordinary environment variables. ConClear derives source facts from the isolated checkout and treats recognized CI variables only as optional correlation data.

JSON mode writes one result object to standard output and diagnostics to standard error. Its exit statuses are:

| Exit | Meaning |
| ---: | ------- |
|  `0` | Success |
|  `1` | Operational failure because ConClear could not establish fact |
|  `2` | Rule rejection |
| `64` | Invalid invocation or configuration |

Persist the evidence artifacts and authoritative signed attestations required by your release process. Do not treat logs or a mutable registry tag as release evidence.
