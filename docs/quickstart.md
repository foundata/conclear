# ConClear quick start

ConClear takes a reviewed Git commit through local qualification, publication,
signing, verification and tag promotion.

A container project adopts it by adding a repository configuration, making each
Containerfile comply with the guide and declaring any runtime inputs its tests
need. Release credentials and trust policy stay outside the project repository.

This quick start is the shortest path from installation to a first release. The
[README](../README.md) is the project overview, the
[architecture](../ARCHITECTURE.md) is the current behavioral contract, the
[implementation matrix](./implementation-1.0.0.md) links its promises to code
and tests, and the [conformance catalog](./conformance.md) lists the checks
ConClear applies.


## Contents

- [1. Install ConClear and its tools](#1-install-conclear-and-its-tools)
- [2. Prepare the repository](#2-prepare-the-repository)
- [3. Make the Containerfile qualify](#3-make-the-containerfile-qualify)
- [4. Define the build context](#4-define-the-build-context)
- [5. Add `conclear.toml`](#5-add-concleartoml)
- [6. Describe application test inputs when needed](#6-describe-application-test-inputs-when-needed)
- [7. Run the local checks](#7-run-the-local-checks)
- [8. Assemble a release candidate](#8-assemble-a-release-candidate)
- [9. Update pinned references](#9-update-pinned-references)
- [10. Create a release profile](#10-create-a-release-profile)
- [11. Check and run the release environment](#11-check-and-run-the-release-environment)
- [12. Use the same commands in CI](#12-use-the-same-commands-in-ci)
- [13. Retain evidence and operate supported releases](#13-retain-evidence-and-operate-supported-releases)


## 1. Install ConClear and its tools

ConClear requires Python 3.12 or newer. Install the published package as a tool
and confirm its identity:

```sh
uv tool install conclear
conclear version --format json
```

`pipx install conclear`, or `pip install conclear` inside a virtual environment,
works as well. Use the published package for qualification and release work: a
development checkout identifies itself as `development-source-tree` and cannot
emit release evidence.

Qualification and release also need the rootless container toolchain. ConClear
accepts each tool within the accepted version interval listed under
[Supported tools](../README.md#supported-tools) in the README, rejects the
listed excluded versions, and records the exact version it used; the table
also names the versions the real-tool tests exercised. A distribution package
may lag behind an accepted line, Trivy in particular. The
[native-tool installation recipe](./native-tool-installation.md) provides
verified release artifacts, the exact search path and installation diagnostics.
An executable in `~/.local/bin` is outside ConClear's host-tool search path.
Use rootless Buildah and Podman; ConClear creates isolated storage for each run
and does not use the workstation's existing containers or images.


## 2. Prepare the repository

ConClear reads a committed Git revision through an isolated checkout. Configure
the credential-free canonical HTTPS repository identity. The checkout's observed
remote may use that HTTPS URL or the equivalent `git@host:owner/repository.git`
or `ssh://git@host/owner/repository.git` form; ConClear canonicalizes supported
SSH transports before comparison and records only HTTPS in evidence. The
ordinary checkout may be dirty: uncommitted and untracked files do not enter a
release build.

Add these files to the container project:

- `conclear.toml` describes images, platforms, runtime behavior, test inputs,
  release tags and pinned image inputs.
- `.containerignore` defines the effective build context.
- Each Containerfile supplies the required OCI metadata and follows the guide's
  build rules.
- Optional repository hooks add application assertions after ConClear's built-in
  runtime checks pass.

Do not store registry credentials, signing keys, builder identities or signer
identities in the project repository.


## 3. Make the Containerfile qualify

Every external image in `FROM`, `COPY --from` or `RUN --mount=...,from=...` must
use a fully qualified tag and digest. Declare the same reference in
`conclear.toml`; ConClear rejects undeclared and unused pins. Check the
[supported Containerfile syntax](../ARCHITECTURE.md#supported-containerfile-syntax)
before adopting files with builder extensions. Heredocs, backtick escapes and
`ONBUILD` are outside ConClear's current subset.

The final image must use the numeric user declared in `conclear.toml` and a
JSON-array `ENTRYPOINT` or `CMD`. Use a non-zero UID unless the image has a
reviewed root requirement as described below. Do not add Docker-format
`HEALTHCHECK` metadata. Declare the health command in `conclear.toml` so
ConClear can run and record it itself.

ConClear supplies `IMAGE_REVISION`, `IMAGE_CREATED`, `IMAGE_VERSION` when a
version was requested, and `SOURCE_DATE_EPOCH`. The built image must record the
observed source and revision, plus non-empty title and license labels. When
present, version and creation labels must match the supplied values.

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

Projects without release versions omit `IMAGE_VERSION` and the corresponding
label.


## 4. Define the build context

`.containerignore` must effectively exclude source-control data, environment
files, private keys and local environments. ConClear evaluates the ordered rules
instead of requiring one particular spelling.

A default-deny allowlist is usually the shortest safe form:

```gitignore
*
!Containerfile
!conclear.toml
!app
```

Keep later negations narrow. A rule that re-includes `.git`, `.env`, a
private-key extension or a virtual environment is rejected with `CC0202`,
including nested variants.


## 5. Add `conclear.toml`

`conclear.toml` is reviewed at the selected source revision and holds project
facts and the exceptions the guide permits, never credentials. Unknown keys are
errors, so a misspelled security setting cannot be silently ignored.

An existing repository can start by using the `conclear adopt` command. It reads
the conventional Containerfiles and the Git origin, changes nothing, and prints
what it observed, what it suggests and what only you can decide. The
Containerfile's entrypoint selects the proposed runtime profile before the
checks run, so a systemd image is held to `USER 0`, a root requirement and
`STOPSIGNAL SIGRTMIN+3` while every other image is held to a numeric non-root
user. A conventional root Containerfile gets the repository root as a suggested
build context, and the draft omits `context` because `.` is the default; a
nested or explicitly selected Containerfile leaves the context a decision with a
`DECIDE` placeholder. Every image carries a decision whether it is released or
exists only as a test dependency, and a project with several images carries a
decision about which image depends on which; the draft explains that a test-only
image drops `repository` and `[images.release]` and must be listed in a
depending image's `[images.test]` dependencies. With `--output` the command
writes a draft whose unresolved values are marked `DECIDE`. Validation lists
all pending values together. There is no separate adoption table to clear.
Memory, CPU, process and open-file limits remain decisions until you supply
measurements; observed facts and owner review remain distinct in text and JSON.

This example declares one `linux/amd64` service image. Its resource numbers
illustrate the syntax; replace them with measurements for your application:

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
immutable_tags = ["{version}"]
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

Every image must include `linux/amd64`; `linux/arm64` is optional.
`containerfile` defaults to `Containerfile` and `context` to `.`, both relative
to the repository root. `native_test_platforms` identifies platforms that must
run without emulation and defaults to `["linux/amd64"]`. Trivy is fixed policy;
there is no `scanner` setting to repeat. Empty optional tables and arrays can be
omitted. Each release needs at least one immutable or moving tag, but an unused
tag class can be omitted. Keep `latest` in `moving_tags`, outside the registry's
immutable-version policy. Version-dependent templates require `--version`;
missing versions and rendered tag collisions fail before build or signing tools
are resolved for a new source run.

The Containerfile must contain the complete tagged digest reference, for example
`quay.io/example/base:1@sha256:<digest>`. The pin declaration above supplies
only tag intent. ConClear derives the digest from the Containerfile and rejects
missing, unused, duplicate or ambiguous declarations at the configuration or pin
gate. `FROM`, external `COPY --from` and `RUN --mount=from` inputs all need
coverage; local stages and `scratch` do not.

Inspect the resolved configuration before qualification:

```sh
conclear config show --version 1.2.3
conclear config show --format json
```

The summary shows values, their origins, policy maxima and why measured or
reviewed decisions are needed. Systemd-provided mounts are listed separately
from the effective writable set. It executes no host tools, contacts no registry
and makes no qualification claim. With several images it shows all of them;
`--image` filters the view. Other commands infer the image only when exactly one
release image exists, ignoring test-only dependencies. `--platform` is still
required for a platform command and never defaults to the host architecture.

Use `profile = "one-shot"` for a command that should exit. The test launch
contract may set its expected exit status. The root filesystem defaults to
read-only; a reviewed `writable_root_requirement` permits a writable root.
Runtime writable mounts must still be listed explicitly. The effective
set is exact: a Containerfile or base-image `VOLUME` creates an anonymous
writable mount and its destination must also appear in `writable_mounts`.
ConClear retains declared anonymous volumes in its isolated run-owned Podman
storage and places private tmpfs at declared destinations the image does not
provide. The static check reports an undeclared `VOLUME` in the final local
build stage as `CC0116`; the runtime check reports inherited or otherwise
unexpected writable mounts as `CC0401` and names the differing paths.
Repository configuration can narrow ConClear's built-in time limits in
`[images.limits]` but cannot extend or disable them.

UID 0 is accepted only with a source-reviewed exception that states why root is
required, who owns the decision and what change triggers another review:

```toml
[images.runtime]
profile = "service"
user = 0
memory = "512MiB"
cpus = 1.0
pids = 256
nofile = 1024

[images.runtime.root_requirement]
rationale = "The service manages operating-system identities."
owner = "platform@example.com"
review_trigger = "Review when upstream supports an unprivileged mode."
```

Root inside the container remains rootless on the host. ConClear still uses a
private user and cgroup namespace and the declared resource limits. A root
requirement alone leaves the read-only root, dropped capabilities and
`no-new-privileges` defaults unchanged. Separate permissions below cover
operations that need different functional controls. ConClear does not
offer privileged mode, host namespaces, host devices or repository-selected
writable host paths. The separately declared run-owned test outputs described
below remain the only writable bind-mount source.

Use `profile = "systemd"` only when systemd is the documented lifecycle manager.
The Containerfile must set `USER 0`, use systemd as its entrypoint and set
`STOPSIGNAL SIGRTMIN+3`, the signal systemd documents for orderly shutdown.
ConClear always stops a systemd container with that signal, so the profile does
not declare it. The runtime contract adds the reviewed root requirement plus
systemd-specific readiness:

```toml
[images.runtime]
profile = "systemd"
user = 0
memory = "1GiB"
cpus = 2.0
pids = 512
nofile = 4096

[images.runtime.root_requirement]
rationale = "The image tests operating-system services under systemd."
owner = "platform@example.com"
review_trigger = "Review when the image no longer needs a system manager."

[images.runtime.systemd]
required_units = ["multi-user.target", "sshd.service"]
```

The systemd profile provisions `/run`, `/run/lock`, `/tmp` and
`/var/log/journal` as private tmpfs mounts. Declare any additional writable
paths normally, including additional destinations declared by the image's
`VOLUME` metadata. Do not repeat the four profile-provided paths. Qualification
verifies systemd as PID 1, contacts the manager, waits for every required unit
and the optional health command within one startup deadline, sends `SIGRTMIN+3`
and verifies bounded shutdown and the expected exit status. The other runtime
profiles explicitly disable Podman's automatic systemd mode.


### Reviewed sudo and filesystem permissions

Startup root and sudo access have separate justifications. A non-root service
can support sudo; a systemd integration-test target may need both requirements.
Keep the actual authorization in sudoers and describe its intended scope here:

```toml
[images.runtime.sudo_requirement]
rationale = "Integration tests exercise Ansible become through sudo."
owner = "platform@example.com"
review_trigger = "Changes to test purpose, callers or sudo authorization."
mode = "escalation"
scope = "The test account administers a disposable OS; other accounts cannot."
setid_paths = ["/usr/bin/sudo"]

[images.test.sudo]
user = 10001
denied_user = 65534
target_user = 0
command = ["/usr/bin/id", "-u"]
expected_stdout = "0\n"
timeout_seconds = 30
```

Use existing named accounts with those numeric UIDs. Root-startup images can
also supply account and sudoers files as declared read-only launch fixtures;
sudoers must appear root-owned inside the container. For a non-root startup
identity, bake the policy into the image because ConClear's user mapping makes
host-owned fixture files belong to that identity. The permitted account must
be authorized for the test command without an interactive password; the other
account must be denied. ConClear invokes `sudo -n` itself. This example tests
identity escalation; repository application tests still need to cover the
intended Ansible tasks. Passwords do not belong in the configuration or image.

Only `mode = "escalation"` permits functional runtime escalation. Use
`mode = "presence-only"` when the package is needed without claiming working
escalation, and omit `[images.test.sudo]`. `setid_paths` defaults to
`["/usr/bin/sudo"]`; presence-only mode may declare an empty array if its sudo
executable has no set-ID bits. Each declared path is checked for protected
ownership and set-ID mode. Other required set-ID executables use separate
`[[images.runtime.setid_requirements]]` tables with `path`, `rationale`, `owner`
and `review_trigger`.

Declare the capabilities needed by the operation under `[images.runtime]`;
sudo commonly needs `CAP_SETUID` and `CAP_SETGID`, and the command may need
others. ConClear adds none automatically. Keep narrow writable mounts where
possible. An OS target that needs a writable root must also declare:

```toml
[images.runtime.writable_root_requirement]
rationale = "The tested administration tasks install packages and modify /etc."
owner = "platform@example.com"
review_trigger = "Changes to the administration tasks or writable paths."
```

The sudo tests validate policy with `visudo -c`, retain its files in the test
report, and exercise permitted and denied access from non-root accounts. A
separate restrictive container uses a read-only root, no capabilities and
`no-new-privileges`; escalation must fail. The probes require a POSIX shell,
`sleep`, `readlink`, `stat`, `id`, `cat`, `env` and sudo/visudo. The installed
validator must identify the checked files with its `path: parsed OK` output.
The normal lifecycle test still uses the image's declared user and command.

Review inherited set-ID executables and sudo presence in the final image;
ConClear's declared-path checks do not inventory every inherited executable.
Unrestricted sudo gives the account root-equivalent access within the container
and needs a scope that explains why. No declaration enables privileged mode,
host namespaces or arbitrary writable host mounts.

## 6. Describe application test inputs when needed

An image that starts without extra input needs no `[images.test]` table. For an
input-dependent service or one-shot tool, declare the inputs instead of hiding
startup behind a hook.

The test model supports:

- Reviewed repository fixtures, always mounted read-only. Fixtures must be
  ordinary source-tree files or directories with no symbolic links or unsafe
  permissions.
- Run-owned generated outputs. They exist only below the run workspace. An
  output mounted writable must target a path the selected image declares in
  `runtime.writable_mounts`; a read-only mount of an output may target any
  path.
- Secret outputs. An output marked `secret = true` has no path, value or content
  digest in public evidence, is unavailable to repository hooks and is destroyed
  before a hook runs.
- Ordered preparation commands executed inside the primary image or an exact
  sibling image. A preparation command replaces only that exact image's
  entrypoint.
- Launch arguments and non-secret environment values that keep the primary
  image's original entrypoint.
- Sibling image dependencies built from the same isolated source revision,
  timestamp, platform, version input and Buildah toolchain. Every dependency
  passes the same static checks and the same pin gate as the qualified image
  before anything is built, under its own pins and pin limits, and ConClear
  imports each validated layout by digest before preparation starts.

Commands are arrays and are never interpreted by a shell.

For example, a runtime image can depend on a generator image declared in the
same file. The generator creates a private key and a generated test artifact,
and the primary image is launched with only the non-secret artifact:

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

A mount names a declared fixture or output and is read-only unless it sets
`read_only = false`. ConClear creates every output as an empty private directory
before the first preparation runs. A read-only mount may name only an output
that an earlier preparation wrote, and every output must be mounted writable by
at least one preparation or by the launch. An output that only the launched
container writes, such as a state or work directory, therefore needs no
preparation: declare it, mount it with `read_only = false` at a destination the
runtime contract lists in `writable_mounts`, and ConClear records what the
container left there. The `generator` image must be another `[[images]]` entry
in the same file, cover every tested platform and declare `/output` in its own
`images.runtime.writable_mounts`. An image that exists only for tests omits
`repository` and `[images.release]`: ConClear builds it as a dependency under
its runtime contract but refuses to select it for a build, qualification,
release or rescan, and rejects the keys only a qualified image uses. An image
that is released and also used as a dependency keeps its complete declaration.

ConClear still owns layout validation, digest-preserving import, runtime
controls and container hardening, startup, health, signal and exit observation,
expected exit status, journaling and cleanup. A reviewed repository hook
receives `CC_TEST_INPUT_MANIFEST`, which contains exact layout paths and digests
plus non-secret fixture and output handles. Hooks can add assertions but cannot
replace a built-in check or mark it as passed. ConClear records their command
and result but does not sandbox a reviewed hook from invoking other host
executables.


## 7. Run the local checks

Run the static checks first:

```sh
conclear check --image app
```

`check` runs ConClear's static checks and Hadolint. Hadolint uses a committed
`.hadolint.yaml` or `.hadolint.yml` in the image's `context` directory when
present; document each ignored rule there, as the guide requires, instead of
passing flags.

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

ConClear writes run state below `$XDG_STATE_HOME/conclear/` and keeps Trivy
database snapshots below `$XDG_CACHE_HOME/conclear/`. Preserve the protected pin
history and distribute the exact selected Trivy database snapshot when
qualification runs on more than one worker. Also distribute
`data.qualificationWindow.startedAt` from the first qualification result and
pass it with `--qualification-started-at` alongside `--database-digest` on later
workers. Approval expires after at most 24 hours; pin evidence or vulnerability
exceptions may impose an earlier deadline. Delayed assembly, publication and
promotion require new qualification once that deadline passes. Candidate
retention is independent of this approval window. Historical evidence remains
available for inspection and rescanning.


## 8. Assemble a release candidate

Each `qualify` is one worker run. To turn accepted qualifications into a release
candidate, export each one as a transport and assemble them in a new coordinator
run, on the same workstation or after moving the archives between hosts:

```sh
conclear transport export <worker-run-id> --platform linux/amd64 \
  --output ../transports/app-linux-amd64.tar --format json

conclear assemble --source . --revision HEAD --image app --version 1.2.3 \
  --transport ../transports/app-linux-amd64.tar sha256:<transport-digest> \
  --format json
```

`transport export` prints the transport digest and the qualification-record
digest. Hand the transport digest to the coordinator separately from the
archive; `assemble` refuses a transport whose digest differs, verifies every
member and record, and requires exactly one accepted qualification per platform
declared in `conclear.toml`. A multi-platform image repeats `qualify` and
`transport export` per platform and passes one `--transport` pair per platform.
Do not copy run workspaces or records by hand.

The README describes the identifiers involved and the verification that
`assemble` performs under
[Distributed qualification](../README.md#usage-distributed), including how to
pin every worker to the same vulnerability database.


## 9. Update pinned references

When a base image publishes a new digest, let ConClear propose and apply the pin
update instead of editing digests by hand. This runs entirely on the maintainer
workstation and requires no Renovate runner, other updater, CI, branch, pull
request or hosted writer. Qualification and release do not require an external
updater either.

`pins propose` resolves every declared readable tag exactly once, binds that
digest to each `FROM`, `COPY --from` and
`RUN --mount=from` input that names the same reference, and writes one
schema-validated proposal without touching the repository. The proposal records
the ConClear and guide identity, the canonical repository and its current
commit, the configuration digest, one lookup per pinned reference with old and
new digest and resolution time, and every file with its digest and the exact
byte spans that would change. The intent-only `conclear.toml` is bound by its
digest and remains unchanged. Only the digest of a reference changes; registry,
repository and tag spelling stay as written. A change under an
`immutable-version` tag is marked as requiring supply-chain review and reported
as `CC0205`; ConClear never accepts it automatically and offers no way to skip
that review. An already-current repository yields a successful proposal that
changes nothing.

`pins apply` reads the proposal, verifies the repository, commit, configuration
digest, every target file digest, the reparsed dependency set and every old byte
sequence, and only then replaces the proposed spans through same-directory
temporary files. It never resolves a tag again and never commits, builds,
publishes or signs. If anything fails, every target keeps its original bytes.

```sh
conclear pins propose --output ../pins-proposal.json
conclear pins apply --proposal ../pins-proposal.json
conclear pins check --image app
conclear check --image app
git diff --check
git diff
```

`pins apply` prints one follow-up `pins check` command for every affected image.
Run all of them, and run each image's repository checks including
`conclear check`, before accepting the update. `pins check` remains the
freshness and divergence gate and the only command that updates durable pin
observations. Review the complete diff, run the project's checks, commit through
the repository's normal process, and qualify the committed revision.

A pinned, self-hosted updater such as Renovate may schedule this workflow and
deliver the resulting reviewed diff through an updater-owned branch or pull
request. That is an optional delivery layer around ConClear's proposal and
application operations, not a second pin resolver, a required writer or a
release prerequisite.


## 10. Create a release profile

The complete release needs a maintainer-controlled profile outside the
application repository. Reuse one protected profile for the organization's
shared build trust domain; adopting another image repository does not require
another builder identity or copies of its keys. It holds trust roots, signing
keys and registry credential locations. If it does not exist yet, create
`$XDG_CONFIG_HOME/conclear/foundata.toml`:

```toml
schema_version = 1
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

The profile and every secret file must be owned by the invoking user and carry
private permissions. `cosign_private_key` may instead name a supported KMS or
HSM handle. CI may supply the signing passphrase through `--passphrase-fd`
instead of a file. Secret values are never accepted through project
configuration, command-line literals or inherited environment variables.

Keep writer permissions scoped to the intended repositories wherever the
registry's credential model allows it. A shared profile does not require broad
organization-wide write access. Its auth file can hold the needed registry
credentials; the separate Quay control token still needs the documented
permissions on each destination. Do not copy either into `conclear.toml`.
Use a separate profile when the trust domain or signing authority is genuinely
different, not simply because the image repository has another name.

`builder.id` names the complete build-platform trust domain and must be a
public, credential-free HTTPS documentation URI. It identifies the documented
build environment, not ConClear itself. The simple v1 identity covers foundata's
operator-controlled workstation workflow and claims SLSA Build L1 only; a
materially different workstation policy or CI trust boundary needs a different
builder identity. ConClear records its own version and source revision
separately and verifies the configured signer and builder identities before
promotion.

`ci_context` controls optional CI correlation metadata. `omit` does not inspect
CI variables, `observe` records complete matching context when available, and
`require` stops when recognized context is absent, malformed or inconsistent
with the isolated checkout. ConClear recognizes GitHub Actions, GitLab CI, Gitea
Actions, Forgejo Actions and Woodpecker CI. The normalized public record
contains the provider, repository, full revision and provider run identifier.
Provider environment variables are not authentication and never control the
release verdict, source identity, signer identity or artifact digest.

Repository configuration may name any fully qualified OCI registry for local
checks, qualification, assembly and provenance. The complete `publish` through
`promote` workflow requires an explicitly selected registry control backend. A
supported backend must provide exact tag observation, digest-preserving graph
handling, Cosign referrers, an independently enforced candidate lifetime,
selective tag protection, exact tag assignment, deletion and ambiguous-write
recovery. `quay` is currently the only implemented backend. A release profile
that selects `quay` rejects a destination
on another registry before qualification or remote mutation.

Publication also requires Quay's repository auto-prune API and an API token
with `repo:admin` access to the destination. Before uploading a candidate,
ConClear creates or reuses an age-based retention rule restricted to its
generated candidate tags. It verifies that rule, then uploads the image and
sets the exact per-tag expiration. The rule remains across releases and covers
an interrupted upload without needing the publishing process to resume.
Existing rules are not relaxed; a stricter rule may remove a candidate earlier.
No repository suppression or release-profile option disables this requirement.
If the API is unavailable or the token cannot manage these rules, publication
stops before uploading. Local qualification and assembly remain available.

The registry operator must keep Quay's asynchronous auto-pruner running and
monitor its scheduling delay. ConClear checks the stored policy, not the health
of that remote worker. No build CI service is needed for this registry control.

Configure a selective immutability policy in the Quay organization or repository
before the first publication. For version tags such as `1.2.3` and `v1.2.3`, a
matching policy with `tagPattern = "v?[0-9]+\\.[0-9]+\\.[0-9]+"` covers those
names without freezing candidates or `latest`. Adjust the pattern to your
actual version naming, including any prereleases. Quay applies full-match
semantics. ConClear checks both repository and inherited organization policies
before upload and promotion; a broader inherited policy can still block a
moving tag. The API token needs `repo:admin` and `org:admin` access to read both
policy scopes. ConClear does not create, broaden or remove immutability policies
and rejects unavailable controls. Candidates remain mutable so retention and
cleanup can remove them.

A failed attempt can use the same requested version in a new run while that
final version tag is absent. Once a final tag exists, retries must preserve its
digest, even if a later moving-tag update failed. Changed image bytes need a new
version; `latest` advances only after verification.


## 11. Check and run the release environment

`doctor` checks the environment for one scope without publishing or signing.
`--scope qualify` needs no release profile and proves the static toolchain,
run-owned rootless storage and an execution mode for every configured platform;
the default `release` scope adds the release profile, the selected registry
backend and the public Sigstore services.

Release-scope `doctor` currently probes a tag read and Sigstore initialization,
not the required policy APIs or their enforcement. Its success does not replace
the registry-control checks above or an owned complete release drill. Every
missing or unsupported tool of the scope is reported at once:

```sh
conclear doctor --config conclear.toml --scope qualify
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

`release` resolves the Git selector, creates a detached checkout, qualifies
`linux/amd64` before any additional platform, assembles the accepted layouts,
publishes one registry-controlled candidate, signs and verifies every digest and
attestation, and promotes only the verified digest. The stages are `qualify`,
`assemble`, `provenance`, `publish`, `attest`, `verify` and `promote`. A
rejection or operational failure stops promotion. An interrupted run can be
resumed as described in the README under
[Resuming an interrupted run](../README.md#usage-resume).

Quay is currently the only registry backend for the complete publication
workflow. Projects targeting another registry can use local qualification,
assembly and provenance, but cannot use ConClear's `publish` through `promote`
stages there yet.


## 12. Use the same commands in CI

ConClear has no separate CI execution mode. A CI job invokes the same CLI and
supplies the protected profile, credentials, cache and state through its normal
secret and artifact mechanisms. Platform workers publish their
`transport export` archives as job artifacts and their transport digests as job
outputs; the coordinator job passes each digest to `assemble` from the job
output, not from a file inside the artifact.

Do not pass source identity, builder identity, signer identity, release verdicts
or artifact digests through repository configuration or ordinary environment
variables. ConClear derives source facts from the isolated checkout and treats
recognized CI variables only as optional correlation data.

Every command that produces a result supports `--format json`, which writes one
result object to standard output and diagnostics to standard error. The exit
statuses are listed in the README under
[JSON output and exit codes](../README.md#usage-json-exit-codes).

Persist the evidence artifacts and authoritative signed attestations required by
your release process. Do not treat logs or a mutable registry tag as release
evidence.


## 13. Retain evidence and operate supported releases

Before cleaning a successful run, follow the
[evidence-retention recipe](./evidence-retention.md). It exports each platform's
qualification payloads, preserves selected release records and the exact source
checkout, and keeps protected logs and credentials out of the shareable bundle.
For distributed releases, retain the original worker transports before their
workspaces disappear.

Later rescans need the original `conclear.toml` bytes and the files its paths
reference. They verify the signed release evidence and use a fresh database;
they do not rebuild the old source or require its qualification window to
remain current. The recipe includes a rescan command using a restored checkout.

Assign owners for key custody, registry writers and retention, the inventory of
supported digests, scheduled rescans, triage and rebuilds. A systemd timer or
cron job on an existing managed host can call ConClear, with persistent state
and monitoring for failed or missed assessments. CI is optional. A verified
authoritative rescan with a rejecting verdict still advances the history; keep
its result digest and notify the triage owner.
