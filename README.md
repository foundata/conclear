# ConClear (container clearance before promotion)

ConClear builds, tests and scans OCI container images, then signs and releases
the digest that passed its checks. It applies the technical requirements of
[foundata's OCI container image build and release guide](https://github.com/foundata/guidelines/blob/main/oci-container-image-guide.md)
without requiring you to maintain your own release scripts or CI service.

> **Important:** ConClear is built for foundata's own release processes. You are
> welcome to use it if you adopt the linked guide's requirements. Requests to
> adapt ConClear to different release policies are out of scope.

<!-- rumdl-disable MD033 -->
<!-- HTML for consistent rendering across limited platform parsers -->
<div align="center" id="project-readme-header">
<br>
<br>

**⭐ Found this useful? Support open-source and star this project:**

[![GitHub repository](https://img.shields.io/github/stars/foundata/conclear.svg)](https://github.com/foundata/conclear)

<br>
</div>
<!-- rumdl-enable MD033 -->


## Table of contents<a id="toc"></a>

- [Features](#features)
- [Installation](#installation)
  - [Fedora](#installation-fedora)
  - [Updating](#installation-update)
  - [Miscellaneous notes](#installation-misc)
- [Usage](#usage)
  - [Configuration (Host)](#usage-host-config)
  - [Configuration (Container repos)](#usage-repo-config)
  - [Quick start: First release of a repository](#usage-first-release)
  - [Quick start: Running a release](#usage-release)
  - [Advanced](#usage-advanced)
    - [Checking locally](#usage-check)
    - [Accepting a stale Java database](#usage-stale-java-database)
    - [Resuming an interrupted run](#usage-resume)
    - [Archives](#usage-archives)
    - [Verifying a release without ConClear](#usage-independent-verification)
    - [Updating image pins](#usage-pins)
    - [Rescans and triage](#usage-rescan-triage)
    - [Retiring a published tag](#usage-retire-tag)
    - [Distributed qualification](#usage-distributed)
    - [Command help](#usage-commands)
    - [Output, JSON and exit codes](#usage-json-exit-codes)
- [Records and schemas](#records-schemas)
- [Backup](#backup)
- [Conformance](#conformance)
- [Contributing](#contributing)
- [Licensing, copyright](#licensing-copyright)
  - [Trademarks](#trademarks)
- [Author information](#author-information)


## Features<a id="features"></a>

- **Checked releases with one command:** `conclear release` runs the checks and
  points your release tags to the exact image digest that passed them.
- **No CI required:** run from a Linux workstation or VM. CI can call the same
  commands when you need it.
- **Auditable releases:** retrieve signed SBOMs and release evidence from the
  registry. [Cosign](https://docs.sigstore.dev/cosign/) records signatures in
  the [public transparency log](https://search.sigstore.dev/).
- **Multi-platform builds and pin updates:** qualify platforms on separate
  machines and update base-image digests without running an update bot.


## Installation<a id="installation"></a>

ConClear is published on PyPI as
[`conclear`](https://pypi.org/project/conclear/) and requires Python 3.12 or
newer. Install it as a tool with [uv](https://docs.astral.sh/uv/):

```sh
uv tool install conclear
conclear version
```

`pipx install conclear`, or `pip install --upgrade conclear` inside a virtual
environment, works as well.

Install the external tools below from distribution packages or upstream
downloads. Use versions within the accepted ranges, avoiding excluded versions.

<!-- supported-tools:begin -->

|   Tool   |     Accepted versions      | Excluded versions | Real-tool tested versions | Pinned image |
| -------- | -------------------------- | ----------------- | ------------------------- | ------------ |
| Git      | 2.43.0 <= version < 3.0.0  | none              | 2.55.0                    | none         |
| Buildah  | 1.40.0 <= version < 1.44.0 | none              | 1.43.2                    | none         |
| Podman   | 5.8.4 <= version < 6.0.0   | none              | 5.8.4                     | none         |
| Skopeo   | 1.14.0 <= version < 2.0.0  | none              | 1.22.2                    | none         |
| Hadolint | 2.12.0 <= version < 3.0.0  | none              | 2.14.0                    | ghcr.io/hadolint/hadolint |
| Trivy    | 0.74.0 <= version < 0.75.0 | none              | 0.74.0                    | ghcr.io/aquasecurity/trivy |
| Cosign   | 3.1.3 <= version < 4.0.0   | none              | 3.1.3                     | none         |

<!-- supported-tools:end -->


Install them and other dependencies as follows:

### Fedora (x86_64)<a id="installation-fedora"></a>

```bash
sudo dnf install --refresh \
  buildah \
  hadolint \
  podman \
  skopeo \
  ca-certificates \
  coreutils \
  curl \
  git-core \
  gzip \
  jq \
  tar

# needed if the tools already installed in the base OS
sudo dnf upgrade --refresh \
  buildah \
  hadolint \
  podman \
  skopeo \
  git-core

# if there is a packaged Trivy, it is usually too old
sudo dnf remove trivy
```

For Trivy and Cosign, use upstream releases when suitable packages are
unavailable:

```bash
# Create temp download dir and define helper function
work="$(mktemp -d "${TMPDIR:-/tmp}/conclear-tools.XXXXXXXX")"
fetch() { curl -fSL --proto '=https' --proto-redir '=https' "$@"; }

# Determine latest versions (adapt manually if versions are not within
# Conclear's supported range)
fetch 'https://api.github.com/repos/sigstore/cosign/releases/latest' -o "${work}/cosign-release.json"
fetch 'https://api.github.com/repos/aquasecurity/trivy/releases/latest' -o "${work}/trivy-release.json"
cosign_version="$(jq -er '.tag_name | ltrimstr("v")' "${work}/cosign-release.json")"
trivy_version="$(jq -er '.tag_name | ltrimstr("v")' "${work}/trivy-release.json")"
printf 'Cosign: %s\nTrivy: %s\n' "${cosign_version}" "${trivy_version}"

# Download and install Cosign
cosign_base="https://github.com/sigstore/cosign/releases/download/v${cosign_version}"
fetch "${cosign_base}/cosign-linux-amd64" -o "${work}/cosign" && \
sudo install -o root -g root -m 0755 "${work}/cosign" "/usr/local/bin/cosign"

# Download and install Trivy
trivy_base="https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}"
fetch "${trivy_base}/trivy_${trivy_version}_Linux-64bit.tar.gz" -o "${work}/trivy.tar.gz" && \
tar --extract --gzip --file "${work}/trivy.tar.gz" --directory "${work}" \
  --no-same-owner --no-same-permissions trivy && \
sudo install -o root -g root -m 0755 "${work}/trivy" "/usr/local/bin/trivy"

# Check
which cosign && cosign version
which trivy && trivy --version
```

### Updating<a id="installation-update"></a>

Update ConClear with `uv tool upgrade conclear`. For host tools, repeat the
installation steps with supported versions. Finish active runs before updating.

### Miscellaneous notes<a id="installation-misc"></a>

ConClear runs on a native Linux host with rootless Podman and Buildah. Continue
with [host configuration](#usage-host-config) before your first release.


## Usage<a id="usage"></a>

The examples use a release profile named `foundata`. Run repository commands
from the image repository's root; add `--image <id>` when it has multiple
release images.


### Configuration (Host)<a id="usage-host-config"></a>

Use a normal user account and a Linux login session with a user-owned,
mode-0700 `XDG_RUNTIME_DIR`, normally `/run/user/<uid>`.

On SELinux hosts, label ConClear's private state directory for container storage
before the first build:

```sh
state="${XDG_STATE_HOME:-${HOME}/.local/state}/conclear"
install -d -m 0700 "${state}"
chcon -t container_file_t "${state}"
```

Keep SELinux enforcing. Repeat this after a filesystem relabel or state path
change; do not relabel your entire home directory. For systemd targets, also run
`sudo setsebool -P container_manage_cgroup on`.

Reuse your organization's release profile and signing key if available.
Otherwise, create credentials and an encrypted key outside source repositories:

```sh
umask 077
install -d -m 0700 "${HOME}/.config/conclear"
podman login --authfile "${HOME}/.config/conclear/auth.json" quay.io
cosign generate-key-pair --output-key-prefix "${HOME}/.config/conclear/cosign"
```

Obtain a Quay API token with tag read, write and delete access and store it in
`~/.config/conclear/quay.token`. Create `~/.config/conclear/foundata.toml` (or
`$XDG_CONFIG_HOME/conclear/foundata.toml` if set; adapt the name to fit your
organization if not working for foundata), adjusting paths, ownership and policy
choices:

```toml
schema_version = 1
ci_context = "observe"
# Git origins your release checkouts may have; the list never leaves this file.
allowed_source_origins = ["https://github.com/foundata/"]
auth_file = "~/.config/conclear/auth.json"
cosign_private_key = "~/.config/conclear/cosign.key"
cosign_public_key = "~/.config/conclear/cosign.pub"
# Durable, backed-up directory for release and rescan archives; --archive-dir overrides it.
archive_dir = "/srv/archives/conclear"

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

Keep the profile and secret files owned by your user with mode `0600`.
Reuse the profile across repositories. Set `builder.id` to the URL documenting
your build environment; use foundata's identity only for that environment.

Where selective tag protection is available, enable it for version tags,
exclude `latest` and candidates, and set `tag_protection.mode = "required"`
without `rationale` or `owner`. This also needs repository and organization
policy-read access. Cleanup can use `manual` or `auto-prune` instead of
`tag-expiration`; keep an owner and procedure in every case. See
[registry options](./ARCHITECTURE.md#publication-and-promotion).

ConClear prompts for the signing passphrase. For automation, configure a
protected `passphrase_file` or use `--passphrase-fd`. **Never put secrets in
command-line values, ordinary environment variables or repository files.
Policy descriptions appear in public release evidence.**

Create an archive directory on durable, backed-up storage writable by your
release user, outside source repositories and ConClear working directories:

```sh
archives=/srv/archives/conclear
install -d -m 0700 "${archives}"
```

Back up keys and host settings separately; see [backup](./docs/backup.md).


### Configuration (Container repos)<a id="usage-repo-config"></a>

Create a Quay destination repository and grant your release account writer
access. From your source repository's root, generate a configuration:

```sh
conclear adopt --output conclear.toml
```

If the file already exists, edit it instead. Resolve every `DECIDE` value and
use your project's identities, measured resource limits and health command.
Provisional limits are fine at first: `conclear test` and `conclear qualify`
report the observed footprint of the running container, so you can tighten
them afterwards. A service image configuration looks like this:

```toml
schema_version = 1

[project]
name = "example"
# Public URL where users find the code; it need not be a Git repository.
source = "https://foundata.com/en/projects/example/#source"

# Optional: where the project states its version. Every declared source must
# agree with --version, or the release is rejected before the build.
# [[project.version_sources]]
# kind = "changelog"
# path = "CHANGELOG.md"

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

The resource numbers are illustrative. Keep credentials out of this file and
list every release platform explicitly.

Prepare the build inputs:

- Pin external images in the Containerfile as `image:tag@sha256:<digest>` and
  declare each tag and its intent under `[[images.pins]]`.
- Supply the
  [required OCI labels](https://github.com/foundata/guidelines/blob/main/oci-container-image-guide.md#image-metadata).
  Declare and use the `IMAGE_CREATED`, `IMAGE_REVISION` and `IMAGE_VERSION`
  build arguments for their corresponding labels.
- Match the numeric `USER` to `images.runtime.user`. Declare writable paths
  and put the health command in `conclear.toml`.
- Allow only required build inputs in `.containerignore`, for example:

```gitignore
*
!Containerfile
!conclear.toml
!app
```

Use `one-shot` or `systemd` instead of `service` where appropriate. For root,
sudo, writable-root requirements or test fixtures, use the
[configuration reference](./ARCHITECTURE.md#configuration-and-trust-inputs).

Commit the configuration, Containerfile and test inputs. Builds use the selected
Git revision, not uncommitted changes. You can [check locally](#usage-check)
before releasing.


### Quick start: First release of a repository<a id="usage-first-release"></a>

Once, from the root of a configured repository:

```sh
version=1.2.3
conclear adopt --output conclear.toml   # draft; resolve every DECIDE value by hand
# Containerfile: pinned FROM, IMAGE_* build arguments, OCI labels, numeric USER
# .containerignore: "*" first, then allow only the build inputs
git add Containerfile .containerignore conclear.toml && git commit
conclear check                          # static Containerfile and context checks
conclear pins check                     # declared base digests are still current
conclear qualify --revision HEAD --version "${version}"   # build, test, scan; publishes nothing
conclear doctor --scope release --profile foundata      # registry, key, tools
```

Then continue with [running a release](#usage-release). Qualification takes a
few minutes; the release repeats it, so fix findings here first.


### Quick start: Running a release<a id="usage-release"></a>

From a configured repository on your configured host:

```sh
version=1.2.3
archives=/srv/archives/conclear
conclear doctor --profile foundata --version "${version}"
conclear release --revision HEAD --version "${version}" --profile foundata \
  --archive-dir "${archives}"
```

Replace `HEAD` with a Git tag or commit to release another revision. With the
configuration above, this publishes `1.2.3`, updates `latest` to the same digest
and writes a verified `.tar.gz` to `--archive-dir`. Use a new version if its
final tag already names different image bytes.

After checking that the archive is safely retained, clean up the reported run:

```sh
conclear cleanup "<run-id>" --profile foundata --retire
```

`--retire` also deletes the run directory with its layouts and evidence once the
run is dead: finished, interrupted without a way to resume, or past its
qualification window. Omit it to keep the directory for inspection. A release
that could still resume is refused; add `--abandon` to give it up anyway.
Working data a repository hook left in its scratch directory is removed as well;
if anything else blocks the removal, the command names the exact path.


### Advanced<a id="usage-advanced"></a>

#### Checking locally<a id="usage-check"></a>

```sh
version=1.2.3
conclear config show --version "${version}"
conclear check
conclear pins check
conclear doctor --scope qualify
```

Fix errors and commit changes. To build, test and scan one platform without
publishing:

```sh
conclear qualify --revision HEAD --version "${version}" --platform linux/amd64
```

This separate qualification is optional; `release` runs its own checks.


#### Accepting a stale Java database<a id="usage-stale-java-database"></a>

Trivy keeps a second index, the Java database, that identifies jar artifacts by
content when they carry no Maven coordinates. Its publisher sometimes lets it
expire for days. `CC0507` rejects a qualification only when the image's SBOM
actually inventories Java artifacts and that index has passed its next-update
time; images without Java are never affected. When it blocks a release you need,
record the risk and continue:

```sh
conclear release --revision HEAD --version "${version}" --profile foundata \
  --accept-stale-java-database
```

The option also exists on `qualify` and `rescan`. Every affected record keeps
`javaDatabase` with the acceptance and the artifact count, and the rejection
becomes a `CC0507` warning, so the decision stays visible in the evidence. A
resumed release reuses the decision the run recorded.

`conclear doctor --scope qualify` reports the installed database's freshness and
warns about an expired Java database before any image is built.


#### Resuming an interrupted run<a id="usage-resume"></a>

From the same repository, with the original profile and tools:

```sh
conclear release --resume "<run-id>" --profile foundata --archive-dir "${archives}"
```

If the qualification or candidate has expired, or required inputs have changed,
start a new `release`. Clean up the abandoned run after retaining needed
evidence.


#### Archives<a id="usage-archives"></a>

`release`, `promote` and `rescan` write to `--archive-dir`, or to the profile's
`archive_dir` when the option is omitted, and report each archive's path, size
and SHA-256 digest. Release archives contain exact source
and configuration, SBOMs, scan and test reports, image metadata and signed
attestations. Add `--include-image-layers` to retain image layers too.

Signing keys, credentials, protected profiles, raw logs, private test outputs
and scanner database caches are excluded. Source and reports may still be
sensitive; review archives before sharing them.

Keep archives while the release is supported and for your chosen review period
afterward. Keep referenced source archives beside their rescans. See
[backup](./docs/backup.md) for retention and separate key backups.

Verify an archive against your trusted profile key:

```sh
bundle="${archives}/<archive-name>.tar.gz"
conclear archive verify "${bundle}" --profile foundata
```

Verification needs Cosign trust data but not registry access. Unsigned
diagnostic rescans are not signed release evidence.

If a release or rescan completed but archiving failed, keep its workspace and
retry the archive without publishing or rescanning:

```sh
conclear archive create "<run-id>" --profile foundata --archive-dir "${archives}"
```

Clean up the run only after the archive is safely retained.


#### Verifying a release without ConClear<a id="usage-independent-verification"></a>

Anyone with Skopeo, Cosign and your public key can check a release. Cosign
reads Docker-style credentials; for a private repository point it at a copy of
your auth file:

```sh
image=quay.io/foundata/example
version=1.2.3
key=~/.config/conclear/cosign.pub
export DOCKER_CONFIG=$(mktemp -d); cp ~/.config/conclear/auth.json "${DOCKER_CONFIG}/config.json"

skopeo inspect --format '{{.Digest}}' "docker://${image}:${version}"
skopeo inspect --format '{{.Digest}}' "docker://${image}:latest"      # same digest
skopeo inspect "docker://${image}:${version}" | jq '.Labels'            # source, revision, version, created
cosign tree "${image}:${version}"                                       # signature, provenance, release verification
cosign verify --key "${key}" "${image}:${version}"
cosign verify-attestation --key "${key}" --type slsaprovenance1 "${image}:${version}"
```

The SPDX SBOM is attached to each platform manifest, not to the image index.
Verify it per platform digest; a single-platform image has exactly one:

```sh
for digest in $(skopeo inspect --raw "docker://${image}:${version}" | jq -r '.manifests[]?.digest // empty'); do
  cosign verify-attestation --key "${key}" --type spdxjson "${image}@${digest}"
done
```

Each release archive keeps the Sigstore bundles under `signatures/`. Their
`logIndex` names the entry in the
[public transparency log](https://search.sigstore.dev/):

```sh
tar -xzf "${bundle}" -C "${dir}"
jq '.verificationMaterial.tlogEntries[] | {logIndex, integratedTime}' "${dir}"/signatures/*.sigstore.json
# https://search.sigstore.dev/?logIndex=<logIndex>
```

`conclear archive verify` checks the inclusion proofs offline. The lookup adds
the one thing it cannot: that the entry is visible in the live log.


#### Updating image pins<a id="usage-pins"></a>

Generate a proposal at a new path:

```sh
conclear pins propose --output ../pins-proposal.json
```

Review the proposal, then apply and check it:

```sh
conclear pins apply --proposal ../pins-proposal.json
conclear pins check
conclear check
git diff
```

Run project tests and commit the Containerfile changes before releasing.


#### Rescans and triage<a id="usage-rescan-triage"></a>

Rescan a published image to check for newly disclosed vulnerabilities without
rebuilding it. Use its release archive or latest rescan archive, with the
referenced source archive beside it:

```sh
archives=/srv/archives/conclear
bundle="${archives}/<archive-name>.tar.gz"
conclear rescan --archive "${bundle}" --profile foundata \
  --authoritative --archive-dir "${archives}"
```

On a restored host, install ConClear and its supported tools, then restore
the protected profile, trusted public key and registry access separately.
Authoritative rescans also need the signing key. No import of old run workspaces
is needed. The image and signed history must still exist in the registry, even
when the archive includes layers.

Omit `--authoritative` for a diagnostic. Add `--triage-file triage.json` for
reviewed vulnerability decisions; do not edit archived configuration.

For ongoing checks, schedule a timer or cron job on a managed host and serialize
rescans per digest. Keep the resulting archives, assign triage and rebuild
owners, and alert on rejected, failed or overdue assessments. A completed
authoritative assessment is retained even when its verdict is rejected (exit 2).
Maintain your supported-release inventory and schedules separately.


#### Retiring a published tag<a id="usage-retire-tag"></a>

Delete tags through the registry's own API with the same token ConClear uses
for its owned tags. On Quay a robot account with write access cannot delete
through `skopeo delete`, and `cosign clean` does not remove OCI referrers:

```sh
api="https://quay.io/api/v1/repository/foundata/example"
for tag in latest "${version}"; do
  curl -X DELETE -H "Authorization: Bearer $(cat ~/.config/conclear/quay.token)" "${api}/tag/${tag}"
done
skopeo list-tags "docker://${image}"
```

Quay drops the manifest with its last tag and garbage-collects the signatures
and attestations that referred to it. Transparency-log entries are permanent;
the release archive remains your evidence, and `conclear archive verify` still
works on it. A rescan of a retired subject fails because the registry no longer
holds it.


#### Distributed qualification<a id="usage-distributed"></a>

To build and test platforms on separate machines, follow
[distributed qualification](./docs/distributed-qualification.md), then assemble
and release the combined image from one machine.


#### Command help<a id="usage-commands"></a>

Use `conclear --help` to list commands and `conclear <command> --help` for
options. `release` is the normal workflow; individual build, test, signing and
promotion commands are listed in the
[command reference](./ARCHITECTURE.md#command-model).


#### Output, JSON and exit codes<a id="usage-json-exit-codes"></a>

Stdout carries what a command produced and nothing else: the result, or with
`--format json` one machine-readable result document. Stderr carries what
happened on the way: which phase is under way, and every external command that
really ran, marked with a bold `$`. A build, qualification or release is
minutes of container work, so that narration is how you see it move.

```console
$ conclear qualify --revision HEAD --version 1.2.3 --platform linux/amd64
» Building app for linux/amd64
$ buildah --root … build --platform linux/amd64 …
» Testing app for linux/amd64
$ podman --root … run --rm …
» Scanning app for linux/amd64
» Recorded the accepted qualification of app for linux/amd64
Platform qualification is accepted
```

`-q`/`--quiet` before the command keeps stdout and drops the narration on
stderr; it never suppresses an error or a warning. `2>/dev/null` does the same,
and `2>&1 | tee run.log` keeps both together. Redirected output stays plain;
`NO_COLOR` disables colour on a terminal and `FORCE_COLOR` demands it where no
terminal is detected. Nothing narrated ever enters a record, an archive or the
release-gate artifacts.

| Exit code | Meaning |
| --------: | ------- |
|       `0` | Success. |
|       `1` | Operational failure, such as an unavailable tool or service. |
|       `2` | A policy check rejected the image or evidence. |
|      `64` | Invalid invocation or configuration. |



## Records and schemas<a id="records-schemas"></a>

The [JSON schemas](./src/conclear/schemas/) define configuration, profiles,
command results and release records. Use [archives](#usage-archives) to verify
retained reports and source for release reviews, troubleshooting and later
rescans.


## Backup<a id="backup"></a>

See [backup and retention](./docs/backup.md) for what to preserve, when it can
be deleted, and a daily archive recipe for secure storage.


## Conformance<a id="conformance"></a>

Look up `CCnnnn` failures in the [conformance catalog](./docs/conformance.md).
It also identifies guide requirements that need manual review or external
controls. The [guide options](./docs/conformance.md#guide-options) section lists
supported and unsupported choices.

For implementation details, see [ARCHITECTURE.md](./ARCHITECTURE.md), the
[implementation matrix](./docs/implementation.md) and the
[compatibility inventory](./docs/compatibility-inventory.json).


## Contributing<a id="contributing"></a>

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the contribution workflow and
[`DEVELOPMENT.md`](./DEVELOPMENT.md) for the development environment, test tiers
and the clean-checkout release gate.


## Licensing, copyright<a id="licensing-copyright"></a>

<!--REUSE-IgnoreStart-->
<!-- rumdl-disable-next-line MD034 --><!-- should match SPDX-PackageSupplier -->
Copyright (c) 2026, foundata GmbH (https://foundata.com)

This project is licensed under the GNU General Public License v3.0 or later
(SPDX-License-Identifier: `GPL-3.0-or-later`), see
[`LICENSES/GPL-3.0-or-later.txt`](LICENSES/GPL-3.0-or-later.txt) for the full
text.

The [`REUSE.toml`](REUSE.toml) file provides detailed licensing and copyright
information in a human- and machine-readable format. This includes parts that
may be subject to different licensing or usage terms, such as third-party
components. The repository conforms to the
[REUSE specification](https://reuse.software/spec/). You can use
[`reuse spdx`](https://reuse.readthedocs.io/en/latest/readme.html#cli) to create
a
[SPDX software bill of materials (SBOM)](https://en.wikipedia.org/wiki/Software_Package_Data_Exchange).
<!--REUSE-IgnoreEnd-->

[![REUSE status](https://api.reuse.software/badge/github.com/foundata/conclear)](https://api.reuse.software/info/github.com/foundata/conclear)


### Trademarks<a id="trademarks"></a>

- Red Hat® and Quay® are trademarks of Red Hat, Inc., registered in the US and
  other countries
- Docker® is a trademark of Docker, Inc.
- Linux® is a registered trademark of Linus Torvalds

Their use here is purely descriptive and does not imply any affiliation with or
endorsement by the trademark holders.


## Author information<a id="author-information"></a>

This [project](https://foundata.com/en/projects/) was created and is maintained
by [foundata](https://foundata.com/).
