# ConClear (container clearance before promotion)

ConClear builds, tests and scans OCI container images, then signs and releases
the digest that passed its checks. It applies the technical requirements of
[foundata's OCI container image build and release guide](https://github.com/foundata/guidelines/blob/main/oci-container-image-guide.md)
without requiring you to maintain your own release scripts or CI service.

> **Important:** ConClear is built for foundata's release process. You are
> welcome to use it if you adopt the linked guide's requirements. Pull requests
> to adapt ConClear to different release policies are out of scope.

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
  - [Getting started](#usage-getting-started)
  - [Checking locally](#usage-check)
  - [Setting up release access](#usage-access)
  - [Running a release](#usage-release)
  - [Resuming an interrupted run](#usage-resume)
  - [Updating image pins](#usage-pins)
  - [Rescans and triage](#usage-rescan-triage)
  - [Distributed qualification](#usage-distributed)
  - [Command help](#usage-commands)
  - [JSON output and exit codes](#usage-json-exit-codes)
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
  the public transparency log.
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

|   Tool   |     Accepted versions      | Excluded versions | Real-tool tested versions |
| -------- | -------------------------- | ----------------- | ------------------------- |
| Git      | 2.43.0 <= version < 3.0.0  | none              | 2.55.0                    |
| Buildah  | 1.39.0 <= version < 1.44.0 | none              | 1.43.2                    |
| Podman   | 5.8.4 <= version < 6.0.0   | none              | 5.8.4                     |
| Skopeo   | 1.14.0 <= version < 2.0.0  | none              | 1.22.2                    |
| Hadolint | 2.12.0 <= version < 3.0.0  | none              | 2.14.0                    |
| Trivy    | 0.74.0 <= version < 0.75.0 | none              | 0.74.0                    |
| Cosign   | 3.1.3 <= version < 4.0.0   | none              | 3.1.3                     |

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

- Run ConClear as a normal user with working rootless Podman and Buildah.
- Use a Linux login session with a user-owned, mode-0700 `XDG_RUNTIME_DIR`,
  normally `/run/user/<uid>`.
- For systemd targets on SELinux hosts, enable cgroup management with
  `sudo setsebool -P container_manage_cgroup on`.
- From a configured image repository, run `conclear doctor --scope qualify` to
  check local prerequisites. Use the [release check](#usage-release) for signing
  and registry access.

On SELinux hosts, label ConClear's private state directory for container storage
before the first build. Keep SELinux enforcing:

```sh
state="${XDG_STATE_HOME:-$HOME/.local/state}/conclear"
install -d -m 0700 "$state"
chcon -t container_file_t "$state"
```

Repeat the label setup after a filesystem relabel or when changing the state
directory. Do not relabel your entire home directory.


## Usage<a id="usage"></a>

Run these commands from your image repository's root. With multiple release
images, add `--image <id>` to select one.


### Getting started<a id="usage-getting-started"></a>

Generate a configuration from your existing Containerfile:

```sh
conclear adopt --output conclear.toml
```

If the file already exists, edit it instead. Resolve every `DECIDE` value and
use your project's identities, measured resource limits and health command.
A service image configuration looks like this:

```toml
schema_version = 1

[project]
name = "example"
source = "https://github.com/foundata/example"

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


### Checking locally<a id="usage-check"></a>

```sh
version=1.2.3
conclear config show --version "$version"
conclear check
conclear pins check
conclear doctor --scope qualify
```

Fix reported errors, then commit the configuration, Containerfile and test
inputs. Builds use the selected Git revision, not uncommitted changes.

To build, test and scan one platform without publishing:

```sh
conclear qualify --revision HEAD --version "$version" --platform linux/amd64
```

This separate qualification is optional; `release` runs its own checks.


### Setting up release access<a id="usage-access"></a>

Create a Quay destination repository and grant your release account writer
access. Obtain a Quay API token with tag read, write and delete access.

Reuse your organization's release profile and key if available. For first-time
setup, create credentials and a new encrypted key outside the image repository:

```sh
umask 077
install -d -m 0700 "$HOME/.config/conclear"
podman login --authfile "$HOME/.config/conclear/auth.json" quay.io
cosign generate-key-pair --output-key-prefix "$HOME/.config/conclear/cosign"
```

Store the API token in `~/.config/conclear/quay.token`. Create
`~/.config/conclear/foundata.toml` (or `$XDG_CONFIG_HOME/conclear/foundata.toml`
if set), adjusting paths, ownership and policy choices:

```toml
schema_version = 1
ci_context = "observe"
auth_file = "~/.config/conclear/auth.json"
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


### Running a release<a id="usage-release"></a>

```sh
version=1.2.3
archives=/srv/archives/conclear
mkdir -p "$archives"
conclear doctor --profile foundata --version "$version"
conclear release --revision HEAD --version "$version" --profile foundata \
  --archive-dir "$archives"
```

Replace `HEAD` with a Git tag or commit to release another revision. With the
configuration above, a successful release creates `1.2.3` and updates `latest`
to the same digest. Use a new version if its final tag already names different
image bytes.

Every release writes a verified `.tar.gz` to the required `--archive-dir`.
Use durable, backed-up storage outside the image repository. Keep the archives
while the release is supported and for as long as you need its evidence.
They contain source, reports, image metadata and signed attestations; signing
keys, credentials and raw logs are excluded. Review source and reports before
sharing. Add `--include-image-layers` to retain the image filesystem too.

After checking that the archive is safely retained, clean up the reported run:

```sh
conclear cleanup "<run-id>" --profile foundata
```


### Resuming an interrupted run<a id="usage-resume"></a>

From the same repository, with the original profile and tools:

```sh
conclear release --resume "<run-id>" --profile foundata --archive-dir "$archives"
```

If the qualification or candidate has expired, or required inputs have changed,
start a new `release`. Clean up the abandoned run after retaining needed
evidence.

If publication succeeded but archiving failed, keep the workspace and retry
only the archive:

```sh
conclear archive create "<run-id>" --profile foundata --archive-dir "$archives"
```


### Updating image pins<a id="usage-pins"></a>

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


### Rescans and triage<a id="usage-rescan-triage"></a>

Rescan a published image to check for newly disclosed vulnerabilities without
rebuilding it. Use triage to record whether findings apply and track
remediation. See
[restore and rescan](./docs/evidence-retention.md#rescan-on-a-restored-host) for
commands and [scheduling](./docs/evidence-retention.md#scheduled-operation) for
ongoing checks.


### Distributed qualification<a id="usage-distributed"></a>

To build and test platforms on separate machines, follow
[distributed qualification](./docs/distributed-qualification.md), then assemble
and release the combined image from one machine.


### Command help<a id="usage-commands"></a>

Use `conclear --help` to list commands and `conclear <command> --help` for
options. `release` is the normal workflow; individual build, test, signing and
promotion commands are listed in the
[command reference](./ARCHITECTURE.md#command-model).


### JSON output and exit codes<a id="usage-json-exit-codes"></a>

Add `--format json` for machine-readable results on stdout. Diagnostics go to
stderr.

| Exit code | Meaning |
| --------: | ------- |
|       `0` | Success. |
|       `1` | Operational failure, such as an unavailable tool or service. |
|       `2` | A policy check rejected the image or evidence. |
|      `64` | Invalid invocation or configuration. |



## Records and schemas<a id="records-schemas"></a>

The [JSON schemas](./src/conclear/schemas/) define configuration, profiles,
command results and release records. Follow the
[archive usage](./docs/evidence-retention.md) to verify retained reports and
source for release reviews, troubleshooting and later rescans.


## Backup<a id="backup"></a>

See [backup and retention](./docs/backup.md) for what to preserve, when it can
be deleted, and a daily archive recipe for secure storage.


## Conformance<a id="conformance"></a>

Look up `CCnnnn` failures in the [conformance catalog](./docs/conformance.md).
It also identifies guide requirements that need manual review or external
controls. The [guide-option inventory](./docs/guide-options-1.0.0.md) lists
supported and unsupported choices.

For implementation details, see [ARCHITECTURE.md](./ARCHITECTURE.md), the
[implementation matrix](./docs/implementation-1.0.0.md) and the
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

This project was created and is maintained by [foundata](https://foundata.com).
