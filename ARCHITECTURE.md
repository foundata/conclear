# ConClear architecture

This document defines the architecture and current behavioral contract
implemented by ConClear. It contains no planned or speculative behavior; future
changes belong in [GitHub issues](https://github.com/foundata/conclear/issues)
until their implementation and tests land with the contract change.

Current implementation promises are marked with stable `IPnnnn` anchors. The
generated [implementation matrix](./docs/implementation-1.0.0.md) links every
promise to its production code and verification tests for this ConClear version.

The
[foundata OCI container image build and release guide](https://github.com/foundata/guidelines/blob/main/oci-container-image-guide.md)
is normative. This document explains how ConClear implements that guide's
automatable rules. Each ConClear release selects and embeds an exact guide
revision; when the documents conflict, that selected guide revision takes
precedence and this document must be corrected.

The terms MUST, SHOULD and MAY are used as defined in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) and
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174).


## Table of contents<a id="table-of-contents"></a>

- [Product contract](#product-contract)
- [Goals](#goals)
- [Terminology](#terminology)
- [Core model](#core-model)
- [Invariants](#invariants)
- [Guide identity and conformance](#guide-identity-and-conformance)
- [Configuration and trust inputs](#configuration-and-trust-inputs)
- [Built-in limits](#built-in-limits)
- [Pin updates](#pin-updates)
- [Command model](#command-model)
- [Records and workspaces](#records-and-workspaces)
- [Tool execution](#tool-execution)
- [Build and qualification](#build-and-qualification)
- [Publication and promotion](#publication-and-promotion)
- [Provenance, signing and verification](#provenance-signing-and-verification)
- [Rescans](#rescans)
- [Implementation structure](#implementation-structure)
- [Testing](#testing)
- [Maintaining this document](#maintaining-this-document)


## Product contract<a id="product-contract"></a>

<a id="promise-ip0001"></a>
ConClear is a command-line application that checks, builds, tests and qualifies
OCI container images; publishes accepted candidates; attaches release evidence;
verifies the published subject; and promotes only a verified digest. The
complete workflow runs on a maintainer-controlled Linux workstation and can run
unchanged in protected CI.

<a id="promise-ip0002"></a>
ConClear verifies declared container-image dependencies and base-image pins,
generates non-mutating pin-update proposals from its own registry resolution,
and applies a proposal to the local worktree only after verifying it against the
current repository state. Checking, proposing, applying and accepting a pin
update are distinct operations; acceptance stays with the repository owner's
review of the resulting diff.

ConClear does not deploy workloads, operate registries, schedule recurring jobs,
manage the supported-release inventory, perform vulnerability triage, rebuild
affected projects, orchestrate running services, build virtual machines, process
unrelated artifact types, or invoke Renovate or another external updater. An
external updater may deliver a ConClear proposal through a review branch or pull
request, but that delivery is optional and never required for an authorized
local maintainer workflow. Docker, Windows containers and GitHub container
actions are outside the supported and tested surface.


## Goals<a id="goals"></a>

- Provide one fail-closed release workflow from a reviewed source commit through
  promotion.
- Use the same commands, rules and record schemas on a workstation and in CI.
- Run rootless with Buildah, Podman and Skopeo and require no Docker daemon.
- Keep all rejecting content gates local until an accepted digest is ready for
  public upload.
- Bind builds, tests, scans, SBOMs, provenance, signatures and verification
  results to immutable digests.
- Make every release decision reconstructible from machine-readable records
  without treating logs as evidence.
- Resolve and record the actual tools used by each release while allowing
  supported tool upgrades between releases.
- Keep repository configuration narrow, reviewable and unable to relax
  unconditional guide requirements.
- Fail without promotion when a required fact, test, signature, attestation or
  remote digest cannot be established.


## Terminology<a id="terminology"></a>

- An **authorized release environment** is a maintainer-controlled Linux
  workstation or protected CI job with external registry credentials, signing
  authority and trust configuration. A workstation release is not a lesser class
  of release.
- **Repository configuration** is the reviewed `conclear.toml` at the selected
  source revision. It contains project facts and exceptions permitted by the
  guide, but no signing or registry credentials.
- A **release run** is one ConClear invocation and its resumable workspace. Its
  identity is a lowercase ULID generated by ConClear.
- A **platform qualification** is the immutable
  `platform-qualification-<platform>.json` record for one image and one target
  platform. It binds the built layout, tests, SBOM, scans, execution facts and
  verdict by digest.
- A **release candidate** is the immutable `release-candidate.json` aggregate
  produced from exactly one accepted qualification for each required platform.
- A **candidate reference** is the single-use registry tag used to publish one
  accepted candidate before verification and promotion.
- A **release image** is a platform manifest or image index that has passed the
  required gates and has been published by the release process.
- **Release provenance** is machine-readable evidence of how and where an image
  was built and which source and dependencies were used.
- **Evidence** is the digest-bound, machine-readable output of the release
  process. Signed registry attestations are the authoritative retained evidence;
  workspace files are convenience copies.
- A **trust root** is the approved public signing key or managed-key identity
  used to verify signatures and attestations. It comes from
  maintainer-controlled release or protected deployment configuration, never
  from the repository being verified.
- A **rule rejection** means that observed content violates the guide or
  effective repository configuration. An **operational failure** means that
  ConClear could not establish a result, for example because a tool, network
  operation or registry comparison failed.


## Core model<a id="core-model"></a>

<a id="promise-ip0003"></a>
The canonical pre-publication artifact is an OCI image layout, not a mutable
local image name. A release follows this data flow:

```text
reviewed source commit
  -> isolated detached worktree
  -> platform OCI layout                         build
  -> digest-reverified Podman import and tests   test
  -> SBOM, scans and platform qualification      evidence
  -> verified manifest or image index            assemble
  -> release candidate and provenance predicate  provenance
  -> registry candidate digest                   publish
  -> signatures and attestations                 attest
  -> signed release-verification attestation     verify
  -> immutable and convenience release tags      promote
```

<a id="promise-ip0004"></a>
`conclear release` owns this ordering and can execute every step in one local
process. ConClear deliberately completes and accepts `linux/amd64` qualification
before starting additional required platforms. This is stricter than the guide's
build-and-test ordering and fails the required platform early. Platform
qualification may instead run in separate worker runs, on one host or on
several: each worker invokes the same `qualify` command, exports its accepted
qualification as a digest-bound transport, and a coordinator run created by
`assemble` verifies and assembles those transports through the same assembly
path. External automation may move transports, prepare the host, unlock
credentials and schedule later rescans; it does not reimplement release
decisions.

<a id="promise-ip0005"></a>
The release state advances monotonically through `created`, `qualified`,
`assembled`, `published`, `attested`, `verified` and `promoted`. `rejected` and
`incomplete` results never satisfy a later state's prerequisite. Retrying a
network operation may resume the same state only when all immutable inputs and
expected digests still match.


## Invariants<a id="invariants"></a>

<a id="promise-ip0006"></a>

1. No rebuild occurs between qualification and publication.
2. Every test, scan, SBOM, signature and attestation identifies an immutable
   manifest or index digest.
3. Runtime tests use a digest-reverified import of the exact OCI layout that
   qualification records.
4. Required skipped tests produce an incomplete run, not a successful
   qualification.
5. `conclear.toml` may narrow built-in rules but cannot relax an unconditional
   `MUST` or `MUST NOT` or extend a built-in maximum.
6. A workstation invocation and a CI invocation use the same state machine and
   can produce equally authoritative evidence.
7. Source identity comes from the isolated Git checkout, builder identity comes
   from the protected release profile, ConClear implementation identity comes
   from embedded version data, and signer identity comes from the configured
   signing key. Caller-provided labels cannot replace these values.
8. A candidate reference is generated once and is reused after an ambiguous
   write only when the registry resolves it conclusively to the unchanged
   expected digest within its recorded lifetime; otherwise the release requires
   a new run and candidate reference.
9. Promotion writes only the digest accepted by release verification and
   verifies every written tag by resolving it again.
10. ConClear deletes only local and remote resources recorded as owned by the
    current release run.
11. Secrets are never accepted as command-line literals, stored in repository
    configuration, included in evidence or written to logs.
12. Rule rejections and operational failures remain distinguishable in human
    output, JSON output and process exit status.


## Guide identity and conformance<a id="guide-identity-and-conformance"></a>

<a id="promise-ip0007"></a>
Every ConClear build embeds its version, full source revision, and the title,
repository, path and full revision of the guide it implements.
`conclear version` and `conclear version --format json` expose those values in
the forms required by the guide. They are build inputs and MUST NOT be read from
the application repository at runtime.

ConClear owns stable check identifiers in the form `CC` followed by four decimal
digits, for example `CC0101`. An identifier is never reused for a different
rule; removal leaves a retired entry so historical findings remain
understandable. Findings, narrow suppressions and documentation use these
identifiers.

One machine-readable check catalog is the implementation source for each
identifier, summary, severity, automatable behavior and the guide requirement
identifiers (`IGnnnn`) the check covers. ConClear ships the guide's requirement
inventory for the embedded revision and a coverage file that gives every
requirement no check covers one status: automated, manual, external or
unsupported. `docs/conformance.md` is generated from those three sources and
records the selected guide revision. CI verifies that identifiers are unique,
that every referenced requirement exists in the inventory, that every
requirement has exactly one status and that generated documentation is current.

Requirements that need human judgment are listed as manual in the conformance
documentation. ConClear MUST NOT claim that a mechanical check implements them.
Built-in defaults and maximums are listed in the same document so a tool release
completely identifies the rules it applies.


## Configuration and trust inputs<a id="configuration-and-trust-inputs"></a>

<a id="promise-ip0008"></a>
ConClear has one repository-owned configuration file: `conclear.toml`. Its
schema is versioned and validated before any build or network operation. Unknown
keys are errors so misspelled security settings cannot be ignored.

The configuration declares image definitions, Containerfile and context paths, a
fully qualified release destination for every releasable image, required
platforms, native-testing requirements, runtime expectations, resource limits,
typed test inputs, test-image dependencies, test hooks, image-pin intent,
candidate lifetime reductions and permitted exceptions. Paths resolve below the
isolated source root and cannot escape through `..`, symlinks or archive
entries. The configured source is always a credential-free canonical HTTPS
repository identity. An observed Git remote may use that HTTPS form or an
equivalent `git@host:owner/repository.git` or
`ssh://git@host/owner/repository.git` transport form. ConClear converts a
supported observed remote to the canonical HTTPS identity before comparison and
records only that identity in evidence. It rejects arbitrary SSH users, host
aliases, local paths and other remote forms whose equivalence cannot be
established from their syntax alone; it never requires a maintainer to change an
equivalent local SSH remote.

An illustrative configuration is:

```toml
schema_version = 1

[project]
name = "example"
source = "https://github.com/foundata/example"

[[images]]
id = "example"
containerfile = "Containerfile"
context = "."
repository = "quay.io/foundata/example"
platforms = ["linux/amd64", "linux/arm64"]
native_test_platforms = ["linux/amd64"]
scanner = "trivy"

[images.limits]
candidate_lifetime = "168h"

[images.release]
immutable_tags = ["{version}"]
moving_tags = ["stable"]

[images.runtime]
profile = "service"
user = 65532
memory = "512MiB"
cpus = 1.0
pids = 256
nofile = 1024
health_command = ["/usr/local/libexec/example-healthcheck"]

[[images.pins]]
reference = "quay.io/fedora/fedora-minimal:<release>@sha256:<digest>"
tag_intent = "moving-release-line"
```

`containerfile`, `context` and `native_test_platforms` default to
`Containerfile`, `.` and `["linux/amd64"]`. The optional `scanner` key names the
gating scanner for the reader and accepts only the supported stack. The root
filesystem defaults to read-only; writable paths are declared individually. A
`writable_root_requirement` with rationale, owner and review trigger permits a
writable container root without granting writable host paths. Release tag
templates may use only the documented
`{version}` value; unversioned projects omit version-dependent templates.
Candidate tags remain entirely ConClear-owned.

The configured runtime user is a numeric non-zero UID by default and must match
the final Containerfile `USER`. UID 0 is accepted only when the runtime also
contains a closed `root_requirement` table with non-empty `rationale`, `owner`
and `review_trigger` values. The exception is reviewed repository input and is
recorded in the platform qualification. A root requirement is rejected for a
non-zero UID.

A separate `sudo_requirement` records rationale, owner, review trigger,
authorization scope and either `presence-only` or `escalation` mode. Only
escalation disables `no-new-privileges` in the functional runtime. It requires
`test.sudo` to name distinct non-root permitted and denied callers, a distinct
target UID, an absolute command and exact expected stdout. Tests use
noninteractive sudo; test accounts and policy must exist in the image.
Root-startup images may instead use declared read-only launch fixtures whose
policy files appear root-owned in the container's user namespace.
Sudo executable paths default to
`/usr/bin/sudo`; other set-ID executables require individual
`setid_requirements`. These declarations do not add capabilities or change the
startup user or root filesystem mode.

The `service`, `one-shot` and `scratch` profiles use the ordinary process
lifecycle and explicitly disable Podman's automatic systemd mode. The separate
`systemd` profile requires UID 0, a root requirement and a closed `systemd`
table containing at least one `required_units` entry. The profile declares no
stop signal: systemd shuts down on `SIGRTMIN+3`, ConClear always sends that
signal, and the Containerfile must set the same `STOPSIGNAL`. The profile adds
`/run`, `/run/lock`, `/tmp` and `/var/log/journal` to the effective
private tmpfs set. Repository configuration may declare further writable paths,
but an immutable path cannot overlap any effective writable path.

The effective writable set is exact. It includes every read-write mount that
Podman observes, regardless of whether ConClear supplied it or the image created
an anonymous mount through `VOLUME`. Every image-declared volume destination
must therefore be present in `writable_mounts` unless the selected profile
already supplies it. A declared image volume keeps its anonymous backing in the
run-owned isolated Podman storage; ConClear supplies private tmpfs only for a
declared path that the image does not provide. It rejects any unexpected or
missing writable destination. Static checks reject an undeclared `VOLUME` in
the final local build stage; inherited volume metadata is authoritatively
detected by the runtime observation.

Repository test hooks are argument arrays, not shell strings. ConClear supplies
documented paths and immutable references as individual environment values.
Hooks cannot interpolate command text and cannot override release state,
evidence fields, registry subjects or signer identity.

<a id="promise-ip0009"></a>
An image may declare a `test` table containing repository fixture handles,
run-owned output handles, ordered preparation steps, launch inputs and
dependencies on other image IDs from the same configuration. A fixture names an
immutable source-tree path and is always mounted read-only. An output names a
run-owned directory that ConClear creates empty before the first preparation
runs and that may be mounted writable only at a destination already declared
by the selected image's runtime profile. A read-only mount may name only an
output that an earlier preparation wrote, and every output must be mounted
writable by at least one preparation or by the launch. An output that only the
launched container writes needs no preparation; its final content is observed
and recorded, not required. Fixture and output names share one namespace, so a
mount identifies its source by name alone and is read-only unless it declares
otherwise. An output marked secret is never exposed to repository hooks or
included by value or content digest in public evidence.

Each preparation step selects the primary image or one of its declared
test-image dependencies, replaces that exact image's entrypoint with an argument
array, supplies only declared non-secret environment values and mounts, and
declares a bounded timeout and expected exit status. Preparation executes under
the selected image's configured user, root filesystem mode, capability,
`no-new-privileges`, platform and resource controls. It cannot alter those
controls or the main launch verdict. The main launch retains the tested image's
original entrypoint and may add an explicit argument array, non-secret
environment values and declared mounts; its expected one-shot exit status
defaults to zero.

Test-image dependencies form an acyclic graph of image IDs declared in the same
`conclear.toml`. ConClear rejects unknown IDs, self-dependencies, duplicates,
cycles and dependencies that do not cover every platform of the depending image.
Before a qualification builds anything, the static checks and the pin gate run
for the complete dependency closure in stable dependency-first order: every
transitive dependency, then the selected image, each under its own
Containerfile, context, declared pins and pin limits at one instant. Every
distinct readable tag is resolved once for the whole closure, so images that
share a tag observe one digest, and a static rejection anywhere in the closure
stops the run before any registry is contacted. Every finding of the closure
names the image it concerns, so a rejection is attributable. ConClear then
builds each dependency once from the same isolated revision, source timestamp,
target platform, version input and resolved Buildah toolchain, validates its OCI
layout and labels, imports it by its reverified manifest digest, and exposes no
mutable reference. A dependency participates only in the primary image's tests
and is not represented as independently qualified or releasable. The platform
qualification records, for each dependency, its Containerfile and context
digests, build arguments, external images, pin observations and effective pin
limits next to its layout and manifest digests. Transport import and assembly
verify that evidence against the configured dependency set, pins and limits, and
assembly requires it to agree across platforms. Build arguments are never
trusted from a record: the `assemble` command derives the one map every build of
the run received, from the selected source revision, the commit time Git
observed for it and the release version, when it imports each transport and
again when it assembles the candidate, and it rejects any qualified image or
dependency whose recorded map differs from that derived map in any key. Release
provenance names each dependency's Containerfile, context, tested manifest and
external images as resolved dependencies.

An image is releasable when it declares a `repository`; it then also declares
its release tags. An image without a repository is test-only: it declares only
what a dependency uses, namely its build inputs, platforms, pins, pin limits,
runtime contract and its own dependencies, and the keys that only a qualified
image uses are rejected there. ConClear's typed model mirrors that split: the
common build-image model holds exactly those facts, the release image type adds
the destination, tags, native-test requirements, scanner and rescan policy,
test inputs, hooks, vulnerability exceptions and release limits, and scanning,
runtime qualification, assembly, publication and rescan accept only the
release image type, so release-only state cannot exist on a test-only image.
ConClear refuses to select a test-only image for a build, qualification, release
or rescan, ignores it when probing or cleaning registry destinations, and
rejects a test-only image that no image depends on. A releasable image may serve
as a test dependency as well; both roles use the same declaration.

Vulnerability exceptions use a dedicated typed table declared inside the image
they apply to, which identifies the image as the guide requires; each exception
states component, advisory, rationale, reachability, exposure, compensating
controls, owner, expiry and review trigger. ConClear verifies structure, expiry
and an exact finding match, and records the image identifier with every applied
exception. Security-owner review remains a repository merge-control
responsibility and is not inferred from a self-declared field.

<a id="promise-ip0010"></a>
Maintainer-controlled release configuration is separate from the application
repository. A named profile under `$XDG_CONFIG_HOME/conclear/` supplies a public
HTTPS SLSA builder identity and explicitly selects one compiled registry control
backend with its host, API and credential locations. The profile may also
identify a containers-auth file, Cosign private-key and public-key paths, a
passphrase provider, or a KMS/HSM key handle. It contains trust identities and
credential locations, not alternative guide rules or secret values. ConClear
rejects release configuration and file-based credentials with unsafe ownership
or permissions. Backend selection is never inferred from a repository hostname.

The release profile configures optional CI context handling as `omit`, `observe`
or `require`. `omit` does not inspect provider variables. `observe` records
complete context that agrees with the isolated checkout and otherwise writes a
local diagnostic without changing the release result. `require` treats missing,
malformed or inconsistent context as an operational failure. ConClear recognizes
GitHub Actions, GitLab CI, Gitea Actions, Forgejo Actions and Woodpecker CI
through provider-specific adapters. Gitea and Forgejo markers take precedence
over their GitHub-compatible variables.

Public CI context has one provider-neutral shape: provider,
`provider-environment` source, repository, full source revision and provider run
identifier. The values are correlation metadata from ordinary process
environment variables, not authenticated CI identity. They cannot override the
isolated checkout, builder, signer, ConClear run identifier, artifact digest or
release verdict. Full provider origins stay in local diagnostics so signed
public evidence does not disclose internal hostnames.

On a workstation, the signing passphrase may be read from the controlling
terminal. Automation may provide a read-once file descriptor or mounted secret.
If Cosign requires a child-process environment variable, ConClear creates it
only for that Cosign process from the protected source and removes it from all
logs and evidence. Secret values are never inherited from ordinary project
environment configuration.


## Built-in limits<a id="built-in-limits"></a>

<a id="promise-ip0011"></a>
ConClear ships enforceable limits. Repository configuration may shorten these
intervals but cannot extend or disable them.

|                                            Limit                                             | Built-in maximum |
| -------------------------------------------------------------------------------------------- | ---------------: |
| Age of a successful pin resolution used for qualification                                    |         24 hours |
| Divergence between a declared tag and its pinned digest                                      |           7 days |
| Candidate lifetime before promotion                                                          |           7 days |
| Remediation after an authoritative rescan finds a fixable `HIGH` or `CRITICAL` vulnerability |          30 days |

Pin observations are stored in durable ConClear state outside the project
checkout. CI must persist that state through a protected cache. When a
divergence has no earlier observation, ConClear records the current registry
resolution as the first observation and marks the history as newly initialized
in evidence.

The seven-day divergence maximum applies to both pin intents. Divergence under
an `immutable-version` tag immediately emits a non-suppressible, review-required
supply-chain finding; the pin gate may continue to use the pinned digest within
the interval, but the review obligation does not pause or extend the maximum.
Divergence under a `moving-release-line` tag is a routine update proposal within
the interval. Either intent rejects qualification after the maximum expires.

Changing a built-in limit changes release behavior and therefore requires a
reviewed code change, conformance update and ordinary ConClear release. Evidence
identifies the exact ConClear and guide revisions that supplied the effective
limit.


## Pin updates<a id="pin-updates"></a>

`pins check` remains the freshness and divergence gate and the only owner of
durable pin observations. It never edits project files. `pins propose` and
`pins apply` are separate explicit operations that implement the guide's
pin-update contract without an external updater.

<a id="promise-ip0012"></a>
`pins propose` resolves every distinct readable tag exactly once through
ConClear's authenticated Skopeo resolution and binds that one observed digest to
every occurrence of the tag. It derives the required occurrence set from the
parsed repository configuration and the parsed Containerfiles, not from a
caller-supplied list or a repository-wide text search: the `reference` value of
every `[[images.pins]]` declaration and the exact external image input of every
`FROM`, `COPY --from` and `RUN --mount=from` instruction that names the same
tagged and digest-pinned reference. A declared pin without a Containerfile
occurrence, an undeclared Containerfile input, conflicting tag intents for one
readable tag, a reference that appears in a comment, an unrelated value or an
undeclared file, an ambiguous or unsupported spelling, and any duplicate or
overlapping span are rejected; nothing is rewritten opportunistically. Proposal
generation is repository-wide by default. An image selection is accepted only
when it omits no other image bound to the same readable tag. `pins propose` does
not modify project files, create commits or branches, or update durable pin
observations. Its explicitly requested output file is its only persistent write,
and it refuses to overwrite an existing file.

The proposal is a schema-validated version-1 record with `recordType`
`pinUpdateProposal`. It records the ConClear version, source revision and
embedded guide revision; the resolving tool identity; the creation time from an
injected UTC clock; the canonical repository identity, current full Git
revision, configuration path and SHA-256 digest; the selected image IDs; one
lookup per original tagged-digest reference with its affected image IDs,
declared tag intent, resolved tagged-digest reference, old and new digest and
resolution time; and one entry per affected file with its repository-relative
path, original and expected resulting SHA-256 digests and exact non-overlapping
byte spans with their exact old and replacement bytes. Only the digest of a
reference changes; registry, repository and tag spelling are preserved byte for
byte, and a fully qualified reference is never normalized into another name. The
proposal contains no credentials, authentication-file paths or registry tokens.
Its serialization is canonical JSON, so fixed repository bytes, clock, resolver
observations and tool identity produce identical bytes; its identity is the
SHA-256 of those exact stored bytes. An already-current repository produces a
successful proposal with no file entries. A digest change under an
`immutable-version` tag is recorded as review-required and reported with
`CC0205`; there is no skip, override or automatic acceptance.

<a id="promise-ip0013"></a>
`pins apply` consumes one proposal and never resolves a tag again. Before its
first project-file write it completes a read-only preflight: it validates the
proposal schema and ConClear-supported record identity, confines every path
below the repository root without following symbolic links and rejects absolute
paths, traversal, symbolic links and non-regular targets, matches the canonical
repository identity and current full Git revision, matches the current
configuration digest and every target file's complete SHA-256 digest, reparses
the current configuration and Containerfiles and proves that their dependency
set, paths and occurrence cardinality equal the proposal, validates every span
boundary, old byte sequence, replacement reference, digest and non-overlap
invariant, and rejects a proposal whose resolution time exceeds the effective
pin-resolution freshness limit of the affected images without substituting a
newer digest. It constructs every resulting file in memory, proves that only the
proposed spans differ, writes each file through a same-directory temporary file
created with restrictive permissions, preserves the original mode, flushes and
durably replaces the target, then reparses and verifies the complete result
against the proposal. A proposal with no file entries touches nothing, and a
proposal whose files already carry the expected result is reported as already
applied without writes. On any detected preparation, write, flush, replace or
verification error, every target is restored to its exact original bytes and the
command returns an operational failure; a known partial application is never
left behind. `pins apply` never commits, creates a branch, pushes, merges,
builds, qualifies, publishes, signs or promotes, and it names the follow-up
`pins check` invocation that must confirm the result. A proposal and its
application are not release evidence.


## Command model<a id="command-model"></a>

<a id="promise-ip0014"></a>
The public command surface is composable, but `release` is the normal release
interface. Individual commands support diagnosis, distributed platform work and
recovery without defining an alternative workflow.

A typical local release is selected explicitly:

```sh
conclear release \
  --image example \
  --revision v1.8.2 \
  --version 1.8.2 \
  --profile foundata
```

`--revision` is a Git selector that ConClear resolves and observes; `--version`
supplies release naming and may be omitted for an unversioned project;
`--profile` selects maintainer-controlled trust and credential locations outside
the repository.

|      Command       | Responsibility |
| ------------------ | -------------- |
| `version`          | Report ConClear and implemented-guide identity in human-readable or JSON form. |
| `adopt`            | Assess an existing repository read-only: observe its conventional Containerfiles, source identity, external inputs and runtime facts, suggest conservative values, list the decisions only a maintainer can make, and render a deliberately invalid draft `conclear.toml`. |
| `doctor`           | Validate the environment for one scope without publishing content: `check` resolves the static toolchain, `qualify` adds run-owned rootless storage and an execution mode for every configured platform, and `release` adds trust inputs, selected registry access and public Sigstore transparency-service access. A profile is accepted for a scope only when it names every input the scope's commands use, so the release scope requires registry write authentication, the control-plane token and signing authority without performing a write or signature. Every missing or unsupported tool of the scope is reported at once. |
| `check`            | Run static Containerfile, context, metadata, pin-declaration and repository-hygiene checks. |
| `pins check`       | Resolve declared image references, update durable observations, report freshness and divergence, and never edit project files. |
| `pins propose`     | Resolve each declared readable tag once, bind the observed digest to every configuration declaration and Containerfile occurrence, and write one schema-validated non-mutating proposal. |
| `pins apply`       | Verify one proposal against the current worktree, Git revision and file digests, then replace only the proposed byte spans all-or-nothing without resolving, committing, building or publishing. |
| `build`            | Build one platform into isolated Buildah storage and export an OCI layout plus build metadata. |
| `test`             | Validate and import one layout, compare its imported digest, and run generic and repository-specific tests under the declared runtime constraints. |
| `qualify`          | Run `check` and the pin gate for the image and its test dependencies, then `build`, `test` and evidence generation for one platform in its own worker run and emit `platform-qualification-<platform>.json`. |
| `transport export` | Write one accepted qualification, its OCI layout and the evidence payloads it names as a new archive or directory transport with a digest-binding manifest, and report the transport and record digests. |
| `assemble`         | Create a coordinator run from the reviewed source revision, import each transport only against a caller-supplied digest, verify every record, layout, descriptor and payload, require exact platform coverage, create an index when needed and emit `release-candidate.json`. |
| `provenance`       | Generate an in-toto Statement predicate using SLSA Provenance v1 from the accepted candidate and observed release data. |
| `publish`          | Copy the accepted subject to one generated candidate reference, set its expiration and compare the complete remote digest graph. |
| `attest`           | Attach platform SBOMs and provenance and sign the index and every platform manifest. |
| `verify`           | Verify the remote graph, signatures, attestations, identities and guide evidence and attach a signed release-verification result. |
| `promote`          | Apply configured immutable and moving release tags to the verified digest, verify each tag and delete the candidate tag. |
| `release`          | Create an isolated checkout and execute the complete workflow through promotion, locally or in CI. |
| `rescan`           | Re-evaluate a released digest from retained SBOMs or immutable image content and emit a new linked rescan result. |
| `cleanup`          | Resume cleanup of resources recorded as owned by one release run. |

A command that writes to the registry or signs refuses a release profile that
lacks the auth file or the signing key before it creates or reopens a run. An
option that escalates what a command executes carries its own declaration:
`rescan --authoritative` attaches a signed result and is therefore held to the
write and signing rule, while a diagnostic rescan stays read-only.

`release` selects an image and a Git revision, resolves that selector to a
complete commit ID, creates a detached worktree and derives all source facts
from the checkout. A version supplied for naming is a validated invocation
parameter, not evidence of source identity.

`release --resume <run-id>` resumes only after verifying the recorded source,
configuration, tools, layouts, evidence and remote digests. It refuses to resume
across a changed immutable input. A resumed run reuses its recorded candidate
reference only when the registry resolves that reference conclusively to the
unchanged expected digest within its recorded lifetime. Otherwise the run cannot
continue: a candidate reference is never reused for a second publication
attempt, and the release restarts as a new run with a new run identifier and
candidate reference.

Commands support `--format json`. JSON mode writes one documented result object
to standard output and diagnostics to standard error. The result schema
documents the `data` object of every command: a successful result carries
exactly the documented keys, and a failed result carries only documented keys or
none. A command that created a run before failing names that run as `runId` in
its failure result and diagnostics and leaves the run in the `rejected` or
`incomplete` state, so the journaled resources of every failed run can be found
and removed with `cleanup`. Exit statuses are `0` for success, `1` for
operational failure, `2` for rule rejection and `64` for invalid invocation or
configuration.


## Records and workspaces<a id="records-and-workspaces"></a>

<a id="promise-ip0015"></a>
Every record is UTF-8 JSON validated against a versioned schema. It includes
`schemaVersion`, `recordType`, `createdAt`, `runId`, ConClear and guide
identity, canonical source repository and revision, SHA-256 of the exact
`conclear.toml` bytes, relevant tool identities and a verdict. Timestamps use
UTC RFC 3339 form with whole-second precision and a `Z` suffix. ConClear
truncates a sub-second observation when it reads its clock and never rounds, so
a recorded time never post-dates the observation and identical inputs serialize
to identical bytes. A record digest is the SHA-256 of its exact stored bytes.

`platform-qualification-<platform>.json` additionally binds the target platform;
OCI descriptor and manifest digest; Containerfile, context and effective build
arguments; external image digests; build and test host, target and execution
architectures; emulation or cross-build mechanism; runtime constraints;
non-secret test-input and preparation identities; exact test-image dependency
descriptors and manifest digests; test result digests; SBOM digest and SPDX
version; scan-result and vulnerability-database identities; applied exceptions;
and the platform verdict.

`transport.json` is the `qualificationTransport` record written by
`transport export`. It carries the worker run identity, source, configuration
digest and tool identities of the qualification it wraps and binds the
qualification-record digest, the layout descriptor, the platform-manifest digest
and every member path, size and digest. A transport contains only the
qualification record, the OCI layout and the evidence payloads the record names.

`release-candidate.json` binds exactly one accepted qualification per required
platform, every qualification and payload digest, the worker run identity of
each qualification and the transport digest of each imported one, every
platform-manifest digest, the index digest when present, the required and
accepted platform sets, candidate naming inputs and the aggregate verdict. Its
own run identity is the coordinator run, which also names the candidate
reference. A single-platform release uses the same aggregate schema and assembly
step.

A pin-update proposal uses its own version-1 schema rather than the public
record envelope: it is a reviewable input to a repository change, not release
evidence, and it carries no run identifier.

`release-verification.json` contains the subject and platform digests; ConClear
version and source revision; guide title, repository, path and revision; SHA-256
of `conclear.toml`; host architecture, run identity, protected builder identity
and optional observed CI context; signer mode and public-key fingerprint or
managed-key identity; and digests of the qualifications, SBOMs, scan results,
provenance and candidate record. It is an intermediate predicate, not a source
comment or committed project file. Its signed registry attestation is
authoritative.

<a id="promise-ip0016"></a>
A run workspace is stored under `$XDG_STATE_HOME/conclear/runs/<run-id>/`:

```text
run.json
resources.json
source/
logs/
layouts/<image>/<platform>/
reports/<image>/<platform>/
records/platform-qualification-<platform>.json
records/release-candidate.json
records/provenance.json
records/release-verification.json
exports/sbom/<platform>.spdx.json
summary.json
```

`<platform>` is a filesystem key formed by joining the normalized OCI operating
system, architecture and optional variant with hyphens. For example,
`linux/amd64` becomes `linux-amd64`; records continue to use the canonical
slash-separated OCI value.

ConClear writes `run.json`, `resources.json` and state transitions atomically.
`resources.json` records each local path, Buildah storage location, Podman
import, test container, transport staging directory, imported layout, assembled
candidate layout, candidate reference, expiration and tag write before and after
mutation. Generated test outputs and private test material are created only
below a journaled run-owned directory. Each entry distinguishes ephemeral
run-owned resources from durable release outputs. Cleanup follows only ephemeral
ownership records and never deletes promoted tags, signatures, attestations,
transported inputs, caller-owned paths or pre-existing registry content.

Rejected runs retain reports with `verdict: rejected`. Interrupted runs are
`incomplete`. Workspaces may be removed after authoritative evidence has been
retained, but ConClear never presents its local state directory as an archive or
registry backup.


## Tool execution<a id="tool-execution"></a>

<a id="promise-ip0017"></a>
The required core tools are Git, Buildah, Podman, Skopeo, Hadolint, Trivy and
Cosign, executed as host executables. External updaters and Testinfra project
tests are not hidden ConClear services: an updater such as Renovate stays
outside ConClear as optional review delivery, while Testinfra may be invoked
through a declared repository hook whose interpreter and dependency lock are
recorded.

Each ConClear release carries a tool-specific compatibility policy for every
host tool: an inclusive minimum, an exclusive maximum and explicitly excluded
versions with known defects or advisories, derived from the flags, output fields
and behaviors each adapter uses. The policy is a compatibility statement, not
run identity; the exact versions ConClear's real-tool tiers ran against are
recorded separately as tested versions, and the real-tool tier fails on a host
whose version is not yet listed. Every command declares the host tools its call
path executes and resolves only those: it resolves each executable to an
absolute path, parses its canonical version, records that version and the
executable digest, and rejects a version outside the accepted interval or in the
exclusion list with a diagnostic naming the observed version, the interval, the
exclusions and the tested versions. A run pins a tool's identity from the first
phase that resolves it. A later phase that resolves the same tool must observe
the identical executable, a phase that first uses a tool binds it then, and a
promoted or rejected run records nothing further. `release` resolves the
complete toolchain at start and holds it constant; ConClear rechecks every
recorded identity before later use so a package upgrade during a run cannot
silently change the toolchain, and distributed qualifications of one release
must report identical normalized tool versions, never merely compatible ones. A
later release run may use newer accepted tools. `doctor` validates one scope,
`check`, `qualify` or `release`, by resolving the union of the tools those
commands declare and reporting every failure instead of the first.

All external commands use argument arrays, sanitized environments, explicit
timeouts, bounded retries and captured logs. ConClear never constructs a shell
command from project input. Logs redact credentials, authorization headers,
passphrases and secret mount paths before they are persisted or displayed.

Buildah receives a run-specific root and runroot. Podman imports use run-owned
names and are resolved back to their immutable manifest digest before testing.
No command relies on the user's mutable short-name search configuration.

<a id="promise-ip0018"></a>
The Trivy database cache lives under `$XDG_CACHE_HOME/conclear/`. Refresh uses a
lock, a same-filesystem temporary directory, validation and atomic rename. At
release start, ConClear selects one validated database snapshot and holds its
content digest constant across every platform scan in the release. Distributed
workers receive or resolve that exact snapshot by digest. A stale or corrupt
cache triggers one bounded refresh and never falls back silently to unvalidated
data.


## Build and qualification<a id="build-and-qualification"></a>

<a id="promise-ip0019"></a>
`release` creates its build context from an isolated detached worktree of the
selected commit. The ordinary checkout may be dirty, but its uncommitted and
untracked files cannot enter the context. ConClear validates `.containerignore`,
rejects source paths outside the checkout and records the exact Containerfile
and configuration digests. Hadolint runs with the image's context directory as
its working directory and, when that directory contains a committed regular
`.hadolint.yaml` or `.hadolint.yml`, receives it explicitly, so the reviewed
checkout rather than the invoking directory or the operator's home defines lint
policy.

<a id="promise-ip0020"></a>
Buildah produces OCI format in rootless mode and exports an OCI layout. ConClear
derives `SOURCE_DATE_EPOCH` from the source commit time where the project build
supports it. Timestamp rewriting is a build input and is never applied after
testing.

ConClear supplies `IMAGE_REVISION` from the full observed source commit,
`IMAGE_VERSION` from the validated release version when present and
`IMAGE_CREATED` as an RFC 3339 representation of the controlled source
timestamp. It inspects the final image configuration and rejects missing
mandatory `org.opencontainers.image.*` labels or source, revision, version and
creation values that disagree with those observations.

<a id="promise-ip0021"></a>
Every release includes `linux/amd64`. `linux/arm64` is optional and required
only when declared; omitting it needs no reason and leaves no trace in
configuration or evidence. `native_test_platforms` must be a subset of
`platforms` and makes native runtime testing mandatory for the listed targets;
emulated tests reject qualification there. Every other target qualifies through
native or QEMU user-mode emulated build and runtime tests alike, provided build
and test records identify the target, host, execution architecture and emulation
mechanism; ConClear neither asks for nor records a justification for emulation.
KVM is recorded only as acceleration for an executable guest architecture and is
never treated as cross-architecture emulation. Before building or testing a
platform whose architecture differs from the host, ConClear requires an enabled
`binfmt_misc` handler for that architecture; without one the phase fails
operationally, names the missing handler and leaves the platform unqualified,
and ConClear never installs emulators or registers handlers itself. Assembly
rejects a qualification record whose execution observation claims native
execution for a foreign architecture or emulated execution for the host
architecture.

At configuration-to-layout boundaries, `linux/arm64` and `linux/arm64/v8` select
the same target because an omitted OCI arm64 variant denotes the v8 baseline.
This equivalence applies to required-platform, native-test, dependency-coverage,
qualification-transport and assembly checks. Other variants remain distinct, and
assembled descriptors and platform-manifest evidence retain the exact variant
observed in the image configuration.

<a id="promise-ip0022"></a>
For each platform, ConClear validates the primary layout and every declared
test-image dependency recursively, imports them through a digest-preserving
containers-storage path, resolves every imported manifest and compares it with
the corresponding layout digest before starting preparation or tests. A mismatch
is an operational failure. Tests address run-owned names created from those
verified imports rather than mutable registry references.

Before the primary container starts, ConClear creates declared output
directories with private ownership and validates every repository fixture
without following symbolic links. It rejects path escape, symbolic links,
special files, unsafe ownership or modes, writable repository fixtures,
undeclared mount sources, overlapping container targets and writable
destinations outside the selected image's declared runtime mounts. Preparation
containers run sequentially from exact imported images. After each step ConClear
verifies its exit status and the ownership, type and mode of every generated
output before a later step may consume it.

<a id="promise-ip0023"></a>
Built-in runtime checks cover the configured user, root filesystem mode,
writable mounts, private user and cgroup namespaces, absence of privileged
mode, capabilities, `no-new-privileges`, startup, health command, signal
forwarding, expected exit-status propagation, shutdown, file ownership and
resource behavior. The observed writable destinations must equal the effective
declared set; this comparison includes anonymous volumes created from image
metadata. Runtime application files expected to remain immutable are checked
for root ownership and permission modes that deny group and other writes. They
cannot overlap a writable runtime mount. For a non-root runtime identity,
owner-write bits do not grant that identity access and are not rejected. For
UID 0 with a read-only root, the root and non-overlap requirements keep those
paths immutable. An authorized administrator on a writable root can change
them; ownership checks then protect against direct unprivileged writes only.
Launch arguments and non-secret environment values supplement the
image's original entrypoint; they cannot replace it or override a built-in gate.

Every runtime container uses rootless Podman with an explicit private user
namespace and private cgroup namespace. Container UID 0 therefore maps through
the invoking rootless user's namespace and does not grant host root. ConClear
never enables privileged mode, a host user or cgroup namespace, host devices or
repository-selected writable host paths. Only separately declared, run-owned
test outputs may be writable bind mounts. It drops every capability before
adding only the exact reviewed set in configuration and verifies the resulting
bounding and effective sets. These constraints apply equally to the systemd
profile.

Permission probes use separate, journaled containers from the exact imported
artifact. The sudo probe resolves declared executables, checks their set-ID
modes and root ownership, and checks that their parent directories are not
writable by unprivileged users. It validates sudoers with `visudo -c`, checks
policy ownership and parents, and retains the validated files with their
digest in the test report. The permitted operation must succeed with exact
stdout; the denied caller must fail both authorization and execution. ConClear
queries that caller's authorization as container root with `sudo -l -U`, so a
missing password cannot be mistaken for policy denial. It executes the
negative operation as the actual non-root caller and records both identities.
The probe observes each non-root caller's UID and kernel `NoNewPrivs` flag.

A functional contract with escalation, a writable root or extra capabilities
also receives a restrictive probe with read-only root, no capabilities and
`no-new-privileges`. Sudo escalation must fail there. Generic restrictive probes
check effective controls without requiring administrative startup to succeed.
Set-ID inspection requires a POSIX shell, `sleep`, `readlink` and `stat`.
Sudo tests also require `id`, `cat`, `env` and the image's sudo/visudo
implementation. The probes are
removed before the primary lifecycle test; declared launch fixtures are the
same in each container. Final-image inventory and the adequacy of each
authorization scope remain reviewed responsibilities, including undeclared
privileged executables inherited from a base image.

For a systemd image, ConClear explicitly enables Podman's systemd mode and
applies the `SIGRTMIN+3` stop signal. It verifies that PID 1 is `systemd`, that
a `systemctl` manager query succeeds and that every configured required unit
becomes active. Required-unit probes and an optional application health command
share the one monotonic startup budget. The profile then sends `SIGRTMIN+3` and
applies the ordinary bounded shutdown and exit-status checks. Failure of PID 1,
manager, unit, health or shutdown expectations produces a `CC0403` rejection; an
inability to invoke or observe Podman remains an operational failure.

For a service health command, a nonzero application status means not ready and
is retried at a bounded implementation-owned interval until success or the
configured startup deadline. The startup timeout is one monotonic readiness
budget: every probe is bounded by its remaining time and cannot restart the
budget. A service that exits before readiness or remains unhealthy at the
deadline produces a `CC0403` rejection. A Podman operation failure, an
unavailable or unexecutable health command, or an inability to inspect the
service remains an operational failure rather than an application-health result.
Readiness evidence records the attempt count, configured timeout, elapsed wait,
final command status, final container state and a digest of the final bounded
redacted command output; run-owned command logs retain that bounded output for
diagnostics.

Smoke tests apply explicit memory, CPU, process and file-descriptor limits from
repository configuration and record the effective values. Health checks run the
repository-declared command; ConClear does not expect an OCI image to contain
Docker-format `HEALTHCHECK` metadata. Test evidence records hashes of the launch
declaration, each preparation declaration, the exact image manifest supplying
its executable, non-secret fixture and output trees, and every dependency layout
and manifest. Secret output facts identify the producing step and use but omit
values, paths and content digests.

<a id="promise-ip0024"></a>
Repository hooks add application-specific assertions but cannot skip built-in
gates. A hook receives a run-owned non-secret test-input manifest containing the
primary and dependency layout paths, immutable digests and non-secret generated
output handles; it receives no mutable image reference or secret output path.
Hooks are reviewed source commands run with ConClear's sanitized host
environment, but ConClear cannot sandbox them from invoking other host
executables. Their recorded executable and output identities make that trust
boundary observable; a hook-side rebuild or pull cannot replace ConClear's
exact-image built-in results.

ConClear destroys preparation containers, generated outputs and secret material
on success and on ordinary failure cleanup. Cleanup failures preserve failed
journal entries and identify retained resources; they do not authorize deletion
of an unjournaled path. ConClear does not provide a success-retention mode for
test secrets.

<a id="promise-ip0025"></a>
Trivy is the authoritative scanner for packages, vulnerabilities, secrets and
configuration. It scans the build context for secrets, the Containerfile and
image configuration for insecure settings, and the final layout for packages,
vulnerabilities, secrets and configuration. A fixable `HIGH` or `CRITICAL`
vulnerability rejects qualification unless an exact, approved and unexpired
repository exception applies. Trivy is the only supported scanner stack, and
exactly one vulnerability result gates a release. Every rejecting scan runs
against local content and the digest-addressed layout before publication. Every
failed Trivy configuration check rejects qualification except `DS-0026`, which
demands a Containerfile `HEALTHCHECK` that the guide forbids in OCI-format
images and `CC0112` rejects; that single check is inapplicable by construction
and is not a repository exception.

Each platform SBOM is SPDX 2.3 JSON. ConClear validates the document, records
its exact specification version and exports the raw JSON.

<a id="promise-ip0026"></a>
A qualification is validated in one of two ways and never by rewriting it. A
record owned by the assembling run must name that run. A transported record
keeps its worker run identity and is accepted only through a transport: the
coordinator compares the transport with a digest the caller supplied
independently before trusting any member, stages the content below its own
workspace through the bounded, link-free archive extractor or a member-by-member
copy that follows no symbolic link, and rejects absolute paths, traversal,
symbolic and hard links, device nodes, duplicate, missing and undeclared members
and size or member-count abuse. It then verifies every member against the
manifest, the qualification-record digest, the record schema and verdict, the
layout graph, the platform descriptor and image configuration, the
platform-manifest digest and the evidence payloads, installs the verified copies
at the standard workspace locations under journaled ownership, and only then
reads the qualification. Failed imports retain their staging directory under a
failed journal entry for cleanup.

<a id="promise-ip0027"></a>
Assembly requires matching source repository and revision, repository
configuration, guide and ConClear identity and release version across all
qualifications and against the coordinator run; a qualification produced by
another ConClear revision is rejected without an override. For every external
tool used on multiple platform workers, its normalized reported version must
match. Platform-specific executable digests may differ and remain recorded in
each qualification. The authoritative vulnerability-database content digest, the
declared pin set, the observed pin digests and the effective limits must match
exactly across all platform qualifications. Assembly also compares OCI platform
descriptors with image configuration, rejects missing, duplicate and unexpected
platforms, and creates one image index for a multi-platform release whose
candidate reference is named for the coordinator run. No record with an
incomplete or rejected verdict can enter a candidate, and copying workspaces or
records outside a transport is not a supported path.


## Publication and promotion<a id="publication-and-promotion"></a>

<a id="promise-ip0028"></a>
Public foundata images are published to configured repositories on `quay.io`.
Consumed images and prepublication release destinations may use another fully
qualified authoritative registry. ConClear rejects short names and does not
rewrite an upstream reference to prefer one provider.

ConClear separates OCI transport from provider control. Skopeo copies and
resolves OCI content. A compiled registry backend observes and changes
provider-specific tag controls. The release profile selects the backend
explicitly, and the complete `publish` through `promote` workflow rejects an
incompatible destination before qualification or remote mutation. The local
`check`, `pins check`, `build`, `test`, `qualify`, `assemble` and `provenance`
stages remain available for destinations without a supported backend.

A supported registry backend must provide exact tag observation,
digest-preserving manifest-list and platform graph handling, OCI referrer
support compatible with Cosign, an independently enforced candidate lifetime,
exact digest tag assignment, owned-tag deletion and post-write observation that
resolves ambiguous writes. It must enable selective immutable-tag protection
where the provider enforces it and report the control as unavailable where the
provider accepts but does not enforce it; repository-wide immutability does not
satisfy the requirement. Local timestamps and best-effort cleanup never satisfy
the lifetime requirement. Quay.io provides the required controls, does not
currently enforce per-tag immutability, and `quay` is the only implemented
backend.

<a id="promise-ip0029"></a>
The default candidate lives in the final release repository so signatures and
OCI referrers remain with the subject. A versioned release uses
`<version>-candidate.<run-id>.g<source-revision-short>`. An unversioned release
uses `g<source-revision-short>-candidate.<run-id>`. ConClear generates the
lowercase ULID, uses the first eight hexadecimal characters of the full source
revision for the short form and validates every component before creating the
tag.

`publish` checks that the candidate tag is unused, then copies the accepted
manifest or index with Skopeo's digest-preserving path, including every platform
for an index. It resolves the remote index, platform manifests and referenced
content and compares the complete graph with the local candidate. Registries do
not provide a portable compare-and-swap operation, so pre-write checks detect
ordinary collisions while post-write verification determines success.

Immediately after a successful copy, ConClear asks the selected backend to
enforce and verify the candidate lifetime. Failure to establish that independent
control stops the release before attestation. ConClear enables candidate tag
immutability when the backend supports it and otherwise records that the
recommended control was unavailable. A failed or ambiguous publication is
recorded for cleanup; resume reuses its tag only after conclusively resolving it
to the unchanged expected digest within its lifetime. Candidate content and
evidence must be safe for public disclosure; later provider garbage collection
is outside the release verdict.

<a id="promise-ip0030"></a>
Promotion first confirms that the candidate has not expired, then resolves and
verifies the signed release-verification attestation. It refuses to replace an
immutable version tag that already names another digest, whether or not the
registry enforces immutability. It writes only the verified digest to each
requested immutable or moving tag, enables registry tag protection where the
backend supports it and records when that control was unavailable, resolves
every tag afterward and records the observed result separately. A partial
multi-tag update is an operational failure and is never hidden by rollback or
repointing.

After successful promotion, ConClear deletes the candidate tag and verifies its
removal. An abandoned or rejected candidate may be deleted with `cleanup` or
left to its recorded expiration. Failure to delete after successful promotion is
reported as cleanup failure without changing the release digest's verified
status.


## Provenance, signing and verification<a id="provenance-signing-and-verification"></a>

<a id="promise-ip0031"></a>
ConClear generates release provenance as an in-toto Statement with a SLSA
Provenance v1 predicate. It derives the subject graph from
`release-candidate.json`, source identity from the isolated Git checkout,
builder identity from the protected release profile, ConClear implementation
identity from embedded data, and the run identity from observed execution.
Repository configuration, CI environment metadata, labels and arbitrary
command-line values cannot override those identities.

The SLSA builder ID is a stable, credential-free HTTPS documentation URI naming
one complete build-platform trust domain. The protected release profile supplies
it, and the workspace binds it as an immutable release input.
Security-significant environments use different builder IDs.
`runDetails.builder.version` records the ConClear version and full source
revision, so application upgrades do not change the identity of an otherwise
unchanged build platform.

The first documented builder is
`https://foundata.com/en/projects/conclear/builder/simple-v1/`. It covers the
foundata operator-controlled workstation environment and claims SLSA Build L1
only. An arbitrary CI worker is outside that trust domain, even when it invokes
ConClear. A separately controlled CI platform needs its own builder identity and
documentation; ordinary provider environment variables cannot authenticate or
select it.

Materials include the canonical source repository and full commit,
Containerfile, repository configuration, external image digests and other
integrity-checked dependencies known to the build. Parameters exclude
credentials and secret values. Verification requires the exact profile-selected
builder ID and embedded ConClear version, then binds the accepted builder ID
into `release-verification.json`. Consumers accept only explicitly configured
signer and builder pairs.

The predicate is generated from the accepted candidate before publication. After
publication, ConClear verifies the final registry digest, validates that it
equals the predicate subject and only then attaches provenance. Cosign wraps
every attestation around exactly one subject, so ConClear attaches the
provenance predicate to the index digest and, separately, to each platform
manifest digest; the local `provenance.json` statement records the complete
subject set and every attached copy must carry the identical predicate.

<a id="promise-ip0032"></a>
The baseline signer is a foundata-managed Cosign key pair. The encrypted private
key and its passphrase are supplied to the authorized release environment
through protected secret mechanisms; the approved public key is supplied
independently through maintainer-controlled trust configuration. A KMS- or
HSM-protected key SHOULD be used when that infrastructure is available. A
workstation holding the managed signing authority can produce a valid release.

Signer identity is the SHA-256 fingerprint that ConClear computes from the
approved public key, or the managed-key identity resolved by the Cosign adapter.
It remains distinct from the build-platform identity, ConClear implementation
identity and Git source identity. Neither private key material nor its
passphrase appears in a project file, command-line literal, ordinary environment
configuration, log, provenance statement or evidence record.

The managed-key-pair baseline requires a supported registry backend, the private
key, the independently supplied public key and access to Cosign's supported
default public Sigstore transparency service. The Cosign adapter uses run-owned
configuration directories and an adapter-controlled release configuration so
ambient user settings cannot replace or disable that service. It does not expose
a release option to disable log upload or ignore log verification. Failure to
obtain or verify log inclusion stops the release.

No ConClear command signs before `publish`. In particular, `check`, `build`,
`test`, `qualify`, `assemble` and `provenance` produce no signature or
transparency-log entry. ConClear provides neither a manual signing-experiment
mode nor a no-log release mode; manual signing experiments use disposable test
keys outside ConClear as described by the guide.

`attest` resolves the remote subject again, attaches one signed SBOM attestation
to each platform manifest, attaches provenance covering the index and platforms,
and signs the index digest and every platform-manifest digest. Every operation
obtains public transparency-log inclusion. A single-platform release signs its
manifest once. Partial attachment, signing or log inclusion leaves an unverified
candidate and blocks promotion; retry first verifies the unchanged expected
subject graph.

The signed SPDX attestation is the repository-scoped consumer copy. ConClear
retrieves and validates its predicate through Cosign during verification and
rescans; it does not use Cosign's deprecated unsigned raw SBOM attachment
command.

<a id="promise-ip0033"></a>
`verify` starts from the candidate digest rather than its tag. It recursively
compares the registry graph with the candidate, verifies every required image
signature and transparency-log inclusion against the external trust root,
retrieves and verifies one SBOM per platform, validates the recorded SPDX
version, verifies provenance subject coverage, signer identities and log
inclusion, and checks that all evidence digests match the qualification records.

After those checks pass, ConClear creates `release-verification.json`, records
the single-subject in-toto Statement it expects Cosign to produce, has Cosign
sign and attach the record as that statement's predicate with public log
inclusion, retrieves it again and verifies its subject, predicate digest, signer
and log inclusion. Only that post-attachment success advances the run to
`verified`. Promotion immediately repeats verification of this attestation, its
log inclusion and the subject digest.


## Rescans<a id="rescans"></a>

<a id="promise-ip0034"></a>
`conclear rescan --subject <repository>@<digest> --image <image>` accepts an
immutable released subject. It retrieves and verifies the signed
release-verification attestation, including transparency-log inclusion, and
rejects a missing or conflicting result. It takes the required
repository-configuration digest from that predicate, then enumerates every
platform manifest, retrieves each signed SBOM, verifies the attestation, signer
and log inclusion against the external trust root, and evaluates the current
vulnerability data for the complete platform set.

An SBOM rescan is explicitly recorded as vulnerability matching against retained
inventory only. A rescan that requires secret or configuration analysis
retrieves the immutable image content and repeats those scans. Partial platform
coverage cannot produce an accepted result.

The rescan result records the released subject, platform manifests, scanner and
database identity, ConClear and guide identity, repository-configuration digest,
findings, triage state, previous result digest and verdict. A change in triage,
remediation or exception state produces a new linked result and never mutates an
earlier result.

An authoritative rescan signs and attaches its result to the released digest,
after which ConClear retrieves and verifies it. The successful post-attachment
verification time starts the remediation clock. The signed rescan attestations
on the released digest are the authoritative history. ConClear also keeps that
history in protected durable state outside the project checkout and requires
each later authoritative or diagnostic rescan to link the exact latest result,
so omitting a prior result cannot reset a finding's clock. Durable state is a
cache of the attested history rather than a separate source of truth: when it is
absent or older than the subject, as on a first rescan from another authorized
release environment or a replaced machine, ConClear reconstructs the chain from
the verified rescan attestations and continues it instead of starting a new one.
Durable state that conflicts with the attested chain is an operational failure.
The result records each active fixable finding's effective deadline when a prior
authoritative observation started its clock and rejects an overdue finding. An
invocation without signing authority emits a local diagnostic only and does not
advance the history. Scheduling, the supported-release inventory, triage,
advisory publication and rebuilds remain external responsibilities.


## Implementation structure<a id="implementation-structure"></a>

<a id="promise-ip0035"></a>
ConClear is implemented in Python 3.12 or newer with a `src/` package layout,
`uv_build` and a committed `uv.lock`. Click provides the command hierarchy and
JSON Schema validates configuration and public records. Internal models are
typed dataclasses or narrowly typed value objects; there is no generic artifact
framework.

The implementation separates these responsibilities:

- CLI parsing and human or JSON presentation.
- Version and guide identity embedded at build time.
- Configuration loading, path validation and effective-limit calculation.
- Check catalog and guide-conformance generation.
- Structured external-command execution and redaction.
- Run workspace, ownership journal and atomic state transitions.
- Git source selection and isolated worktree management.
- Buildah, Podman, Skopeo, scanner and Cosign adapters, plus a provider-neutral
  registry control contract and compiled backend selection.
- OCI layout, descriptor and registry-graph validation.
- Qualification, assembly, provenance, publication, attestation, verification
  and promotion services.
- Versioned JSON schemas and deterministic record serialization.

Adapters return typed observations and never decide the release verdict
themselves. Workflow services apply the guide rules to those observations.
Presentation consumes the same result objects used for JSON output so human and
machine modes cannot disagree.

Network operations are bounded and classified by idempotency. Reads may retry. A
write retries only when the remote state can be checked first and the ownership
journal makes the result unambiguous. Errors retain tool output after redaction
and add actionable context without converting an unknown state into success.


## Testing<a id="testing"></a>

<a id="promise-ip0036"></a>
Ruff, strict mypy, pytest and coverage run for the Python code. The hermetic
unit suite carries an enforced minimum branch-coverage floor that the
distribution gate applies; the floor is raised as coverage grows and is never
met by excluding code. Tests use explicit markers for unit, local integration,
emulation and network access so the default suite never publishes or requires
credentials.

Unit tests cover configuration validation, limit narrowing, check identifiers,
candidate naming, state transitions, record schemas, digest binding, platform
coverage, command redaction, error classification, deterministic pin-proposal
generation with an injected resolver and clock, and all-or-nothing proposal
application with injected write, flush, replace and verification faults.
Property tests cover reference parsing, path containment, archive extraction and
OCI descriptor graphs.

Rootless integration tests exercise real supported versions of Buildah, Podman,
Skopeo, Hadolint, Trivy and Cosign. Fixtures include a non-root service, a
one-shot image, a `scratch` image, a documented PID-1 supervisor and a
multi-platform index. Tests assert that runtime resource controls remain
effective and that OCI format does not preserve Docker-only health metadata.

Network tests for the implemented backend use a disposable Quay repository, a
dedicated test signing key and credentials with the narrowest practical scope.
Release-path tests use the public transparency service because they must
exercise the production policy; their repository and key identity clearly mark
the resulting permanent entries as tests. They cover digest-preserving
publication, candidate expiration, referrers, partial signing, log inclusion and
verification, tag races, promotion and candidate deletion. Destructive tests
never target a shared production repository or use a release signing key.

The
[foundata declarative OpenLDAP image](https://github.com/foundata/oci-openldap-declarative)
is a continuing end-to-end compatibility project. It exercises the documented
supervisor contract, root-owned immutable runtime files, deployment-owned health
checks and measured resource limits. Compatibility is asserted by running its
normal release configuration, not by adding product-specific rules to ConClear.

The acceptance test for release behavior is a complete workstation invocation
from an ordinary checkout, even when that checkout is dirty: ConClear must
isolate the selected reviewed commit, qualify every required platform, publish
and verify a unique candidate, sign with externally supplied managed key
material, promote the verified digest and retain the required evidence without
CI-only services.

The provider-independent distribution gate may retain its validated source
distribution and wheel in a caller-selected new directory. It embeds the clean
committed ConClear revision before building, builds the wheel from the source
distribution, validates both artifacts, installs and smoke-tests that exact
wheel, and makes the artifact directory visible only after every gate succeeds.
It never rebuilds retained artifacts, derives identity from an application
repository, follows a symbolic-link destination or overwrites a pre-existing
output.


## Adopting an existing repository<a id="adopting-an-existing-repository"></a>

<a id="promise-ip0037"></a>
`adopt` assesses an existing repository before it has a `conclear.toml`. It is
read-only and hermetic: it executes only Git to observe the origin URL and
revision, contacts no registry, resolves no pin and writes nothing except an
explicitly requested draft, which it creates atomically and refuses to
overwrite. It discovers only the conventional `Containerfile`,
`Containerfile.<name>`, `Dockerfile` and `Dockerfile.<name>` files at the
repository root, refuses a root that mixes both families or has none unless
paths are given, and confines explicit paths below the root. Through the same
structural parsers `check` uses, it observes the Containerfile path, the
canonical source identity, every external image input and its pin quality, the
final `USER`, `VOLUME` destinations, `STOPSIGNAL`, static labels and a
recognizable systemd entrypoint. The structural facts select the proposed
runtime profile before the profile-dependent checks run: a systemd entrypoint is
checked against the numeric `USER 0`, the fixed systemd stop signal and the
systemd writable mounts that profile requires, every other image against a
numeric non-root user, so findings, suggestions, decisions and draft values
agree. A build context is not observable; a conventional root Containerfile
receives the repository root as a suggestion and any other selection leaves it a
decision. Every result separates observed facts from suggestions and from
required decisions. Suggestions are limited to image ids derived from file
names, conservative resource limits, release tag templates, the runtime profile
the entrypoint implies, the numeric user the Containerfile states and writable
mounts equal to observed `VOLUME` destinations. It never invents a release
destination, platforms, a root justification, application writable paths, health
behavior, test inputs, dependencies, hooks, exceptions or credentials; each of
those is a listed decision, as is whether an image is released or exists only as
a test dependency, and the draft states what a test-only image must drop and
that an image no image depends on is invalid. The draft names every unresolved
value with a `DECIDE` placeholder that fails the configuration schema and
carries an `[adopt]` table the schema rejects, so an incomplete draft cannot
pass `check` or `qualify`. The JSON result is a closed schema of observations,
suggestions, required decisions, findings and the draft text.


## Maintaining this document<a id="maintaining-this-document"></a>

This document describes only behavior implemented and tested in the current
source tree. Planned or speculative behavior belongs in a
[GitHub issue](https://github.com/foundata/conclear/issues) until its
implementation, tests and contract text land together. Contributors update the
matching `IPnnnn` promise in `src/conclear/data/implementation.json` whenever
current behavior, its implementation ownership or its verification changes, then
regenerate the versioned implementation matrix.

A guide revision update requires reviewing every added, removed or reworded
requirement, updating the embedded guide identity, requirement inventory, check
catalog, coverage file, generated conformance document, affected schemas and
tests. ConClear must not advertise the new guide revision until its automatable
rules are implemented and passing.

Public command behavior and record schemas change deliberately. Each JSON schema
has its own integer version; incompatible field or meaning changes increment its
major schema version, while readers may accept explicitly documented older
versions. Stable check identifiers, implementation-promise identifiers and
published Markdown anchors are never silently repurposed. A generated, committed
internal inventory enumerates the command hierarchy with its options and
arguments, the schema identifiers and versions, the public record types, the
exit statuses, the active and retired check identifiers and the current
implementation-promise identifiers. Its JSON layout is not a supported external
interface. Tests and the release gate verify that the inventory is current, so
every change to an inventoried compatibility surface is an explicit, reviewable
regeneration.
