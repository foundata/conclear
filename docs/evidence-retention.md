# Release evidence and later rescans

This recipe uses existing ConClear commands and ordinary files on a managed
host. It needs no CI service. The operator owns the archive location, access
permissions, backups, supported-release inventory and rescan schedule.

## Contents

- [What to retain](#what-to-retain)
- [Export before cleanup](#export-before-cleanup)
- [Restore and rescan](#restore-and-rescan)
- [Operate the schedule](#operate-the-schedule)

## What to retain

Keep a bundle for each released repository and digest. A version or `latest`
alone is not a stable archive key. The bundle contains:

- One accepted qualification transport per platform, with its export result.
  Each transport includes the exact qualification, OCI layout, SBOM, raw scan
  reports and test report named by the qualification, plus a member manifest.
- The candidate record, provenance statement, release-verification record and
  its statement, and the release summary naming the promoted digest and tags.
- The reviewed source checkout, including the exact `conclear.toml`,
  Containerfiles, build contexts, test fixtures and hook scripts.
- Selected non-secret generated test artifacts when a reviewer needs their
  bytes. The standard transport includes their observations and content
  digests, not every generated output directory.

Qualification and predicate hashes do not replace these files. Preserve the
ConClear and guide identities recorded in the evidence, and access to a
ConClear distribution that can read those record schemas.

Keep command logs, release profiles, private keys, registry authentication,
environment directories and secret test inputs outside the bundle. Logs can
contain application output even when ConClear redacts its own secrets. The
archive starts private; review its source, scan reports and test content before
sharing it. Do not recursively publish a run workspace or its `reports/` tree.

The local release-verification statement is an unsigned convenience copy of
the statement signed in the registry. A checksum manifest detects changed
archive bytes; it does not establish publisher identity. Consumers obtain the
trusted public key independently and verify the registry attestations that
authenticate the evidence digests. Registry backups must separately preserve
the signed envelopes, verification material and every subject's referrers;
neither this bundle nor `skopeo copy --all` is a complete registry backup.

## Export before cleanup

Run this while the successful release workspace, source checkout and selected
Git executable are still available and unchanged. `transport export` rechecks
the source and recorded tool identity; it does not impose a new qualification
age limit. Stop other work on the run while collecting its files.

For a single-host release with `linux/amd64`, set `RUN_ID` to the successful
release run and `BUNDLE` to a new absolute directory under your retention
location. Its parent directory must already exist. The following Bash commands
refuse an existing destination:

```bash
set -euo pipefail
umask 077
: "${RUN_ID:?Set the completed release run ID}"
: "${BUNDLE:?Set a new absolute evidence directory}"
[[ "${BUNDLE}" = /* ]]
run="${XDG_STATE_HOME:-${HOME}/.local/state}/conclear/runs/${RUN_ID}"

jq -e '.state == "promoted"' "${run}/summary.json" >/dev/null
mkdir -- "${BUNDLE}"
mkdir -- "${BUNDLE}/records"

conclear transport export "${RUN_ID}" --platform linux/amd64 \
  --output "${BUNDLE}/platform-linux-amd64.tar" --format json \
  >"${BUNDLE}/platform-linux-amd64.json"

for name in release-candidate.json provenance.json \
  release-verification.json release-verification-statement.json; do
  cp -- "${run}/records/${name}" "${BUNDLE}/records/${name}"
done
cp -- "${run}/summary.json" "${BUNDLE}/summary.json"
tar --exclude='./.git' -C "${run}/source" \
  -cf "${BUNDLE}/source.tar" .
```

Repeat the export for every required platform before finalizing the archive.
Use the platform key in the filenames, for example `platform-linux-arm64.tar`.
Keep the JSON result: `data.transportDigest` identifies the archive and
`data.recordDigest` identifies the qualification bound by the candidate.

For distributed qualification, retain the original transport from each worker
and its export result when it is sent to the coordinator. Check its recorded
transport digest against the coordinator's candidate record. Imported
qualifications retain their worker run IDs, so a coordinator cannot re-export
them as its own qualifications. Copy the coordinator's selected release
records, summary and source checkout as above; do not copy its whole workspace.

Non-secret generated test outputs, when needed, live below
`reports/<image>/<platform>/test-inputs/outputs/<name>/` in the worker run.
Select only outputs declared non-secret, review their contents and copy their
files without following links outside that output. Preserve their paths,
executable modes and the recorded tree-digest observation. Secret outputs are
deliberately destroyed and have no place in this bundle. Add any supplementary
artifact archives to the checksum list below.

The copied source tree, unlike a new export from today's working checkout,
contains the configuration that the release actually used. Verify its recorded
digest after restoration. The transport verifies its qualification's payload
bytes during export; release verification binds the candidate, qualifications,
scans, SBOMs and provenance. Check those bindings when reviewing a restored
bundle against the signed registry statement, not just the local statement.

After all exports and reviewed additions are present, create and verify the
archive checksums:

```bash
(
  cd -- "${BUNDLE}"
  sha256sum -- source.tar summary.json records/*.json \
    platform-*.tar platform-*.json >SHA256SUMS
  sha256sum --check SHA256SUMS
)
```

Copy the completed bundle to the retained location and check `SHA256SUMS`
there. Test retrieval and source restoration before running ConClear cleanup
or deleting the worker and coordinator workspaces. Record the archive location
and a protected copy of its checksum manifest in the supported-release
inventory. Publish the reviewed bundle through an existing release-asset or
download location when consumers need it; recording a path on a maintainer's
laptop does not make the files accessible to them.

## Restore and rescan

Restore only an archive you trust, into a new directory separate from the
current image checkout. `RESTORED` below is that new absolute directory, with an
existing parent. Keep the restored files unchanged:

```bash
set -euo pipefail
umask 077
: "${BUNDLE:?Set the retained evidence directory}"
: "${RESTORED:?Set a new absolute source directory}"
[[ "${BUNDLE}" = /* && "${RESTORED}" = /* ]]
(
  cd -- "${BUNDLE}"
  sha256sum --check SHA256SUMS
)
mkdir -- "${RESTORED}"
tar -xf "${BUNDLE}/source.tar" -C "${RESTORED}"
expected="$(jq -er '.repositoryConfiguration.sha256' \
  "${BUNDLE}/records/release-verification.json")"
actual="$(sha256sum "${RESTORED}/conclear.toml" | cut -d ' ' -f 1)"
test "sha256:${actual}" = "${expected}"
```

Take `SUBJECT` from the protected supported-release inventory and confirm it
matches the bundle's summary. It is a tag-free reference such as
`quay.io/example/app@sha256:<digest>`. For an image named `app` and protected
profile named `foundata`, its first authoritative rescan is:

```sh
conclear rescan --subject "${SUBJECT}" \
  --config "${RESTORED}/conclear.toml" --image app \
  --profile foundata --authoritative --format json
```

This command verifies the original signed registry evidence and its
configuration digest. It selects a fresh Trivy database, assesses every
platform and signs a new result without rebuilding or executing the old source.
The original qualification can be expired. An SBOM-only scope performs current
vulnerability matching, while `full-image` also repeats secret and configuration
scans. Both currently retrieve the released image graph from the registry, so
the command needs registry availability even when the bundle is local.

The complete retained checkout matters: configuration loading checks referenced
Containerfiles, contexts and test files even though a rescan does not build
them. Copying only `conclear.toml` may fail. Editing it, including changing an
exception or rescan scope, changes its digest and is not a way to rescan the old
release. Triage decisions use the separately supported `--triage-file` input.

Keep the rescan's JSON result and non-secret `rescan-result.json`, scans and
SBOMs from its run. For each later rescan, pass the latest verified
authoritative `data.recordDigest` as `--previous-result` in addition to the
arguments above. ConClear verifies that it is the signed history's current
head. Omitting it cannot start a new clock for an already observed finding.
Retain the signed history and protected local state across scheduler jobs.

## Operate the schedule

Keep the cleanup owner and procedure in the protected profile current. Review
abandoned runs regularly, including uploads whose acknowledgement was lost.
After retaining their evidence, run `conclear cleanup RUN_ID --profile foundata`
and check the reported result before discarding local ownership state. Native
expiration and auto-prune reduce dependence on this review, but their workers
still need monitoring. Manual cleanup mode requires no registry policy API.

If ownership state is lost, reconcile candidate tags with retained run records
before deleting them. Do not sweep version tags, moving tags or referrers for
supported digests. An expired authorization prevents ConClear promotion; it
does not prove that the registry has deleted the tag or collected its content.

A systemd timer or cron job can run one authoritative rescan per due digest
under an existing managed account. Serialize work for the same digest. The
account needs the retained configuration, supported tools, protected release
credentials, a persistent `XDG_STATE_HOME`, database cache space and network
access. The timer or cron entry does not provide failure notifications by
itself; arrange monitoring and a named responder.

Handle the result before updating the inventory:

|                         Outcome                         | Operator action |
| ------------------------------------------------------- | --------------- |
| Exit 0 with a verified authoritative result             | Retain the result, advance the history head and last-assessment time, and schedule the next assessment. |
| Exit 2 with a verified authoritative result             | Retain and advance the same fields, alert the triage owner and track remediation. A rejecting verdict is still a completed assessment. |
| Operational failure, invalid invocation or interruption | Keep the prior completed-assessment time and history head, retain protected diagnostics and arrange recovery. |

Require `data.authoritative = true` and a non-null `data.verifiedAt` before
accepting a new history head. A diagnostic rescan never advances it. If a
process died after attaching a result, or another authorized host rescanned the
digest, reconcile with the verified registry history instead of discarding
state or repeatedly retrying an obsolete `--previous-result`.

Monitor overdue inventory entries as well as failed processes. A powered-off
host produces neither a clean verdict nor a process failure notification.
Preserve and test recovery of pin observations, rescan history and keys; record
support termination and replacement digests explicitly. ConClear does not
operate this schedule, send advisories or release a corrected image on its own.
