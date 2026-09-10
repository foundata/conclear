# Release evidence and later rescans

Archive each release before cleanup. Use its retained source for later rescans.

## Contents

- [What to retain](#what-to-retain)
- [Export before cleanup](#export-before-cleanup)
- [Restore and rescan](#restore-and-rescan)
- [Operate the schedule](#operate-the-schedule)

## What to retain

Keep one bundle per repository and released digest, containing:

- A qualification transport and export JSON per platform: image, SBOM, scans
  and test report.
- Release records and summary.
- The complete release source, including its unchanged `conclear.toml`.
- Any needed non-secret generated test outputs; transports retain their hashes,
  not all output files.

Keep access to a compatible ConClear distribution. Store logs, release profiles,
keys, credentials, environment directories and secret inputs separately with
restricted access. Review the bundle before sharing; never publish a whole run
workspace or `reports/` tree.

Checksums detect changed bytes. To verify publisher identity, use the signed
registry attestations and an independently trusted public key. The bundle's
local statement is unsigned. Back up registry signatures and referrers
separately; neither this bundle nor `skopeo copy --all` preserves them all.

## Export before cleanup

Keep the release workspace, source and recorded Git executable unchanged until
export finishes. Stop concurrent work on the run.

For a single-host release, set `RUN_ID` to the completed run and `BUNDLE` to a
new absolute directory whose parent exists. The Bash example below exports
`linux/amd64`; repeat the export for every platform, adjusting filenames.

For distributed releases, replace the export command with copies of the
original worker transports and export JSON, using the filenames below. Check
their transport digests against the coordinator's candidate record. Use the
coordinator's `RUN_ID` for the remaining files; it cannot re-export imported
qualifications.

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

If needed, review and add outputs declared non-secret from the worker's
`reports/<image>/<platform>/test-inputs/outputs/<name>/`. Preserve paths and
executable modes without following links outside that output. Include any
extra archives in the checksum list below.

After collecting every platform, create and verify the checksums:

```bash
(
  cd -- "${BUNDLE}"
  sha256sum -- source.tar summary.json records/*.json \
    platform-*.tar platform-*.json >SHA256SUMS
  sha256sum --check SHA256SUMS
)
```

Back up the bundle, verify `SHA256SUMS` at its destination and test restoration
before cleanup. Record its location and a protected checksum manifest in your
supported-release inventory. Share reviewed bundles through your release or
download location when consumers need access.

## Restore and rescan

Use a trusted bundle. Set `RESTORED` to a new absolute directory whose parent
exists. Restore the complete source and keep it unchanged; `conclear.toml`
alone is insufficient.

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

Set `SUBJECT` from your protected inventory and check it against the bundle's
summary. Use a digest reference such as `quay.io/example/app@sha256:<digest>`.
For image `app` and profile `foundata`, run the first authoritative rescan:

```sh
conclear rescan --subject "${SUBJECT}" \
  --config "${RESTORED}/conclear.toml" --image app \
  --profile foundata --authoritative --format json
```

Rescans need registry access, even with a local bundle. An expired original
qualification is allowed. `--authoritative` signs and publishes the result;
omit it for a local diagnostic.

For later rescans, add `--previous-result` with the latest verified
authoritative `data.recordDigest`. Use `--triage-file` for new vulnerability
decisions instead of editing the retained configuration. Keep each rescan's
JSON result and non-secret `rescan-result.json`, scans and SBOMs.

See the [rescan reference](../ARCHITECTURE.md#rescans) for verification rules
and scan scopes.

## Operate the schedule

Use a systemd timer or cron job on a managed host; no CI service is needed.
Serialize rescans for each digest. Provide retained source, supported tools,
protected credentials, persistent `XDG_STATE_HOME`, cache space and network
access. Assign owners for triage, rebuilds and cleanup.

Only accept a new history head when the result has `data.authoritative = true`
and a non-null `data.verifiedAt`:

|                Outcome                | Action |
| ------------------------------------- | ------ |
| Exit 0, verified authoritative result | Retain the result; update the inventory's history head and assessment time. |
| Exit 2, verified authoritative result | Make the same updates; alert the triage owner and track remediation. |
| Failure or interruption               | Keep the previous head and assessment time; retain protected diagnostics and recover. |

After an interrupted publication or a rescan on another host, reconcile with
verified registry history before retrying `--previous-result`. Preserve signed
history and protected local state; test recovery of that state and keys.

Monitor failed jobs and overdue releases. Keep the inventory's next assessment
date, support status and replacement digest current. Arrange alerts to a named
responder; ConClear does not schedule work, send advisories or rebuild images.

Review abandoned runs regularly. After retaining their evidence, run
`conclear cleanup RUN_ID --profile foundata` and verify success before deleting
local state. Monitor registry expiration and auto-prune too; expiration alone
does not confirm deletion. If ownership state is lost, reconcile candidate tags
with retained run records before deletion. Never sweep release tags, moving
tags or referrers for supported digests.
