# Release archives and rescans

`release`, `promote` and `rescan` require `--archive-dir`. Each completed
operation writes a compressed tarball there and reports its path, size and
SHA-256 digest. Use durable, backed-up storage outside source repositories and
ConClear working directories. See [backup](./backup.md) for keys and state.

## Archive contents

Release archives contain the exact source and `conclear.toml`, qualification
records, SBOMs, scan and test reports, declared non-secret test outputs, OCI
indexes/manifests/configurations, and signed attestation bundles. Image layers
are excluded unless `--include-image-layers` is set.

Signing keys, credentials, protected profiles, raw logs, private test outputs
and database caches are excluded. Source and reports can still be sensitive;
review an archive before sharing it.

Keep release and rescan archives together while supported, then for your chosen
review period. Rescans made from an archive reference its source archive by
digest instead of copying the source again. Keep that referenced archive too.
Neither an archive nor its age grants permission to publish an image.

## Verify or retry

Verify a retained archive against your independently trusted profile key:

```sh
conclear archive verify "$bundle" --profile foundata
```

This checks member hashes, evidence bindings and retained Sigstore bundles.
It needs Cosign trust data but does not retrieve attestations from the registry.
The archive manifest is unsigned; checksums alone do not establish authorship.
Diagnostic rescans remain unsigned diagnostics.

If a release or rescan completed but its archive failed, keep the workspace:

```sh
conclear archive create "<run-id>" --profile foundata --archive-dir "$archives"
```

This retries export without publishing or rescanning. Clean up the run after
the archive is safely retained.

## Rescan on a restored host

Install ConClear and its supported tools. Restore the protected profile, trust
key and registry access separately. Authoritative rescans also need the signing
key. No import of old run workspaces is needed:

```sh
conclear rescan --archive "$bundle" --profile foundata \
  --authoritative --archive-dir "$archives"
```

Use a release archive or the latest rescan archive; keep its referenced source
archive beside it. ConClear restores the source privately, verifies registry
history and selects its latest result. It rejects history missing a retained
authoritative checkpoint. Fresh scanner data supplies the new assessment.
The image and signed history must still be available in the registry, even
when the archive includes layers.

Omit `--authoritative` for a diagnostic. Add `--triage-file triage.json` for
reviewed vulnerability decisions; do not edit archived configuration.

## Scheduled operation

Use a timer or cron job on an existing managed host. Serialize rescans per
digest, preserve their archives, and assign owners for triage and rebuilds.
An authoritative result with `data.verifiedAt` is retained even when its verdict
is rejected (exit 2). Alert on rejected, failed or overdue assessments.

Archive creation does not schedule jobs or record support obligations. Keep
your release inventory, owners and schedules in your usual operational records.
