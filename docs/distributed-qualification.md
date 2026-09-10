# Distributed qualification

Use separate workers when one machine cannot build and test every required
platform. Complete the [repository and release setup](../README.md#usage)
first.

Declare both `linux/amd64` and `linux/arm64` in `images.platforms`. Use the same
source revision, release version, ConClear and host-tool versions on every
worker.

## Qualify each platform

On the first worker:

```sh
conclear qualify --revision v1.2.3 --version 1.2.3 \
  --platform linux/amd64 --format json
conclear transport export "<worker-run-a>" --platform linux/amd64 \
  --output ./app-linux-amd64.tar --format json
```

Use the qualification result's `data.runId` as `<worker-run-a>`. Keep both
commands' JSON results.

Take `data.databaseDigest` and `data.qualificationWindow.startedAt` from the
qualification result. Copy its database snapshot from
`${XDG_CACHE_HOME:-$HOME/.cache}/conclear/trivy/snapshots/<digest-without-sha256-prefix>`
to the same cache-relative path on the next worker:

```sh
conclear qualify --revision v1.2.3 --version 1.2.3 \
  --platform linux/arm64 --database-digest "sha256:<database-digest>" \
  --qualification-started-at "<startedAt>" --format json
conclear transport export "<worker-run-b>" --platform linux/arm64 \
  --output ./app-linux-arm64.tar --format json
```

Use this worker's `data.runId` as `<worker-run-b>` and keep both JSON results.

## Assemble and release

Copy both archives to the release machine. Obtain each `data.transportDigest`
directly from its worker, separately from the archive. From the matching source
repository, assemble and finish the release:

```sh
conclear assemble --revision v1.2.3 --version 1.2.3 --profile foundata \
  --transport ./app-linux-amd64.tar "sha256:<transport-digest-a>" \
  --transport ./app-linux-arm64.tar "sha256:<transport-digest-b>" --format json
conclear release --resume "<coordinator-run-id>" --profile foundata \
  --archive-dir "$archives"
```

Use the `data.runId` returned by `assemble`. Complete the release before the
reported qualification deadline; after expiry, qualify again with a fresh
database. Set `$archives` to existing durable storage outside the repository.
The release tarball includes every platform's evidence and declared non-secret
test outputs. Keep it before cleaning up the coordinator and workers.
