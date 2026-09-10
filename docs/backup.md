# Backup

Point `--archive-dir` at durable, backed-up storage. Keep the tarballs while
releases are supported and for your chosen review period afterward. Keep
referenced source archives beside their rescans and test retrieval with
`conclear archive verify`. See [archive usage](../README.md#usage-archives).

Release/rescan archives exclude signing keys, credentials and raw logs. Source
and reports may still be sensitive. Back up keys and durable state separately:

|          What           |                        What to preserve                        |              Needed for               |           Criticality           | When to clean up / what gets lost |
| ----------------------- | -------------------------------------------------------------- | ------------------------------------- | ------------------------------- | --------------------------------- |
| Release/rescan archives | Tarballs in `--archive-dir`                                    | Review and historical rescans         | High while supported            | After support and review needs end. Loss removes evidence and possibly the only original source/configuration. |
| Keys and access         | `~/.config/conclear/` and referenced external keys/credentials | Signing identity and release access   | Critical for active keys        | Retire private keys when signing no longer needs them; keep trusted public keys for historical verification. Credentials can be reissued. |
| Durable state           | `pins/` and `rescans/` under `~/.local/state/conclear/`        | Pin continuity and rescan checkpoints | High for pin history            | Remove obsolete subjects after support ends. Lost pin observations cannot be reconstructed; intact signed registry history can reconstruct rescan state. |
| Registry content        | Images, signatures and attestations/referrers                  | Existing digest pulls and rescans     | Critical for release continuity | Keep supported digests available. Loss may require a replacement release and updated consumer pins. |

Honor `XDG_CONFIG_HOME` and `XDG_STATE_HOME` when set. Keep support inventory,
owners and schedules in your usual operational records.

## Registry backup

Registry backup is optional when rebuilding and updating consumers is
acceptable. Rebuilding can change the digest and does not restore original
signatures or rescan history. `--include-image-layers` preserves exact image
bytes, but the archive is not a complete registry backup or an automatic
registry-restoration command.

## Daily local backup

Set `secure_storage` to an existing absolute secure/encrypted directory outside
the selected sources. Add external keys and credentials to `paths`; symlink
targets are not followed. Keep passphrase recovery separate from private keys.
Schedule this Bash/GNU-tools snippet while ConClear jobs are idle. Archive
storage has its own backup policy; this saves local settings and durable state.

```bash
set -euo pipefail
umask 077
unset TAR_OPTIONS
: "${secure_storage:?Set secure_storage to the secure backup directory}"
[[ "${secure_storage}" = /* && -d "${secure_storage}" ]]
secure_storage="$(realpath -e -- "${secure_storage}")"

paths=(
  "${XDG_CONFIG_HOME:-${HOME}/.config}/conclear"
  # Add absolute paths to external keys and credentials.
)
for name in pins rescans; do
  path="${XDG_STATE_HOME:-${HOME}/.local/state}/conclear/${name}"
  if [[ -d "${path}" ]]; then paths+=("${path}"); fi
done
members=()
for path in "${paths[@]}"; do
  [[ "${path}" = /* ]]
  source="$(realpath -e -- "${path}")"
  if [[ "${source}" = / || "${secure_storage}" = "${source}" ||
        "${secure_storage}" = "${source}/"* ]]; then
    printf 'Backup target must be outside every source: %s\n' "${path}" >&2
    exit 1
  fi
  members+=("${path#/}")
done

work="$(mktemp -d -- "${secure_storage}/.conclear-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
trap 'rm -rf -- "${work}"' EXIT
trap 'exit 1' HUP INT TERM
tar --create --gzip --acls --xattrs --file "${work}/local.tar.gz" \
  --directory / -- "${members[@]}"
tar --list --gzip --file "${work}/local.tar.gz" >/dev/null
(
  cd -- "${work}"
  sha256sum -- local.tar.gz >SHA256SUMS
  sha256sum --check SHA256SUMS
)
name="${work##*/}"
backup="${secure_storage}/${name#.}"
mv -T -- "${work}" "${backup}"
trap - EXIT HUP INT TERM
printf 'Backup: %s\n' "${backup}"
```

Each backup is a full copy of the selected files. Deleted or replaced versions
survive only in older backups. Alert on failures and periodically test a restore
into an empty directory, preserving ownership and permissions. These backups
contain secrets: keep them private.

Run workspaces and caches are excluded. Recovering an unfinished release also
requires its workspace, original inputs/tools and unexpired deadlines.

## Remove older local backups

After a successful backup, keep the newest `keep` copies (default: 7), ordered
by directory modification time. Run without concurrent backup/cleanup jobs.
This verifies retained copies before deleting older ones; it does not remove
release or rescan tarballs.

```bash
set -euo pipefail
export LC_ALL=C
: "${secure_storage:?Set secure_storage to the secure backup directory}"
[[ "${secure_storage}" = /* && -d "${secure_storage}" ]]
secure_storage="$(realpath -e -- "${secure_storage}")"
keep="${keep:-7}"
if [[ ! "${keep}" =~ ^[1-9][0-9]{0,8}$ ]]; then
  printf 'keep must be an integer between 1 and 999999999\n' >&2
  exit 1
fi

listing="$(find "${secure_storage}" -regextype posix-extended \
  -mindepth 1 -maxdepth 1 -type d \
  -regex '.*/conclear-[0-9]{8}T[0-9]{6}Z-[[:alnum:]]{6}' \
  -printf '%T@ %f\n' | sort -rn)"
backups=()
while read -r timestamp name; do
  [[ -n "${name}" ]] || continue
  directory="${secure_storage}/${name}"
  if [[ -f "${directory}/local.tar.gz" && ! -L "${directory}/local.tar.gz" &&
        -f "${directory}/SHA256SUMS" && ! -L "${directory}/SHA256SUMS" ]]; then
    backups+=("${directory}")
  fi
done <<< "${listing}"

if (( ${#backups[@]} <= keep )); then exit 0; fi
for directory in "${backups[@]:0:keep}"; do
  (cd -- "${directory}" && sha256sum --check SHA256SUMS)
done
for directory in "${backups[@]:keep}"; do
  printf 'Deleting backup: %s\n' "${directory}"
  rm -rf -- "${directory}"
done
```
