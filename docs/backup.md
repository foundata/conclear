# Backup

Criticality describes the impact of loss, not a mandatory retention period.

|               What               |                                                                        What to preserve                                                                         |                               Needed for                               |                                    Criticality                                    | When to clean up / what gets lost |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------- |
| Signing keys                     | Cosign private key, trusted public keys and recoverable passphrase. Encrypt private-key backups; protect passphrase recovery separately.                        | Signing with the same identity and verifying historical releases.      | Critical for an active signing identity.                                          | Delete private keys only when no release or rescan requires them. Loss prevents signing with that identity. Keep public keys while historical verification matters. |
| Release profiles and credentials | `~/.config/conclear/` plus referenced external files.                                                                                                           | Restoring release access and trusted configuration.                    | High; credentials can be reissued.                                                | Revoke replaced credentials; remove obsolete copies after your recovery window. Delete profiles when no workflow needs them. Loss requires rebuilding configuration and restoring access. |
| Release evidence bundles         | Platform transports/export JSON, release records, reports, checksums, complete original source with unchanged `conclear.toml`, rescan results and triage files. | Release review, troubleshooting and historical rescans.                | High while supported; afterward depends on review needs.                          | Reduce or delete after support and your review period end. Deleting reports loses detailed test and scan evidence. Losing the only original source/configuration copy can prevent rescans. Full bundles are unnecessary for rescans if original source/configuration and registry evidence remain available. |
| Persistent state                 | `~/.local/state/conclear/`: `pins/`, `rescans/` and `runs/`. Treat it as sensitive.                                                                             | Pin-observation continuity, interrupted-run recovery and cleanup.      | High for pin history and unfinished runs; lower for reconstructible rescan state. | Delete run workspaces after retaining needed evidence and successful cleanup. Losing `pins/` loses observations; losing run journals complicates recovery and ownership checks. Local rescan history can be reconstructed from intact signed registry history. |
| Operator records                 | Supported-release inventory, bundle locations, latest rescan digests, schedules, owners and recovery instructions.                                              | Tracking support, scheduling assessments and assigning follow-up work. | High for supported releases.                                                      | Retire scheduling entries when support ends, recording that decision. Keep historical entries while images or evidence remain retained. Loss leaves support status, obligations and archive locations uncertain. |
| Registry content                 | Released manifests/layers, signatures and all attestations/referrers, including rescan history.                                                                 | Image pulls, evidence verification and later rescans.                  | Critical for those workflows.                                                     | Delete after support and download/verification commitments end, or after testing a complete backup restoration. Loss can prevent pulls, verification and rescans. Local evidence bundles do not replace registry content. |

Paths above use defaults; honor `XDG_CONFIG_HOME` and `XDG_STATE_HOME` when set.
Use support status and review needs to set retention, not a blanket one-year
cutoff. See [evidence retention](./evidence-retention.md) to export bundles.

## Daily local archive

Set `secure_storage`, `evidence_dir` and `operations_dir` to existing absolute
directories. The target must already be secure/encrypted and outside the
selected sources. Add external keys, credentials and other operator files to
`paths`; symbolic-link targets are not followed automatically.

Run with Bash and GNU tools, with read access to all selected files. Schedule
daily while ConClear jobs and evidence exports are idle. This backs up local
files only; arrange registry backup separately.

```bash
set -euo pipefail
umask 077
unset TAR_OPTIONS
: "${secure_storage:?Set secure_storage to the secure backup directory}"
[[ "${secure_storage}" = /* && -d "${secure_storage}" ]]
secure_storage="$(realpath -e -- "${secure_storage}")"

paths=(
  "${XDG_CONFIG_HOME:-${HOME}/.config}/conclear"
  "${XDG_STATE_HOME:-${HOME}/.local/state}/conclear"
  "${evidence_dir:?Set evidence_dir to the retained evidence directory}"
  "${operations_dir:?Set operations_dir to the operator records directory}"
  # Add absolute paths to external keys, credentials and other required files.
)
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

Each run creates a new dated directory containing `local.tar.gz` and
`SHA256SUMS`. Failures exit nonzero; alert on failed or missed backups. The
archive is a full copy of the selected sources at that time. Earlier versions
of changed or deleted files survive only in older backups. Keep these archives
private: they can contain signing keys, passphrases and logs.

Check `SHA256SUMS` after copying. Periodically extract into an empty directory
and test recovery, preserving ownership and permissions. Archive paths omit
the leading `/`; never test by extracting over the live filesystem.

The default database cache is excluded. Add its selected snapshot if recovering
an unfinished release matters. Resume still needs the original inputs/tools
and unexpired deadlines; a file archive is not a running-host snapshot.

## Remove older backups

After a successful backup, use this to keep the newest `keep` complete backups
(default: 7), ordered by directory modification time. Run without concurrent
backup or cleanup jobs. It verifies retained archives before deleting older
ones and ignores unfinished directories, symbolic links and unrelated names.

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

if (( ${#backups[@]} <= keep )); then
  exit 0
fi
for directory in "${backups[@]:0:keep}"; do
  (cd -- "${directory}" && sha256sum --check SHA256SUMS)
done
for directory in "${backups[@]:keep}"; do
  printf 'Deleting backup: %s\n' "${directory}"
  rm -rf -- "${directory}"
done
```
