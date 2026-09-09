# Install native host tools

Use this Fedora x86_64 recipe when distribution packages are too old for
ConClear. Use a native host or VM with working rootless Podman/Buildah. Finish
active ConClear runs before installing or updating tools; run ConClear without
`sudo`. No CI or registry credentials are needed.

ConClear finds host tools on this fixed path, ignoring the caller's `PATH`:

```text
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

`~/.local/bin` is fine for the `conclear` entry point, but not its host tools.
The recipe installs root-owned binaries under `/usr/local/libexec` and links
them into `/usr/local/bin`, leaving distribution binaries unchanged.

## Install distribution tools

```bash
sudo dnf install --refresh git-core buildah podman skopeo hadolint \
  curl jq ca-certificates tar gzip coreutils
sudo dnf upgrade --refresh git-core buildah podman skopeo hadolint
```

The upgrade step is necessary for tools already installed in the base OS.

## Select releases

Run the remaining blocks in one Bash session. Discover releases through the
[GitHub API](https://docs.github.com/en/rest/releases/releases#get-the-latest-release):

```bash
set -euo pipefail
umask 077
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
work="$(mktemp -d "$HOME/conclear-tools.XXXXXXXX")"
cd -- "$work"
fetch() { curl -fsSL --proto '=https' --proto-redir '=https' "$@"; }

fetch https://api.github.com/repos/sigstore/cosign/releases/latest -o cosign-release.json
fetch https://api.github.com/repos/aquasecurity/trivy/releases/latest -o trivy-release.json
cosign_version="$(jq -er '.tag_name | ltrimstr("v")' cosign-release.json)"
trivy_version="$(jq -er '.tag_name | ltrimstr("v")' trivy-release.json)"
printf 'Cosign: %s\nTrivy: %s\n' "$cosign_version" "$trivy_version"
```

Check both versions against your ConClear version's
[supported-tool policy](../README.md#supported-tools) before continuing.
If latest is unsupported, replace `/latest` with `/tags/vVERSION` in the
relevant URL and repeat selection. Do not lower version floors.

## Verify downloads

Cosign's bootstrap checksum comes from GitHub's HTTPS release metadata. This
trusts GitHub and the upstream repository; the subsequent self-verification
is not an independent trust anchor. For independent verification, use an
already-trusted Cosign. Stop on any checksum or signature failure.

```bash
cosign_base="https://github.com/sigstore/cosign/releases/download/v${cosign_version}"
fetch "$cosign_base/cosign-linux-amd64" -o cosign-linux-amd64
jq -er '.assets[] | select(.name == "cosign-linux-amd64") | .digest
  | select(test("^sha256:[0-9a-f]{64}$"))
  | ltrimstr("sha256:") + "  cosign-linux-amd64"' cosign-release.json \
  | sha256sum --check --strict -
chmod 0700 cosign-linux-amd64
fetch "$cosign_base/cosign-linux-amd64.sigstore.json" -o cosign-linux-amd64.sigstore.json
./cosign-linux-amd64 verify-blob \
  --bundle cosign-linux-amd64.sigstore.json \
  --certificate-identity keyless@projectsigstore.iam.gserviceaccount.com \
  --certificate-oidc-issuer https://accounts.google.com \
  cosign-linux-amd64

trivy_base="https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}"
archive="trivy_${trivy_version}_Linux-64bit.tar.gz"
checksums="trivy_${trivy_version}_checksums.txt"
for asset in "$archive" "$checksums" "$checksums.sigstore.json"; do
  fetch "$trivy_base/$asset" -o "$asset"
done
./cosign-linux-amd64 verify-blob \
  --bundle "$checksums.sigstore.json" \
  --certificate-identity \
  "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v${trivy_version}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$checksums"
sha256sum --check --strict --ignore-missing "$checksums"
mkdir unpacked
tar --extract --gzip --file "$archive" --directory unpacked \
  --no-same-owner --no-same-permissions trivy
```

## Activate and check

This first-install block refuses existing local installations, including
dangling links. Review those separately. Keep `$work` as the installation
record; never activate a link to a user-writable download.

```bash
cosign_dir="/usr/local/libexec/conclear-tools/cosign-${cosign_version}"
trivy_dir="/usr/local/libexec/conclear-tools/trivy-${trivy_version}"
for path in /usr/local/bin/cosign /usr/local/bin/trivy \
  "$cosign_dir" "$trivy_dir"; do
  if sudo test -e "$path" || sudo test -L "$path"; then
    printf 'Refusing existing installation: %s\n' "$path" >&2
    exit 1
  fi
done
sudo install -d -o root -g root -m 0755 "$cosign_dir" "$trivy_dir" /usr/local/bin
sudo install -o root -g root -m 0755 cosign-linux-amd64 "$cosign_dir/cosign"
sudo install -o root -g root -m 0755 unpacked/trivy "$trivy_dir/trivy"
sudo ln -sT "$cosign_dir/cosign" /usr/local/bin/cosign
sudo ln -sT "$trivy_dir/trivy" /usr/local/bin/trivy

tool_path='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
env PATH="$tool_path" trivy --version
env PATH="$tool_path" cosign version
```

From your image repository, with a valid `conclear.toml`:

```bash
conclear doctor --config conclear.toml --scope qualify --format json
```

`CC0301` reports unsupported versions. Check for older binaries earlier on the
fixed path; changing your shell's `PATH` cannot fix selection. Qualification
diagnostics check local tools and rootless storage; Cosign and
[external release prerequisites](./quickstart.md#10-create-a-release-profile)
need release-scope checks. A passing diagnostic is not a complete release drill.

For updates, verify a supported release, install a new root-owned version
directory, switch its activation link and rerun diagnostics. Never change tools
during an active or resumable release.

Installation, PATH isolation, refusal checks and reboot persistence were tested
on Fedora 44 x86_64 (2026-09-09, run `20260909T012036Z-tool-bootstrap`). Release
discovery, signatures and invalid metadata rejection were retested in an
isolated workspace (run `20260909T074959Z-tool-discovery`).
