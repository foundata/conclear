# ConClear — container clearance before promotion

ConClear is a command-line application for checking, building, testing, qualifying, publishing, signing, verifying and promoting OCI container images. It implements the automatable requirements of the foundata [OCI container image build and release guide](https://github.com/foundata/guidelines/blob/main/oci-container-image-guide.md) through one digest-bound workflow that runs on a maintainer workstation or in protected CI.

ConClear requires Python 3.12 or newer. Release workflows use rootless Buildah, Podman and Skopeo, with Hadolint for Containerfile linting, Trivy for scanning and SBOM generation, Cosign for signing and attestations, and Quay for public publication.

Install the locked development environment and inspect the command surface:

```sh
uv sync --dev
uv run conclear --help
```

Repository behavior is declared in `conclear.toml`. Trust roots, signing keys and registry credentials stay outside the repository in a named release profile under `$XDG_CONFIG_HOME/conclear/`.

ConClear is licensed under GPL-3.0-or-later.
