#!/usr/bin/env bash
# Installs the pinned mise release on a CI runner, so every job can run the same `mise run <task>` a developer runs.
#
# mise is pinned like an action (docs/07-supply-chain.md §3.3): one release tarball per runner platform, fetched over
# HTTPS only and checked against the SHA-256 below before it runs. Tools then come from mise.toml with
# `MISE_LOCKED=1` (set in the workflow), so mise refuses a tool with no mise.lock entry and checks each download
# against the lockfile checksum. Bumping mise means updating the version and both digests from the release's published
# asset digests (`gh api repos/jdx/mise/releases/tags/v<version> --jq '.assets[]|{name,digest}'`) and an independent
# download, and reading the release diff — the same review as an action pin. Keep the version in step with
# `cloud-setup.sh` and `min_version` in mise.toml.
#
# Usage: .github/scripts/install-mise.sh   (puts mise on PATH for later steps through $GITHUB_PATH)
set -euo pipefail

version="2026.9.11"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    platform=macos-arm64
    sha256=34e8296f932c1d6f3b84d924bbb9f2841336d7bee1c373005d479e13664cb6c0
    ;;
  Linux-x86_64)
    platform=linux-x64
    sha256=02a19e4a5eda23cda916503ad09dbc608a249fe7a7d5686c5a74ff3a7ce3b7e0
    ;;
  *)
    echo "::error::No pinned mise build for $(uname -s)-$(uname -m)"
    exit 1
    ;;
esac

dest="${RUNNER_TEMP:?install-mise.sh is for CI runners}"
archive="$dest/mise.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$archive" \
  "https://github.com/jdx/mise/releases/download/v${version}/mise-v${version}-${platform}.tar.gz"
echo "${sha256}  ${archive}" | shasum -a 256 --check --strict
tar -xzf "$archive" -C "$dest"

"$dest/mise/bin/mise" --version
echo "$dest/mise/bin" >> "$GITHUB_PATH"
