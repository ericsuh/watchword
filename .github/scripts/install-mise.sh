#!/usr/bin/env bash
# Installs the pinned mise release on a CI runner and configures it for every later step, so each job can run the same
# `mise run <task>` a developer runs.
#
# mise is pinned like an action (docs/07-supply-chain.md §3.3): one release tarball per runner platform, fetched over
# HTTPS only and checked against the SHA-256 below before it runs. Bumping mise means updating the version and both
# digests from the release's published asset digests (`gh api repos/jdx/mise/releases/tags/v<version> --jq
# '.assets[]|{name,digest}'`) and an independent download, and reading the release diff — the same review as an action
# pin. cloud-setup.sh pins the same release for cloud sessions; `mise run audit:mise-pins` fails if the two disagree.
#
# The settings written to $GITHUB_ENV apply to every later step in the job:
#   MISE_LOCKED=1                  refuse a tool with no mise.lock entry; check each download against its checksum
#   MISE_TASK_RUN_AUTO_INSTALL=0   `mise run` installs nothing, so a job downloads only tools it names (`mise install`)
#   MISE_USE_VERSIONS_HOST=0       no version listing via mise-versions.jdx.dev; mise.lock already names each URL
#   MISE_DISABLE_TOOLS=xcodegen    Linux only: XcodeGen publishes macOS builds only
#   MISE_TRUSTED_CONFIG_PATHS      trust this checkout's mise.toml without a prompt
# Nothing here runs `mise --version`: it checks mise.jdx.dev for a newer release, a fetch the job does not need.
#
# Usage: .github/scripts/install-mise.sh   (puts mise on PATH for later steps through $GITHUB_PATH)
set -euo pipefail

readonly MISE_VERSION="2026.9.11"
readonly MISE_SHA256_MACOS_ARM64="34e8296f932c1d6f3b84d924bbb9f2841336d7bee1c373005d479e13664cb6c0"
readonly MISE_SHA256_LINUX_X64="02a19e4a5eda23cda916503ad09dbc608a249fe7a7d5686c5a74ff3a7ce3b7e0"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) platform=macos-arm64 sha256="$MISE_SHA256_MACOS_ARM64" ;;
  Linux-x86_64) platform=linux-x64 sha256="$MISE_SHA256_LINUX_X64" ;;
  *)
    echo "::error::No pinned mise build for $(uname -s)-$(uname -m)"
    exit 1
    ;;
esac

dest="${RUNNER_TEMP:?install-mise.sh is for CI runners}"
archive="$dest/mise.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$archive" \
  "https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-${platform}.tar.gz"
echo "${sha256}  ${archive}" | shasum -a 256 --check --strict
tar -xzf "$archive" -C "$dest" mise/bin/mise
echo "Installed mise ${MISE_VERSION} (${platform}) at $dest/mise/bin"

echo "$dest/mise/bin" >> "$GITHUB_PATH"
{
  echo "MISE_LOCKED=1"
  echo "MISE_YES=1"
  echo "MISE_USE_VERSIONS_HOST=0"
  echo "MISE_TASK_RUN_AUTO_INSTALL=0"
  echo "MISE_TRUSTED_CONFIG_PATHS=${GITHUB_WORKSPACE:?}"
  if [ "$platform" = linux-x64 ]; then echo "MISE_DISABLE_TOOLS=xcodegen"; fi
} >> "$GITHUB_ENV"
