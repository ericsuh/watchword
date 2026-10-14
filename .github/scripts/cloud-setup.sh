#!/usr/bin/env bash
# Provisions a Claude Code cloud-session VM with a Swift toolchain.
#
# This is the body of the "Setup script" field on a cloud environment at claude.ai/code; see
# docs/09-cloud-sessions.md for the rest of the environment configuration. It lives in the
# repository so that the shell which runs as root on a VM holding this checkout is reviewed like
# any other operational script — the same reason select-xcode.sh exists instead of a third-party
# action (docs/07-supply-chain.md §3).
#
# Target: Ubuntu 24.04 on x86_64, running as root, before Claude Code launches. There is no Xcode
# on that VM and there cannot be one; docs/09-cloud-sessions.md §1 records what that costs.
#
# Two constraints the hosting imposes shape the whole script:
#   - It must exit 0. A non-zero exit means the session never starts, so every step that is not
#     load-bearing is guarded and the script ends with an unconditional `exit 0`. A broken
#     toolchain is reported in the log and left for the session to deal with.
#   - It must finish in roughly five minutes, or the filesystem snapshot is not cached and every
#     later session pays the full cost again. The apt dependencies and the swiftly download
#     therefore run concurrently, and the warm-up build is bounded by `timeout`.
set -uo pipefail

readonly FALLBACK_VERSION="6.4.1"   # used only when .swift-version is missing or unreadable
readonly SWIFTLY_URL="https://download.swift.org/swiftly/linux/swiftly-x86_64.tar.gz"
readonly WORK="/tmp/watchword-cloud-setup"

log() { printf '[cloud-setup %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

mkdir -p "$WORK"

# ---------------------------------------------------------------------------- 1. find the checkout
# The repository is cloned before the setup script runs, but its path is not promised anywhere, so
# locate it rather than hard-code one. A miss is survivable: only the warm-up build needs it.
repo=""
for candidate in /root/* /workspace/* /home/*/* /root /workspace; do
    if [ -f "$candidate/Package.swift" ] && grep -q 'name: "Watchword"' "$candidate/Package.swift" 2>/dev/null; then
        repo="$candidate"
        break
    fi
done
if [ -n "$repo" ]; then
    log "checkout at $repo"
else
    log "checkout not found; skipping warm-up build"
fi

# ------------------------------------------------- 2. system dependencies and swiftly, in parallel
# The dependency list is the one swift.org publishes for Ubuntu 24.04. It is spelled out rather
# than left to `swiftly init` so that a change in the installer cannot quietly change what gets
# installed as root on this VM.
(
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq \
        && apt-get install -y -qq --no-install-recommends \
            binutils git gnupg2 libc6-dev libcurl4-openssl-dev libedit2 libgcc-13-dev \
            libncurses-dev libpython3-dev libsqlite3-0 libstdc++-13-dev libxml2-dev libz3-dev \
            pkg-config tzdata zip unzip zlib1g-dev
) > "$WORK/apt.log" 2>&1 &
apt_pid=$!

( curl -fsSL --retry 3 --retry-delay 2 -o "$WORK/swiftly.tar.gz" "$SWIFTLY_URL" ) > "$WORK/curl.log" 2>&1 &
curl_pid=$!

wait "$apt_pid" || { log "apt dependencies failed; see $WORK/apt.log"; tail -20 "$WORK/apt.log"; }
wait "$curl_pid" || log "swiftly download failed; see $WORK/curl.log"
log "dependencies installed, swiftly fetched"

# ------------------------------------------------------------------------ 3. toolchain via swiftly
# swiftly resolves release URLs itself, which keeps a download.swift.org path layout out of this
# script. Default install locations are used deliberately: swiftly's proxy binaries find their home
# directory from $HOME, and the session runs as the same root user, so /root/.local resolves in
# both. Overriding SWIFTLY_HOME_DIR here would break those proxies at session time.
version="$FALLBACK_VERSION"
if [ -n "$repo" ] && [ -r "$repo/.swift-version" ]; then
    version="$(tr -d '[:space:]' < "$repo/.swift-version")"
fi
log "pinning Swift $version"

if [ -s "$WORK/swiftly.tar.gz" ]; then
    tar -xzf "$WORK/swiftly.tar.gz" -C "$WORK" || log "swiftly tarball did not extract"

    init_args=(--assume-yes --no-modify-profile)
    # --skip-install avoids downloading "latest" and then the pinned release. Probed rather than
    # assumed, so an installer that drops the flag degrades to one extra download, not a failure.
    if "$WORK/swiftly" init --help 2>/dev/null | grep -q -- '--skip-install'; then
        init_args+=(--skip-install)
    fi
    "$WORK/swiftly" init "${init_args[@]}" || log "swiftly init reported a failure; continuing"

    swiftly_bin="$HOME/.local/bin/swiftly"
    [ -x "$swiftly_bin" ] || swiftly_bin="$WORK/swiftly"
    "$swiftly_bin" install --use "$version" || log "swiftly could not install $version"
fi

# ------------------------------------------------ 4. fall back to the release tarball if necessary
# Reached only when swiftly is unavailable or refused the pinned release. The URL layout is stable
# but it is still a second way to be wrong, which is why it is the fallback and not the main path.
toolchain_bin="$(find "$HOME/.local/share/swiftly/toolchains" -maxdepth 3 -type d -path '*/usr/bin' \
    2>/dev/null | sort -V | tail -1)"

if [ -z "$toolchain_bin" ]; then
    log "swiftly produced no toolchain; falling back to the release tarball"
    tag="swift-${version}-RELEASE"
    url="https://download.swift.org/${tag}/ubuntu2404/${tag}/${tag}-ubuntu24.04.tar.gz"
    if curl -fsSL --retry 3 -o "$WORK/swift.tar.gz" "$url"; then
        mkdir -p /opt/swift
        tar -xzf "$WORK/swift.tar.gz" -C /opt/swift --strip-components=1 \
            && toolchain_bin="/opt/swift/usr/bin"
    else
        log "tarball download failed: $url"
    fi
fi

# ----------------------------------------------------------------------------- 5. expose on $PATH
# Claude Code's Bash tool does not run a login shell, so a profile script alone is not enough.
# Only the driver binaries are symlinked into /usr/local/bin: the `swift` driver finds build, test,
# format and friends relative to its own resolved path, and symlinking the whole toolchain would
# shadow the system clang for every other build on the VM.
if [ -n "$toolchain_bin" ]; then
    for tool in swift swiftc swift-format sourcekit-lsp; do
        [ -e "$toolchain_bin/$tool" ] && ln -sf "$toolchain_bin/$tool" "/usr/local/bin/$tool"
    done
    printf 'export PATH="%s:$PATH"\n' "$toolchain_bin" > /etc/profile.d/swift.sh
    chmod 0644 /etc/profile.d/swift.sh
    log "toolchain exposed from $toolchain_bin"
else
    log "no Swift toolchain was installed; the session will have to install one itself"
fi

# ----------------------------------------------------------------------------- 6. warm the caches
# The environment snapshot keeps files, so a build done here is a build no later session repeats.
# Bounded and optional: busting the five-minute cache window would cost more than it saves.
if [ -n "$repo" ] && command -v swift > /dev/null 2>&1; then
    log "warming the build cache"
    ( cd "$repo" && timeout 150 swift build --build-tests ) > "$WORK/build.log" 2>&1 \
        || { log "warm-up build did not complete; see $WORK/build.log"; tail -20 "$WORK/build.log"; }
fi

# ------------------------------------------------------------------------------------- 7. report
if command -v swift > /dev/null 2>&1; then
    swift --version 2>&1 | sed 's/^/[cloud-setup] /'
    if swift format --version > /dev/null 2>&1; then
        log "swift format present: $(swift format --version 2>&1)"
    else
        log "WARNING: swift format is unavailable; the lint gate cannot run in this session"
    fi
else
    log "WARNING: swift is not on PATH"
fi

log "done"
exit 0
