#!/usr/bin/env bash
# Provisions a Claude Code cloud-session VM with a Swift toolchain.
#
# This is the body of the "Setup script" field on a cloud environment at claude.ai/code; see
# docs/09-cloud-sessions.md for the rest of the environment configuration. It lives in the
# repository so that the shell which runs as root on a VM holding this checkout is reviewed like
# any other operational script — the same reason select-xcode.sh exists instead of a third-party
# action (docs/07-supply-chain.md §3). It is also safe to run by hand inside a session, which is
# the recovery path when a cached environment predates a change here.
#
# Target: Ubuntu 24.04 on x86_64, running as root, before Claude Code launches. There is no Xcode
# on that VM and there cannot be one; docs/09-cloud-sessions.md §1 records what that costs.
#
# Two constraints the hosting imposes shape the whole script:
#   - It must exit 0. A non-zero exit means the session never starts, so every step that is not
#     load-bearing is guarded and the script ends with an unconditional `exit 0`.
#   - It must finish in roughly five minutes, or the filesystem snapshot is not cached and every
#     later session pays the full cost again. The apt dependencies and the installer download
#     therefore run concurrently, and the warm-up build is bounded by `timeout`.
#
# Because a failure here cannot stop the session, it has to announce itself instead: everything is
# logged to $LOG, and a session that ends up without a toolchain is told so through root's
# CLAUDE.md (§8). Exiting 0 on a broken toolchain and saying nothing is the one outcome this script
# must never produce — it was the original failure mode of this file.
set -uo pipefail

readonly FALLBACK_VERSION="6.4.1"   # used only when .swift-version is missing or unreadable
readonly SWIFTLY_URL="https://download.swift.org/swiftly/linux/swiftly-x86_64.tar.gz"
readonly WORK="/tmp/watchword-cloud-setup"
readonly LOG="/var/log/watchword-cloud-setup.log"

mkdir -p "$WORK"
# /tmp is not a safe place to leave evidence: it can be cleared when a VM boots from the snapshot.
# Everything is teed to /var/log so the log outlives setup and a session can read it.
exec > >(tee -a "$LOG") 2>&1

log() { printf '[cloud-setup %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

log "starting; logging to $LOG"

# ---------------------------------------------------------------------------- 1. find the checkout
# The repository is cloned before the setup script runs, but its path is not promised anywhere, so
# locate it rather than hard-code one. A miss is survivable: only the version pin and the warm-up
# build need it.
repo=""
for candidate in . /root/* /workspace/* /home/*/* /root /workspace; do
    if [ -f "$candidate/Package.swift" ] && grep -q 'name: "Watchword"' "$candidate/Package.swift" 2>/dev/null; then
        repo="$(cd "$candidate" && pwd)"
        break
    fi
done
if [ -n "$repo" ]; then
    log "checkout at $repo"
else
    log "checkout not found; using the fallback version pin and skipping the warm-up build"
fi

version="$FALLBACK_VERSION"
if [ -n "$repo" ] && [ -r "$repo/.swift-version" ]; then
    version="$(tr -d '[:space:]' < "$repo/.swift-version")"
fi
log "want Swift $version"

# ------------------------------------------------ 2. system dependencies and installer, in parallel
# The dependency list is the one swift.org publishes for Ubuntu 24.04. It is spelled out rather
# than left to the installer so that a change upstream cannot quietly change what gets installed as
# root on this VM.
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

wait "$apt_pid" || { log "apt dependencies FAILED; see $WORK/apt.log"; tail -20 "$WORK/apt.log"; }
wait "$curl_pid" || log "swiftly download FAILED; see $WORK/curl.log"
log "dependencies installed, installer fetched"

# ------------------------------------------------------------------- 3. locate an installed toolchain
# Both install methods below are judged by this one function, so neither gets to claim success it
# did not achieve. Prints the toolchain's usr/bin, or nothing.
find_toolchain_bin() {
    local found
    found="$(find "$HOME/.local/share/swiftly/toolchains" -maxdepth 3 -type d -path '*/usr/bin' \
        2>/dev/null | sort -V | tail -1)"
    [ -z "$found" ] && [ -x /opt/swift/usr/bin/swift ] && found="/opt/swift/usr/bin"
    [ -n "$found" ] && [ -x "$found/swift" ] && printf '%s' "$found"
}

# ------------------------------------------------------------------------- 4. install: tarball first
# The tarball is tried first because it is a handful of commands against a published URL layout,
# with no CLI contract to get wrong, and because it is the path that can be signature-checked.
#
# The URL layout is not guessable and was wrong in the first version of this script: the release
# directory is lower-case (`swift-6.4.1-release`) while the directory and filename inside it are
# upper-case (`swift-6.4.1-RELEASE`). It is reproduced here from swiftlang/swift-docker's
# Dockerfile, which is what the official images build from. The probe follows redirects — without
# -L, download.swift.org answers a bad path with a 302 that curl -f reports as success, which is
# how the wrong URL survived review.
readonly SWIFT_SIGNING_KEY="52BB7E3DE28A71BE22EC05FFEF80A866B47A981F"

install_via_tarball() {
    local tag dir arch_suffix url sig_url
    tag="swift-${version}-RELEASE"
    dir="swift-${version}-release"
    arch_suffix=""
    [ "$(uname -m)" = "aarch64" ] && arch_suffix="-aarch64"
    url="https://download.swift.org/${dir}/ubuntu2404${arch_suffix}/${tag}/${tag}-ubuntu24.04${arch_suffix}.tar.gz"
    sig_url="${url}.sig"

    log "probing $url"
    if ! curl -fsIL --retry 2 "$url" > /dev/null 2>&1; then
        log "tarball URL not available: $url"
        return 1
    fi

    log "downloading the release tarball and its signature"
    curl -fsSL --retry 3 --retry-delay 2 -o "$WORK/swift.tar.gz" "$url" || {
        log "tarball download FAILED"
        return 1
    }
    # A toolchain is compile-time code execution on every later build, so it is verified rather
    # than trusted (docs/07-supply-chain.md, T3). The fingerprint is pinned here; only the key
    # material comes from the keyserver, so a hostile keyserver cannot substitute a different key.
    if curl -fsSL --retry 3 -o "$WORK/swift.tar.gz.sig" "$sig_url" \
        && gpg --batch --quiet --keyserver keyserver.ubuntu.com --recv-keys "$SWIFT_SIGNING_KEY" \
        && gpg --batch --verify "$WORK/swift.tar.gz.sig" "$WORK/swift.tar.gz"; then
        log "signature verified against $SWIFT_SIGNING_KEY"
    else
        log "SIGNATURE VERIFICATION FAILED; discarding the download"
        rm -f "$WORK/swift.tar.gz" "$WORK/swift.tar.gz.sig"
        return 1
    fi

    mkdir -p /opt/swift
    tar -xzf "$WORK/swift.tar.gz" -C /opt/swift --strip-components=1 || {
        log "tarball did not extract"
        return 1
    }
    return 0
}

# swiftly resolves release URLs itself, so it is the second opinion when the URL layout above has
# moved. Default install locations are used deliberately: swiftly's proxy binaries find their home
# directory from $HOME, and the session runs as the same root user, so /root/.local resolves in
# both. Overriding SWIFTLY_HOME_DIR here would break those proxies at session time.
#
# --assume-yes on BOTH subcommands is the whole point. `swiftly install` prompts for confirmation,
# and a setup script has no TTY: without the flag it fails on EOF, which is exactly how this script
# first shipped a VM with no `swift` on it.
install_via_swiftly() {
    [ -s "$WORK/swiftly.tar.gz" ] || { log "no swiftly archive to install from"; return 1; }
    tar -xzf "$WORK/swiftly.tar.gz" -C "$WORK" || { log "swiftly archive did not extract"; return 1; }

    # --overwrite keeps a re-run idempotent; init refuses an existing installation without it.
    "$WORK/swiftly" init --assume-yes --no-modify-profile --skip-install --overwrite \
        || log "swiftly init reported a failure; trying install anyway"

    local swiftly_bin="$HOME/.local/bin/swiftly"
    [ -x "$swiftly_bin" ] || swiftly_bin="$WORK/swiftly"
    "$swiftly_bin" install "$version" --assume-yes --use || {
        log "swiftly could not install $version"
        return 1
    }
    return 0
}

toolchain_bin="$(find_toolchain_bin)"
if [ -n "$toolchain_bin" ]; then
    log "a toolchain is already present at $toolchain_bin"
else
    for method in tarball swiftly; do
        log "installing via $method"
        "install_via_$method" || log "$method did not complete"
        toolchain_bin="$(find_toolchain_bin)"
        if [ -n "$toolchain_bin" ]; then
            log "$method produced a toolchain at $toolchain_bin"
            break
        fi
        log "$method produced no usable toolchain"
    done
fi

# ----------------------------------------------------------------------------- 5. expose on $PATH
# Claude Code's Bash tool does not run a login shell, so a profile script alone is not enough —
# /usr/local/bin is what actually makes `swift` resolvable in the commands the agent runs. Only the
# driver binaries are linked: the `swift` driver finds build, test, format and friends relative to
# its own resolved path, and linking the whole toolchain would shadow the system clang for every
# other build on the VM.
if [ -n "$toolchain_bin" ]; then
    for tool in swift swiftc swift-format sourcekit-lsp; do
        [ -e "$toolchain_bin/$tool" ] && ln -sf "$toolchain_bin/$tool" "/usr/local/bin/$tool"
    done
    printf 'export PATH="%s:$PATH"\n' "$toolchain_bin" > /etc/profile.d/swift.sh
    chmod 0644 /etc/profile.d/swift.sh
    log "linked drivers into /usr/local/bin from $toolchain_bin"
fi

# ----------------------------------------------------------------------------- 6. warm the caches
# The environment snapshot keeps files, so a build done here is a build no later session repeats.
# Bounded and optional: busting the five-minute cache window would cost more than it saves.
if [ -n "$repo" ] && command -v swift > /dev/null 2>&1; then
    log "warming the build cache"
    ( cd "$repo" && timeout 150 swift build --build-tests ) > "$WORK/build.log" 2>&1 \
        || { log "warm-up build did not complete; see $WORK/build.log"; tail -20 "$WORK/build.log"; }
fi

# -------------------------------------------------------------------------------- 7. verify loudly
ok=0
if command -v swift > /dev/null 2>&1 && swift --version > /dev/null 2>&1; then
    ok=1
    swift --version 2>&1 | sed 's/^/[cloud-setup] /'
    if swift format --version > /dev/null 2>&1; then
        log "swift format present: $(swift format --version 2>&1)"
    else
        log "WARNING: swift format is unavailable; the lint gate cannot run in this session"
    fi
fi

# --------------------------------------------------------- 8. tell the session when setup failed
# A setup script cannot fail a session start, so a silent failure reaches the agent as a confusing
# "swift: command not found" much later. Root's CLAUDE.md is loaded as user instructions in the
# session, which makes it the one channel that reports this at the top rather than on first use.
note="/root/.claude/CLAUDE.md"
mkdir -p "$(dirname "$note")"
sed -i '/<!-- watchword-cloud-setup -->/,+6d' "$note" 2>/dev/null || true

if [ "$ok" -eq 1 ]; then
    log "SUCCESS: swift is on PATH at $(command -v swift)"
else
    log "FAILURE: no working Swift toolchain. Session will be told via $note"
    cat >> "$note" <<EOF
<!-- watchword-cloud-setup -->
The cloud environment's setup script could not install a Swift toolchain, so \`swift\`,
\`swift build\`, \`swift test\` and \`swift format\` are all unavailable in this session. Read
$LOG for the reason before trying to build anything, and tell the user what it says. The usual
cause is that the environment's network access is \`Trusted\` rather than \`Custom\` with
\`download.swift.org\` allowed; see docs/09-cloud-sessions.md §4. To retry inside this session, run
\`.github/scripts/cloud-setup.sh\`.
EOF
fi

log "done"
exit 0
