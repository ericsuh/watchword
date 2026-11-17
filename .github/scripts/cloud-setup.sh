#!/usr/bin/env bash
# Provisions a Claude Code cloud-session VM with a Swift toolchain and the repository's mise tools.
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
#
# Every outbound request goes over HTTPS on port 443. The session's egress proxy carries nothing
# else: a gpg keyserver lookup (hkp on 11371, or hkps via dirmngr, which ignores $HTTPS_PROXY)
# timed out or returned no data, and that alone left an earlier version of this script with no
# toolchain even though download.swift.org was reachable the whole time.
set -uo pipefail

readonly FALLBACK_VERSION="6.4.1"   # used only when .swift-version is missing or unreadable
# The second way to install a toolchain, and one this script cannot check: the URL names no version, and no checksum or
# signer is pinned for it here, yet what it serves is run as root. It is fetched and run only when the verified
# tarball could not be had *and* WATCHWORD_ALLOW_UNVERIFIED_SWIFTLY=1 says the person accepts that
# (docs/09-cloud-sessions.md §3). It is never the answer to a download that failed verification.
readonly SWIFTLY_URL="https://download.swift.org/swiftly/linux/swiftly-x86_64.tar.gz"
readonly ALLOW_UNVERIFIED_SWIFTLY="${WATCHWORD_ALLOW_UNVERIFIED_SWIFTLY:-0}"
readonly SWIFT_KEYS_URL="https://www.swift.org/keys/all-keys.asc"
# Empty except under Tests/ScriptTests, which runs this script against stand-in tools with every path it reads or
# writes moved below a scratch directory. Nothing else sets it.
readonly ROOT="${WATCHWORD_SETUP_TEST_ROOT:-}"
readonly WORK="$ROOT/tmp/watchword-cloud-setup"
readonly LOG="$ROOT/var/log/watchword-cloud-setup.log"

# mise, pinned. The developer tools themselves are pinned in the checkout's mise.toml (CLAUDE.md, "Commands"); this pins
# the tool that installs them. Same version and linux-x64 checksum as CI (.github/scripts/install-mise.sh); `mise run
# audit:mise-pins` fails if they disagree. The checksum is GitHub's published
# SHA-256 for that release asset; mise.jdx.dev serves the identical file, so one checksum covers both sources.
readonly MISE_VERSION="2026.9.11"
readonly MISE_ARCHIVE="mise-v${MISE_VERSION}-linux-x64.tar.gz"
readonly MISE_SHA256="02a19e4a5eda23cda916503ad09dbc608a249fe7a7d5686c5a74ff3a7ce3b7e0"
# mise.jdx.dev first: it is a plain CDN on the session's network allowlist. A github.com release URL is tried second,
# because GitHub traffic from a session goes through the GitHub proxy, which refuses some requests for repositories
# not attached to the session (docs/09-cloud-sessions.md §2).
readonly MISE_URLS="https://mise.jdx.dev/v${MISE_VERSION}/${MISE_ARCHIVE} https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/${MISE_ARCHIVE}"
# XcodeGen publishes macOS builds only, and there is no Xcode here to use it with.
readonly MISE_LINUX_DISABLED_TOOLS="xcodegen"

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
for candidate in . "$ROOT"/root/* "$ROOT"/workspace/* "$ROOT"/home/*/* "$ROOT/root" "$ROOT/workspace"; do
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

# ------------------------------------------------------------- 2. system dependencies, in parallel
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

# mise and the checkout's tools, alongside the Swift install. Small downloads, but they share the five-minute budget, so
# they run concurrently and are bounded. Not load-bearing for building the package: a failure is logged, never fatal.
install_mise() {
    local current="" url verified=0
    command -v mise > /dev/null 2>&1 && current="$(mise --version 2>/dev/null | awk '{print $1}')"
    if [ "$current" = "$MISE_VERSION" ]; then
        log "mise $MISE_VERSION already installed"
    else
        for url in $MISE_URLS; do
            rm -f "$WORK/$MISE_ARCHIVE"
            if ! curl -fsSL --retry 3 --retry-delay 2 -o "$WORK/$MISE_ARCHIVE" "$url"; then
                log "mise download failed from $url"
                continue
            fi
            if echo "$MISE_SHA256  $WORK/$MISE_ARCHIVE" | sha256sum --check --quiet - > /dev/null 2>&1; then
                verified=1
                log "mise $MISE_VERSION verified (SHA-256) from $url"
                break
            fi
            log "mise CHECKSUM MISMATCH from $url; discarding the download"
        done
        if [ "$verified" -ne 1 ]; then
            rm -f "$WORK/$MISE_ARCHIVE"
            log "mise could not be installed; tools pinned in mise.toml are unavailable"
            return 1
        fi
        tar -xzf "$WORK/$MISE_ARCHIVE" -C "$WORK" mise/bin/mise \
            && install -m 0755 "$WORK/mise/bin/mise" "$ROOT/usr/local/bin/mise" \
            || { log "mise archive did not install"; return 1; }
        rm -f "$WORK/$MISE_ARCHIVE"
    fi
    [ -n "$repo" ] || { log "no checkout, so no mise.toml to install from"; return 0; }
    # Trusting the checkout's mise.toml lets mise act on it as root. That is no new trust: the warm-up build below
    # already runs code from this checkout (SwiftPM evaluates Package.swift).
    (
        cd "$repo" \
            && MISE_YES=1 mise trust \
            && MISE_YES=1 MISE_DISABLE_TOOLS="$MISE_LINUX_DISABLED_TOOLS" timeout 120 mise install
    ) > "$WORK/mise.log" 2>&1 || {
        log "mise trust/install FAILED; see $WORK/mise.log"
        tail -20 "$WORK/mise.log"
        return 1
    }
    log "mise tools installed: $(cd "$repo" && MISE_DISABLE_TOOLS="$MISE_LINUX_DISABLED_TOOLS" mise ls --local --current 2>/dev/null \
        | awk '{printf "%s%s %s", sep, $1, $2; sep=", "}')"
}
install_mise &
mise_pid=$!

wait "$apt_pid" || { log "apt dependencies FAILED; see $WORK/apt.log"; tail -20 "$WORK/apt.log"; }
log "dependencies installed"

# ------------------------------------------------------------------- 3. locate an installed toolchain
# Both install methods below are judged by this one function, so neither gets to claim success it
# did not achieve. Prints the toolchain's usr/bin, or nothing.
find_toolchain_bin() {
    local found
    found="$(find "$HOME/.local/share/swiftly/toolchains" -maxdepth 3 -type d -path '*/usr/bin' \
        2>/dev/null | sort -V | tail -1)"
    [ -z "$found" ] && [ -x "$ROOT/opt/swift/usr/bin/swift" ] && found="$ROOT/opt/swift/usr/bin"
    [ -n "$found" ] && [ -x "$found/swift" ] && printf '%s' "$found"
}

# ------------------------------------------------------------------------- 4. install: tarball first
# The tarball is tried first because it is a handful of commands against a published URL layout,
# with no CLI contract to get wrong, and because it is the path that can be signature-checked.
#
# It answers in three ways, and the difference between the last two is the point of this section:
#   0  a verified toolchain was extracted;
#   1  the tarball could not be had at all (no such URL, a failed download): nothing was learnt about it;
#   2  a tarball arrived and could not be shown to be the one the pinned key signed (no signature, no key bundle, a
#      signature by any other key). That is what tampering looks like, so it is where installing stops: section 4b
#      tries nothing else, and the session is told why.
#
# The URL layout is not guessable and was wrong in the first version of this script: the release
# directory is lower-case (`swift-6.4.1-release`) while the directory and filename inside it are
# upper-case (`swift-6.4.1-RELEASE`). It is reproduced here from swiftlang/swift-docker's
# Dockerfile, which is what the official images build from. The probe follows redirects — without
# -L, download.swift.org answers a bad path with a 302 that curl -f reports as success, which is
# how the wrong URL survived review.
readonly SWIFT_SIGNING_KEY="52BB7E3DE28A71BE22EC05FFEF80A866B47A981F"

# A toolchain is compile-time code execution on every later build, so it is verified rather than
# trusted (docs/07-supply-chain.md, T3).
#
# The key material comes from swift.org's published bundle over HTTPS, because that is the only
# route the session proxy carries (see the header). The bundle holds every Swift signing key —
# nine of them, including the one that signs swiftly — so `gpg --verify` exiting 0 proves only that
# *some* key in it signed the file. The pin is therefore enforced on gpg's machine-readable status
# output: the last field of VALIDSIG is the signer's primary-key fingerprint, and it must equal
# SWIFT_SIGNING_KEY. A substituted bundle can add keys but cannot make one of them that key.
#
# A private GNUPGHOME keeps the bundle out of root's keyring and makes a re-run start clean.
verify_pinned_signature() {
    local sig="$1" file="$2" gnupg="$WORK/gnupg"
    rm -rf "$gnupg"
    mkdir -m 700 "$gnupg"
    curl -fsSL --retry 3 -o "$WORK/swift-keys.asc" "$SWIFT_KEYS_URL" || {
        log "could not fetch $SWIFT_KEYS_URL"
        return 1
    }
    GNUPGHOME="$gnupg" gpg --batch --quiet --import "$WORK/swift-keys.asc" 2>/dev/null
    GNUPGHOME="$gnupg" gpg --batch --status-fd 1 --verify "$sig" "$file" 2>/dev/null \
        | awk -v pin="$SWIFT_SIGNING_KEY" '$2 == "VALIDSIG" && $NF == pin { ok = 1 } END { exit !ok }'
}

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
    if curl -fsSL --retry 3 -o "$WORK/swift.tar.gz.sig" "$sig_url" \
        && verify_pinned_signature "$WORK/swift.tar.gz.sig" "$WORK/swift.tar.gz"; then
        log "signature verified against $SWIFT_SIGNING_KEY"
    else
        log "SIGNATURE VERIFICATION FAILED; discarding the download"
        rm -f "$WORK/swift.tar.gz" "$WORK/swift.tar.gz.sig"
        return 2
    fi

    mkdir -p "$ROOT/opt/swift"
    tar -xzf "$WORK/swift.tar.gz" -C "$ROOT/opt/swift" --strip-components=1 || {
        log "tarball did not extract"
        return 1
    }
    # The archive is over a gigabyte and the snapshot keeps files; don't cache it twice.
    rm -f "$WORK/swift.tar.gz"
    return 0
}

# swiftly resolves release URLs itself, so it is the second opinion when the URL layout above has
# moved. It verifies the toolchain signature on its own ("Verifying toolchain signature..."), but
# nothing here verifies swiftly: the archive is whatever SWIFTLY_URL serves today, and it runs as
# root. So it is fetched here, not up front, and only on the opt-in (section 4b). Default
# install locations are used deliberately: swiftly's proxy binaries find their home directory from
# $HOME, and the session runs as the same root user, so /root/.local resolves in both. Overriding
# SWIFTLY_HOME_DIR here would break those proxies at session time.
#
# --assume-yes on BOTH subcommands is the whole point. `swiftly install` prompts for confirmation,
# and a setup script has no TTY: without the flag it fails on EOF, which is exactly how this script
# first shipped a VM with no `swift` on it.
install_via_swiftly() {
    rm -f "$WORK/swiftly.tar.gz"
    curl -fsSL --retry 3 --retry-delay 2 -o "$WORK/swiftly.tar.gz" "$SWIFTLY_URL" || {
        log "swiftly download FAILED"
        return 1
    }
    [ -s "$WORK/swiftly.tar.gz" ] || { log "no swiftly archive to install from"; return 1; }
    tar -xzf "$WORK/swiftly.tar.gz" -C "$WORK" || { log "swiftly archive did not extract"; return 1; }

    # --overwrite keeps a re-run idempotent; init refuses an existing installation without it.
    "$WORK/swiftly" init --assume-yes --no-modify-profile --skip-install --overwrite \
        || log "swiftly init reported a failure; trying install anyway"

    # `init` *moves* itself into its bin directory: afterwards $WORK/swiftly no longer exists, and
    # the binary is in $SWIFTLY_BIN_DIR, which defaults to ~/.local/share/swiftly/bin — not
    # ~/.local/bin. Guessing the latter is how the previous version of this script failed with
    # "No such file or directory" after a successful init.
    local swiftly_bin
    for swiftly_bin in "${SWIFTLY_BIN_DIR:-$HOME/.local/share/swiftly/bin}/swiftly" \
        "$HOME/.local/bin/swiftly" "$WORK/swiftly"; do
        [ -x "$swiftly_bin" ] && break
    done
    [ -x "$swiftly_bin" ] || { log "swiftly binary not found after init"; return 1; }

    # Run from $WORK: `--use` updates a .swift-version in the working directory when it finds one,
    # and this script must never edit the checkout.
    ( cd "$WORK" && "$swiftly_bin" install "$version" --assume-yes --use ) || {
        log "swiftly could not install $version"
        return 1
    }
    return 0
}

# ------------------------------------------------------------ 4b. choose, and know when to stop
# Each method is still judged by find_toolchain_bin, not by its own exit status. What changed is
# what follows a failure. A tarball that failed verification ends the attempt: an attacker who can
# alter what download.swift.org serves fails that check on purpose if the answer to failing it is an
# installer nobody checks. And a tarball that simply could not be fetched leads to swiftly only when
# the person has said so, because the same attacker can make a URL fail too. `why_no_toolchain` is
# what the session is told in section 8.
toolchain_bin="$(find_toolchain_bin)"
why_no_toolchain=""
if [ -n "$toolchain_bin" ]; then
    log "a toolchain is already present at $toolchain_bin"
else
    log "installing via tarball"
    install_via_tarball
    tarball_status=$?
    toolchain_bin="$(find_toolchain_bin)"
    if [ -n "$toolchain_bin" ]; then
        log "tarball produced a toolchain at $toolchain_bin"
    elif [ "$tarball_status" -eq 2 ]; then
        log "REFUSING to try another install method: the toolchain download did not verify against the pinned key"
        why_no_toolchain="unverified"
    else
        log "tarball produced no usable toolchain"
        if [ "$ALLOW_UNVERIFIED_SWIFTLY" = 1 ]; then
            log "installing via swiftly, which this script cannot verify (WATCHWORD_ALLOW_UNVERIFIED_SWIFTLY=1)"
            install_via_swiftly || log "swiftly did not complete"
            toolchain_bin="$(find_toolchain_bin)"
            if [ -n "$toolchain_bin" ]; then
                log "swiftly produced a toolchain at $toolchain_bin"
            else
                log "swiftly produced no usable toolchain"
            fi
        else
            log "NOT falling back to swiftly: it is unverified, and WATCHWORD_ALLOW_UNVERIFIED_SWIFTLY is not 1"
            why_no_toolchain="fallback-refused"
        fi
    fi
fi

# ----------------------------------------------------------------------------- 5. expose on $PATH
# Claude Code's Bash tool does not run a login shell, so a profile script alone is not enough —
# /usr/local/bin is what actually makes `swift` resolvable in the commands the agent runs. Only the
# driver binaries are linked: the `swift` driver finds build, test, format and friends relative to
# its own resolved path, and linking the whole toolchain would shadow the system clang for every
# other build on the VM.
if [ -n "$toolchain_bin" ]; then
    for tool in swift swiftc swift-format sourcekit-lsp; do
        [ -e "$toolchain_bin/$tool" ] && ln -sf "$toolchain_bin/$tool" "$ROOT/usr/local/bin/$tool"
    done
    printf 'export PATH="%s:$PATH"\n' "$toolchain_bin" > "$ROOT/etc/profile.d/swift.sh"
    chmod 0644 "$ROOT/etc/profile.d/swift.sh"
    log "linked drivers into /usr/local/bin from $toolchain_bin"
fi

# ----------------------------------------------------------------------------- 6. warm the caches
# The environment snapshot keeps files, so a build done here is a build no later session repeats.
# Bounded and optional: busting the five-minute cache window would cost more than it saves. A cold
# `swift build --build-tests` of milestone 0 takes about 20 seconds on this VM.
if [ -n "$repo" ] && command -v swift > /dev/null 2>&1; then
    log "warming the build cache"
    ( cd "$repo" && timeout 150 swift build --build-tests ) > "$WORK/build.log" 2>&1 \
        || { log "warm-up build did not complete; see $WORK/build.log"; tail -20 "$WORK/build.log"; }
fi

# -------------------------------------------------------------------------------- 7. verify loudly
wait "$mise_pid" || log "WARNING: mise setup did not complete; see $WORK/mise.log"
if command -v mise > /dev/null 2>&1; then
    log "mise present: $(mise --version 2>&1)"
fi

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
#
# The note is fenced by begin/end markers so removing it does not depend on its line count. The
# second sed removes the unfenced seven-line note an earlier version wrote, so a snapshot that
# still carries one is cleaned up on the next successful run.
note="$ROOT/root/.claude/CLAUDE.md"
mkdir -p "$(dirname "$note")"
sed -i -e '/<!-- watchword-cloud-setup:begin -->/,/<!-- watchword-cloud-setup:end -->/d' \
    -e '/^<!-- watchword-cloud-setup -->$/,+6d' "$note" 2>/dev/null || true

if [ "$ok" -eq 1 ]; then
    log "SUCCESS: swift is on PATH at $(command -v swift)"
else
    log "FAILURE: no working Swift toolchain. Session will be told via $note"
    case "$why_no_toolchain" in
        unverified)
            detail="The toolchain that download.swift.org served did not verify against the pinned Swift
signing key (or its signature or the key bundle could not be fetched), so it was discarded and no other
installer was tried. Treat that as possible tampering with the download, not as a flaky network: tell the
user exactly this, and do not install a toolchain from any other source in this session unless they ask."
            ;;
        fallback-refused)
            detail="The signed release tarball could not be downloaded. The script's other method, swiftly,
is an installer it cannot verify and runs as root, so it is used only when the environment sets
WATCHWORD_ALLOW_UNVERIFIED_SWIFTLY=1 (docs/09-cloud-sessions.md §3). Tell the user; do not set it for them.
If the download was refused, the environment's network access may not allow \`download.swift.org\` (§4)."
            ;;
        *)
            detail="If a download was refused, the environment's network access may not allow
\`download.swift.org\` and \`www.swift.org\` (docs/09-cloud-sessions.md §4)."
            ;;
    esac
    cat >> "$note" <<EOF
<!-- watchword-cloud-setup:begin -->
The cloud environment's setup script could not install a Swift toolchain, so \`swift\`,
\`swift build\`, \`swift test\` and \`swift format\` are all unavailable in this session. Read
$LOG for the reason before trying to build anything, and tell the user what it says; the
log names the step that failed. $detail
To retry inside this session, run \`.github/scripts/cloud-setup.sh\`.
<!-- watchword-cloud-setup:end -->
EOF
fi

log "done"
exit 0
