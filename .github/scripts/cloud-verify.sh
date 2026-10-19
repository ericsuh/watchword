#!/usr/bin/env bash
# Runs every CI gate that a Linux cloud-session VM can honestly run.
#
# Four of the five `ci.yml` jobs survive the move to Linux: package-tests, adversarial-tests,
# strict-memory-safety and lint. What does not survive is anything that needs Xcode — the `app-tests`
# job, the XCUITest and AutoFill extension suites, and any future module built on CryptoKit,
# Security.framework or LocalAuthentication (docs/09-cloud-sessions.md §1). A green run here is
# evidence the pure modules are sound, never evidence the app is.
#
# Each gate is the `mise run <task>` that the matching `ci.yml` step calls, so a gate cannot drift
# from CI by being copied here. cloud-setup.sh installs mise on a best-effort basis, though, so when
# mise is missing (or cannot read this checkout's tasks) the script falls back to the plain `swift`
# commands, which cover build, both test suites, the strict build and lint but not the audits or
# the tasks' checks that each framework and adversarial suite actually ran.
#
# Usage: .github/scripts/cloud-verify.sh [--quick]
#   --quick  build and test only; skips the strict-memory-safety, audit and lint gates.
set -uo pipefail

quick=0
[ "${1:-}" = "--quick" ] && quick=1

cd "$(dirname "$0")/../.."

if ! command -v swift > /dev/null 2>&1; then
    echo "error: swift is not on PATH. The environment's setup script (.github/scripts/cloud-setup.sh)"
    echo "       either did not run or failed; see docs/09-cloud-sessions.md §4."
    exit 1
fi

# A string rather than an array: referencing an empty array under `set -u` is an error in the
# bash 3.2 that macOS still ships, and this script should run unchanged on a developer machine.
failures=""
skipped=""
run() { # run <label> <command...>
    local label="$1"
    shift
    printf '\n===== %s =====\n' "$label"
    # `echo`, not `printf`: a format string beginning with "-" is read as options by bash's printf.
    if "$@"; then
        echo "----- $label: pass"
    else
        echo "----- $label: FAIL"
        failures="${failures}${failures:+, }${label}"
    fi
}
skip() { # skip <label> <reason...>
    local label="$1"
    shift
    printf '\n===== %s =====\n' "$label"
    echo "warning: $*"
    echo "----- $label: skipped"
    skipped="${skipped}${skipped:+, }${label}"
}

# `mise tasks info` parses mise.toml and mise-tasks/ without running anything, so it fails on a mise
# older than mise.toml's min_version or a config it cannot read — the cases where every gate below
# would fail for a reason that has nothing to do with the code.
runner="swift"
if command -v mise > /dev/null 2>&1; then
    if probe="$(mise tasks info build 2>&1 < /dev/null)"; then
        runner="mise"
    else
        echo "warning: mise is on PATH but cannot read this checkout's tasks; using plain swift instead."
        echo "         Check \`mise --version\` against min_version in mise.toml; mise's error follows."
        printf '%s\n' "$probe" | sed 's/^/         /'
    fi
else
    echo "warning: mise is not on PATH; using plain swift. The audit gates will not run."
    echo "         cloud-setup.sh installs it; see docs/09-cloud-sessions.md §4 if it failed."
fi

if [ "$runner" = "mise" ]; then
    # XcodeGen publishes macOS builds only (docs/09-cloud-sessions.md §2). None of these gates uses a
    # pinned tool, so don't let `mise run` try to install one either.
    [ "$(uname -s)" = "Linux" ] && export MISE_DISABLE_TOOLS="${MISE_DISABLE_TOOLS:-xcodegen}"
    export MISE_TASK_RUN_AUTO_INSTALL=false
fi

swift --version

has_swift_format=0
swift format --version > /dev/null 2>&1 && has_swift_format=1

if [ "$runner" = "mise" ]; then
    run "build" mise run build
    # Both frameworks must keep executing tests; the task greps its own log for evidence of each, so
    # its output stays visible rather than being piped away.
    run "tests (Swift Testing + XCTest)" mise run test
    run "adversarial suite" mise run test:adversarial

    if [ "$quick" -eq 0 ]; then
        run "strict memory safety" mise run build:strict
        run "unsafe confinement" mise run audit:unsafe
        # `swift package dump-package` comes with the toolchain; python3 does not, on a minimal VM.
        if command -v python3 > /dev/null 2>&1; then
            run "no dependencies" mise run audit:dependencies
        else
            skip "no dependencies" "python3 is not on PATH, and audit:dependencies parses the manifest with it."
        fi
        run "action pins" mise run audit:actions
        if [ "$has_swift_format" -eq 1 ]; then
            run "lint" mise run lint
        else
            skip "lint" "swift format is unavailable in this toolchain; let the GitHub Actions lint job cover it."
        fi
    fi
else
    run "build" swift build
    run "tests (Swift Testing + XCTest)" swift test --parallel
    run "adversarial suite" swift test --filter WatchwordAdversarialTests

    if [ "$quick" -eq 0 ]; then
        run "strict memory safety" swift build -Xswiftc -strict-memory-safety -Xswiftc -warnings-as-errors
        if [ "$has_swift_format" -eq 1 ]; then
            run "lint" swift format lint --strict --recursive --configuration .swift-format \
                Package.swift Sources Tests Apps
        else
            skip "lint" "swift format is unavailable in this toolchain; let the GitHub Actions lint job cover it."
        fi
    fi
fi

printf '\n===== summary (%s) =====\n' "$runner"
[ -z "$skipped" ] || printf 'skipped: %s\n' "$skipped"
if [ -z "$failures" ]; then
    echo "All Linux-runnable gates passed. Xcode-only gates (app-tests, XCUITest, AutoFill) were not run."
    exit 0
fi
printf 'failed: %s\n' "$failures"
exit 1
