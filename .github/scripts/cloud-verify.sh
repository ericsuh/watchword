#!/usr/bin/env bash
# Runs every CI gate that a Linux cloud-session VM can honestly run.
#
# Four of the five `ci.yml` jobs are expressible as plain `swift` commands and so survive the move
# to Linux: package-tests, adversarial-tests, strict-memory-safety and lint. What does not survive
# is anything that needs Xcode — the `app-tests` job, the XCUITest and AutoFill extension suites,
# and any future module built on CryptoKit, Security.framework or LocalAuthentication
# (docs/09-cloud-sessions.md §1). A green run here is evidence the pure modules are sound, never
# evidence the app is.
#
# Usage: .github/scripts/cloud-verify.sh [--quick]
#   --quick  build and test only; skips the strict-memory-safety and lint gates.
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

swift --version

run "build" swift build
# Both frameworks must keep executing tests; CI greps the log for evidence of each, so keep the
# output visible rather than piping it away.
run "tests (Swift Testing + XCTest)" swift test --parallel
run "adversarial suite" swift test --filter WatchwordAdversarialTests

if [ "$quick" -eq 0 ]; then
    run "strict memory safety" swift build -Xswiftc -strict-memory-safety -Xswiftc -warnings-as-errors
    if swift format --version > /dev/null 2>&1; then
        run "lint" swift format lint --strict --recursive --configuration .swift-format \
            Package.swift Sources Tests Apps
    else
        echo
        echo "warning: swift format is unavailable in this toolchain; the lint gate was skipped."
        echo "         Run it locally or let the GitHub Actions lint job cover it."
    fi
fi

printf '\n===== summary =====\n'
if [ -z "$failures" ]; then
    echo "All Linux-runnable gates passed. Xcode-only gates (app-tests, XCUITest, AutoFill) were not run."
    exit 0
fi
printf 'failed: %s\n' "$failures"
exit 1
