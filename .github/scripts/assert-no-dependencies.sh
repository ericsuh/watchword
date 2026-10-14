#!/usr/bin/env bash
# Enforces the zero-runtime-dependency invariant (PRD P4, ADR 0001).
#
# The strongest supply-chain position available to this project is to have no third-party package
# to compromise. Adding one is a deliberate decision that needs an ADR, so it must not be
# possible to do it quietly in a pull request.
set -euo pipefail

fail=0

if grep -nE '^[[:space:]]*\.package\(' Package.swift; then
  echo "::error file=Package.swift::A third-party dependency was added. This requires an ADR; see docs/07-supply-chain.md."
  fail=1
fi

if grep -nE 'unsafeFlags|\.binaryTarget|\.plugin\(|packageAccess' Package.swift; then
  echo "::error file=Package.swift::Binary targets, build plugins, and unsafeFlags are not permitted."
  fail=1
fi

if [ -f Package.resolved ]; then
  pins=$(python3 -c 'import json,sys; d=json.load(open("Package.resolved")); print(len(d.get("pins", d.get("object",{}).get("pins",[]))))')
  if [ "$pins" != "0" ]; then
    echo "::error file=Package.resolved::Package.resolved pins $pins dependencies; expected 0."
    fail=1
  fi
fi

if [ "$fail" -eq 0 ]; then
  echo "No third-party dependencies, binary targets, or build plugins. "
fi
exit "$fail"
