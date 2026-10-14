#!/usr/bin/env bash
# Enforces that unsafe code exists only in Sources/SecureMemory (ADR 0001).
#
# The strict-memory-safety job proves every unsafe construct is *marked* with `unsafe`; it cannot prove the marker
# appears only in SecureMemory, because a marked construct compiles anywhere. This check closes that gap: any code
# line outside SecureMemory that mentions `unsafe` in any form (the `unsafe` expression, `Unsafe*Pointer`,
# `withUnsafe*`, `unsafeBitCast`, `nonisolated(unsafe)`, `unowned(unsafe)`) or `@unchecked` fails the build.
# Comment lines are ignored. Tests are out of scope: they are not shipped and not built by the strict job.
set -euo pipefail

matches=$(grep -rniE 'unsafe|@unchecked' Sources --include='*.swift' \
  | grep -v '^Sources/SecureMemory/' \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true)

if [ -n "$matches" ]; then
  echo "::error::Unsafe constructs outside Sources/SecureMemory (ADR 0001):"
  echo "$matches"
  exit 1
fi
echo "Unsafe constructs are confined to Sources/SecureMemory."
