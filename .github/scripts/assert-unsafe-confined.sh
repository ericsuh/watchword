#!/usr/bin/env bash
# Enforces that unsafe code exists only in Sources/SecureMemory (ADR 0001).
#
# The strict-memory-safety job proves every construct the compiler classifies as unsafe is *marked* with `unsafe`;
# it cannot prove the marker appears only in SecureMemory, because a marked construct compiles anywhere. Nor does the
# compiler classify everything memory-unsafe: an `@_silgen_name` declaration with integer parameters binds a C
# function such as `memset` without any pointer type in sight (review finding R1). This check covers both:
#
# 1. No symlinks under Sources/ or Tests/: grep does not follow them, but SwiftPM compiles them.
# 2. Only .swift files under Sources/: a C, C++ or assembly file would be a target nobody scans.
# 3. Outside SecureMemory, no code line mentions `unsafe` in any form (the `unsafe` expression, `Unsafe*Pointer`,
#    `withUnsafe*`, `unsafeBitCast`, `nonisolated(unsafe)`, `unowned(unsafe)`), `@unchecked`, any underscored
#    attribute (`@_silgen_name`, `@_cdecl`, `@_extern`, `@_section`, `@_used`, ...), `@extern`, `@section`, `@used`
#    or `@exclusivity`.
# 4. Nowhere, SecureMemory included, binds a foreign symbol by hand (`@_silgen_name`, `@_cdecl`, `@_extern`,
#    `@extern`): C functions come only from imported system modules.
#
# Comment lines are ignored. This is a tripwire, not a proof: review (and CODEOWNERS on Sources/SecureMemory) remains
# the backstop. Tests are out of scope: they are not shipped and not built by the strict job.
set -euo pipefail

fail=0
report() {
  echo "::error::$1"
  echo "$2"
  fail=1
}

links=$(find Sources Tests -type l)
[ -z "$links" ] || report "Symlinks under Sources/ or Tests/ are not permitted (grep would not scan them):" "$links"

foreign=$(find Sources -type f ! -name '*.swift')
[ -z "$foreign" ] || report "Only .swift files may live under Sources/:" "$foreign"

code_lines() {
  grep -rnE "$1" Sources --include='*.swift' | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true
}

outside=$(code_lines '[Uu]nsafe|@unchecked|@_[A-Za-z]|@(extern|section|used|exclusivity)([^A-Za-z0-9_]|$)' | grep -v '^Sources/SecureMemory/' || true)
[ -z "$outside" ] || report "Unsafe constructs outside Sources/SecureMemory (ADR 0001):" "$outside"

bindings=$(code_lines '@(_silgen_name|_cdecl|_extern|extern)([^A-Za-z0-9_]|$)')
[ -z "$bindings" ] || report "Hand-written foreign symbol bindings are not permitted anywhere:" "$bindings"

[ "$fail" -eq 0 ] && echo "Unsafe constructs are confined to Sources/SecureMemory; no hand-bound foreign symbols."
exit "$fail"
