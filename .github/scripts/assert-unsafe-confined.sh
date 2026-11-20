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
# 5. Fuzz/ (the libFuzzer harness, a package of its own that no app links): only .swift files under Fuzz/Sources, and
#    the same constructs confined to one file, Fuzz/Sources/WatchwordFuzz/LibFuzzerEntry.swift. libFuzzer calls a C
#    function with a pointer and a length, so that file must name a pointer type and export the symbol; its one
#    permitted attribute is `@_cdecl("LLVMFuzzerTestOneInput")`, and nothing in Fuzz/ may bind a foreign symbol.
#
# 6. Test hooks stay in tests (review of round 7, Z168; round 8, Z172): `package` members that exist so a test can play
#    an adversary or leave a check out are visible to every target of the package, WatchwordPlatform and
#    WatchwordPresentation included, so the compiler would let a shipped target call one. Each may be named in code
#    only on the lines below that define or apply it, matched whole (leading white space aside) and counted (a line
#    listed once may appear once in its file, so a copy of an allowed line elsewhere in that file is refused; one
#    that must appear twice is listed twice, review of round 9, Z178), and anywhere under
#    Sources/WatchwordTestSupport (Tests/ is not scanned): `playModifiedClient` and the state it sets,
#    `playsModifiedClient` (a session that writes and publishes in a shared vault whatever its device ID, Z162),
#    `assigningDeviceID` (enrolment under a named device ID that commits to nothing, Z157), `MemberKeyCheck.unchecked`
#    (a member key check that compared nothing, so keys are wrapped to unpinned bundles) and `MemberKeyCheck`'s
#    initialiser (the same, built by hand). Names are matched as words with or without backticks, a member reference
#    whether applied or not and on a line of its own (`.unchecked`, one line of a chain), and a bare `unchecked(` (a
#    call from an extension of the type). A bare unapplied `unchecked` inside such an extension, or `.init(` with the
#    type inferred, is not found: a tripwire, not a proof. A new line that names a hook gets an entry in `hook_lines`
#    in the same change; a new hook, an entry in `test_hooks`. `dropKeys` and the other `package` members are
#    production code shared between modules, not hooks.
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

roots=(Sources Tests Apps)
[ -d Fuzz ] && roots+=(Fuzz)
links=$(find "${roots[@]}" -type l -not -path 'Fuzz/.build/*')
[ -z "$links" ] || report "Symlinks under Sources/, Tests/, Apps/ or Fuzz/ are not permitted (grep would not scan them):" "$links"

foreign=$(find Sources -type f ! -name '*.swift')
[ -z "$foreign" ] || report "Only .swift files may live under Sources/:" "$foreign"

# Apps/: XcodeGen compiles every file under a target's source path, so a .c, .m or .h file there would be built with
# nothing scanning it. Tracked files only: the generated project, Info.plists and entitlements are gitignored.
apps_foreign=$(git ls-files Apps | grep -vE '(\.swift|^Apps/project\.yml)$' || true)
[ -z "$apps_foreign" ] || report "Only .swift files and project.yml may be committed under Apps/:" "$apps_foreign"

# Apps/ is scanned too: the app and extension targets are built by xcodebuild, not by the strict-memory-safety job, so
# this script is the only gate that keeps unsafe code out of them.
code_lines() {
  grep -rnE "$1" Sources Apps --include='*.swift' | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true
}

outside=$(code_lines '[Uu]nsafe|@unchecked|@_[A-Za-z]|@(extern|section|used|exclusivity)([^A-Za-z0-9_]|$)' | grep -v '^Sources/SecureMemory/' || true)
[ -z "$outside" ] || report "Unsafe constructs outside Sources/SecureMemory (ADR 0001):" "$outside"

bindings=$(code_lines '@(_silgen_name|_cdecl|_extern|extern)([^A-Za-z0-9_]|$)')
[ -z "$bindings" ] || report "Hand-written foreign symbol bindings are not permitted anywhere:" "$bindings"

# A name, then the pattern that finds it in a code line.
test_hooks=(
  'playModifiedClient|(^|[^A-Za-z0-9_])playModifiedClient([^A-Za-z0-9_]|$)'
  'playsModifiedClient|(^|[^A-Za-z0-9_])playsModifiedClient([^A-Za-z0-9_]|$)'
  'assigningDeviceID|(^|[^A-Za-z0-9_])assigningDeviceID([^A-Za-z0-9_]|$)'
  'MemberKeyCheck.unchecked|\.[[:space:]]*`?unchecked`?([^A-Za-z0-9_]|$)'
  'MemberKeyCheck.unchecked|(^|[^@A-Za-z0-9_.`])`?unchecked`?[[:space:]]*\('
  'MemberKeyCheck.init|(^|[^A-Za-z0-9_])MemberKeyCheck[[:space:]]*(\(|\.[[:space:]]*`?init([^A-Za-z0-9_]|$))'
)
# A file, then a line of it (leading white space removed) that may name a hook: where each is defined or applied, as
# many times as it may appear there.
hook_lines=(
  'Sources/WatchwordKit/VaultSession.swift|var playsModifiedClient = false'
  'Sources/WatchwordKit/VaultSession+Sharing.swift|if playsModifiedClient { return true }'
  'Sources/WatchwordKit/VaultSession+Sharing.swift|package func playModifiedClient(_ playing: Bool = true) {'
  'Sources/WatchwordKit/VaultSession+Sharing.swift|playsModifiedClient = playing'
  'Sources/WatchwordKit/VaultSession+Sync.swift|if sharing.vaults[location.vaultID] != nil, !playsModifiedClient,'
  'Sources/WatchwordKit/VaultSession+Account.swift|password: password, secretKey: secretKey, accountID: accountID, assigningDeviceID: identity?.id)'
  'Sources/WatchwordKit/VaultSession+Account.swift|package func enrol(password: String, secretKey text: String, accountID: UUID?, assigningDeviceID: UUID?)'
  'Sources/WatchwordKit/VaultSession+Account.swift|if let assigningDeviceID {'
  'Sources/WatchwordKit/VaultSession+Account.swift|deviceID = assigningDeviceID'
  'Sources/WatchwordSharing/MemberKeyCheck.swift|package static func unchecked(in ledger: MembershipLedger) -> MemberKeyCheck {'
  'Sources/WatchwordSharing/MemberKeyCheck.swift|MemberKeyCheck(vaultID: ledger.vaultID, head: ledger.state.hash, substituted: [], unverified: [])'
  'Sources/WatchwordSharing/MemberKeyCheck.swift|return MemberKeyCheck('
)
allowed_hook_lines=$(printf '%s\n' "${hook_lines[@]}")
for entry in "${test_hooks[@]}"; do
  name=${entry%%|*}
  pattern=${entry#*|}
  hooks=$(code_lines "$pattern" | ALLOWED="$allowed_hook_lines" awk '
    BEGIN { count = split(ENVIRON["ALLOWED"], list, "\n"); for (i = 1; i <= count; i++) allowed[list[i]]++ }
    index($0, "Sources/WatchwordTestSupport/") == 1 { next }
    {
      path = $0; sub(/:.*/, "", path)
      text = $0; sub(/^[^:]*:[0-9]+:/, "", text); sub(/^[ \t]+/, "", text)
      key = path "|" text
      if (++seen[key] > allowed[key] + 0) print
    }' || true)
  [ -z "$hooks" ] || report "A test hook ($name) named outside the lines that define or apply it and Sources/WatchwordTestSupport (tests only):" "$hooks"
done

if [ -d Fuzz ]; then
  entry=Fuzz/Sources/WatchwordFuzz/LibFuzzerEntry.swift
  fuzz_foreign=$(find Fuzz/Sources -type f ! -name '*.swift')
  [ -z "$fuzz_foreign" ] || report "Only .swift files may live under Fuzz/Sources/:" "$fuzz_foreign"

  fuzz_lines() {
    grep -rnE "$1" Fuzz/Sources --include='*.swift' | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true
  }
  fuzz_outside=$(fuzz_lines '[Uu]nsafe|@unchecked|@_[A-Za-z]|@(extern|section|used|exclusivity)([^A-Za-z0-9_]|$)' | grep -v "^$entry:" || true)
  [ -z "$fuzz_outside" ] || report "Unsafe constructs in Fuzz/ outside $entry:" "$fuzz_outside"

  fuzz_attributes=$(fuzz_lines '@_[A-Za-z]|@(extern|section|used|exclusivity)([^A-Za-z0-9_]|$)' | grep -vF '@_cdecl("LLVMFuzzerTestOneInput")' || true)
  [ -z "$fuzz_attributes" ] || report "The only underscored attribute permitted in Fuzz/ is libFuzzer's entry point:" "$fuzz_attributes"

  fuzz_entries=$(fuzz_lines '@_cdecl' | wc -l | tr -d ' ')
  [ "$fuzz_entries" -le 1 ] || report "Fuzz/ may export one symbol, libFuzzer's entry point:" "$(fuzz_lines '@_cdecl')"
fi

[ "$fail" -eq 0 ] && echo "Unsafe constructs are confined to Sources/SecureMemory (and libFuzzer's entry point in Fuzz/); no hand-bound foreign symbols; test hooks only in tests."
exit "$fail"
