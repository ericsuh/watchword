# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Watchword is a native iOS/iPadOS/macOS password manager for a household, end-to-end encrypted and
synced through the user's own iCloud (or any file-based cloud). The repository is in the **design
phase**: `docs/` is the primary deliverable, and `Sources/` holds the milestone-0 pure modules, the
milestone-1 cryptographic core, milestone 2's local vault (`WatchwordStore`, `WatchwordKit`,
`WatchwordPlatform`), milestone 3's sync (`WatchwordSync`, and in `VaultSession` the production keyring, multiple
vaults, the device registry and enrolment over the transport) short of its CloudKit and iCloud Drive transports,
milestone 4's sharing protocol core (`WatchwordSharing`), which nothing calls yet, milestone 5's portable AutoFill core
(`WatchwordAutoFill`) short of the extension adapter, milestone 6's portable hygiene core (`WatchwordHygiene`) short
of its network adapter, session wiring and UI, and milestone 7's import and export parsers (`WatchwordInterchange`)
short of their wiring into the session and the apps. `Apps/project.yml` is the XcodeGen spec for the iOS and macOS apps, their
AutoFill extension shells and the UI tests; the generated `.xcodeproj`, Info.plists and entitlements
are not committed.

## Commands

Every CI step is a `mise run <task>`, so the command in a failing step's name reproduces it locally. One-line tasks
are in `mise.toml`; the rest are scripts in `mise-tasks/` whose `#USAGE` header documents their flags
(`mise run <task> --help`, `mise tasks` for the list).

```sh
mise trust && mise install                             # once per checkout (XcodeGen, gh; checksums in mise.lock)
mise run check                                         # every package gate in ci.yml: lint, audits, tests
mise run check:all                                     # ...plus both app test suites (macOS + Xcode only)

mise run build                                         # swift build (extra arguments are passed through)
mise run test                                          # Swift Testing + XCTest; fails unless both frameworks ran
mise run test --filter WatchwordGeneratorTests.PasswordGeneratorTests   # one Swift Testing suite, by type name
mise run test --filter WatchwordMatchingTests.ItemRankerTests   # one XCTest class; a filter matching no test fails
mise run test --coverage                               # also writes an llvm-cov report to coverage.txt
mise run test:adversarial                              # security suite only (its own CI job)
mise run test:long --seed 1234                         # the nightly long randomised run; replay a nightly's seed
mise run test:scripts                                  # the repository's own scripts (screenshots.yml's steps, app:screenshots), against stand-in tools
mise run fuzz --max-total-time 60                      # libFuzzer over every target in Fuzz/ (--target <name>, --list)

mise run lint                                          # swift format lint --strict (alias fmt:check)
mise run fmt                                           # swift format --in-place
mise run audit                                         # dependency, unsafe, strict-build, action-pin, mise-pin tripwires
mise run build:strict                                  # -strict-memory-safety, warnings as errors; skips before Swift 6.2

# Apps (macOS only; mirrors the app-tests CI job). Each regenerates the project from Apps/project.yml first.
mise run app:generate                                  # xcodegen; refuses an XcodeGen other than mise.toml's
mise run app:build [ios|macos]                         # both by default; --configuration Release
mise run app:test [ios|macos]                          # both by default; --only-testing <id> (needs a platform), --results, --simulator
mise run app:diagnose [TestResults]                    # print a failed run's summary, runner logs and crash reports
mise run app:screenshots [ios|macos]                   # the screenshot tour: Screenshots/<set>/*.png, index and a one-PNG contact sheet; --appearance dark, --device ipad
mise run app:test-keychain --team <ID>                 # real Keychain round trip, signed with your team (local only)
mise run clean                                         # .build, generated project, logs, result bundles
mise run ci:gate <gate> [--filter=…] [--platform …]   # one gate as its ci.yml job runs it, plus a failure summary: what mac-run.yml runs (app:screenshots too)
```

UI tests launch the app with `--uitest`, which (Debug builds only) swaps in in-memory ports and the KDF floor, and
syncs over an in-memory transport with `UITestPeer`, a second session of the same account the test drives from a
Debug-only Settings section (it unlocks with `WATCHWORD_UITEST_PASSWORD` from the launch environment).
`ScreenshotTourTests` is the screenshot tour: one pass through every flow that attaches a picture of each major
screen (`Screens.capture("name", in: app)`, numbered in capture order, the app's window on macOS and the screen on
iOS). A new screen is one `Screens.capture` line where the tour reaches it; capture after a tap or keystroke, or after
waiting for the element that proves the screen is complete, never after a sleep. `app:test` runs the tour as an
ordinary end-to-end test; `app:screenshots` runs it alone and writes `Screenshots/<set>/<NN-name>.png`, `index.md`,
`index.html` and `Screenshots/watchword-screens-<set>.png` (every screen in one picture), failing on a missing or blank
picture or a set in the wrong appearance. Only a complete set is written there: anything less goes to
`Screenshots/<set>-incomplete/`, whose index says first what is wrong, with XCUITest's own failure screenshots.
`--uitest-appearance=light` or `=dark` (Debug only, with `--uitest`) draws the app in that appearance whatever the
machine's is; the task passes one for every set, so `Screenshots/macos` is light on a Mac in Dark Mode.
macOS UI tests also need "automation mode" enabled on the machine, which needs an administrator; CI runners
have it. Real Keychain round trips need a signed, entitled process, so `swift test` and CI skip them.
`app:test-keychain` runs `SystemKeychainStoreTests` in the `WatchwordKeychainTests` bundle, hosted by a do-nothing
app whose only entitlement is its own Keychain access group, so a free Personal Team can sign it; the team ID goes
on the command line (`--team` or `DEVELOPMENT_TEAM`), never in `Apps/project.yml`, and xcodebuild runs with
`-allowProvisioningUpdates`. It sets `WATCHWORD_REQUIRE_KEYCHAIN`, so a missing entitlement fails instead of skipping.

Requires Xcode 16.4+ (Xcode 26 for strict memory safety). Other developer tools come from the project-level
`mise.toml`, never Homebrew or the global mise config; Swift and swift-format come from the selected Xcode. CI runs the same matrix: Xcode 16.4 on
macOS 15 and Xcode 27.0 on macOS 27 (the `xcode-27` runner; GitHub keys macOS images by Xcode major, so there is
no `macos-27` label).

### Xcode MCP server (local macOS sessions only)

In a local macOS CLI session, enable the Xcode MCP server and prefer its tools over shelling out:
`BuildProject`, `RunAllTests` / `RunSomeTests` / `GetTestList`, `GetBuildLog`,
`XcodeListSchemes` / `XcodeListTestPlans` / `XcodeListRunDestinations`, and the simulator and
debugger tools. It drives the same toolchain the CI matrix uses, surfaces structured diagnostics
instead of scraped log text, and will be the only practical way to run the XCUITest and AutoFill
extension suites once `Apps/` exists.

Do **not** rely on it in CI or in hosted/remote sessions — no Xcode GUI, no simulators, and no MCP
server there. Those environments use the `mise run` tasks above (plain `swift` and `xcodebuild`
underneath), which is why every workflow step stays expressible as shell. Keep it that way: an
MCP-only step is a step CI cannot run.

### Cloud sessions run on Linux, so some of this repository is invisible there

A Claude Code cloud session (claude.ai/code, `claude --cloud`, routines) is a fresh **Ubuntu 24.04
x86\_64** VM. `docs/09-cloud-sessions.md` is the setup runbook; the part that matters while working
is what the platform excludes. There is no Xcode, no simulator, no Apple SDK, and no Xcode MCP
server, and the base image cannot be replaced. So in a cloud session:

- `mise run build`, `test`, `test:adversarial`, `build:strict`, the `audit:*` tasks and `lint` all
  work — four of the five `ci.yml` test jobs. Run `.github/scripts/cloud-verify.sh` for the lot: it runs
  those same tasks with a pass/FAIL line each (`--quick` for build and tests only).
- The setup script installs mise and runs `mise trust && mise install` (XcodeGen skipped: macOS
  only), but best-effort: without a working `mise`, `cloud-verify.sh` warns and falls back to plain
  `swift` commands, which skip the audits. The shims are not on `PATH` in the Bash tool, so run pinned
  tools as `mise exec -- <tool>`.
- Anything importing Security.framework, LocalAuthentication, SQLite3 or CoreGraphics does not compile, and
  `xcodebuild` is absent. The Keychain adapters, the SQLite store and the PDF (`docs/02-architecture.md` §15) can be
  drafted there but **not** built or tested there. `WatchwordCrypto`, PBKDF2 and `VaultSession` do build and test:
  `import Crypto` is CryptoKit on Apple platforms and swift-crypto's BoringSSL on Linux (ADR 0006), so a Linux pass is
  evidence about the logic, not about what ships. Push the branch and
  dispatch `.github/workflows/mac-run.yml` on it (`mise run ci:gate`, `docs/09-cloud-sessions.md` §5) to compile and
  test it on a macOS runner; until a run passes, say so rather than reporting a layer as verified.
- The toolchain is Swift 6.4, newer than the Xcode 16.4 CI leg. A clean cloud build is not evidence
  that leg passes.

If an agent needs the real toolchain, the answer is Remote Control on a Mac (`claude
--remote-control`), not a cloud session — that is the only arrangement with `xcodebuild`, a
simulator and the Xcode MCP server.

`WatchwordModel`, `WatchwordMatching`, `WatchwordGenerator`, `WatchwordEnvelope`, `WatchwordSync` and
`WatchwordInterchange` import only `Foundation`, `Testing` and `XCTest`, which is the sole reason they are testable on Linux. Treat that portability as a
property to keep: `WatchwordSync` reaches keys only through its `SyncKeyring` and `RecordMerger` ports, and the day it
imports CryptoKit, milestone 3 becomes Mac-only. `WatchwordStore`'s port, `InMemoryRecordStore` and `WatchwordKit`'s
policies and ports are portable too, and so are `WatchwordCrypto`, `WatchwordSharing`, `VaultSession` and `WatchwordAutoFill` through
swift-crypto (ADR 0006);
`SQLiteRecordStore` (`#if canImport(SQLite3)`, which is false on Linux, so guard test helpers that name it) and all of
`WatchwordPlatform` are not. `WatchwordHygiene` is wholly portable: it imports `Foundation`, `Crypto`, `SecureMemory`
and `WatchwordModel`, and its only way to the network is the `HTTPClient` port, so the day it imports `URLSession`
its tests stop being able to say what leaves the device.

## Architecture

Read `docs/02-architecture.md` before changing anything security-relevant; its section numbers are
cited throughout the code. `docs/01-prd.md` requirement IDs (`F6.6`, `SEC6`, …) are the other half of
that vocabulary and appear in doc comments.

Fourteen shipped modules, dependency-ordered, plus test support:

- **`WatchwordModel`** — pure data types (`Item`, `Field`, `ServiceScope`). No dependencies.
- **`WatchwordMatching`** — the AutoFill security boundary. Depends on `WatchwordModel`.
- **`WatchwordGenerator`** — password/passphrase/PIN generation, generic over `RandomNumberGenerator`.
- **`WatchwordEnvelope`** — envelope format, canonical CBOR, `EnvelopeContext` (the AAD), every check that
  can run before decryption, and KDF parameter validation. Does no cryptography itself.
- **`SecureMemory`** — `SecureBytes` (zeroising, page-locked key buffers), `ConstantTime`, the
  CommonCrypto PBKDF2 call, and the four system bindings with pointer-typed signatures (SQLite,
  `SecItemCopyMatching`, `LAContext.canEvaluatePolicy`, the PDF `CGContext`). The only module allowed unsafe
  code (ADR 0001 and its milestone-2 amendment).
- **`WatchwordCrypto`** — Secret Key, 2SKD, KDF calibration, keyset, vault keys, HPKE grants, signatures,
  fingerprints, record sealing; device keys and signatures (`DevicePublicKey`, `DeviceSignatures`,
  `SoftwareDeviceKey`, `EnrolmentKey`), the device registry (`RegistryEntry`, `DeviceRegistry.evaluate`) and the
  published account header (`AccountHeaderObject`). Depends on `SecureMemory` and `WatchwordEnvelope`.
- **`WatchwordStore`** — the `RecordStore` port, `InMemoryRecordStore` and `SQLiteRecordStore` (the App Group
  ciphertext database). Envelopes plus storage locations only; never keys.
- **`WatchwordSync`** — milestone 3's portable half: object layout, the `SyncTransport` port with
  `InMemorySyncTransport` and `FileSyncTransport`, signed sealed segments and snapshots (`SyncPayload`,
  `SignedObject`), the `SyncKeyring`/`RecordMerger`/`SyncStateStore` ports, conflict-keeping `ItemMerge` over
  `ItemState` (the item as a state-based CRDT, `docs/10-sync-correctness.md`) and line-level `NoteText`,
  `ItemRecordMerger` (the one item merger, over an `ItemSealer`), `KindRoutingMerger`, `SyncEngine`,
  `DeletionRecordingStore`, `AccountObjectLocation` (names of the account's own objects), `AutoSyncPolicy` (when to
  sync, pure), and `SQLiteSyncStateStore` (`sync.sqlite`, beside the record store). Depends on
  `WatchwordModel`, `WatchwordEnvelope`, `WatchwordStore`, and `SecureMemory` for `SQLiteConnection` only; no CryptoKit.
- **`WatchwordSharing`** — milestone 4's protocol core for shared vaults: the signed membership chain
  (`MembershipRecord`, `MembershipRules`, `MembershipLedger`, `writePermission`, `writeStanding` and the
  `WriteCut`, `status(of:)`), fingerprint
  verification (`FingerprintCode`, `VerifiedContacts` and its `VerifiedContact` token, `MemberKeyCheck`), both sides
  of an invitation, key grants (`KeyGrantCodec`, `grantSender`/`openGrant`), `LeaveRequest`, and rotation as data
  (`RotationPlanner`, `RotationPlan`, `PendingRotation`, `recordsToReseal`). Ports: `KeyBundleDirectory`,
  `VerifiedContactStore`. Depends on `WatchwordEnvelope`, `WatchwordCrypto` and `SecureMemory`; not on
  `WatchwordSync` or `WatchwordKit`, and nothing depends on it yet (`docs/02-architecture.md` §8.8 is what the
  integration will call).
- **`WatchwordHygiene`** — milestone 6's portable core: `PwnedPasswordsClient` (the k-anonymity range API) and
  `BreachedAccountClient` over the `HTTPClient` port, the `PwnedRangeCache` port, `ScanSchedule`/`ScanLedger` (when to
  check, as a value), `StrengthEstimator` (zxcvbn-class, with embedded word lists), `ReuseIndex`, `ItemAnalyzer`,
  the `SiteDirectory` seam, `HygieneReport`, and `HygieneEngine`, the actor the session will drive between unlock and
  lock. Depends on `WatchwordModel`, `SecureMemory` and `Crypto`; knows nothing of the session or the store.
- **`WatchwordKit`** — `VaultSession` (the actor every UI calls: create, unlock, quick unlock, lock, items,
  history, trash, password change, deletion, `sync()`, conflict resolution; vaults, move, copy and search in
  `VaultSession+Vaults.swift`; enrolment, devices, revocation and the account's objects on the transport in
  `VaultSession+Account.swift`), `UnlockPolicy`, `AutoLockPolicy`, `ItemCodec`, `VaultMetadataCodec`, `ItemSearch`,
  `EmergencyKit`, the ports (`KeychainStore`, `BiometricGate`, `WallClock`, `DeviceKeyStore` with the software
  `KeychainDeviceKeyStore`), and `VaultSyncAdapter`, the production `SyncKeyring` and `ItemSealer`
  (`VaultSession+Sync.swift`).
- **`WatchwordAutoFill`** — the credential provider extension's portable core (milestone 5): `CredentialProviderModel`
  (one method per request the OS makes: credential list, passwords, one-time codes, text to insert, passkey
  registration and assertion, save and generate password, credential-update reports), `ReleaseGate`, `TOTP`,
  `PasskeyAuthenticator` and `PasskeyPRF`, `RelyingPartyID`, `PasswordRules`, `CredentialIdentityPlanner`, and the
  ports `CredentialVault`, `CredentialIdentityPublisher` and `AutoFillClock`. Depends on `WatchwordModel`,
  `WatchwordMatching`, `WatchwordGenerator`, `SecureMemory` and `Crypto`; not on `WatchwordKit` (`VaultSession`
  conforms to its port) and never on AuthenticationServices.
- **`WatchwordPlatform`** — Apple adapters: `SystemKeychainStore`, `LocalAuthenticationGate`, the Emergency Kit
  PDF, the App Group path. In the package rather than `Apps/` so every CI gate covers them.
- **`WatchwordInterchange`** — import and export of other password managers' formats (milestone 7): `CSVReader`/
  `CSVWriter` and `PasswordCSV` (1Password and Apple Passwords CSV), `OnePUX`, `CredentialExchange` (CXF 1.0), the
  `ZIPArchive` reader and `Inflater` they need, `ImportAssembler`, `StoredItemSize`, `DuplicateDetector`,
  `InterchangeGuide`. Depends on `WatchwordModel` and `WatchwordMatching`; Foundation only, no keys, files or clocks.
- **`WatchwordTestSupport`** — `SeededGenerator`, `RepeatingGenerator`, hex helpers, the nightly knobs, and the
  fakes (`FakeKeychain`, `FakeBiometricGate`, `FakeClock`, `FakeDeviceKeyStore`, `TestVault`, whose
  `enrolledDevice` enrols a real second device over the transport; `RegistryFixture` for hand-built registry
  entries; for sync `FakeSyncKeyring` over a keyed checksum that is not cryptography, `FakeItemMerger`,
  `SyncTestClient`, `SimulatedServer`; for AutoFill `FakeCredentialVault`, `FakeCredentialIdentityPublisher`,
  `AutoFillHarness` and the S1 to S4 items in `AutoFillFixtures`; for hygiene `FakeHTTPClient`, which records every
  request, `RecordingPwnedRangeCache`, `SimulatedPwnedPasswords`; for sharing, with real keys, `HostileSharingStore`,
  `SimulatedMember` (the reference for the integration's sync pass, §8.8), `SharingHousehold` and `ForgedRecord`, an
  encoder of its own for records the module would never sign; for imports `ZIPFixture` and `DeflateFixture`, which
  build the archives and streams no real writer produces). Test targets only; not a product, and no production target
  may depend on it.

`docs/02-architecture.md` §15 maps each module to its milestone; §14 describes import and export as built; §7.5
describes sync as built, §7.6 the vault side (keyring, saves, state, conflict UI), §7.7 vaults, the account's objects
on the transport and enrolment, §7.8 the device registry (and what revocation does not do), §7.9 automatic syncing;
`docs/10-sync-correctness.md` is the model of an item as a CRDT and the argument that sync converges;
`docs/03-implementation-plan.md` milestone 3 lists what is still open (CloudKit and iCloud Drive transports, the
Secure Enclave device key, sync in production builds, `UITestPeer`). §8 describes sharing as built, and milestone 4
what is open there (wiring into `VaultSession` and sync, `CKShare`, the UI). §13 describes hygiene as built, and
milestone 6 what is still open (the `URLSession` adapter, session wiring, background glue, the report UI). Milestone 7
lists what is open for import and export (session wiring, the encrypted archive, Credential Exchange, the screens).

### `WatchwordHygiene` invariants

- Only five hexadecimal characters of a password's SHA-1 ever leave the device, in
  `GET https://api.pwnedpasswords.com/range/XXXXX` with `Add-Padding: true` and the `User-Agent`. The hosts are the two
  constants of `HygieneHost`; `HTTPSURL` has no public initialiser. Never add a configurable host, follow a
  redirect, or put anything else in a request.
- A response that could not be read is an error, never "not breached": the parser's bounds (bytes, lines) fail closed
  and counts saturate. Suffix comparison (`PwnedRange.result`) scans every entry without branching on a match. The
  breached-account response is bounded *while reading* (entry 2,001 ends the read); never decode a whole array and
  count afterwards.
- **Only while keys are resident (ADR 0005 and its amendment).** `HygieneEngine` keeps everything derived from a
  password in one optional that `lock()` clears, and `lock()` then calls `PwnedRangeCache.lock()`, which empties the
  in-memory cache: the set of prefixes is password-derived and must not outlive the keys, in memory either. Every
  hashing entry point checks the optional, and a scan re-checks the lock epoch after each suspension (the client
  again after its cache write), so a lock during a request wins and nothing is cached or recorded. `PasswordDigest`,
  `ReuseToken`, `ReuseIndex`, `ItemAnalysis` and the report are not `Codable`: keep them that way.
- What survives a lock is `ScanPacing` (token bucket, backoff) and nothing else: it is not password-derived, and
  dropping it would let each unlock forget `Retry-After` and start a new burst. It names no item. A scan that a
  lock interrupts writes to it and to nothing else (`recordInterrupted`): requests sent are charged, and a refusal
  that came back after the lock still backs off.
- Unlocked to locked always empties the prefix cache, whichever call did it: `unlock` over an unlocked engine is
  `lock()` first, and a cancelled `unlock` ends in `lock()`. Do not add a path that drops the resident state
  without `client.lockCache()`.
- **`lock()` must never queue behind the vault.** `unlock` is `async`, analyses one item per turn and stops when it
  finds the engine locked or its task cancelled; until it returns, `next` waits, `scan` is `.busy` and `report`
  throws. Do not add a synchronous loop over every item to the actor. The session zeroises the keyset *before*
  calling `lock()`, never after.
- **Stale copies are refused.** The engine remembers the highest version of each item it has seen; an older copy
  (or one from before a trash or deletion) changes nothing: `update` returns `false`, `scan` returns `.stale`. A
  scan whose item changed while its requests were in flight records nothing.
- "Clear" is about every password in the item: more than 16 password fields is `incomplete`, and two password
  fields sharing an ID share the worse result. An unknown result is never "not breached".
- The prefix cache and the `ScanLedger` are password-derived (which prefixes; breach counts). They are persisted only
  sealed, per device, unsynced. Nothing here writes to disk.
- Nothing password-derived or identifying prints: digests, tokens, prefixes (`hex` is the accessor), assessments
  (the exact estimate is internal; a rank names a common password), analyses, ledgers, addresses, URLs
  (`absoluteString`) and header values (`HTTPHeaders.fields`) all have redacting descriptions and mirrors. A new
  type that holds any of these needs the same.
- The breached-account lookup sends an identifier, so it takes an `IdentifierDisclosure` and nothing schedules it.
- Time is a parameter and jitter an injected generator: no timers, no `Date()`, no sleeping, in the module or its
  tests. Every request is paid for in `ScanSchedule`'s token bucket, including the several an item with several
  passwords makes. An item whose check failed goes to the back of the queue, and a new weekly pass begins a week
  after the last began whether or not it finished: one range the server refuses must not stall the rest. Which
  items failed is in the ledger (`ScanLedger.Failure`), never in memory only: it must outlast the backoff, across
  locks and restarts, so the session stores `ledger()` after a failed scan too. A remembered time further ahead
  than the policy could have set it (a clock put back) is overwritten in `distrustFutureTimes`, not merely
  bounded when read; a new stored time needs a line there.
- The estimator analyses 64 scalars, keeps one match per stretch, and looks words up by walking a sorted table of
  scalar arrays (`WordTable`): never build or hash a `String` per stretch (hashing non-ASCII text normalises it, a
  denial-of-service on a shared vault), and anything that makes its cost depend on the password's full length is
  one too. A cover costs `k! ×` the product of its parts, without zxcvbn's `10000^(k-1)` bonus, which rated
  `Spring2026!` strong; keyboard zigzags and parallel columns are single patterns. Explanations never quote the
  password.

### `WatchwordInterchange` invariants

An import file is hostile (adversary A7); `docs/02-architecture.md` §14 is the description. Before editing:

- Limits are enforced before or while the cost is incurred (`InterchangeLimits`; an initialiser can tighten one, never
  loosen it). A file ends in one `InterchangeError`; a bad entry is skipped or degraded and listed in the
  `ImportReport`. Never drop, change or refuse something without a line in the report, on import or on export
  (`ExportReport`, `ExportSupport`).
- Per-entry and per-file limits do not bound their product, so the import as a whole has budgets
  (`maximumTotalFields`, `maximumScopeDerivations`), counted in `ImportAssembler.add` before an entry is built. A new
  per-entry cost needs a place in one of them. CSV rows are streamed (`CSVReader.forEachRecord`), never held beside
  the drafts. A draft is measured as the vault will store it (`StoredItemSize`, checked against `ItemMerge.stamped`
  and `ItemCodec` by the adversarial suite): if the stored form of an item changes, that estimate changes with it.
- A merge never widens (`DuplicateDetector`), here or in a file exported afterwards: scopes, sign-in fields and
  `url` fields from a file reach an existing item only through `MergeChoices`, one host or field at a time, and an
  accepted URL stays a website (`InterchangeMeta.websiteType`) only where the merged item is scoped to its host.
  Don't add an "accept all", and don't make `merged` add any of them by default.
- An export never widens either: `ExportSupport.websites` is the one place that decides what a format writes as a
  sign-in URL, and it writes none for a host the item is not scoped to (reported as `websiteNotScoped`). Don't let an
  exporter put some other `url` field where a format keeps an entry's sites.
- Every format hands its entries to `ImportAssembler`, the one place drafts are made: IDs from the injected generator
  and the vault ID from the caller, never from the file; a URL becomes a scope only through `ScopeDerivation`
  (`HostNormalizer`, then `ScopePolicy`) and otherwise stays a `url` field with a warning (a URL that says more than
  its host is also kept as text beside its scope, and `ExportSupport.websites` writes it back); TOTP values go through
  `OTPParameters`, passkeys through `PasskeyCredential`. Don't build an `Item` in a format's parser.
- The ZIP reader validates every member and decompresses only the one asked for. Nothing is extracted to disk, nested
  archives are never opened, and anything with two readings is refused. Don't add leniency to "support" a real-world
  archive without an adversarial test for what the leniency admits.
- JSON is walked one item at a time (`JSONReader.readBoundedValue`); don't materialise a document. No
  `JSONSerialization`: its behaviour differs between Linux and Apple platforms.
- Invalid UTF-8 is refused, never repaired. Cells and fields are data in both directions: an import takes a cell
  exactly as written and every export writes the stored value unaltered (RFC 4180 quoting only). Nothing
  neutralises spreadsheet formulas, on export or import (owner decision, 2026-11-16: the CSV is not for spreadsheets;
  `InterchangeGuide` warns instead). Don't add an apostrophe, and don't strip one.
- Checks on names, cells and URLs work on bytes or Unicode scalars, never on `Character`s and never through
  Foundation's string searches or white-space sets: to `split` and `hasPrefix`, a slash followed by a combining mark
  is not a slash (`../` + U+0301 passed as a name until review caught it), and `whitespacesAndNewlines` differs
  between Linux and Apple platforms. Use `UTF8Text.trimmed`.
- Searches over an entry's fields, URLs or sections use sets or dictionaries: a file can make any list long, and the
  fuzz and adversarial suites assume linear work.
- Exporters return plaintext bytes and a report and do nothing else. Password re-entry, file protection and the OS
  Credential Exchange calls belong to the session and the apps.
- The fuzz harness is its own package (`Fuzz/`, built only by `mise run fuzz`) so the shipped manifest never mentions
  it; libFuzzer's entry point in `Fuzz/Sources/WatchwordFuzz/LibFuzzerEntry.swift` is the one pointer outside
  `SecureMemory`, and both tripwires hold it there. A new parser of hostile bytes gets a target in `FuzzTarget` and a
  seed in `Fuzz/Corpus/<target>/`.

### `SyncEngine` invariants

- Objects are created, never overwritten; each device writes only its own stream. Never add an "update" to
  `SyncTransport`.
- Download needs no keys and checks signatures before staging; merge re-verifies staged objects and checks kind,
  context, AEAD, then payload, in that order. A stream is merged strictly in sequence: never skip a gap.
- A segment carries only its author's versions, and each record envelope's own context must match its entry
  before anything is applied. Record versions above `maximumVersion` or jumps beyond `maximumVersionJump` are
  quarantined (U5).
- **Never lose data (PRD F7.6, F7.7).** `ItemMerge` is a multi-value register per group: a value is replaced only
  by one written *knowing about it* (its `GroupStamp.seen` vector contains it); concurrent values all stay, in
  `Item.conflicts`, until the person edits the group or calls `ItemMerge.resolve`. Notes merge line by line
  (`NoteText`). Merges never shorten a history; quarantined versions are kept. A permanent deletion carries an
  erasure summary and removes only what its author had seen; anything else is kept, trashed
  (`Item.keptAfterDeletion`). Every discard is the person's: a permanent deletion, `ItemMerge.resolve`, and the 30-day
  trash purge (F1.5). Sync can leave an item in the trash that nobody chose to discard, so the purge removes only
  `Item.isTrashedByPerson`: a trash written knowing every edit the item holds, with no concurrent restore, and not a
  version kept after a deletion. Item history is never pruned (F1.4).
- A version must contain its predecessor: `ItemMerge.stamped` on every save (it also keeps `modifiedAt` monotonic).
  The clock records *edits* only; a merge result is sealed through `ItemMerge.written`, which sets the version and
  nothing else, so devices that merged the same edits hold the same state. The long simulation diverged each time one
  of these was broken.
- **The merge is a join, and must stay one** (`docs/10-sync-correctness.md`): `ItemMerge.merge` is commutative,
  associative and idempotent on whole items, on any metadata, and every update (`stamped`, `resolve`, `settle`)
  contains the version it was made on. Every component of `ItemState` is a semilattice — registers (the values no
  other supersedes, where "supersedes" is strict coverage of the stamps' vectors), field order (`Item.fieldOrder`,
  last-writer-wins), note lines (`NoteText.join` per ID), history (union), retained values less what
  `Item.discards` covers. Never drop a value at merge time for any reason but a value that supersedes it (not even an
  equal one), never truncate, and never order by anything but `CanonicalWriter` bytes — each of those was a
  convergence bug (Y18, Y22). A change here runs `LongRunningItemMergeLawTests` and
  `LongRunningItemMergeExhaustiveTests`, whose asserted counts change only for a reason you can state.
- Sync metadata is a writer's claim. Every item is read through `ItemState.init` (`ItemMerge.canonical`): no count
  above the row's version, no value under a group it does not belong to, repeated identifiers joined. Do not read
  `revisions`, `conflicts` or `noteLines` of a stored item any other way in merge code.
- An edit of a group that holds a conflict moves the conflicting values to `Item.retainedValues`; only
  `ItemMerge.resolve` (an explicit choice) discards them, and records what it had seen in `Item.discards` so they
  stay discarded.
- A permanent deletion, applied to a version it does not cover, is one write by the deleting device at the
  tombstone's revision (`ItemMerge.settle`, from the `ItemErasure` the tombstone carries): the same on every device,
  never a fresh edit per device. Several deletions of one item are several such writes (`ItemErasures`, their set),
  never one write claiming what another deletion had seen; a version is erased when they had, between them, seen all
  of it. The engine passes the latest tombstone's stamp (`resolveErasure(_:of:above:)`), never a version that depends
  on the copy in question: the merger believes no summary naming a later row (Y28) and writes a kept version above
  that stamp and the row, through `ItemMerge.written`.
- Deletions are explicit (`DeletionRecordingStore`), never inferred from a missing row, and a pending deletion
  counts as an erasure while merging. The outbox compares rows with `SyncState.published`, not `known`.
- A record can be erased more than once. A device remembers the join of every erasure of a record
  (`RecordMerger.joinErasureSummaries`; for items the union of `ItemErasures`, stamped with the later stamp) and
  judges versions against that, so arrival order decides nothing. A pending
  deletion is done only when this device published a deletion at or after its stamp *and* the join already holds
  what it had seen; never skip one because another device's erasure, or this device's own earlier one, is stamped
  later (W13, W18).
- The next sequence number is never below the stream's highest on the transport; every listed snapshot is merged;
  a segment is collected only once every other stream acknowledges it and a listed snapshot covers it.
- Store writes name the version they read (`StoreChange.expectations`), because the merger awaits.
- Every object carries two signatures over `name ‖ 0x00 ‖ envelope` under `SignatureDomain.logSegment`: the
  account key's and the writing device's own (`DualSignature`). `verify` accepts only a device the registry holds
  as registered and not revoked; while locked it uses the Keychain's `accountSigningKey` copy and registry anchor,
  and with no trusted key or registry every object is refused (`trustedKeyUnavailable`).
- A revoked device (`SyncKeyring.retiredAuthors`) is not read, not waited for by garbage collection or snapshot
  election (Y6), and what a device had merged from it is handed on in a snapshot of that device's own. Snapshot
  entries are always merged, stale coverage or not: merging is idempotent, and that snapshot may be the only carrier.
- One engine per vault; a vault's log carries items and the vault's description, each merged by its own merger
  (`KindRoutingMerger`). Never let a record of one kind reach another kind's merger.
- Pending deletions in the state store are signed by the session (`AuthenticatedSyncState`,
  `SignatureDomain.pendingDeletion`); one that does not verify is ignored, so a row planted in the file erases nothing.

### `WatchwordSharing` invariants

- **The owner is fixed** (never removed, never re-roled), and **the administrator set changes only in records the
  owner signed**: adding, removing or re-roling an administrator and deleting the vault are owner-only
  (`MembershipRules.authorise`). The fork rule and "nobody can be locked out" both rest on these two; do not add an
  operation that breaks either (ownership transfer needs a new design, not a new case).
- A record is verified against the state *before* it, and the signer's key comes from that state, never from the
  record. Cheap checks first, then the signature, and only then anything the record brought with it (a new member's
  bundle, a leave request). The member list in a record must equal the previous list with the operation applied.
- A removal or departure always names a vault key ID the chain has never used; nothing but those and `rotateKey`
  changes the key (principle 5; ADR 0007: rotation re-encrypts, there are no per-item keys).
- **The ledger is a grow-only set of valid records, and the accepted chain is a pure function of it**
  (`MembershipLedger.resolve`): records that lose a fork are kept (`branches`, bounded, persisted), `ingest` only
  ever adds, never throws for count and never depends on order or batching. A change that makes the result depend on
  the order of arrival breaks convergence; `LongRunningMembershipForkTests` is the property test.
- **Fork rule**: most owner-signed records on the path, then most records, then the lower hash where two such
  paths part. Owner-signed first, because a hash-only or length-only rule lets a former administrator rewrite history
  from before their removal (S1); length before hash, so a record signed on a stale head and released late displaces
  nothing built since (S18, S19).
- **Removal wins**: a removal on a losing branch whose signer may still remove that member is owed
  (`owedRemovals`): the member's writes count only as far as that record's cut, `recordsToReseal` is empty, and
  any device that may sign it
  plans it again. Everything else that loses is proposed again by its author (`status(of:)`); a device ingests
  before it proposes and never publishes a record that is not `awaitingPublication`.
- A record's hash covers its signed content, not its signature; candidates sharing a hash are each examined until
  one verifies (S3, S4). Every object *name* ends in a digest of the whole object, signature included, so nobody can
  take a predictable record's name (S20).
- Cheap checks, then the signature, then anything that costs work: unsigned junk costs one signature check, and no
  examination is bounded by a count that junk can fill (ledger candidates, grants, leave requests).
- Nothing is wrapped to, and no chain is anchored on, a bundle that is not a `VerifiedContact`; only
  `VerifiedContacts` makes one. Keep that typing, as with `NormalizedHost`. Wrapping to the bundles a chain lists
  (a rotation, `makeGrant`) takes a `MemberKeyCheck` made on the current head, which only
  `MembershipLedger.checkMemberKeys` makes: a member whose listed keys differ from the pin is refused.
  (`MemberKeyCheck.unchecked` is for `WatchwordTestSupport`; no production target calls it.)
- Bundles are compared with `hasSameKeys`, never `==`: Ed25519 signing is randomised on CryptoKit, so the same keyset
  gives a different self-signature each time. A Linux pass cannot show a mistake here.
- A grant's vault, key ID and recipient come from its storage location, and its sender must be the one account
  `grantSender` names: the signer of the record that entitled the recipient to that key. Not "any administrator".
- Read-only and "former member" are client rules, not cryptography (F4.5). `writePermission(for:)` is for a
  device's own writes; for anyone else's, `writeStanding(of:)`: everything an account signed while it may write
  *now*, and once it may not, exactly what is inside the `WriteCut` of the record that ended it. That record (a
  removal or departure of a member who could write, a change to read-only) and no other carries a cut, signed, so
  every device applies the same one **whenever it heard of the record**: a write outside it is taken out again by a
  device that had merged it, held aside, and never published on (S28). "Judged when merged, merged for good" is the
  rule this replaced; do not bring it back, and do not judge a version only by who signed its envelope (it may
  carry another account's work). The cut's bytes are the integrator's (§8.8 says what they must bind).
- While a removal is owed, the displaced record's cut is believed only if that record and the one holding the cut
  were signed by accounts that could sign them on the accepted head; a former administrator's dead branch decides
  nothing about a member's writes (S29).
- An invitation to a vault the device ever held continues that ledger (`accept(…, continuing:)`); it is never
  rebuilt from the store (S26).
- Local state is signed by the account's own key and re-verified on load (pins, the saved ledger, a rotation plan);
  a plan's object names and the account it removes are derived again from its signed contents. One that does not
  verify is ignored or refused.
- Every signature here uses `SignatureDomain.membership`, and every signed message starts with its own magic
  (`WWMR`, `WWLR`, `WWCP`, `WWML`, `WWRP`). A new signed message needs a new magic.
- Every parser is bounded and exact (size before copying, counts before allocating, one canonical encoding); the
  module imports no `WatchwordSync` or `WatchwordKit`, and its transport names live under `sharing/`, outside what
  the sync engine lists.

### `VaultSession` invariants

- Nothing unlocks on a boolean. `BiometricGate` reports enrolment only; quick unlock needs the Keychain to release
  the Local Unlock Key, that key to open the wrapped AUK, and the AUK to open the keyset. Keep it that way.
- A refused quick unlock *deletes* the Local Unlock Key; it is not merely ignored.
- The actor is re-entrant across `await`: after every suspension, re-check the lock epoch (`requireKeys(since:)`)
  before touching key material, so `lock()` always wins.
- Read contexts come from the store row, and a decrypted item's `id`/`vaultID`/`version` must equal the row's.
- Scopes are checked with `ScopePolicy` in `save`, whatever the UI sends (and in `resolveConflict`).
- The vault owns sync metadata: every write goes through `ItemMerge.stamped` and commits conditionally on the row it
  read (`commitItem`); a caller's `revisions`, `clock` or `conflicts` are never trusted. The session's deletions go
  through `writer(for:)` (`DeletionRecordingStore` when sync is configured); the engine writes to `store` directly.
- The sync adapter holds the session, never a key; every key operation re-enters the actor and throws
  `SyncKeyringError.locked` after `lock()`.
- Every invariant above holds per vault. A vault's key and identity come from its `vaultKeyWrap` row; which vaults
  exist comes from the directory rows under the account's ID, and a vault counts as deleted only on a deletion
  signed by the account key and a registered device for that vault. The Personal vault is never deleted. Deleting
  a vault deletes its items through the path of a permanent deletion; what the deletion had not seen stays, and is
  *shown* trashed and kept after a deletion (`VaultSession.presented`), never written that way: an automatic write
  per device is an edit the next deletion elsewhere has not seen.
- A move is a copy (derived ID) plus the original trashed in **one commit**, then the original deleted like any
  permanent deletion. Never move by changing a row's vault, and never move an item with unresolved values.
- Search runs over decrypted items in memory (`ItemSearch`); nothing is indexed on disk, and secret fields are
  never searched.

### Device registry and account objects (`docs/02-architecture.md` §7.7, §7.8)

- The registry is a grow-only set of entries named by their SHA-256; `DeviceRegistry.evaluate` is a pure,
  deterministic function of the entries, the pinned genesis entry and the pinned credential entry. Keep it that
  way: no clock, no arrival order, no local state.
- Password changes are checkpoints: what a credential entry had seen is replayed before what it had not. A
  candidate change is judged by replaying with it as the last checkpoint, never by its place among unsealed
  entries (a revoked device can back-date entries in front of it; review finding W1).
- Every entry needs the account key's signature and its author's (a registered device, or the current enrolment
  key); a credential entry also the previous generation's enrolment key. A revoked ID or key never returns.
- What a device trusts is in the Keychain (`deviceRegistryAnchor`, `accountSigningKey`), never in the database.
  The local store must still hold everything the anchor names, or the registry is unavailable and nothing verifies.
- Everything fetched before a key is held is hostile: headers are bounded and KDF-validated before any derivation,
  authenticated by the binding under the derived AUK, and the genesis entry comes from that binding only.
- A device with a password change it has not been given neither merges nor publishes, refuses the old password
  once it holds the new header, and adopts the change only when the person's password opens it.
- Revocation stops writing, not reading: do not describe it as more (§7.8 states the limits; the re-key is open).

### `CredentialProviderModel` invariants

`docs/02-architecture.md` §9.2 is the description; these are the rules to keep when editing `WatchwordAutoFill`.

- **One gate, by construction.** A secret leaves an item only through an `Authorization`, whose initialiser is
  private to `ReleaseGate.swift`; `ReleaseGate.authorize` is its one caller and runs `AutoFillGate.authorize` (or
  `authorizeOneTimeCode`) first. A new request type reads secrets through `Authorization`'s methods, never from an
  `Item` it looked up itself, and an explicit choice by the person is authorised like any other (SEC6, F11.1).
- **No override.** Nothing releases after a refusal: no flag, no presence level, no second call (F11.4, F11.7). A
  look-alike host gets `LookAlikeWarning` in place of a list. Do not add a "fill anyway".
- Shadowed items are listed (`otherAccounts`) and never released; archived items and items marked
  `excludedFromSuggestions` rank but are not listed, released or written (F6.8: reachable only in the app); trashed
  items do neither. The gate ranks among items with only the scopes `ScopePolicy` accepts, so a stored `com` scope
  matches nothing; the stored item is not rewritten. An item ID two readable items share names neither
  (`VaultSnapshot.duplicatedIDs`): both rank, neither is released. Use `snapshot.itemInUse(_:)`, not `all.first`.
- **The page, or nothing.** The gate is asked about a host only when the system named it for this request (list
  identifiers, a passkey's relying party, a save's identifier). A QuickType tap hands back the identity Watchword
  published and *not the page*, and the system chooses where to offer an identity (assume: anywhere under the
  registrable domain). So `passwordWithoutInteraction` and `oneTimeCodeWithoutInteraction` treat the request's
  identifier as a lookup key and answer only an identity `CredentialIdentityPlanner` would publish for the vault now;
  never pass a page URL there, and build test inputs with `handedBack`. A passkey needs only the gate.
- `CredentialIdentityPlanner` is a whole-vault function: a password or code identity exists only for a scope that
  covers its whole site (host equal to `PublicSuffix.broadestSite`, subdomains on, nothing excluded), with no other
  item scoped below that host and none at that host sharing the suggested name; a passkey identity only when the
  gate would release it. One item's change is published as the difference between the whole sets before and after.
- No host, no secret. With no service identifier every gated request is refused (`noServiceIdentifier`), text
  included. The system's host-less text insertion is `textInsertionListWithoutHost()` /
  `textToInsertWithoutHost(for:)`, through `ManualChoice`, which gives only fields whose kind is not a secret. Do not
  fold the two back into "empty identifiers".
- A passkey is bound twice: the stored relying party ID must equal the request's, and the item must pass the gate
  for that relying party as a host. A relying party ID is a `RelyingPartyID` (normalised, canonical, scope policy)
  before anything is hashed, stored or signed. Flags are truthful: UP/UV from the `PersonPresence` the adapter
  reports, BE always, BS from `CredentialVault.isBackedUp()`; the counter is zero; no extension data in
  authenticator data. `prf` is evaluated only when the person was verified (one secret per credential).
- A page cannot plant, widen or hide: a saved login is scoped to the exact host, without subdomains, titled by the
  host, through `ScopePolicy`; an update changes a password and never a scope, and is never made without UI. A new
  item that would outrank accounts already offered on the host says so (`NewItemProposal.hiddenAccounts`) and
  offers their scope instead (`newItemBesideExisting`); the model never picks between the two unasked. No
  registration adds a scope to an item (F11.7); a login scoped under the relying party is only named
  (`relatedLogins`). A conditional registration adds a passkey to the one saved password login for that relying
  party and user, and only if the item holds no passkey yet; an item holds at most `maximumPasskeysPerItem`.
- A remote party never deletes: reports set or clear `Field.meta` flags or rename a passkey's account, only on items
  the gate would release to the reporter, at most once per field per `reportInterval` (history is never pruned).
- Locked is a state the model reports (`vaultLocked`, `requiresInteraction(.vaultLocked)`). Each request reads the
  items once; writes are compare-and-swap on the version read (`saveCredentialItem(_:replacingVersion:)`); and every
  request that hands a secret back does so through `releasing(_:)`, which calls `CredentialVault.confirmUnlocked()`
  as the last suspension, so a lock that lands after the read wins.
- Published identities are plaintext outside the app: `CredentialIdentityPlanner` emits hosts, user names, credential
  IDs, user handles and UUID record identifiers, never a title, label, note or secret, and nothing for excluded,
  archived or trashed items.
- Everything a page can influence is bounded here (identifier count, allow-list length, `prf` input, blob, password
  rules, names), and `PasswordRules` cannot take a generated password outside the generator's 4 to 128 characters.

### The matching pipeline is the whole point of `WatchwordMatching`

A credential may only reach the OS through one path, and each stage fails closed:

```
ServiceIdentifier (OS-supplied, attacker-influenced)
  → HostNormalizer.normalize   rejects user-info, non-http(s) schemes, ASCII percent-escapes,
                               structural characters, over-long labels → NormalizedHost
  → ScopeMatcher.match         exclusions first; exact = 2·labels+1, subdomain = 2·labels
  → ItemRanker.rank            top specificity wins; less specific matches are *shadowed*
                               (keeps Amazon retail off the AWS console), ties are ambiguous
  → AutoFillGate.decide        .fill / .chooseAmong / .refuse(FillRefusal)
  → AutoFillGate.authorize     re-checks scope even for an explicit user choice (SEC6)
```

Two invariants to preserve when touching this module:

- Comparison functions take `NormalizedHost`, never `String`, so an un-normalised identifier cannot
  reach a match. Keep that typing.
- Normalisation may never *invent* a match. If an input is not unambiguously a hostname, throw.

`PhishingDetector` exists because the above is silent by design: on `аmazon.com` (Cyrillic а) nothing
matches, the UI shows nothing, and the person types the password by hand. It turns that silence into
`PhishingAssessment.suspicious` (visual-skeleton confusables, mixed script, punycode, bounded edit
distance, saved label out of registrable position). `FillRefusal` carries the assessment so the UI can
explain itself. See `docs/05-anti-phishing.md`.

`PublicSuffix` is a deliberately small embedded list, not the full PSL — adopting the ~14,000-entry
file is a supply-chain decision with an open ADR. Don't expand it into a de facto PSL; add the
entry and note the tradeoff, or escalate to the ADR.

### Fail-closed validation in `WatchwordEnvelope`

`EnvelopeHeader` is the authenticated prefix `magic(4) version(2) kind(1) keyID(16) nonce(12)
aadLength(2) aad ciphertext`. Kind, version and magic are checked *before* any payload is touched, so
record-swap and kind-confusion attacks fail without decryption. `Envelope.parse(_:expecting:)` then
checks the key ID and compares the embedded `aad` byte-for-byte with `EnvelopeContext.canonicalAAD()`
re-derived from the storage location (record, vault, schema, kind, key, record version); only then does
`RecordCipher.open` decrypt, with the *whole* serialized header as the AEAD's associated data. Callers
build the expected context from where they found the record, never from the record.

`KDFParameters` enforces two-sided bounds: a floor against downgrade (650k PBKDF2 iterations, 16-byte
salt) and a ceiling against a tampered header turning every unlock into a hang (25M iterations). Both
directions are tested; keep both when adjusting constants.

### The cryptographic core

`docs/02-architecture.md` §4 is the spec; the code cites it. Invariants worth knowing before editing:

- Key bytes live in `SecureBytes`, not in CryptoKit key objects: `EncryptionKey`, `Keyset` and `SecretKey`
  hold `SecureBytes` and build `SymmetricKey`/`Curve25519` keys per operation, so `zeroise()` on lock is
  real. Reading a zeroised buffer traps on purpose (an all-zero key is the worst key). CryptoKit
  plaintext comes back as `Data`; convert with `SecureBytes(wiping:)`.
- Decryption and HPKE failures all surface as `CryptoError.authenticationFailed` — never distinguish a
  wrong password from tampering.
- Every nonce is claimed in the key's `NonceLedger` (shared by all copies of an `EncryptionKey`) and a
  repeat throws `nonceReuseDetected`. Seal only through `RecordCipher.seal`.
- Every signature is domain-separated (`SignatureDomain`), and `Signatures.verify` rejects small-order
  Ed25519 keys; `PublicKeyBundle.init` validates (lengths, low-order X25519, small-order Ed25519,
  self-signature), so a bundle value is always a checked one.
- Anything unwrapped or opened takes its identity (vault ID, key ID, account ID) from the storage
  location the caller passes in, never from the record or grant itself — `VaultKey.unwrap`,
  `Keyset.unwrap` and `VaultKeyGrant.open(as:from:vaultID:keyID:)` all follow this.
- Production code never copies key material out with `Array(secureBytes)`; use `unprotectedCopy()` for
  non-secret values so every escape is searchable.
- Crypto code imports `Crypto` (apple/swift-crypto), never `CryptoKit`, and carries no platform conditional: on Apple
  platforms `Crypto` re-exports CryptoKit, on Linux it is the same API over BoringSSL (ADR 0006). The one exception is
  `PBKDF2.swift`, which calls CommonCrypto on Apple platforms and swift-crypto's `CryptoExtras` (linked on Linux only,
  because it compiles BoringSSL) elsewhere; keep the conditional there. Linux results are evidence about the logic;
  the macOS CI matrix, against CryptoKit, is the gate.

## Conventions

- **Swift 6 language mode**, strict concurrency. Public types are `Sendable` and usually `Hashable`.
- **Errors, not optionals, for security decisions.** Typed error enums (`HostNormalizationError`,
  `FillRefusal`, `KDFValidationError`, `EnvelopeError`) name the reason so tests assert on it.
- **No third-party dependencies, ever, without an ADR.** The one exception is swift-crypto (ADR 0006).
  `.github/scripts/assert-no-dependencies.sh` fails CI on any other package or product, a version or
  `Package.resolved` commit other than the ones it names, `CryptoExtras` linked on a non-Linux platform,
  `.binaryTarget`, `.plugin(` or `unsafeFlags`. Shipped crypto comes only from CryptoKit, Security.framework and
  CommonCrypto.
- **No unsafe constructs** outside `SecureMemory` — enforced by the `strict-memory-safety` job plus the
  `.github/scripts/assert-unsafe-confined.sh` tripwire (a marked construct would compile anywhere, and
  `@_silgen_name`-style bindings are not flagged by the compiler at all). No symlinks or non-Swift files
  under `Sources/`, no custom target paths, no experimental features (`assert-no-dependencies.sh`). Inside
  `SecureMemory`, every unsafe construct is marked `unsafe (expression)` — **with the space**: Swift 6.2+
  parses it as the keyword, and on Swift 6.0/6.1 it is a call to the stand-in in `UnsafeMarker.swift`.
  An outer `unsafe` does not cover closure bodies; mark each level. Calls to stdlib `withUnsafe*` are
  flagged by Swift 6.3 but not 6.4, so pass a method reference (`src.withUnsafeBytes(dst.copyMemory(from:))`)
  to keep the marker necessary on both.
- `WatchwordMatching` deliberately does not import AuthenticationServices; it mirrors
  `ASCredentialServiceIdentifier` with its own `ServiceIdentifier` so the logic is testable under
  plain `swift test`. Keep core modules platform-independent; adapters belong in `Apps/`.
- Doc comments cite the requirement or architecture section that motivates the code. Follow that —
  the "why" is load-bearing here, and `docs/` is updated in the same PR as the behaviour it describes.
- British spelling in prose and comments (normalisation, zeroisation); American in API names
  (`normalize`, `HostNormalizer`).
- swift-format with `.swift-format` is a CI gate: 120-column lines, 4 spaces, ordered imports,
  no block comments, no semicolons.

## Tests

- **Swift Testing** for new suites: `@Suite("display name")`, `@Test("behaviour sentence", arguments:)`.
  Parameterised tests over two sequences use `zip(a, b)`, not two `arguments:` labels.
- **XCTest** survives in `WatchwordMatchingTests` only. Both frameworks must keep executing tests —
  CI greps `test-output.log` for evidence of each and fails if either produced none.
- **Adversarial suites** live in `Tests/WatchwordAdversarialTests`, are named `Adversarial…`, and
  carry `.tags(.adversarial)`. CI asserts each area's `@Suite` display name is present
  (`"envelope and KDF"`, `"AutoFill service matching"`, `"password generator"`,
  `"AutoFill request model"`, `"phishing resistance"`, `"crypto core"`, `"unlock and quick unlock"`,
  `"local vault store"`, `"Keychain item protection"`, `"sync log"`, `"sync log, item metadata"`, `"sync with real keys"`,
  `"hygiene and breach checks"`, `"sharing and membership"`, `"import parsers"`,
  `"account enrolment and device registry"`), so **renaming a suite breaks CI deliberately** — update
  `mise-tasks/test/adversarial-suites.txt` alongside it (both `test` and `test:adversarial` read it). Each adversarial test's doc comment states the concrete threat
  (which adversary from `docs/02-architecture.md` §2, with what access) it checks.
- Any PR touching crypto, envelope, sharing, `SecureMemory`, or a Keychain/LocalAuthentication
  adapter must add or update an adversarial test (`docs/03-implementation-plan.md`, working
  agreements).
- Randomness is injected: production uses `SystemRandomNumberGenerator`, tests use the SplitMix64
  `SeededGenerator` from `WatchwordTestSupport`. Never make production code reach for a seeded generator, and never sleep in a
  test — time will come from an injected `Clock`.
- `WATCHWORD_LONG_TESTS=1` and `WATCHWORD_TEST_SEED` are the nightly workflow's knobs for extended
  randomised runs; new long-running tests should honour them via `TestEnvironment`. `test:long` runs the
  adversarial target plus any test whose identifier contains `LongRunning` (the sync simulations are
  `LongRunningSyncSimulationTests`, over fakes, and `LongRunningVaultSimulationTests`, real sessions with vaults,
  enrolment and a revocation; the membership ledger's convergence property is `LongRunningMembershipForkTests`; the
  merge's laws are `LongRunningItemMergeLawTests` and `LongRunningItemMergeExhaustiveTests`), so name a new
  randomised suite that way to have the nightly widen it.
- Known-answer vectors come from the RFC that defines the primitive, or from an independent
  implementation (Python `hashlib`/`cryptography`), never from round-tripping our own code.

- **Script tests** (`Tests/ScriptTests`, Python `unittest`, `mise run test:scripts`) cover the scripts Swift tests
  cannot reach: `screenshots-index.py`, the `app:screenshots` task, and the inline steps of `screenshots.yml`, each run
  as it is against stand-ins for `gh`, `curl`, `mise`, `xcrun` and `sips`. Standard library only, Python 3.9 syntax
  (Xcode's `python3`), and bash that macOS's 3.2 runs.

`docs/04-test-plan.md` maps every requirement to its obligated tests and is the place to check before
claiming a layer is covered.

## CI

`.github/workflows/ci.yml` — `package-tests` (2-runner matrix), `adversarial-tests`,
`strict-memory-safety`, `lint`, `app-tests` (macOS and iOS-simulator legs), and `required` (`Required checks`), which
fails unless every other job succeeded and is the one check branch protection names, so renaming a matrix leg for a
runner bump never strands `main` waiting on a check that no longer reports. Everything Xcode-, AppKit- or
screen-dependent runs on `xcode-27`; only the Xcode 16.4 floor leg stays on `macos-15`. Each step after checkout and Xcode selection is
`mise run <task>`; put new CI logic in a task, not inline in a workflow. `security-nightly.yml` — long randomised
runs, the libFuzzer harness in `Fuzz/` (`mise run fuzz`), and an audit that every `uses:` is a 40-hex
commit SHA. `mac-run.yml` — dispatch-only, one gate on one branch on a macOS runner (`mise run ci:gate`), so a cloud
session can run Mac-only gates before opening a pull request; it gates nothing. A dispatch runs the workflow and
`ci:gate` as they are on that branch (one cut before mac-run.yml merged needs a rebase first), so `ci:gate`'s refusals
catch mistyped requests, not attackers: write access, no secrets and the read-only token are the controls.
`claude-pr.yml` — Claude reviews a PR an admin opens ready for review or marks ready, and answers an admin's `@claude`
in a PR comment, review or review comment (in the thread, or on the whole PR for a re-review). It is the one workflow
with a secret and a write-scoped token (`pull-requests: write`, never `contents: write`); its Claude job alone runs in
the `staging` environment, which holds that secret. Its controls are in
`docs/07-supply-chain.md` §3.2. `issue_comment` runs the default branch's copy of the file; the other triggers run the
PR's. Its action is the one third-party action, so it needs its own entry in the repository's allowed-actions list
(`docs/08-repository-hardening.md` §1).
`screenshots.yml` — captures the tour's screens for a PR and attaches them: on the `screenshots` label (and each push
while it is on), on a same-repository head commit whose message has a line that is exactly `[screenshots]` (never a
fork's: the marker is honoured only where pushing needs write access), or on dispatch. `decide` (read-only, no
checkout) chooses; `capture` runs the PR's code (`mise run app:screenshots`, read-only token, no secrets, one leg per
platform) and uploads each set and, unzipped, its one-PNG contact sheet; `comment`, the only job with
`pull-requests: write` (plus `actions: read`), checks nothing out, takes only the screen names from `capture`
(pattern, 40 characters, 99 names), finds the artifacts itself by name among the run's own, links the sheet only if
GitHub will serve it as `image/png`, and creates or updates one sticky comment, recognised by its whole header and
never by the bot author alone (`claude-pr.yml` posts as the same account). It is not a required check, and there is
deliberately no comment command (`docs/07-supply-chain.md` §3.2). Its two no-checkout jobs are inline `gh api`, the one
place a mise task cannot go; `mise run test:scripts` (in the `lint` job) runs those two scripts as they are in the file
against a stand-in `gh`, so a change to either needs its test in `Tests/ScriptTests`.
The same capture is the `app:screenshots` gate of `mac-run.yml`.

One check on every PR has **no workflow file**: `Analyze (swift)`, from CodeQL *default setup*,
which GitHub configures in repository settings and runs on a generated workflow you cannot see in
the tree. Don't go looking for it in `.github/`, and don't add a `codeql.yml` to "fix" its absence —
that would run CodeQL twice. Inspect it instead:

```sh
gh api repos/ericsuh/watchword/code-scanning/default-setup   # state, languages, query suite
gh api repos/ericsuh/watchword/code-scanning/alerts --jq '.[] | {rule: .rule.id, state, path: .most_recent_instance.location.path}'
```

Two consequences worth knowing. It is the one piece of CI that does **not** follow the
SHA-pinning rule, because the queries are versioned by GitHub rather than by this repository — an
accepted exception, recorded in `docs/07-supply-chain.md` §3.4, not an oversight. And its check
name is derived from the configured language set, so enabling a second language renames it and
silently drops it from any branch-protection list that named the old one.

Supply-chain rules that apply to edits in `.github/`:

- **Pin actions to full commit SHAs**, never tags; add the `# v4`-style comment and the mapping in the
  header block. The nightly audit fails the build otherwise.
- Keep `permissions: contents: read` at workflow and job level, `persist-credentials: false` on every
  checkout, and the trigger as `pull_request` — never `pull_request_target`. The two jobs with more
  (`pull-requests: write` in `claude-pr.yml` and in `screenshots.yml`'s `comment`) check out and run nothing from
  the pull request; a job that runs the pull request's code never holds a write token.
- Xcode selection goes through `.github/scripts/select-xcode.sh`, not a third-party action.
- Build tools reach CI only through mise with `MISE_LOCKED=1`, so every tool needs a `mise.lock` entry
  (URL and SHA-256). Bump a tool by editing `mise.toml` and running
  `mise lock --platform macos-arm64,linux-x64`; commit both files. mise itself is pinned by version and
  SHA-256 in `.github/scripts/install-mise.sh` (and again in `cloud-setup.sh`; `mise run audit:mise-pins` fails if
  they differ), and a bump is reviewed like an action pin. That script also writes mise's CI settings to
  `$GITHUB_ENV`, including `MISE_TASK_RUN_AUTO_INSTALL=0`, so a job that needs a tool installs it by name
  (`mise install xcodegen`).

`.claude/` and other agent/editor configuration is intentionally uncommitted
(`docs/07-supply-chain.md` §5). `docs/08-repository-hardening.md` is the `gh` runbook for branch
protection, signing and rulesets.
