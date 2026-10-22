# Watchword — Implementation Plan

Version 0.1 (draft). Milestones are ordered so that every security-relevant layer exists, with its
tests, before any UI depends on it. Each milestone lists its exit criteria; the matching test
obligations are in `04-test-plan.md`. Each milestone from 2 onwards also records the environment
it has to be built in — a Mac with Xcode, or a remote/Linux session — summarised in the table
below.

## Where each milestone is built

Two execution environments are available, and the split between them is not a preference. It is the
Apple SDK boundary described in `09-cloud-sessions.md` §1.

- **Local macOS session** (or Remote Control into one): full Xcode, simulators, `xcodebuild`, the
  Xcode MCP server, and every Apple framework. The only environment in which the `app-tests`,
  XCUITest and AutoFill suites can run at all.
- **Remote/Linux session** (cloud session, `claude --cloud`, routines): `swift build`, `swift test`,
  both test frameworks, the adversarial suite, `-strict-memory-safety` and `swift format` — the four
  `ci.yml` jobs that `.github/scripts/cloud-verify.sh` reproduces. No Apple SDKs, ever.

| Milestone | Remote/Linux with no loss of verification | Needs a Mac, and for what |
| --- | --- | --- |
| 0 — repository, toolchain, CI (done) | Yes; this is why cloud sessions work on this package at all | — |
| 1 — cryptographic core (done) | Builds, but the crypto suites are compiled out, not run | CryptoKit, CommonCrypto, Security.framework |
| 2 — local vault and unlock (done) | No | Keychain, LocalAuthentication, App Group container, PDF generation, the `Apps/` project, XCUITest, on-device QuickType |
| 3 — sync (portable half done) | The change log, Lamport merge and multi-client simulation — done, with signing and encryption behind a port | the production keyring and merger in `VaultSession`, sync state in the App Group database, `CloudKitTransport`/`CKSyncEngine`, the iCloud Drive container, the manual CloudKit workflow |
| 4 — sharing | No | Ed25519 and HPKE under the membership chain, `CKShare`, `UICloudSharingController`/`NSSharingService` |
| 5 — AutoFill | No | AuthenticationServices, app-extension targets, simulator and device QA |
| 6 — hygiene | HIBP client, scheduling, strength estimator, reuse/age/2FA checks | the Watchtower-style report UI and its snapshot tests |
| 7 — interchange | Parsers, adversarial parser tests, and the fuzz targets — a better host for them | Credential Exchange on iOS 26/macOS 26, the encrypted Watchword archive |
| 8 — hardening and release | Reading the source for external review | performance and accessibility passes, privacy manifest, TestFlight |

Four rules this split implies, all of which outlive the milestones they came from:

1. **A remote session can draft Apple-framework code; it cannot verify it.** Pair such a session with
   a Mac one that runs the suites before the pull request opens. The adversarial-test obligation in
   the working agreements below is discharged on the Mac, not in the session that wrote the test.
2. **`#if canImport(CryptoKit)` fails silently.** On Linux the crypto suites are *absent*, not red:
   `swift test` goes green with whole files never compiled. Count tests rather than reading the exit
   code, and treat Linux green as a signal, never as the gate (`09-cloud-sessions.md` §4).
3. **Remote-capability is a design lever, not a fact about a milestone.** Milestone 3's merge logic is
   portable exactly as long as segment signing stays behind a port with a fake in
   `WatchwordTestSupport`; the moment `WatchwordSync` imports CryptoKit, the whole milestone becomes
   Mac-only. The ports list in `02-architecture.md` §15 is what keeps the boundary movable, and the
   same reasoning already keeps `WatchwordMatching` free of AuthenticationServices.
4. **No step may exist only as an Xcode MCP call.** The MCP server is a local-macOS convenience over
   the same toolchain CI uses; every milestone step must stay expressible as shell, or CI cannot run
   it (`CLAUDE.md`, and `09-cloud-sessions.md` §1 on Remote Control as the only way an agent reaches
   `xcodebuild`).

## Milestone 0 — Repository, toolchain, CI (done)

- SwiftPM package `Watchword` with the first pure modules (`WatchwordModel`, `WatchwordMatching`,
  `WatchwordGenerator`, `WatchwordEnvelope`) and both Swift Testing and XCTest targets.
- GitHub Actions on macOS runners: `swift build`/`swift test` on Xcode 16.4 (macOS 15) and Xcode 26
  (macOS 26), a dedicated adversarial-suite job, a strict-memory-safety job, formatting lint, and
  an Xcode app-test job that activates when the app project lands.
- Exit: CI green on the pull request; docs in `docs/`.

## Milestone 1 — Cryptographic core (done)

- `SecureMemory`: `SecureBytes` with zeroisation, page locking where available, every unsafe
  construct marked `unsafe`.
- `WatchwordCrypto`: Secret Key generation/formatting/checksum; 2SKD (`PBKDF2` via CommonCrypto,
  `HKDF` via CryptoKit, combined with HKDF rather than XOR — ADR 0003 amendment); keyset creation and wrapping; vault key creation; HPKE wrap/unwrap;
  Ed25519 signing of membership and log segments; KDF calibration.
- `WatchwordEnvelope`: full encoder/decoder with AAD binding and version/kind/key checks.
- Exit: known-answer tests for every primitive, property tests for round-trips, adversarial tests
  for tamper/swap/replay/downgrade, KDF calibration test (≥300 ms on CI hardware is informational).

Status: delivered as specified, with these scoping notes.
- Signing is delivered as domain-separated primitives (`SignatureDomain.membership`, `.logSegment`).
  The membership-record and log-segment *formats* that use them belong to milestones 4 and 3.
- Replay of a record's *older* version is rejected by the sync layer's monotonic check
  (milestone 3); milestone 1 binds the version into the AAD so an old ciphertext cannot be
  presented as a newer one.
- `VaultKeyGrant` has no persisted encoding yet; it arrives with the membership records it travels
  in (milestone 4).
- Secure Enclave wrapping of the Secret Key is part of the Keychain adapter (milestone 2).
- Crypto tests need CryptoKit and run on the macOS CI matrix; the files are wrapped in
  `#if canImport(CryptoKit)` so the package still builds and tests on Linux.

## Milestone 2 — Local vault and unlock (done)

- `WatchwordStore` (SQLite ciphertext store in the App Group), `WatchwordKit.VaultSession`
  (create account, unlock, lock, CRUD items, history, trash), `UnlockPolicy`, Keychain and
  LocalAuthentication adapters, Emergency Kit PDF generation.
- `Apps/`: XcodeGen project with iOS and macOS app targets and AutoFill extension targets; minimal
  SwiftUI screens: onboarding (password + Emergency Kit), unlock, item list/detail/edit.
- Exit: scenario tests S1–S4 pass against `VaultSession` with in-memory ports; XCUITest smoke test
  of onboarding and unlock on both platforms; on-device verification of QuickType behaviour with
  overlapping domain identities (document the result in `02-architecture.md` §9).
- Environment: **Mac with Xcode.** Everything new here is Apple-framework-bound — Keychain,
  LocalAuthentication, the App Group container, Emergency Kit PDF generation — and this is the
  milestone in which `Apps/` first exists, so `xcodebuild`, the simulators and the Xcode MCP server
  become usable (and necessary). A remote session can draft the `WatchwordStore` schema and the
  `VaultSession` state machine, but cannot run S1–S4: those need real keysets.

Status: delivered, with these scoping notes.
- Modules: `WatchwordStore` (port, `InMemoryRecordStore`, `SQLiteRecordStore`), `WatchwordKit`
  (`VaultSession`, `UnlockPolicy`, `AutoLockPolicy`, `ItemCodec`, `EmergencyKit`, the ports) and a
  new `WatchwordPlatform` (Keychain and LocalAuthentication adapters, Emergency Kit PDF). The
  adapters are in the package rather than `Apps/` so every CI gate covers them; the four
  pointer-typed system calls they need live in `SecureMemory` (ADR 0001, milestone 2 amendment).
- `Apps/project.yml` exists, so the `app-tests` job is live: iOS and macOS apps, AutoFill extension
  *shells* (they cancel every request; answering arrives with milestone 5), and one XCUITest smoke
  test of onboarding, the Emergency Kit confirmation, item creation, lock and unlock, run on both
  platforms with in-memory ports (`--uitest`, Debug builds only).
- S1–S4 pass against `VaultSession` with in-memory ports for everything a single person's vault can
  show: S1's fill decisions over items read back from the store, S2's passkey and recovery codes
  (marking a code used is a new version with history), S3's three security questions, S4's PIN and
  card number. The two-member halves of S3 and S4 need the membership chain (milestone 4).
- **Not done:** on-device verification of QuickType behaviour with overlapping domain identities.
  It needs a physical device with the extension publishing identities, which is milestone 5's
  work; it is carried there and stays open in `02-architecture.md` §16.
- Also deferred: the encrypted per-item index record (§5) to milestone 5, the `changelog` and
  `sync_state` tables and tombstones to milestone 3, device-to-device enrolment to milestone 3
  (Emergency Kit entry works now: `unlock(password:secretKey:)`), and the F11.7 add-a-mismatched-host
  confirmation UI to milestone 5, where the mismatch is first observable.
- Real Keychain round trips need an entitled, signed process; `swift test` and CI skip them
  (`errSecMissingEntitlement`) and check the query attributes instead. On a Mac,
  `mise run app:test-keychain --team <ID>` runs the round trip signed, in the app-hosted
  `WatchwordKeychainTests` bundle (a free Personal Team is enough; `04-test-plan.md` §6.2).

## Milestone 3 — Sync

- `WatchwordSync`: change-log segments, snapshots, Lamport merge, `SyncTransport` protocol,
  `InMemorySyncTransport` for tests.
- `CloudKitTransport` with `CKSyncEngine`; `FileTransport` for the iCloud Drive container and
  Files-app folders.
- Exit: multi-client simulation tests (N clients, random partitions, concurrent edits) converge;
  CloudKit integration test against a development container runs in a manually triggered
  workflow with repository secrets; transport contract tests prove no plaintext leaves the core.
- Environment: **split, and worth keeping that way.** The change-log segments, snapshots, Lamport
  merge, `InMemorySyncTransport` and the N-client partition simulation are pure logic and belong in a
  remote session — provided segment signing and record encryption reach them through a port with a
  fake, so nothing in `WatchwordSync` imports CryptoKit. `CloudKitTransport` and the iCloud Drive
  `FileTransport` are Mac-only, as is the manually triggered CloudKit integration workflow.

Status: **portable half delivered** from a remote session, as the split above intended; the Mac half is open.

- Delivered (`WatchwordSync`, verified by `swift test` on Linux): the object layout and names; the `SyncTransport`
  port with `InMemorySyncTransport` and `FileSyncTransport` (a plain directory: create-once by hard link, no
  symbolic links followed, sizes capped); signed, sealed segments and snapshots with a bounded canonical parser;
  the `SyncKeyring`, `RecordMerger` and `SyncStateStore` ports; conflict-keeping merging (`ItemMerge`: a
  multi-value register per field with version vectors, concurrent values kept in `Item.conflicts` until resolved,
  notes merged line by line by `NoteText`; PRD F7.6, F7.7); and `SyncEngine` — download while locked, in-order merge
  that never skips a gap, explicit deletions whose erasure summary removes only what their author had seen
  (`DeletionRecordingStore`), publishing, snapshot election, garbage collection, a quarantine that keeps what it
  refuses, and reconciliation against local rollback. Supporting changes: `StoreChange.expectations` (compare-and-swap
  commits) and envelope kind 5, `snapshot`. Architecture §7.5 describes it.
- Exit criteria: the N-client simulation (random partitions, an eventually consistent server that delays,
  reorders and duplicates, concurrent edits and deletions, devices locking) converges, a device joining afterwards
  from snapshots sees the same vault, and no title or secret reaches the transport — every push, and 2,500-step
  five-device runs nightly. It also checks that no field value any device saved is lost, and models a stray object
  and rolled-back sync state. It found three convergence bugs (`06-adversarial-review.md` §H, Y1–Y3); an independent
  review found six more (Y8–Y13); each now has a regression test that reproduced it. The suite "Simultaneous edits
  across devices" covers the everyday cases end to end: separate fields, separate items, a long note edited in
  different places and on the same line, one field edited on three devices, trash or permanent delete against a
  concurrent edit. The transport contract runs against both transports. The CloudKit
  integration workflow is not built.
- Adversarial suite "sync log" (A1, insider and former devices, A8): byte flips anywhere, moved and replayed
  objects, withheld segments, forgeries, record swaps inside a validly signed segment, versions for another device
  or vault, implausible versions (U5), stale snapshots, local rollback, tampered staging, parser mutations and
  planted symbolic links. Signatures and encryption are fakes there; real primitives are the crypto core suite's.
- **Mac half, not done:** the production `SyncKeyring` (vault keys and `RecordCipher` for segments, the account
  Ed25519 key, later the device key) and `RecordMerger` in `VaultSession` (`merge`, `erasureSummary`,
  `resolveErasure`, sealing results through `ItemMerge.written`), with `VaultSession.write` stamping every save
  through `ItemMerge.stamped` (ignoring the caller's sync metadata) and writing through `DeletionRecordingStore`; a
  conflict UI over `ItemMerge.conflicts` and `ItemMerge.resolve`, and listing the quarantine for the person to
  discard; `sync_state`/staging tables
  in `SQLiteRecordStore`; device enrolment from the account header on the transport; `CloudKitTransport` and the
  coordinated iCloud Drive wrapper around `FileSyncTransport`; the manual CloudKit workflow; and the adversarial
  tests repeated with real keys. The device registry (D9) must land before sync ships.

## Milestone 4 — Sharing

- `WatchwordSharing`: membership chain, invitations, fingerprints, rotation on removal/leave,
  read-only enforcement in the client; CloudKit `CKShare` and `UICloudSharingController`/
  `NSSharingService` integration; folder-share flow for the file transport.
- Exit: S3 and S4 pass end-to-end with two simulated users over `InMemorySyncTransport` and over
  CloudKit (manual workflow); adversarial tests for forged membership, stale-admin signatures,
  key substitution by the server, and post-revocation access.
- Environment: **Mac.** Membership records are Ed25519-signed and wrap vault keys with HPKE, so even
  the chain-walking logic cannot be tested on Linux; the adversarial tests named above — forged
  membership, stale-admin signatures, key substitution, post-revocation access — are precisely the
  ones that need real primitives rather than fakes. `CKShare` and the sharing controllers add the UI
  half.

## Milestone 5 — AutoFill

- `AutoFillExtension` targets for iOS and macOS: credential list, passwords, passkey registration
  and assertion (with `prf`), one-time codes (iOS 18+/macOS 15+), text to insert, save-password
  and generate-password requests, credential-update reports; identity publishing to
  `ASCredentialIdentityStore` with ranks from `WatchwordMatching`.
- Exit: extension view-model tests cover every request type with fakes; manual AutoFill QA
  checklist executed on device for S1 and S2; best-effort XCUITest that enables the provider in
  Settings on the simulator runs as a non-blocking job.
- Environment: **Mac with Xcode, plus a physical device.** The strongest Mac case of the nine: every
  request type is an AuthenticationServices entry point, the targets are app extensions, and the exit
  criteria name simulator and on-device QA. This is the milestone the Xcode MCP server exists for.

## Milestone 6 — Hygiene

- `WatchwordHygiene`: HIBP range client with padding, caching and lenient parsing; scheduling;
  zxcvbn-class estimator (vendored); reuse/age/2FA checks; Watchtower-style report UI.
- Exit: HIBP client tests against recorded fixtures including padded and malformed responses;
  scheduling tests with a fake clock; UI report snapshot tests.
- Environment: **mostly remote/Linux.** The HIBP range client (recorded fixtures, no live calls, so
  nothing to add to a session allowlist), the scheduler against `FakeClock`, the vendored estimator
  and the reuse/age/2FA checks are all portable; add `import FoundationNetworking` under
  `#if canImport` where URLSession needs it on Linux. Only the report UI and its snapshot tests need
  a Mac.

## Milestone 7 — Interchange

- `WatchwordInterchange`: 1PUX, 1Password CSV, Apple CSV, CXF import/export; Credential Exchange
  integration on iOS 26/macOS 26; encrypted Watchword archive; in-app instructions.
- Exit: fixture-based round-trip tests; adversarial parser tests (zip-slip, bomb, formula
  injection, oversized rows); fuzz targets registered in the nightly workflow.
- Environment: **mostly remote/Linux, and the better fuzzing host.** The parsers and their
  adversarial tests (zip-slip, bomb, formula injection, oversized rows) are pure, and libFuzzer with
  the sanitisers on Linux x86\_64 is more comfortable than the macOS nightly leg — so keep the `Fuzz/`
  harnesses free of Apple imports and either host can run them. Credential Exchange on iOS 26/macOS
  26 and the encrypted Watchword archive (crypto) are Mac-only.

## Milestone 8 — Hardening and release

- External review of `WatchwordCrypto`, `WatchwordEnvelope`, `WatchwordSharing`.
- Performance (N1, N2) and accessibility (N4) passes; App Store privacy manifest; TestFlight.
- Environment: **Mac.** The external crypto review reads source anywhere, but the performance (N1,
  N2) and accessibility (N4) passes measure a running app, and the privacy manifest and TestFlight
  submission go through Xcode and App Store Connect.

## Working agreements

- Every pull request that touches `WatchwordCrypto`, `WatchwordEnvelope`, `WatchwordSharing`,
  `SecureMemory`, or any adapter for Keychain/LocalAuthentication must add or update an adversarial
  test and must be reviewed by a second person.
- No new third-party dependency without an ADR.
- `docs/` is updated in the same pull request as the behaviour it describes.
