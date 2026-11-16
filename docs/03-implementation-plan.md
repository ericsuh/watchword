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
| 1 — cryptographic core (done) | Yes since ADR 0006: every crypto suite runs, against swift-crypto's BoringSSL | The implementation that ships (CryptoKit, CommonCrypto), Security.framework |
| 2 — local vault and unlock (done) | No | Keychain, LocalAuthentication, App Group container, PDF generation, the `Apps/` project, XCUITest, on-device QuickType |
| 3 — sync (portable half and vault side done) | The change log, Lamport merge and multi-client simulation — done, with signing and encryption behind a port | done: the production keyring in `VaultSession`, SQLite sync state, the conflict UI and its XCUITest; open: `CloudKitTransport`/`CKSyncEngine`, the iCloud Drive container, the manual CloudKit workflow |
| 4 — sharing (protocol core done) | The protocol core — membership chain, verified contacts, invitations, key grants, rotation plans — with real Ed25519 and HPKE through swift-crypto (ADR 0006), and its adversarial suite | the implementation that ships (CryptoKit); wiring into `VaultSession` and sync; `CKShare`, `UICloudSharingController`/`NSSharingService`, the folder-share flow; the sharing UI |
| 5 — AutoFill (portable core done) | The request model, TOTP, the passkey authenticator and identity planning — done, behind a vault port with fakes | AuthenticationServices, app-extension targets, `VaultSession`'s conformance, simulator and device QA |
| 6 — hygiene (portable core done) | HIBP clients, scheduling, strength estimator, reuse/age/2FA checks, the report and `HygieneEngine` — done | open: the `URLSession` adapter, the wiring into `VaultSession`, background-task glue, the Watchtower-style report UI and its snapshot tests |
| 7 — interchange | Parsers, adversarial parser tests, and the fuzz targets — a better host for them | Credential Exchange on iOS 26/macOS 26, the encrypted Watchword archive |
| 8 — hardening and release | Reading the source for external review | performance and accessibility passes, privacy manifest, TestFlight |

Four rules this split implies, all of which outlive the milestones they came from:

1. **A remote session can draft Apple-framework code; it cannot verify it.** Pair such a session with
   a Mac one that runs the suites before the pull request opens. The adversarial-test obligation in
   the working agreements below is discharged on the Mac, not in the session that wrote the test.
2. **`#if canImport(…)` fails silently.** On Linux a guarded suite is *absent*, not red: `swift test` goes green
   with whole files never compiled. Since ADR 0006 the crypto core, `VaultSession` and their suites have no guard and
   build there against swift-crypto; the SQLite store, the Keychain and the PDF still compile out. Count tests rather than
   reading the exit code, and treat Linux green as a signal, never as the gate (`09-cloud-sessions.md` §4).
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
- Crypto tests need CryptoKit and run on the macOS CI matrix; since ADR 0006 they also run on Linux against
  swift-crypto, which is evidence about the logic and not about the implementation that ships.

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

Status: **portable half delivered** from a remote session, as the split above intended; **the vault side of the Mac
half delivered** on a Mac; the transports are open.

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
- **Vault side, delivered (Mac):** `VaultSession` is the production `SyncKeyring` and `ItemSealer` (AES-GCM under the
  vault key; the account's Ed25519 key over the object's name and envelope, checked while locked against a Keychain
  copy of the public key) and runs `SyncEngine` from `sync()`; the merger is `ItemRecordMerger`, moved into
  `WatchwordSync` so the app and the simulations share it. Every save is stamped through `ItemMerge.stamped`,
  ignoring the caller's sync metadata, and committed conditionally on the row it read; the session's deletions go
  through `DeletionRecordingStore`. `resolveConflict`, `quarantinedVersions` and `discardQuarantined` are the
  person's side of F7.6 and F7.7. `SQLiteSyncStateStore` persists the state in `sync.sqlite` beside the record store.
  The app has Sync Now in Settings, a conflict badge in the list and a conflict section in the item detail;
  `SyncConflictTests` (XCUITest, iOS simulator and macOS) renames one item on two devices — the second is `UITestPeer`,
  an in-process session of the same account — and resolves the conflict through the UI. Architecture §7.6 describes
  it. Tests: suite "Vault session: sync between devices" (two real sessions: round trip, ciphertext only, conflict
  and resolution, locked download, deletion against an unseen edit, the purge, SQLite across a relaunch), "Sync state
  store contract" over both stores, and the adversarial suite "sync with real keys" (byte flips, a foreign signer,
  moved objects, an insider's record swap, a missing Keychain key, the adapter after lock).
- **Still open (Mac):** `CloudKitTransport` and the coordinated iCloud Drive wrapper around `FileSyncTransport`, and
  with them sync in production builds (until then the app is built without `SyncSettings`) and automatic syncing;
  the manual CloudKit workflow; device enrolment from the account header on the transport (tests and `UITestPeer`
  copy the account header, vault-key wraps and Secret Key directly); a quarantine list in the UI; and item history in
  records of its own, so the never-pruned history (F1.4) no longer counts against an item's 1 MiB payload. The device
  registry (D9) must land before sync ships.

## Milestone 4 — Sharing (protocol core done; integration open)

- `WatchwordSharing`: membership chain, invitations, fingerprints, rotation on removal/leave,
  read-only enforcement in the client; CloudKit `CKShare` and `UICloudSharingController`/
  `NSSharingService` integration; folder-share flow for the file transport.
- Exit: S3 and S4 pass end-to-end with two simulated users over `InMemorySyncTransport` and over
  CloudKit (manual workflow); adversarial tests for forged membership, stale-admin signatures,
  key substitution by the server, and post-revocation access.
- Environment: the protocol core was built and tested on **Linux**, which ADR 0006 made possible after this plan
  was first written: Ed25519 and HPKE run there through swift-crypto, so the chain-walking logic and the adversarial
  tests use real primitives, not fakes. Everything else is **Mac**: CryptoKit (the implementation that ships),
  `CKShare`, the sharing controllers and the UI.

**Delivered: the protocol core** (`02-architecture.md` §8), in `WatchwordSharing`, depending only on
`WatchwordEnvelope`, `WatchwordCrypto` and `SecureMemory`:

- the membership chain: `MembershipRecord` (canonical binary, bounded parser), `MembershipRules` (who may sign what),
  `MembershipLedger` (verification from the pinned owner and the records already held; a grow-only tree of valid
  records with the accepted chain a deterministic function of it, so concurrent administrators and any order of
  arrival settle the same way everywhere; removals that lose a fork owed and carried out again; proposal status;
  signed persistence), `writePermission` and `writeStanding` (F4.5): whether an account may write now, and which of
  its writes count once it may not, by the **write cut** that the record ending its permission carries, the same on
  every device;
- fingerprint verification: the typed safety number and the scannable `FingerprintCode`, `VerifiedContacts` (signed
  pins behind the `VerifiedContactStore` port), the `KeyBundleDirectory` port, and both sides of an invitation
  (`OutgoingInvitation`, `IncomingInvitation`) as state machines that cannot wrap or accept a key before the
  fingerprint is confirmed (F4.1, F4.2), and `MemberKeyCheck`, the comparison of a chain's member keys with the
  pins that anything wrapping a key must present;
- key grants: `KeyGrantCodec`, and `MembershipLedger.grantSender`/`openGrant`, which accept a grant only from the
  account the chain entitles;
- removal, leaving and rotation: `RotationPlanner`, `RotationPlan` (data, signed, resumable), `LeaveRequest`,
  `PendingRotation` (F4.3, F4.4), and `recordsToReseal`; the per-item-keys question decided against (ADR 0007,
  closing D10);
- tests: unit suites for every encoding and transition, known answers from an independent Python implementation,
  the two- and three-member simulation over a hostile store (`SharingScenarioTests`: S3 and S4 at the protocol
  level), and the adversarial area "sharing and membership" (`04-test-plan.md` §6.4). Reviewed three times:
  `06-adversarial-review.md` §I (S1 to S16 by the author, S17 to S27 from independent reviews, S28 from the final
  verification and S29 to S31 from the work on it, each fixed with a regression test or recorded as accepted).

Verified on Linux only (swift-crypto over BoringSSL). A macOS run against CryptoKit is still owed; the one place
the two are known to differ, randomised Ed25519 signing, is why bundles are compared by key rather than by value.

**Still open:**

- Integration into `VaultSession`: a ledger, keys, at most one rotation plan and the pending proposals per shared
  vault; the sync pass of `02-architecture.md` §8.8 during `sync()` (`SimulatedMember` is its reference);
  `writeStanding(of:)` and the member's signing key from the ledger in `SyncKeyring.verify`; **the write cut over
  sync's own objects** (`02-architecture.md` §8.8: bound to segments by digest, applied to each value's own author
  through its `GroupStamp` and the device registry, and taken out of what was already merged; until this exists,
  review finding S28 is closed in the module and open in the product); re-sealing through `ItemMerge.written`;
  SQLite adapters for
  `VerifiedContactStore`, the saved ledger, the saved plan and the pending proposals. It depends on the session holding more than one vault
  and on the device registry (D9), which is why this milestone stopped at the protocol.
- The transports' own sharing: `CKShare` with `UICloudSharingController`/`NSSharingService`, the folder-share flow
  for the file transport, and the key directory's adapter (the account record).
- The sharing UI: invitation and fingerprint screens (safety number, QR display and scan), the member list with
  unverified members shown as such (D17), "pending rotation" (F4.3), and the wording F4.3 and F4.5 require.
- Scenarios S3 and S4 end to end through `VaultSession` over `InMemorySyncTransport`, and the manual CloudKit run.

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
- Status: **the portable core is delivered** (`WatchwordAutoFill`, `02-architecture.md` §9.2), which moved
  everything but the adapter off the Mac (rule 3 above): `CredentialProviderModel` answers every request type
  through the `CredentialVault` port, with `TOTP`, `PasskeyAuthenticator` (registration, assertion, `prf`,
  `largeBlob`), `PasswordRules`, and `CredentialIdentityPlanner` with the `CredentialIdentityPublisher` port.
  The first exit criterion is met on Linux: `WatchwordAutoFillTests` covers every request type with
  `FakeCredentialVault`, S1 and S2 run through the model, and the adversarial area "AutoFill request model"
  attacks every request type. That is against swift-crypto's P-256 and HMAC; the macOS matrix runs the same
  suites against CryptoKit, and until a run there passes the module is verified on Linux only.
- Still open, all needing a Mac:
  - the `AutoFillExtension` targets: an `ASCredentialProviderViewController` that converts each request to
    the model's value types, shows what the outcome describes, and returns what it carries, plus the
    `ASCredentialIdentityStore` adapter for `CredentialIdentityPublisher`. No security decision belongs in
    it;
  - `VaultSession`'s conformance to `CredentialVault` (`saveCredentialItem` as a compare-and-swap inside the
    actor's `write`, `isBackedUp` from whether sync is configured, `confirmUnlocked` as the actor's own lock
    check), and unlocking from the extension. When shared vaults arrive, an item ID present in two vaults is
    treated by the model as naming neither item, so a move between vaults must not leave both copies readable.
    `SessionCredentialVault` in `WatchwordAutoFillTests` is a stand-in over the session's public API that the
    S1 and S2 tests already run through; it shows the shape and is not atomic;
  - the encrypted index record, so the extension lists without decrypting every item;
  - on-device QA for S1 and S2, including three things only a device can answer. First, what the system
    hands back for a QuickType tap and on which hosts it offers a stored identity: the core assumes the
    stored identity with no page, offered anywhere under the registrable domain, and so publishes password
    and code identities only for whole-site scopes that nothing else shares or undercuts (`02-architecture.md`
    §9.1). If the system matches exact hosts, that rule can be relaxed; if it hands back the page, the gate
    can be asked. Then whether the system passes `prf` salts unhashed (the model applies WebAuthn's prefix
    hash), and how it treats a conditional registration with UP = 0;
  - an owner decision the review left open: with no host named, text insertion gives only fields that are not
    secrets, which narrows F6.4 (recovery codes, security answers and PINs insert only where the system names
    the host). `ManualChoice.isInsertable` is the one place to change it;
  - the UI tests in `04-test-plan.md` §6.7 ("no override affordance", the F11.7 confirmation in the app).

## Milestone 6 — Hygiene (portable core done)

- `WatchwordHygiene`: HIBP range client with padding, caching and lenient parsing; scheduling;
  zxcvbn-class estimator (vendored); reuse/age/2FA checks; Watchtower-style report UI.
- Exit: HIBP client tests against recorded fixtures including padded and malformed responses;
  scheduling tests with a fake clock; UI report snapshot tests.
- Environment: **mostly remote/Linux.** The HIBP range client (recorded fixtures, no live calls, so
  nothing to add to a session allowlist), the scheduler against `FakeClock`, the vendored estimator
  and the reuse/age/2FA checks are all portable; add `import FoundationNetworking` under
  `#if canImport` where URLSession needs it on Linux. Only the report UI and its snapshot tests need
  a Mac.

**Done** (`02-architecture.md` §13; all of it built and tested on Linux, none of it Apple-bound):

- `PwnedPasswordsClient` (five-character prefix, `Add-Padding`, `User-Agent`, bounded lenient parser,
  constant-time suffix comparison, typed retryable outcomes with bounded `Retry-After`), the `PwnedRangeCache`
  port with a 7-day expiry and `InMemoryPwnedRangeCache`, and `BreachedAccountClient` (F9.4, opt-in per call).
- `ScanSchedule` and `ScanLedger`: on create and edit, changed since the last scan, a weekly pass that
  resumes after a lock, nothing while keys are absent; token-bucket rate limit, jitter and backoff.
- `StrengthEstimator`, written here, with embedded word lists (`07-supply-chain.md` §2.2).
- `ReuseIndex` over HMAC tokens, password age, plain-`http` addresses, and the `SiteDirectory` seam with the
  opt-in `EmbeddedSiteDirectory` for two-step verification and passkeys (F11.8).
- `HygieneReport` and `HygieneEngine`, the actor the session will drive.
- The `HTTPClient` port, with `FakeHTTPClient` and `SimulatedPwnedPasswords` in `WatchwordTestSupport`.
- Tests: `WatchwordHygieneTests` and the adversarial suite "hygiene and breach checks" (`04-test-plan.md` §6.6).
- Hardened after the first security review (each with a regression test): the lock path (the prefix cache is
  emptied at lock, `unlock` is interruptible, pacing survives a lock), stale item copies, the estimator's cost on
  non-ASCII input and its rating of cheap patterns in a row, a failing range no longer stalling the scan, the
  report never calling a partly checked item clear, the breached-account parser's bound, and what prints.
  After the second: failed checks are remembered in the ledger, so a refused range no longer stalls the scan
  across locks and restarts either; a clock put back is waited out once, within the policy's bounds, not for
  the difference; a scan a lock interrupts pays for the requests it sent; and an unlock over an unlocked
  engine, failed or cancelled, leaves the prefix cache empty.
  The fixtures are written to the API's documented format; the live service is not reachable from a cloud
  session and is never called by a test.

**Open:**

- `URLSessionHTTPClient` in `WatchwordPlatform` (ephemeral, no redirects, size and time limits), and a
  capture of real range responses on a Mac to check the fixtures against.
- Wiring into `VaultSession`: the reuse key from `Ksym`, the ledger and the prefix cache as sealed local
  records, `update`/`scan` on save, `unlock`/`lock`.
- `BGProcessingTask` / `NSBackgroundActivityScheduler` glue that wakes the loop.
- The report UI, per-item badges in the item list, settings for the site directory and the HIBP API key, and
  the UI snapshot tests.
- The embedded EFF list came from a mirror (eff.org was unreachable); compare it with EFF's file before the
  generator draws passphrases from it, and keep one copy when the generator gains its own.

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
- A pull request that adds or changes a screen adds it to the screenshot tour (`04-test-plan.md` §5.1: one
  `Screens.capture` line in `ScreenshotTourTests`) and carries the `screenshots` label, so its screens are captured
  on both platforms and linked from the pull request for review by eye (`screenshots.yml`).
