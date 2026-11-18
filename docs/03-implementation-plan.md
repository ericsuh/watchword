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
| 3 — sync (portable half and vault side done) | The change log, Lamport merge and multi-client simulation — done, with signing and encryption behind a port; multiple vaults, the device registry, enrolment over the transport and the automatic sync policy — done, portable, against swift-crypto; the account screens' models (`WatchwordPresentation`) | done: the production keyring in `VaultSession`, SQLite sync state, the conflict UI and its XCUITest; drafted, not yet compiled on a Mac: `CloudKitTransport`, the coordinated iCloud Drive transport, the sync driver, and the vault, device and quarantine screens with their XCUITests; open: a macOS run of those and of everything the sync-core work added, `CKSyncEngine`, sync in production builds, the manual CloudKit workflow, the Secure Enclave device-key adapter |
| 4 — sharing (protocol core done) | The protocol core — membership chain, verified contacts, invitations, key grants, rotation plans — with real Ed25519 and HPKE through swift-crypto (ADR 0006), and its adversarial suite | the implementation that ships (CryptoKit); wiring into `VaultSession` and sync; `CKShare`, `UICloudSharingController`/`NSSharingService`, the folder-share flow; a macOS build of the sharing UI (written) |
| 5 — AutoFill (portable core done) | The request model, TOTP, the passkey authenticator and identity planning — done, behind a vault port with fakes | AuthenticationServices, app-extension targets, `VaultSession`'s conformance, simulator and device QA |
| 6 — hygiene (portable core done) | HIBP clients, scheduling, strength estimator, reuse/age/2FA checks, the report and `HygieneEngine` — done; the device-local file store, tested here too | drafted, not yet compiled on a Mac: the `URLSession` adapter and the report UI; open: a macOS run of them, configuring hygiene in the app, background-task glue, the report's snapshot tests |
| 7 — interchange (parsers, exporters, fuzz targets, session wiring and the encrypted archive done) | Parsers, adversarial parser tests, and the fuzz targets — a better host for them; the session wiring and the encrypted archive, portable through swift-crypto; done | open: Credential Exchange on iOS 26/macOS 26, a macOS build of the screens (written) and a device check of their file protection, and a macOS run of the archive against CryptoKit and CommonCrypto |
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
- Secure Enclave wrapping of the Secret Key was planned for the Keychain adapter (milestone 2) and was **not built**:
  the adapter stores the Secret Key as a Keychain item of class `WhenPasscodeSetThisDeviceOnly` and nothing more
  (`02-architecture.md` §4; review finding Z107). Open, with the Enclave device key of milestone 3.
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
  confirmation UI to milestone 5, where the mismatch is first observable. That confirmation is now built below
  the view (review finding Z61): `VaultSession.save(_:confirmingHosts:)` refuses a look-alike host the caller
  has not named, and `ItemEditorModel` asks; the editor's dialog is written but not yet compiled on a Mac. The
  assessment banner on revealing a secret (`05-anti-phishing.md` L6) is not built and stays open.
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
- **Audit of the merge as a CRDT, delivered** (remote session; `10-sync-correctness.md`, `06-adversarial-review.md`
  §H, Y18–Y30). The item merge is now an exact join on every component — field order included (a stored
  last-writer-wins register), and resolutions' discards (a version vector per group) — on any metadata, not only on
  honest devices'; a permanent deletion is one deterministic write to the versions it does not cover; and a record's
  metadata is bounded by the record's own version as it is read. Checked against the specification of a multi-value
  register under random histories, over every history of small configurations (counts asserted), and on arbitrary
  metadata (suite "sync log, item metadata"). Thirteen findings: ten fixed with regression tests, three outside the
  merge tracked with tests recorded as known issues or a named remedy — the engine must pass a tombstone's version to
  the merger (Y28, fixed when the sync-core work merged: the engine passes the joined erasure's stamp, and a record's
  erasures are joined as a set of deletions, `ItemErasures`), `VaultSession.save` must refuse a draft made from an
  older version (Y29), and the session should show items as the merge reads them (Y30); both fixed when the session
  integration merged (`versionConflict`; every read is `ItemMerge.canonical`).
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
- **Sync core, delivered (portable; written and run in a remote Linux session, against swift-crypto):**
  - *Multiple vaults* (F2.1–F2.3): vaults the account owns are created, renamed, listed and deleted, each with
    its own key wrapped under Ksym and a sealed description; items are listed per vault and across vaults,
    copied, and moved (a copy and the original trashed in one commit, then deleted like any permanent deletion);
    search runs over decrypted items in memory. `sync()` syncs every vault. Architecture §7.7.
  - *Account objects and enrolment* (F5.2, F10.2): the account header, the registry and a vault directory on the
    transport; `VaultSession.enrol` joins a second device from the transport, the password and the Secret Key
    alone; a password change is the account's and reaches every device. Tests enrol devices for real over
    `InMemorySyncTransport` (`TestVault.enrolledDevice`). Architecture §7.7.
  - *Device registry* (review findings D9, Y5, Y6): a device signing key behind the `DeviceKeyStore` port
    (software Ed25519 in the Keychain; P-256 verification in place), both signatures on everything written, a
    grow-only registry of signed entries with password changes as checkpoints, revocation with or without a
    password change, revoked devices retired from garbage collection and snapshot election. Architecture §7.8,
    which also states what revocation does not do.
  - *Automatic sync policy*: `AutoSyncPolicy`, pure and clock-injected. Architecture §7.9.
  - Tests: suites "Device keys and signatures", "Device registry", "Published account header" (crypto);
    "Automatic sync policy", "Account object names", "Sync engine: revoked devices" (sync); "Vault session:
    vaults", "…vaults across devices", "…enrolment from the transport (F5.2)", "…devices, revocation and
    password changes", "Multi-device vault simulation" (`LongRunningVaultSimulationTests`: real sessions,
    several vaults, moves, enrolment and a revocation mid-run; converges and loses nothing); the adversarial area
    "account enrolment and device registry", and more threats in "sync with real keys".
  - **Not verified on a Mac.** Everything above built and ran on Linux only; `SystemKeychainStore` gained two
    Keychain item names without being compiled, and `SQLiteSyncStateStore`/`SQLiteRecordStore` are unchanged but
    now hold new record kinds. Dispatch `mac-run.yml` before relying on it.
  - **`Apps/`:** `UITestPeer` now joins as any new device does, `VaultSession.enrol` with the Emergency Kit's setup
    code over the shared in-memory transport, after the app's session has synced once (`SyncConflictTests` does).
    The screens for vaults, devices, a changed password and revocation are below ("The account screens").
- **Transports and the sync driver, drafted (remote session; `WatchwordPlatform`, architecture §7.2, §7.3, §7.9).**
  Written on Linux, where only the portable parts compile: **none of the Apple code has been compiled or run yet.**
  - Portable, run on Linux: `SyncTransportError` gained `rateLimited(retryAfter:)`, `quotaExceeded`,
    `notAuthenticated`, `storeReset` and `conflictingVersions`, and `stopsSync`; the engine and the session stop a sync
    on each stopping error as they always did on `unavailable`, and the reports carry the reason
    (`transportFailure`); `AutoSyncPolicy.syncThrottled(retryAfter:)` lengthens the backoff to the wait asked, within
    its cap; `FileSyncTransport` exposes synchronous forms for coordinated callers and lists iCloud placeholders;
    the transport contract moved to `WatchwordTestSupport` (`SyncTransportContract`); `AutoSyncDriver`, the timer,
    with an injected clock. Tests: "Sync transport failures", "File sync transport: iCloud placeholders", "Automatic
    sync policy" (throttling), "Automatic sync driver".
  - Mac only: `CoordinatedFileSyncTransport` (file coordination, placeholders and evicted files, conflicts refused)
    with `SyncFolderPresenter`; `CloudKitTransport` (private database, custom zone, create-only saves, typed errors)
    over the `CloudKitDatabase` seam. Tests: "Coordinated iCloud Drive transport", "CloudKit transport" (the contract
    over a fake database with CloudKit's save-policy semantics; a real-container test only with
    `WATCHWORD_CLOUDKIT_CONTAINER` in a signed host), and the adversarial suites "Apple adapters: iCloud Drive
    transport" and "Apple adapters: CloudKit transport".
  - *After the adapters' review* (`06-adversarial-review.md` §P, AD1 to AD10): the sync outcome is read from every
    vault and shared vault, and one sync asks a stopped transport once (`transportStopped`); CloudKit never recreates a
    zone this device has seen (`SyncStoreMarker`), caps listings (`listingTooLarge`) and refuses one broken record alone
    (`objectUnreadable`); the coordinated transport gives up at a deadline and re-checks downloads inside the read;
    the HTTP client clamps its limits and sends minimal headers; the device-local store checks its whole path and
    never writes through a link. The first macOS run (Xcode 27) compiled the adapters and found two test faults (AD9,
    AD10), fixed. Linux tests: "Automatic sync outcome", "Sync transport failures", "Sync store marker", the
    device-local store's suites and "sync log"; the rest are Mac only.
  - **Decisions for the owner:** what to do with an iCloud Drive object that has conflict versions (refused today,
    so its stream waits for good) and with iCloud's `N 2.wwe` copy of a duplicate create (ignored): keeping "the copy
    that verifies" (§7.3) needs the engine; and the flow to start CloudKit again after a `storeReset`, which is also
    where the person's choice forgets the `SyncStoreMarker`.
  - **Before relying on any of it:** dispatch `mac-run.yml` (package tests, adversarial, strict) on the branch, then
    run the CloudKit test from a signed host against a development container (its schema needs `WWObject.name`
    queryable) and the coordinated transport in a real ubiquity container (downloads and evictions by iCloud itself
    are not exercised by any test).
- **The account screens, written (not yet built on a Mac):** the remaining UI of this milestone and of milestones 4,
  6 and 7, over portable view models in a new target, `WatchwordPresentation` (`02-architecture.md` §15), whose
  logic `WatchwordPresentationTests` runs on Linux against real sessions. Settings opens each screen in a sheet of
  its own: **Vaults** (list, create, rename, a vault filter in the item list, and for a shared vault its role and a
  read-only banner, including "update Watchword" for one gone on in a later format); **Devices** (the list,
  removal with a new password by default or, with both statements confirmed, keeping it; a sync status with
  `requiresNewerVersion` as "update the app" and `snapshotWithheldBy` naming the devices); a password changed on
  another device is a notice after sync, and the unlock screen explains `passwordChangedOnAnotherDevice` and offers
  `ignoringPasswordChange` for the person who did not make the change; **Held-Aside Changes**, the quarantine
  (`VaultSession.quarantine()`, new: each version with its vault, so shared vaults' held-aside writes are listed
  first, as review finding S49 requires), discarded only through a confirmation. XCUITests: `DeviceRevocationTests`
  and `QuarantineTests` (`04-test-plan.md` §5), with `UITestPeer` able to join, change the password and write a
  version past the UI-test launch's version-jump ceiling of 16.
- **Still open (Mac):** sync in production builds (choosing a transport, enrolment and settings; until then the app is
  built without `SyncSettings`), with the app creating an `AutoSyncDriver` and registering for CloudKit pushes;
  `CKSyncEngine`, if its scheduling is wanted over the driver; re-uploading after a CloudKit reset (`storeReset` stops
  sync today); keeping the copy that verifies when iCloud Drive holds conflict versions (refused today); the manual
  CloudKit workflow; the Secure Enclave `DeviceKeyStore` adapter; a macOS build and run of the account screens and
  their XCUITests; and item history in records of its own, so the never-pruned history (F1.4) no longer counts
  against an item's 1 MiB payload.
- **Still open (design):** an account re-key — new keyset and Secret Key, vault keys rotated — which is what ends a
  revoked device's reading if it held the keyset (architecture §7.8, §16); it belongs with vault-key rotation in
  milestone 4. It is also the only cure for what a revoked device that kept the account key can still do to the
  other members of a shared vault: keep that member's devices in question (review finding Z6, architecture §8.10).
  Collecting a deleted vault's objects from the transport.
- **Still open, from the audit of 2026-11-17 (`06-adversarial-review.md` §Z, Z20 to Z29):** a Mac run of
  `SQLiteSyncStateStore` at schema version 3 (the indexed quarantine and its migration, Z27) and of the signed state
  row over real files (Z20); keying the record store by (vault, record, kind), with its migration, so that a record
  ID in one vault cannot collide with another's (Z22; the engine now confines a collision to the one entry); a skip
  the author signs and readers honour, for an unsigned object squatting at a device's next sequence number (Z24);
  refusing at download a segment that an ended account's cut cannot admit (Z27); an intent row in the record store's
  own transaction, for a crash between a deletion and its tombstone (Z28). From the review of those fixes (Z30 to
  Z39): a Mac run of `SQLiteSyncStateStore`'s paged migration, clamped sizes and capped digest rows, and of
  `SQLiteConnection.Failure` as a `StorageFailure` (Z39); signing the quarantine's rows and taking out a kept version
  once a version that supersedes it is merged (Z37), which want a column and an index in that schema; charging a
  snapshot's entries to the snapshot's author rather than to the device each names (Z38), which wants a column too;
  and, for a device that has never published in a vault, an unfetchable name in its stream still holds its publishing
  there (Z31).
- **Still open (views, after the audit of 2026-11-17):** choosing between pending password changes on the Devices
  screen (`DevicesModel.passwordChanges` and `follow`, over `pendingPasswordChanges` and `followPasswordChange`; the
  lock screen reports `tooManyPasswordChangesPending` and `passwordChangeRevokesThisDevice` in words, Z1 and Z8);
  showing a member their devices code and taking another member's (`DevicesModel.devicesCode`,
  `SharedVaultModel.verifyDevices`, over `memberDevicesCode` and `verifyMemberDevices`; the member list words the
  warning, Z6). The models are written and tested; no SwiftUI view uses them. Whether that code should instead be
  part of the safety number is ADR 0010's question.

## Milestone 4 — Sharing (protocol core and session integration done; transports and UI open)

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

**Delivered: the integration into `VaultSession` and `SyncEngine`** (`02-architecture.md` §8.10), on Linux: per shared
vault a ledger, keys from grants, at most one rotation plan, the pending proposals and a signed stream index, behind
the `SharingStateStore` and `VerifiedContactStore` ports (in memory, and `SQLiteSharingStore`, Mac-only and not yet
compiled); the sync pass of §8.8 inside `syncAll`; `SyncKeyring.verify` from the ledger's keys, `writeStanding` and the
members' device registries; the write cut over sync's own segments, applied value by value through each value's
revision and taken out of what was merged (S28 closed in the product); re-sealing through `ItemMerge.written`; the
session API a UI calls (verify, share, invite, accept, leave, change role, remove, rotate, status); `SyncEngine`
quarantining a version whose merge cannot be sealed (Y37); scenarios S3 and S4 through `VaultSession`s of different
accounts over `InMemorySyncTransport` (`SharedVaultScenarioTests`) and the adversarial suite "shared vaults through the
session" (a removed and a demoted member's late writes, a forged grant, objects swapped between vaults, a rotation
interrupted by `lock()`). The integration's review (`06-adversarial-review.md` §I, S36 to S43) found S28 still open
through stamps a writer chooses, the vault's description and erasures; values are now judged by their bytes against
the segment that carried them, descriptions by the write that chose them, and a replay rebuilds erasures. Key IDs
another vault holds are refused, member registries are anchored per vault, and a replay that is asked for is written
down. Note-line removals, discards and history entries name the write that made them and are judged like values
(S32, S43), and a version whose clock holds an edit outside a cut is held aside with it (S44), as is one claiming
edits a current member has not published (S46) and a tombstone whose erasure summary does either (S45).

**Still open:**

- A macOS run of all of it against CryptoKit, and of `SQLiteSharingStore` at all.
- Sharing state on a member's other devices (review finding S35): today each device accepts the invitation itself,
  and until it has, holds the vault closed and says so (Z41: the account's signed marker and the granted key's wrap
  tell it the vault is shared). Syncing the ledger and pins between an account's devices, signed by the account, is
  not built; nor is a screen flow of its own for "set up this shared vault here" (the vault's screen shows the
  invitation to paste into the accept screen).
- Sharing a vault whose log was compacted is refused (`historyCompacted`, Z42): values that survive only in a
  snapshot have no attribution in a shared vault. A rule for them (the owner account vouching for its own devices'
  pre-sharing values) is open, and is the owner's decision.
- An addition that loses a fork alone and is never replayed leaves its grant of the current key standing, unreported
  (Z43 covers the addition its branch went on to undo). A member who writes into a device's stream before that
  device's first segment in a vault takes the stream there (Z46, an insider's denial of service). A leaver's device
  cannot take itself off the transport's share (`ShareAccessControl` has no leave operation, Z45).
- An erasure summary claims what a late writer had seen when the deleting device had merged its version (S45), and a
  late version's claims about current members' future edits are carried on (S46).
- A member invited after a demotion with no rotation since holds aside what only vouching could attribute (S42):
  rotate on demotion, or before inviting, when the UI is built.
- The transports' own sharing: `CKShare` with `UICloudSharingController`/`NSSharingService`, the folder-share flow
  for the file transport (the `ShareAccessControl` port is the seam), and the key directory's adapter (the account
  record; `KeyBundleDirectory` is the port, `VaultSession.publicKeyBundle` what it publishes).
- The sharing UI is **written, not yet built on a Mac** (milestone 3's account screens above): share a vault,
  invite (name the account by ID or fingerprint code, compare the safety number by typing it, by the code, or by
  eye, choose a role, send the invitation as text), accept (paste, compare the owner's number, join), the member list
  with unverified members and changed keys shown as such (D17), roles changed and members removed as the rules
  allow, leave, rotate, "pending rotation" (F4.3), the held-aside count linking to the quarantine, and this
  account's own safety number with a QR code. A demotion to read-only is followed by a rotation (S42's way out).
  `VaultSharingTests` invites `UITestPeer`'s second account. Still open: scanning a QR code (camera), and the
  transports' own share sheets.
- The manual CloudKit run of S3 and S4.
- The screen that tells the person to update when a shared vault has gone on in a later format is **written**
  (the vault's banner and row, the item detail's read-only banner with Edit and Move to Trash disabled, and "update
  the app" in the sync status; `SharedVaultStatus.requiresNewerVersion`, `02-architecture.md` §8.10); not in the
  screenshot tour, since no session API makes a later-format record.

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
  - `VaultSession`'s conformance to `CredentialVault` is **done** (Linux; `02-architecture.md` §9.2): the
    compare-and-swap inside the actor's `write`, `isBackedUp` from whether sync is configured, `confirmUnlocked`
    as the actor's own lock check, one ID per item across vaults, and the extension unlocking through quick
    unlock or the password. S1 and S2 run through it ("Request model over a real vault session"), with the CAS,
    a lock between read and release, moves between vaults and the extension's unlock in "Vault session as the
    AutoFill vault". What remains is the extension process itself: building the session over the App Group
    store and the shared Keychain access group;
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
  - the UI tests in `04-test-plan.md` §6.7 ("no override affordance", the F11.7 confirmation in the app; the
    confirmation's logic is tested on Linux, `AdversarialItemEditorTests`, review finding Z61).

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

- `URLSessionHTTPClient` in `WatchwordPlatform` is **drafted, not yet compiled** (remote session, Darwin only;
  `02-architecture.md` §13.8): ephemeral, nothing stored, redirects refused, the decoded body cut at the limit, idle,
  resource and overall time limits, each clamped, `User-Agent: Watchword` by default and a fixed `Accept-Language`.
  Tests through a real `URLSession` with a URL-loading stub: "URLSession HTTP client" and the adversarial suite "Apple
  adapters: HTTP client" (oversized, stalled and dripping against an injected deadline, redirecting, clamped limits).
  Open: a passing Mac run; a compressed body expanding past the limit, which a stub cannot produce (URLSession decodes only what
  its own HTTP stack received); configuring hygiene in the app; and a capture of real range responses on a Mac to
  check the fixtures against.
- Wiring into `VaultSession` is **done** (Linux; `02-architecture.md` §13.8): the reuse key and the device-local
  key derived from `Ksym` under labels of their own, the ledger and the prefix cache as sealed per-device records
  in the `DeviceLocalStore` port, the engine updated on every commit and reconciled with the store before every
  query and after every sync, `unlock`/`lock` in that order around the keyset, and `runHygieneStep()` for the UI or
  a background task to drive. Tests: "Vault session: hygiene" and the adversarial suite "hygiene in the vault
  session". The file adapter, `FileDeviceLocalStore`, is **done** (portable apart from the backup flag and iOS
  protection class; run on Linux): App Group, excluded from backup, `completeUntilFirstUserAuthentication` on iOS,
  atomic writes, fail-closed reads. Tests: "Device-local file store" and the adversarial area "device-local store
  files" (A8's links, directories, huge and stray files). Still open: the app configuring hygiene with it, and a Mac
  run of the backup and protection checks.
- Breach results and scan times synced with the vault is **done** (Linux; owner decision 10, ADR 0005 amendment of
  2026-11-16, `02-architecture.md` §13.9): a `scanStatus` record beside each item, a join per device, results bound to
  each password under a vault-derived key, a synced "not found" only postponing this device's own check (within an
  interval, and 28 days in all) and never hiding a breach it saw. Tests: "Synced scan results", "Vault session:
  synced hygiene" and the adversarial suite "synced breach-check results". Not compiled or run on Apple platforms yet.
- `BGProcessingTask` / `NSBackgroundActivityScheduler` glue that wakes the loop.
- The report UI is **written, not yet built on a Mac**: breached, reused, weak and other findings in sections, a
  breach another device of the vault reported named as such (`ItemHygiene.breachSource`), and Check Now driving
  `runHygieneStep()` until the schedule is idle or asks for a wait longer than ten seconds. Production builds show
  it as not available until `URLSessionHTTPClient` and the file `DeviceLocalStore` exist; `--uitest` launches check
  against `UITestPwnedPasswords`, in process. Still open: per-item badges in the item list, settings for the site
  directory and the HIBP API key, and the UI snapshot tests (the screenshot tour's `security-report` is the
  picture for now).
- The embedded EFF list came from a mirror (eff.org was unreachable). **Verified** on 2026-11-16 against EFF's
  own file, https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt (downloaded that day; SHA-256
  `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`, identical to the mirror's; all 7,776 words
  equal, in order). Still open: keep one copy when the generator gains its own.

## Milestone 7 — Interchange (parsers, exporters and fuzz targets done)

- `WatchwordInterchange`: 1PUX, 1Password CSV, Apple CSV, CXF import/export; Credential Exchange
  integration on iOS 26/macOS 26; encrypted Watchword archive; in-app instructions.
- Exit: fixture-based round-trip tests; adversarial parser tests (zip-slip, bomb, formula-shaped
  values kept exact, oversized rows); fuzz targets registered in the nightly workflow.
- Environment: **mostly remote/Linux, and the better fuzzing host.** The parsers and their
  adversarial tests (zip-slip, bomb, formula-shaped values, oversized rows) are pure, and libFuzzer with
  the sanitisers on Linux x86\_64 is more comfortable than the macOS nightly leg — so keep the `Fuzz/`
  harnesses free of Apple imports and either host can run them. Credential Exchange on iOS 26/macOS
  26 and the encrypted Watchword archive (crypto) are Mac-only.
- Done, on Linux (`02-architecture.md` §14): the module with its hard limits; the ZIP reader, DEFLATE
  inflater and stored-only ZIP writer; the RFC 4180 reader and writer, exact in both directions (formula
  neutralisation removed by owner decision, 2026-11-16: the CSV is not for spreadsheets); the
  1Password 8, 1Password 7 and Apple Passwords CSV mappings and the Apple Passwords CSV export; 1PUX import
  and 1PUX-compatible export; CXF 1.0 import and export; the mapping into item drafts (injected identifiers,
  scopes only through the normaliser and the policy, one-time passwords through `OTPParameters`, passkeys
  through `PasskeyCredential`) with its report; duplicate detection; the instructions as data. Tests: fixtures
  and round trips for each format, DEFLATE vectors from Python's `zlib`, archives from Python's `zipfile`, the
  `import parsers` adversarial area, and the `Fuzz/` package with fourteen libFuzzer targets (fifteen with the
  archive's) and a seed
  corpus, run by `mise run fuzz` and the nightly workflow.
- Done after the first security review of the module (`02-architecture.md` §14): a merge never widens an
  existing item's scopes or adds to its sign-in fields without a per-host, per-field choice (`MergeChoices`);
  import-wide budgets for fields and for URL parsing, CSV rows streamed, a block budget in the inflater, and
  drafts measured as the vault will store them; URLs keep their text beside the scope and are written back
  on export; dates before 1970; saved-form text, mistyped values, CXF numbers, subtitles and Android apps no
  longer dropped in silence; export reports for unresolved sync values (which are now written), history,
  scope restrictions, archived state, tags and recovery-code marks; 1PUX export of email sign-in names and of
  remembered categories.
- Done after the second review: a merge adds no `url` field without a per-field choice either, an accepted
  URL is a website only where the item is scoped to its host, and merged fields drop the hints that speak
  for their entry (category, subtitle). The first fix had left a road open: a URL kept as text was merged
  as a field and then written by every exporter as a sign-in URL of the existing item. Exporters now write
  a sign-in URL only for a host the item is scoped to (or a URL no scope can come from), report the rest
  (`ExportWarning.websiteNotScoped`), and the CSV export no longer puts an arbitrary `url` field in its URL
  column. The `1pux`, `cxf` and `password-csv` fuzz targets check that an export, read back, names no host
  the items were not scoped to.
- Done on the owner's decisions of 2026-11-16: an imported `www` host also matches its apex (a further scope,
  same subdomain setting, through the policy, reported as `apexScopeAdded`; opt-out with
  `ImportOptions.matchApexOfWWWHosts`, which replaced the opt-in `stripsLeadingWWW`), and through the
  session: `previewImport` takes the options, `matchApexOfWWWHosts` on by default, and the preview lists each
  addition as `apexScopeAdded`.
- Done, on Linux, with the session wiring (`02-architecture.md` §14.1): import as preview then commit through
  `VaultSession` (drafts held inside the actor and dropped by `lock()`; every decision checked before anything is
  written; new items through `ItemMerge.stamped`, `ScopePolicy` and `commitItem`, keeping imported history and
  timestamps and none of a file's sync metadata; merges over the item as the write reads it, with only the
  person's `MergeChoices`); plaintext export (CSV, 1PUX, CXF) only with the account password re-verified in the
  same call, and the standing warning from `InterchangeGuide`; the encrypted Watchword archive (`AccountArchive`,
  envelope kind 9, wrapped under the archive passphrase and the Secret Key, ADR 0008), its export and import
  through the same preview and commit, `ArchivedItems` for its items, a known-answer vector and a whole archive
  from an independent Python implementation, the "encrypted Watchword archive" and "interchange through the
  session" adversarial areas, and an `archive` fuzz target with that archive as its seed. Every long step runs off
  the session's actor (`awayFromSession`), so a lock never waits for one: a plaintext file's parse, an archive's
  parse, derivation and decoding, and an export's password check and archive derivation. Not run on a Mac yet:
  the archive's PBKDF2 there is CommonCrypto's and its AES-GCM CryptoKit's.
- The import, export and restore screens are **written, not yet built on a Mac** (milestone 3's account screens):
  import as choose, review, commit, with a duplicate screen that needs a choice for every duplicate and, for a
  merge, names each host it would add (`DuplicateMatch.newHosts`) and shows each sign-in field (secrets hidden until
  shown) and URL with its own switch, all off (`MergeAdditions`, `MergeChoices`); export with the standing warning on
  screen for as long as it is open, the password asked for every time, and the `ExportReport` shown before the file
  is saved; the CSV exactly as stored; the restore screen showing `ImportPreview.archiveCreatedAt` first. The file
  is handed to the system's exporter with `completeUnlessOpen` set on iOS (not yet checked on a device).
  `ImportExportTests` covers both. Open: restoring an archive's vaults as vaults (today every archived item goes
  into the one vault the person chooses, naming the vault it came from); the OS Credential Exchange calls and the
  extension's Info.plist keys; the instruction screens; a CXF file export (the format names the exporting app's
  relying-party ID, its associated domain, which the app does not have yet). Before shipping: a check of the CXF and
  1PUX field names against the published
  formats and real exports from 1Password and Apple Passwords (the specifications were unreachable from the
  session that wrote the parsers), and of the 1PUX export against 1Password's importer. The nightly `fuzz`
  job runs on the macOS runner, whose toolchain may lack the libFuzzer runtime; the task then replays the
  seeds and mutates them blindly and says so, and a Linux leg is the way to get real fuzzing there.

## Milestone 8 — Hardening and release

- External review of `WatchwordCrypto`, `WatchwordEnvelope`, `WatchwordSharing`.
- Performance (N1, N2) and accessibility (N4) passes; App Store privacy manifest; TestFlight.
- Environment: **Mac.** The external crypto review reads source anywhere, but the performance (N1,
  N2) and accessibility (N4) passes measure a running app, and the privacy manifest and TestFlight
  submission go through Xcode and App Store Connect.

## Later (after the first release)

- **Ownership transfer of a shared vault** (owner decision, 2026-11-16: wanted, in a future version). The design is
  `02-architecture.md` §8.9: a `transferOwnership` record in a later `WWMR` format version, signed by the current
  owner and accepted by the new one; rules that read "the owner" as the owner of the state before each record; a fork
  rule that counts transfers first, then records signed by the owner of their time; an invitation that names the
  current owner. Already in place: devices on this version fail closed on a later-format record the owner signed
  (`MembershipLedger.continuesInLaterFormat`), so the first release with sharing is the minimum version a transfer
  can rely on. To do then: the operation and its acceptance, the rule and fork-rule changes with
  `LongRunningMembershipForkTests` extended to transfers, the invitation change, and the screens.

## Working agreements

- Every pull request that touches `WatchwordCrypto`, `WatchwordEnvelope`, `WatchwordSharing`,
  `SecureMemory`, or any adapter for Keychain/LocalAuthentication must add or update an adversarial
  test and must be reviewed by a second person.
- No new third-party dependency without an ADR.
- `docs/` is updated in the same pull request as the behaviour it describes.
- A pull request that adds or changes a screen adds it to the screenshot tour (`04-test-plan.md` §5.1: one
  `Screens.capture` line in `ScreenshotTourTests`) and carries the `screenshots` label, so its screens are captured
  on both platforms and linked from the pull request for review by eye (`screenshots.yml`).
