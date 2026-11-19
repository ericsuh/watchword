# Watchword — Test Plan

Version 0.1 (draft). The goal is that every security-related feature and user flow can be exercised
quickly in CI, without devices, and that the adversarial behaviour of each layer is tested
explicitly, not just its happy path.

## 1. Test pyramid and where each kind runs

| Layer | Framework | Runs where | Target time |
| --- | --- | --- | --- |
| Unit and property tests for pure modules | Swift Testing (parameterised tests, tags) | `swift test` on macOS runners, every push | < 2 min |
| Legacy-style and `XCTestCase`-based tests (measure blocks, expectations, UI tests) | XCTest | `swift test` (package) and `xcodebuild test` (apps) | < 5 min |
| Scenario / integration tests against `VaultSession` with in-memory ports | Swift Testing | `swift test`, every push | < 3 min |
| Multi-client sync and sharing simulations | Swift Testing | `swift test`, every push (short) + nightly (long, randomised) | 2 min / 30 min |
| Adversarial security suite | Swift Testing, suites named `Adversarial…`, tag `.adversarial` | dedicated CI job, every push | < 3 min |
| App UI tests | XCUITest | `xcodebuild test` on macOS and the iOS simulator, every pull request once `Apps/` exists | < 15 min |
| Real Keychain round trip | Swift Testing in an app-hosted unit-test bundle (`WatchwordKeychainTests`) | signed, locally on a Mac (`mise run app:test-keychain --team <ID>`); unentitled in CI, where it skips | < 1 min |
| CloudKit integration | Swift Testing against a development container ("CloudKit transport": the transport contract against the real private database) | a signed host with `WATCHWORD_CLOUDKIT_CONTAINER` set; skipped everywhere else, CI included. The manual `workflow_dispatch` with secrets is not built | < 10 min |
| Fuzzing of parsers and envelope decoder | libFuzzer via `swift build -sanitize=fuzzer` | nightly | 30 min |
| Manual QA checklist (AutoFill on device, Credential Exchange) | checklist in `docs/qa/` | before each TestFlight | — |

Both Swift Testing and XCTest live in the same package; `swift test` runs both (Apple documents
that a test target may contain both as long as a single test does not mix their APIs).

## 2. Architecture for testability

- **Ports and fakes.** Every effectful dependency is a protocol in the core with an in-memory fake
  in `WatchwordTestSupport`: `FakeKeychain` (simulates access-control prompts, enrolment change,
  device-only semantics), `FakeBiometricGate` (scripted success/failure/cancel), `FakeClock`,
  `SeededRandom` (deterministic CSPRNG stand-in for tests only; production uses the OS CSPRNG),
  `FakeHTTPClient` (records every request; scripted or `SimulatedPwnedPasswords` responses), `InMemorySyncTransport` (shared between simulated clients,
  supports partitions, reordering, duplication, and a "malicious server" mode that mutates or
  substitutes records), `FakeIdentityPublisher`.
- **Scenario builders.** `Scenario.household()` yields two simulated users, each with two devices,
  pre-seeded with the PRD scenarios S1–S4, so a test reads like the requirement.
- **One façade.** UI code calls `VaultSession`; tests call the same API. UI tests pass launch
  arguments (`--uitest --scenario S3 --fresh`) that make the app construct itself with fakes and a
  deterministic seed.
- **No sleeping.** Timers depend on `Clock`; tests advance time explicitly.
- **Extension logic without the extension.** `AutoFillRequestHandler` takes a decoded request
  value and returns a response value; the real `ASCredentialProviderViewController` is a thin shell.

## 3. Coverage obligations by requirement

| Requirement | Tests |
| --- | --- |
| F1.x items/fields | Codable round trips; property test "any item survives encode→decode"; history kept whatever its age or length, with `FakeClock`, and an edit past the payload limit refused rather than pruned; `WatchwordModelTests`: "Binary text encodings", "OTP parameters" (the canonical `otpauth` URI round trip, issuers and accounts containing a colon included), "Passkey credential field", "Byte-exact equality of item values", "Sync metadata as stored" |
| F3.x generator | Parameterised tests over all knob combinations; statistical uniformity test (chi-square over 100k samples, seeded); entropy formula tests; site-rule mapping tests |
| F4.2 checking a contact (ADR 0010) | `WatchwordSharingTests` "Vault sharing codes" (typed and scanned input parsed exactly, every board message at its one length, the commitment and codes against Python `hashlib`, the whole transcript and both codes against `hashlib` (`transcriptKnownAnswer`, V30), the transcript binding every input and ignoring a re-signed bundle, an honest session, a scan each way, the invitation inside a session); "Fingerprint verification and invitations" (`reservedMethodIsNoPin`: a pin carrying the removed "compared by eye" is no pin). `WatchwordKitTests` "Vault sharing codes through VaultSession" (pins both ways, the invitation through the session joins the vault, a scan each way, a lock ends the session, no board, a malformed number). `WatchwordPresentationTests` "Screen models: sharing" (`inviteBySharingCode`, `memberVerification`, `memberCheckAgainstTheListedKeys` (V24), `screensDoNotShareASession` (V25), `checkTheOwnerThenJoin` (V27), the fallback by full code, and `fallbackShowsOnlyOwnDigits`: the fallback shows this device's own code and none of the directory's, V17) and the wording tests. Adversarial: "sharing and membership" (`AdversarialSharingCodeTests.swift`) and "shared vaults through the session" (`AdversarialSharedVaultSharingCodeTests.swift`), §6.4. Fuzz: `sharing-code`. UI: `VaultSharingTests`. Manual: `camera-scanning.md`, `vault-sharing-code.md` |
| F4.x sharing | Scenario S3/S4 over `InMemorySyncTransport`; revoke then verify former member cannot decrypt new versions and remaining members can; read-only client refuses writes (protocol core, milestone 4, `WatchwordSharingTests`: "Membership record format", "Sharing formats: known answers", "Membership chain rules", "Membership ledger", "Fingerprint verification and invitations", "Key grants and rotation", and "Shared vault simulation" — two and three members with real keysets over a hostile store: create, invite, verify, accept, write, role change, removal with rotation, leaving, an interrupted rotation, concurrent administrators, deletion; through `VaultSession`s of different accounts over `InMemorySyncTransport`: `WatchwordKitTests` "Shared vaults through VaultSession", S3 and S4 with invitation, verification, read-only refusal, promotion, removal with rotation; over CloudKit: open) |
| F4.7 renaming a shared vault | `WatchwordSharingTests` "Key grants and rotation": which of an account's descriptions count along a chain (all, the cut that ended the role, none), and a cut required exactly where a permission or an administrator's role ends. `WatchwordKitTests` "Shared vaults through VaultSession": `renamingASharedVault` (the typed refusal before anything is sealed, the owner's and an administrator's renames on every device, the member's own vaults unaffected, the role deciding in both directions, a rename made before the device heard of its demotion never published). `WatchwordPresentationTests` "Screen models: sharing": `whoMayRename`. Adversarial: "shared vaults through the session" (`AdversarialSharedVaultRenameTests.swift`) and "sharing and membership" (`administratorStandingFollowsTheOwnersRecord`), below. The view's control (`VaultsView`): not built here |
| F5.x unlock | `UnlockPolicy` table tests for every expiry reason; `FakeKeychain` enrolment change invalidates quick unlock; lock zeroises (inspect `SecureBytes`) |
| F5.1 Emergency Kit | `WatchwordKitTests`: "Vault session: account and unlock" (the kit again, with the password, and not while locked); "Adversarial: unlock and quick unlock" ("a quick-unlocked session cannot read the Emergency Kit without the account password", Z86); `WatchwordPresentationTests`: "Screen models: Emergency Kit and revealed secrets" (the password asked for from Settings, the PDF staged in the swept folder and removed after the save and on lock, Z84); "Emergency Kit PDF" (*Mac only*: the page, the QR code, `write`, the storage line). Manual, on a device: save the kit, cancel once and complete once, and list the container's `tmp/` and `Library/Caches` for a PDF |
| F5.7 screen privacy | What is promised: entry fields are `SecureField`; the iOS app-switcher snapshot is covered (`PrivacyShield`); every revealed secret (item fields, conflict and merge values, the Secret Key) is hidden again when the app resigns active and when the screen starts to be captured, and none can be revealed while it is (`ScreenPrivacy`, `RevealedSecrets`, Z95: "Screen models: Emergency Kit and revealed secrets"); macOS windows are excluded from screen capture (`sharingType = .none`); they stay restorable (Z96, tracked: marking them non-restorable made the next launch open no window). Not promised: anything against a camera, or a capture iOS does not report. *Mac only*, not automated: start a screen recording on a device, reveal a password, and play it back (the value must be hidden as the recording starts); share a Mac window in a call (it must show blank). A Debug `--uitest` launch keeps macOS windows capturable and does not hide on resign-active, so the UI tests and the screenshot tour can see them |
| F5.x Password AutoFill on the app's own fields | Manual, on an iPhone signed in to iCloud Keychain with AutoFill on (Z97): create an account, lock, unlock, then edit an item and save. The check is whether iOS offers the QuickType Passwords key over the account-password field or the item's password field, and whether a "Save Password?" sheet appears afterwards. If either does, try `.textContentType(.oneTimeCode)` on those fields and repeat; record the outcome in `docs/06-adversarial-review.md` Z97 |
| F6.x AutoFill | `HostMatcher` tests (S1), IDN/userinfo/port edge cases, and "Public suffix: the broadest site of a host" (the site a QuickType identity is assumed to reach); request-handler tests per request kind; identity publishing diff tests (`WatchwordAutoFillTests`: "One-time codes (TOTP)" — every vector of RFC 6238 appendix B and RFC 4226 appendix D —, "Passkey authenticator" — known answers from an independent Python implementation for the COSE key, authenticator data, attestation object and `prf`, and a signature that implementation verified —, "Site password rules", "Credential identity publishing", "Request model: credential list and passwords", "… one-time codes and text to insert", "… passkeys", "… saving and generating passwords", "… credential-update reports", "… pages loaded over plain http" (F6.9: every list, release, save and generate request refused for an `http` URL, by choice too; `https` pages and domains unchanged; identities unaffected, and an `http` URL in an identity's place refused), "Scenarios S1 and S2 through the request model", "Request model over a real vault session" — S1 and S2 again over a `VaultSession` as the model's `CredentialVault` —, and "Vault session as the AutoFill vault" in `WatchwordKitTests` — the compare-and-swap, including a save landing between the session's read and its commit, a lock between the model's read and its release, one ID per item across vaults after a move, `isBackedUp`, and the extension's quick unlock; milestone 5) |
| F7.x sync | Convergence under random schedules; offline edits; snapshot GC; locked-device download-only (`WatchwordSyncTests`: "Multi-device sync simulation" — convergence and no lost value —, "Simultaneous edits across devices" — separate fields, separate items, a long note, the same line, one field on three devices, trash or delete against an edit (F7.6), and which trash the 30-day purge may remove (F1.5, F7.7) —, "Sync engine", "Field-level item merge", "Item merge audit regressions", "Item merge laws under random histories" and "Item merge, every small history" — the merge as a CRDT (`10-sync-correctness.md` §7): the specification of a multi-value register at every step, the semilattice laws on whole items, every update inflationary, the same versions in any order with repeats, convergence and nothing typed lost, with the number of histories explored asserted —, "Sync review regressions", "Sync payload format", "Sync transport contract", "Sync state store contract", "SQLite sync state store", "Sync state encoding"; record kinds a device does not know (ADR 0009, N7): "Record kinds a device does not know" — an earlier version merges items past results it cannot read, keeps them byte for byte, acknowledges, writes no snapshot while it holds them so collection loses nothing for a later-version newcomer, and processes them after an upgrade without downloading again, from segments and from snapshots; a critical kind stops the stream at its segment or snapshot, skips nothing, sets `requiresNewerVersion` and stays staged; past the stash's cap entries are dropped, the stream still merges and the upgrade replays the log —, "Unknown record kinds in the payload", "Record kind criticality" (every kind's raw value in the range of its intended criticality), "Sync stash encoding" (round trip, truncations, planted rows) and the state store contract's stash row; in "Record kinds a device does not know" also a revoked device's own entries across a replay, a superseded snapshot entry not kept, a covered critical segment passed without a stop, and an unsaved stash rebuilt; "Record kinds a device does not know, in a shared vault" — a held-aside segment keeps nothing aside, a revoked device's kept tombstone is held aside while its versions are judged as usual, and a replay neither drops a revoked device's kept versions nor processes any kept entry twice; "Record kinds a device does not know: the stash under review" — another carrier's attribution suppresses nothing, crowded-out entries are blamed on nobody and come back once room is freed, a stash row of another generation is rebuilt; "Sync stash encoding" also a row of 8,192 entries in one slot parsed in time and over-cap rows refused from their header; "SQLite sync state store" the migration from version 1; `WatchwordKitTests`: "Vault session: one vault's report over two engine runs"; `WatchwordKitTests`: "Vault session: sync between devices" — two real sessions, AES-GCM and Ed25519: round trip, ciphertext only (F7.3), a conflict kept on both devices and resolved by the person, locked download, a deletion against an unseen edit, the purge, SQLite stores across a relaunch; XCUITest `SyncConflictTests`; milestone 3) |
| F2.x vaults | `WatchwordKitTests`: "Vault session: vaults" — create, list, rename; each vault its own key and a sealed name; items per vault and across; copy; move, and a move interrupted at each commit (never neither, never falsely moved); vault deletion confirmed by item count, the Personal vault undeletable; search over decrypted items, never a secret (F2.3); directory rows edited in the file. "Vault session: vaults across devices" — a vault, its name and items reaching another device; concurrent renames; a move against an unseen edit (kept, in the trash: F7.6); the same move on two devices; unresolved values refused; a vault deleted against concurrent work (what the deletion had not seen is kept: F7.7); a vault deletion outliving the revocation of the device that made it; a move whose copy could not be published (the original stays on the other devices, never neither); a locked device learning of a vault. "Vault session: a lock during the account's objects" — a lock landing in a vault-key fetch or in the reconciliation after an unlock wins, and traps nothing |
| F5.2, F10.1, F10.2 enrolment and devices | `WatchwordKitTests`: "Vault session: enrolment from the transport (F5.2)" — a device joining from the transport, password and Secret Key alone; wrong credentials one failure, leaving nothing behind; an approved device; an account from before the registry; a store restored onto other hardware, and the edits and deletions its old device had not synced reaching the others. "Vault session: devices, revocation and password changes" — a password change reaching other devices (old password refused, quick unlock destroyed, nothing merged or published until the new one is entered); enrolling after a change; revocation with and without a password change; a password change the person did not make, undone; a registry rolled back in the local file. `WatchwordCryptoTests`: "Device keys and signatures", "Device registry", "Published account header". Section 6.9 |
| F7.5 automatic sync | `WatchwordSyncTests`: "Automatic sync policy" — unlock, debounced saves and their cap, a save during a sync, coalesced hints, periodic intervals locked and unlocked, backoff and retry, spacing, a clock moved backwards, a transport's requested wait held to the cap — all with dates, no sleeping; `WatchwordPlatformTests`: "Automatic sync driver" — the timer started and re-armed as the policy decides, download-only while locked, a throttled sync waiting as asked, nothing after `stop()`, against a manual clock |
| F7.x transports | `WatchwordSyncTests`: "Sync transport contract" (`SyncTransportContract`, in-memory and directory), "Sync transport failures" (each stopping error stops the sync like being offline, with the reason in the report), "File sync transport: iCloud placeholders"; on a Mac, `WatchwordPlatformTests`: "Coordinated iCloud Drive transport" (the contract under file coordination, placeholders, concurrent creates of one name, the folder presenter, two engines over it) and "CloudKit transport" (the contract over a fake `CloudKitDatabase` with CloudKit's save-policy semantics, the record layout, create-only saves, paging, assets, the zone, every error mapping, failures reaching the report; the real container only when enabled); adversarial suites "Apple adapters: iCloud Drive transport" and "Apple adapters: CloudKit transport" (§6.10) |
| F8.x interchange | Fixture round trips for each format; instruction text snapshot tests (`WatchwordInterchangeTests`: "CSV reader and writer (RFC 4180)", "Password CSV import and export", "1PUX import and export", "Credential Exchange Format import and export", "ZIP reader and writer", "DEFLATE inflater and CRC-32" — against streams from Python's `zlib` and archives from Python's `zipfile` —, "Bounded JSON reader and writer", "Import mapping into the vault", "Duplicate detection", "Interchange instructions"; milestone 7). Through the session and the encrypted archive (`02-architecture.md` §14.1): "Vault session: import, export and the encrypted archive" (`WatchwordKitTests`; with `apexOfWWWHosts`: a `www` host gains its apex by default, each addition in the preview, and the opt-out), "Items from an encrypted Watchword archive" (`WatchwordInterchangeTests`), "Encrypted archive key derivation" and "Encrypted archive format" (`WatchwordCryptoTests`, a vector from Python `cryptography` and a whole archive written by an independent Python implementation), and the adversarial areas "encrypted Watchword archive" and "interchange through the session" (with `AdversarialSessionLockTests.swift`: a lock during each step the session runs off its actor, through the public call, wins and ends the call in `locked`), and "Forked generator" (`WatchwordCryptoTests`). Still to come: file protection (the app's) and the Credential Exchange calls; the backup's file type: "Screen models: import, export and restore" holds `Apps/project.yml`'s exported type to `ExportKind`'s identifier and `.watchwordbackup` extension, on both apps, and fails if a document type is registered (architecture §14.1) |
| F9.x hygiene | HIBP prefix/suffix logic with padded and malformed fixtures; cache TTL; scheduling with keys absent (`WatchwordHygieneTests`: "Pwned Passwords: digest and prefix", "…: range parser", "…: cache entries", "…: client", "Breach scan scheduling", "Scan ledger", "Strength estimator", "Password reuse", "Item checks", "Hygiene report", "Hygiene engine", "Breached-account lookup", "Synced scan results"; `WatchwordKitTests`: "Vault session: synced hygiene"; milestone 6, synced results per owner decision 10, §6.6) |
| F11.x phishing | Section 6.7: never-release on look-alikes, warn-not-silence, false-positive guards, scope policy, normalisation |
| SEC1–SEC10 | Section 6 below |

## 4. End-to-end scenario tests (normative)

Each test is written once against `VaultSession` and once as an XCUITest where UI is involved.

- **E2E-S1 Amazon vs AWS.** Seed both items. Request credential list for
  `https://signin.aws.amazon.com/signin` → the list contains only the AWS item, and retail (shadowed)
  is neither listed nor released, by choice included; request for `https://www.amazon.com/ap/signin`
  → only retail. Assert the
  TOTP returned for each matches the right item. Assert that with both items in the vault neither
  has a QuickType password or code identity, and that the retail identity a stale store still holds,
  handed back as stored, releases nothing (`02-architecture.md` §9.1: a tap does not name the page).
- **E2E-S2 Google passkey + recovery codes.** Register a passkey for `google.com` via the request
  handler; assert on assertion the signature verifies with the stored public key and the `prf`
  output is stable; mark a recovery code used and verify the item version and history.
- **E2E-S3 Shared bank.** User A creates the item in a shared vault, invites B, both verify
  fingerprints, B fills password + TOTP, B edits the password, A observes the change after sync, A
  revokes B, A rotates automatically, B's client fails closed on the new version.
- **E2E-S4 Shared library.** Same as S3 with PIN and card number inserted via the text-to-insert
  handler, and with B holding `read-only` (B's edit is refused locally and by the transport fake).

Lifecycle flows also covered end to end: onboarding with Emergency Kit confirmation, second-device
enrolment via Secret Key entry, password change, device loss recovery, account deletion, export
with password re-entry, import of 1PUX/CSV fixtures.

## 5. UI tests (XCUITest)

- macOS and iOS simulator jobs run the same test plan: onboarding, unlock (password), quick-unlock
  settings UI (biometrics are simulated with `FakeBiometricGate`; the simulator's Face ID
  enrolment menu is driven where possible), item CRUD, share invite UI up to the system share
  sheet, export warning flow, import picker flow.
- AutoFill in Safari cannot be reliably enabled from automation on the simulator; the job that
  attempts it (via the Settings app) is non-blocking and its result is recorded as an artifact.
- Milestone 2 status: `OnboardingAndUnlockTests` (onboarding with the short-password error, the
  Emergency Kit confirmation, item creation with a generated password, lock, wrong password, unlock, and Move to Trash, which only
  takes effect once its confirmation is accepted)
  runs on the iOS simulator and macOS from `Apps/UITests/Shared`. Milestone 3 adds `SyncConflictTests`: an item
  renamed here and, concurrently, on another device (`UITestPeer`, a second `VaultSession` of the same account in the
  app's process, driven from a Debug-only Settings section) shows both names after Sync Now; keeping the other one
  clears the conflict and is published like any edit. `AutoFillSettingsTests` skips
  itself until the extension answers requests (milestone 5). The accessibility audit is not wired
  in yet.
- The account screens (vaults and sharing, devices, the quarantine, the security report, import, export and
  restore) add, on both platforms: `VaultSharingTests` (a vault created, renamed and shared, and the other person
  invited with a vault sharing code: no role offered before both codes are checked, a wrong code refused with the
  tries left, the invitation sent inside the session and accepted by `UITestPeer`'s second account, the member listed
  with the role given; the same with their screen scanned through the camera's stand-in; and this account joining the
  other person's vault, number typed, codes both ways, the invitation arriving inside the session), `DeviceRevocationTests` (a password changed on the other device announced after a sync, the
  old one refused with the way out shown and taken, then that device removed with a new password, which then
  unlocks), `QuarantineTests` (a version jumping past the
  launch's ceiling held aside, listed by item and discarded only through the confirmation) and `ImportExportTests`
  (an import whose duplicate must be decided first, a merge naming the `www` host it would add, off until accepted,
  with the password hidden; a CSV export's report and the standing warning; a backup restored with its date shown;
  and a lock, through a Debug-only "Lock now" on the screen, with the merge review or the export report open, after
  which neither is there).
  `--uitest` gives them what a release build lacks: sync and sharing over in-memory ports shared with `UITestPeer`
  (another device of the account and another person's account, in the app's process), a version-jump ceiling of 16
  so the peer can produce a quarantined version through the real sync path, no auto-lock (a slow simulator run
  locked part way; the tests lock through Lock and a Debug-only "Lock now"), breach checks answered by
  `UITestPwnedPasswords` (only SHA-1("password") is breached; nothing reaches the network), a sample CSV and the
  last exported archive in place of the system's file picker, and Settings' Debug-only section to drive the peer.
  Elements are found by `AccessibilityID` (`Apps/Shared/AccessibilityID.swift`), compiled into the UI-test bundles
  as well, so the identifiers are one list both sides share; they are stable, and a rename changes every test that
  uses it. The steps they share (`AccountScreenSteps.swift`) are platform-aware: on iOS a form is scrolled by
  swiping; on macOS by a scroll-wheel event on the scroll view that holds the target, or else the frontmost sheet's,
  never one a sheet covers (the first macOS run failed with "unable to find hit point" scrolling the main window under
  Settings). Opening and closing a screen retry a click that did not take, Sync Now and the UI-test hooks work from any
  screen (an open account screen is closed and Settings opened first), waits are bounded (a missing element fails in
  seconds), and every such failure attaches the whole element tree (`attachTree`), kept whether or not the test
  passes. To keep the iOS job short, `DeviceRevocationTests` is one launch; `ImportExportTests` is three (import with a
  lock during the review; export, its report and a lock; a backup and its restore), each within its allowance. The
  export and the backup were one test until it ran 439 s of its 600 on a good CI run and out of time on a slow one:
  every query walks the app's whole accessibility tree, one to two seconds on a CI simulator and, while the
  simulator's own services were crashing, 17 to 28 s four times running; the test made 331 of them. So the helpers
  count queries: an element in view costs `reveal` two (a snapshot for its frame, then whether it can be hit) where
  it cost five or six, and `enter` ends its text with Return on iOS, so no keyboard is left over the next field to be
  found and dismissed (a dozen queries each time). A stalled query is also an error of its own: after three
  30-second attempts XCUITest records "Failed to get matching snapshots: Timed out while evaluating UI query." as a
  failure of the test (the tour failed that way looking for a Settings row, the app idle, nothing it checks wrong).
  So every read the helpers make, and the lookup that begins a tap or typing, goes through `UIQuery.tolerating`
  (`Apps/UITests/Shared/UIQuery.swift`: `isPresent`, `canBeHit`, `appears(within:)`, `disappears(within:)`,
  `enterText`, and `click` on iOS): that one message is taken as expected and the read made again, at most twice,
  with a `UI-test note:` line each time; any other failure is recorded as ever, and a query still unanswered after
  the retries fails the test saying so. `app:diagnose` prints the 150 lines of the session log before a query's
  timeout, which is where XCUITest says what it saw while it waited. The long tests
  (the tour, import and export, sharing, devices, the quarantine) print `STEP <time> [<test>] <step>` before each step
  (`XCTestCase.step`), which `app:diagnose` gathers at the end of a failed job's log (below). Sheets the account screens open close by clearing
  their presenting state, not through `dismiss`, which did not close a sheet over a sheet on macOS. The macOS window
  (820×600) and every sheet fit a 1024×768 screen with the menu bar, as the CI runners have: content scrolls, and
  Done, Cancel and confirm buttons are toolbar items, always in view (a 780-point window put Settings' Done below the
  runner's screen). `reveal` decides by an element's frame before asking whether it is hittable
  (which fails outright for an iOS row scrolled out of view): above the visible area it scrolls back, below it
  scrolls on, not there yet it scrolls the way the caller says, and on screen it waits; on macOS it scrolls only a
  scroll view no sheet covers and learns which way the wheel moves the form. Only after its bounded scrolls does it
  fail, with the element tree, the window's frame and a screenshot attached. A form's row is judged against its
  scrolling container, kept clear of the bars at its edges; a toolbar item (Done, a sheet's + button) against the
  window, since it is in no container (judging Done against the form failed every close of Settings on macOS). Every
  helper failure also prints a compact account to the log (the target's frame and state, the window's and sheets'
  frames, the area judged by, the buttons on screen, the start of the tree), and `mise run app:diagnose` prints the
  failed tests' text attachments (`xcresulttool export attachments --only-failures`, capped), so a failure can be
  read from the job log alone. On iOS a row is judged against the window alone, with no query for its container:
  those queries, made on every check, made each step of an iOS run several seconds long, and the window is the app's
  own frame there (one query, not two). The keyboard is not part of that frame, so a row under it passed as on
  screen and was not hittable (the export report's Save File… after the password was typed): once the quick check
  fails, `reveal` puts away a keyboard that covers the target or that a row below the fold would scroll under
  (Return, else a downward swipe), and the password screens (export, restore, a device's removal) end editing when
  they run and dismiss the keyboard on scrolling, as people need too. A button inside a section made an accessibility container
  (`.accessibilityElement(children: .contain)` on a `Section`, which keeps the report rows' own identifiers) was never
  hittable on iOS, though in full view and enabled, so the export report's Save File… and Lock buttons sit in a
  section of their own, and the form scrolls to them when the report appears. Every test sets an `executionTimeAllowance` (600 s, the tour 1800 s), which
  `app:test` turns on (`-test-timeouts-enabled YES`, a default of 600 s and a ceiling of 2400 s), so a hang fails that
  test with a report. A text expected below the fold (an
  export's report) is scrolled to as well.
- Their logic is tested on Linux without a simulator: every account screen's state and decisions are a model in
  `WatchwordPresentation` (`02-architecture.md` §15), and `WatchwordPresentationTests` drives those models over real
  `VaultSession`s ("Screen models: vaults", "… devices", "… a password changed by someone else", "… held-aside
  changes", "… sharing", "… member trust", "… hosts a merge would add", "… security report", "… import, export and
  restore", and the wording suites; with `WatchwordKitTests` "Vault session: held-aside versions and the lock
  signal"). The adversarial area "account screens" (`AdversarialAccountScreenTests`) attacks them: a pasted
  fingerprint code taken for a comparison, a look-alike host from an import file, a shared vault an administrator
  renamed "Personal" (and a member refused), a device named to pass for this one; and "shared vaults through the session" has the member list after a relaunch
  with a substituted key (`06-adversarial-review.md` §Q). What only an XCUITest checks is that the views lay the models
  out and pass the taps on.
- Accessibility audit (`XCUIApplication.performAccessibilityAudit()`) runs on every screen.

### 5.1 The screenshot tour

`ScreenshotTourTests` (`Apps/UITests/Shared`, iOS simulator and macOS) is one pass through every flow the app has
that attaches a picture of each major screen, so the screens can be audited by eye and a pull request that changes
the UI can carry fresh ones. It is an end-to-end test in its own right: `app:test`, and so `ci.yml`'s `app-tests`
job, runs it with the other UI tests, and a flow that breaks fails it there.

- **What is on screen.** The app is launched with `--uitest`: in-memory ports, an account the test creates, and
  `UITestPeer` as the other device and the other person. `Screens.capture` refuses any other launch. The Secret Key and the generated
  password in the pictures belong to that throwaway account and differ on every run; no real vault, Keychain item
  or secret can appear. The Settings picture includes the Debug-only "UI test: another device" section, which no
  release build has.
- **The screens today**, in flow order: `onboarding`, `emergency-kit`, `item-list-empty`, `item-edit` (a new item,
  its password filled in by the generator), `item-list`, `item-detail` (password hidden), `item-detail-revealed`,
  `trash-confirmation`, `locked`, `unlock-failed`, `settings`, `item-list-conflict` (the badge after a concurrent
  rename), `conflict-resolution`; then the account screens: `vault-list`, `vault-new`, `vault-detail` (not shared
  yet), `invite-start` (what a vault sharing code session asks of both), `invite-sharing-code` (the eight digits and
  their QR code), `invite-their-code` (typing the six digits on their screen), `invite-own-code` (this device's six
  and the role), `invite-sent`, `vault-members` (owner and member after the acceptance), `own-full-code` (the full
  vault sharing code and its QR code), `accept-number`, `accept-codes`, `accept-confirm` (their invitation arrived,
  asked before joining), `accept-invitation` (the fallback: pasting), `quarantine` (a held-aside version with its item, vault and device), `security-report` (a
  breached password reused by two items, after Check Now), `import`, `import-review` (a duplicate waiting for a
  choice), `import-merge` (the `www` host and the sign-in details a merge would add, none accepted, the password
  hidden), `import-done`, `export` (the standing plaintext warning), `export-report`, `restore-review` (the date the
  backup was made, first), `sync-password-changed`, `unlock-password-changed` (the old password refused and the way
  out), `devices`, `device-revoke` and `devices-after-revoke`. Files are numbered in that order
  (`01-onboarding.png`). Not in the tour: a shared vault gone on in a later format (read-only, "update Watchword"),
  which needs a later version's membership record that no session API can make; its wording is tested in
  `WatchwordPresentationTests`.
- **Adding a screen** is one line where the tour reaches it: `Screens.capture("vault-list", in: app, showing:
  "…")`. Names are lower-case words joined by hyphens and unique; the number comes from the order of capture, so a
  screen added in the middle renumbers the later ones. Every milestone that adds a screen adds it to the tour
  (AutoFill settings is still to come).
- **No sleeping.** A capture follows a tap or keystroke (XCUITest waits for the app to be idle around those, which
  covers a sheet or a push animating in) or a wait for the element that proves the screen is complete (the editor's
  title field gone after Save, the error text after a wrong password). Where only the keyboard is moving, the tour
  taps something inert first.
- **The picture.** On macOS it is the app's window, not the screen, so nothing else on the machine is in it; on
  iOS it is the whole screen, so the keyboard and system dialogs are. Attachments are kept whether or not the test
  passes (`XCTAttachment.lifetime = .keepAlways`), and the tour ends by attaching `screens-index`, the list of what
  it captured. A capture of a rotated device (the iPad set) is redrawn before it is attached, because the screen's
  pixels arrive in portrait with the rotation as metadata a PNG does not keep. Two things a reader of the pictures
  should expect: iOS leaves the keyboard out of a capture while a
  password field has the focus, so `onboarding` and `locked` show an empty band where it is on a device; and where
  the list and the item share the window (macOS, an iPad in landscape) `item-list-conflict` and
  `conflict-resolution` are the same picture, because the conflicted item is already selected.
- **`mise run app:screenshots [ios|macos|all]`** runs the tour alone, exports the result bundle's attachments with
  the selected Xcode's `xcresulttool export attachments`, and writes `Screenshots/<set>/<NN-name>.png`, `index.md`,
  `index.html` (a contact sheet over the files beside it) and `Screenshots/watchword-screens-<set>.png` (every
  screen in one picture, each under its name, drawn by the task's own helper from `sips` thumbnails). It fails if
  the tour failed, if the index is absent (the tour stopped part way), if a listed screen has no picture, if a
  picture is not a PNG or is one flat colour, or if the pictures are not in the appearance the set was asked for.
- **Only a complete set is a set.** A capture that fails in any of those ways writes nothing to
  `Screenshots/<set>/`, no contact sheet, and announces no screen names to the workflow. What there is goes to
  `Screenshots/<set>-incomplete/`: the pictures, an `index.md` and `index.html` that begin by saying the set is
  incomplete and why and that keep the tour's own numbering (a missing screen is a row that says so, not a gap
  closed up), and, when the tour stopped part way, XCUITest's own screenshots of the failure as `failure-<n>.png`.
  The job summary gets the same statement instead of an index.
- **Appearance and device.** The task tells the tour which appearance its set is in, and the tour launches the app
  with `--uitest-appearance=light` or `=dark` (Debug only, beside `--uitest`), which fixes the appearance whatever
  the machine's is: the default sets `ios` and `macos` are light on a Mac in Dark Mode, and `--appearance dark`
  gives `ios-dark` and `macos-dark` without a setting changed. Run through `app:test`, with no set asked for, the
  tour follows the system like every other UI test. `--device ipad` tours on an iPad simulator in landscape for
  `ios-ipad`. Neither the dark nor the iPad set runs by default.
- **In CI.** `screenshots.yml` (§7) captures both platforms for a pull request and comments with links;
  `mac-run.yml`'s `app:screenshots` gate does the same capture on a branch for a session without a Mac
  (`09-cloud-sessions.md` §5).

## 6. Adversarial security tests (explicit requirements)

These are mandatory, live in `Tests/WatchwordAdversarialTests` (and later per-module
`Adversarial*` suites), are tagged `.adversarial`, run in a dedicated CI job, and must fail the
build. Each bullet is a test or test group that must exist before the corresponding milestone
closes.

### 6.1 Envelope and crypto

**Implemented in milestone 0** (header-level):
- Change `kind` byte, unknown kind, wrong magic, version 0/2/0xFFFF → rejected before any payload
  is touched.
- Truncation at every offset in the header → rejected.
- A declared AAD length longer than the data → rejected.
- Every single-byte flip in the header is either rejected or changes a bound field.
- Downgrade: `iterations` below `KDFParameters.minimumIterations`, short salt, unknown algorithm,
  non-32-byte output → rejected, including at `Decodable` init so a tampered header cannot decode.
- Ceiling: `iterations` above `KDFParameters.maximumIterations` and absurd salt lengths → rejected
  (availability; review finding C3).

**Implemented in milestone 1** (`AdversarialCryptoTests`, suite "Adversarial: crypto core", and the
context-binding tests added to `AdversarialEnvelopeTests`):
- Flip every byte position of a sealed record (two bit masks each; sampled for a 200 KB record) →
  open throws for the right reason: header fields by an `EnvelopeError` before decryption, nonce,
  ciphertext and tag by `CryptoError.authenticationFailed`; nothing is returned. Truncation at every
  length likewise. A 1 MB envelope offered where a wrapped key is expected is refused by size first.
- Copy a record into another vault's slot → `EnvelopeError.contextMismatch` before decryption.
  Rewrite the embedded AAD to match the new slot → still fails, because the AEAD authenticates
  the whole header.
- Relabel a record as another record ID, a newer `recordVersion`, another schema version, another
  kind or another key ID → rejected before decryption.
- Replay of an *older* version presented as itself → cannot displace newer values: the merge keeps the latest
  revision of every group (milestone 3, suite "sync log": `withheldSegment`, `staleSnapshot`); presenting it as
  newer is rejected by the AAD.
- Nonce uniqueness over 1e5 encryptions under one key (1e6 when `WATCHWORD_LONG_TESTS=1`), and a
  generator that repeats is caught by the key's nonce ledger before the second encryption — including
  across two separate key wraps under the same Ksym, and across copies of the key value.
- HPKE grant to a substituted recipient key is unopenable by the real recipient; a grant signed by
  anyone but the expected sender, or with any field altered, is rejected; a validly signed grant
  found in another vault's or key's slot is refused before decryption (entitlement is per vault);
  a vault-key wrap moved to another slot likewise. A re-signed grant relabelled to another vault
  also fails HPKE (info binding), a narrower layer against a party that can sign but not decrypt. "Signed by a non-*admin*"
  needs the membership chain (milestone 4); "signed by an unexpected key" is tested now.
- Published keys: low-order X25519 points (libsodium's blocklist), small-order Ed25519 keys with
  either sign bit (for which the identity "universal signature" would verify everything), and
  substituted keys under the original self-signature are rejected; a re-signed substitute shows a
  different fingerprint.
- Signatures for one domain never verify for another, nor without the domain prefix.
- Keyset wrap opens only under its own AUK, account ID and version; wrong password or wrong Secret
  Key → `authenticationFailed`; tampered KDF parameters and salt-length mismatch are refused
  before deriving.
- Timing: checksums, fingerprints and `SecureBytes` comparisons go through `ConstantTime.equal`
  (no early exit); this is asserted by code review, not measured — a timing micro-benchmark on
  shared CI runners would be noise.
- Zeroisation: after `zeroise()`, every buffer of a keyset, vault key and Secret Key reads as
  all-zero across its whole allocation; `deinit` wipes before release (observed through a probe,
  since freed memory cannot be read); reading after zeroise, and zeroising during a same-thread
  read, trap (exit tests, Swift 6.2+ only).

Known-answer tests (`PrimitiveKnownAnswerTests`, `PBKDF2Tests`, `TwoSecretKeyDerivationTests`,
`SecretKeyTests`, `CanonicalCBORTests`) use RFC 5869, 7748, 7914, 8032 and 8949 vectors and the GCM
specification, plus vectors from independent Python implementations for HPKE with associated data,
2SKD, the Secret Key format, fingerprints and the canonical AAD.

### 6.2 Unlock (milestone 2)
- Quick unlock refused after enrolment change, after N failures, after interval expiry, after app
  version change, after password/Secret Key change.
- A `FakeBiometricGate` that returns success without the Keychain releasing the LUK must not
  unlock (guards against the "boolean bypass").
- Background → foreground after the grace period locks; secrets absent from memory.

**Implemented in milestone 2**, each test documenting its threat model:
- `AdversarialUnlockTests` ("Adversarial: unlock and quick unlock"): the gate alone never unlocks
  (Keychain fails, cancels or reports the item invalidated); bytes other than the enrolled LUK fail
  authentication and destroy the enrolment; three failures delete the LUK and stop prompting; each
  F5.4 reason (interval, update, re-enrolment, biometrics off, clock wound back) refuses before any
  prompt and deletes the key; an OS-invalidated item forgets quick unlock; a pre-password-change
  enrolment replayed with its counter edited still fails; wrong password and wrong Secret Key are
  indistinguishable; a setup code for another account is refused; idle, sleep, foreground and
  zero-grace backgrounding lock and zeroise every key; a `lock()` landing inside an unlock or a save
  wins; account deletion re-checks the password.
- `AdversarialVaultStoreTests` ("Adversarial: local vault store"), tampering through a raw SQLite
  connection: no title, host, field value or password anywhere in the database files; swapped
  envelopes, and rows relabelled with another version, key or record ID, become unreadable; an item
  envelope planted as a key wrap fails the kind check; a deleted key wrap is an error, never a new
  key; KDF iterations tampered below the floor or to `UInt32.max` are refused before deriving, in
  under five seconds; a substituted salt, keyset, keyset version or account ID fails closed; a
  correctly sealed record whose payload claims another identity is refused; malformed values are
  reported; a symlink at the database path is refused; over-broad scopes are refused at save.
- `AdversarialKeychainAttributeTests` ("Adversarial: Keychain item protection"): every item is
  device-only, non-synchronisable and in the shared access group; the LUK requires the current
  biometric set with no passcode or any-biometry fallback.
- These check the query `SystemKeychainStore` sends, because the data-protection Keychain refuses
  an unsigned process (`errSecMissingEntitlement`). The real store, read, replace and delete
  (`SystemKeychainStoreTests`) runs in the `WatchwordKeychainTests` bundle, hosted by
  `WatchwordKeychainHost`, a do-nothing macOS app whose only entitlement is its own
  `keychain-access-groups` entry, so a free Personal Team can provision it (it cannot provision the
  main app's App Group or AutoFill entitlements). Run it signed with
  `mise run app:test-keychain --team <ID>` (or `DEVELOPMENT_TEAM=<ID>`): it passes
  `-allowProvisioningUpdates` and the team on the command line, never in `Apps/project.yml`, and
  sets `WATCHWORD_REQUIRE_KEYCHAIN`, so a host signed without its entitlement fails rather than
  skipping. The `isEntitled` probe deletes its item (and any an earlier run left) and the signed
  run asserts nothing remains. CI's `app:test macos` runs the same bundle ad hoc signed, where the
  round trip skips.
- Added by the milestone-2 review (`06-adversarial-review.md` §G): a quick-unlocked session cannot
  restart the password interval; cancels count towards the failure limit; activity after the idle
  timeout locks; a committed password change reports success even if the vault locks; a planted
  vault-key row does not block unlock; a planted trigger, view, table or index makes the store refuse
  to open; erasing leaves no ciphertext in the write-ahead log; SQLite refuses oversized values.
- Added by the audit of 2026-11-17 (§Z): an app killed while the biometric prompt is up has still
  used an attempt (`killedDuringThePrompt`, Z7: three prompts that never return, each from a new
  launch, then no prompt and the password; a prompt that ends in the key takes its attempt back).
  Suite "Vault session: a lock during the account's objects" gains three cases (Z4): a lock while a
  password unlock waits on the Keychain, while a quick unlock writes its state, and while a granted
  vault key is being stored. Each trapped before.

### 6.3 AutoFill matching (milestone 2/5)
- Service identifiers with user-info (`https://amazon.com@evil.example/`), ports, trailing dots,
  mixed case, IDN homographs (`xn--` forms) and raw Unicode, IPv6 hosts, `file:` and `data:`
  schemes → never match an unrelated item.
- Public-suffix boundaries once PSL is integrated (`co.uk` scope must not match everything).
- Shadowed items are never listed or auto-selected; the request handler refuses to return a credential for a
  service identifier the chosen item does not match (defence in depth against UI bugs).
- Passkey assertion for a relying party different from the stored `rpID` is refused.

Milestone 5 status: the last two obligations, and the rest of this list as seen from the request handler, are
`Tests/WatchwordAdversarialTests/AdversarialAutoFillRequestTests.swift` ("Adversarial: AutoFill request model"),
against `CredentialProviderModel` with `FakeCredentialVault`:

- *Every request type, one sweep.* A helper asks for everything an item holds through every request that
  releases a secret (password by choice, one-time code by choice, text for every field, passkey assertion by
  choice and by identity, with and without an allow-list; and the two QuickType requests with the page's
  identifier put where the identity's own belongs, which is what a confused adapter would send). For thirty
  hostile identifiers (look-alikes, user-info, percent-escapes, non-web schemes, public suffixes) nothing is
  released for any item; on each real site nothing of any *other* item is released, and the site's own item is,
  which keeps the sweep honest; stuffing a request with extra identifiers widens nothing.
- *QuickType, the request that names no page.* A randomised property test (the nightly widens it) builds vaults
  of items scoped across three sites, a country-code site and two tenants of a shared host, and checks every
  identity the model publishes or answers against the gate itself, page by page: on every host of the
  identity's site, parents and siblings included, the item must be released by choice and be the one account
  offered under that name; and nothing unpublished is answered when handed back. A second test replays the
  retail identity of S1 from a stale store after each change that should retire it (the AWS item arriving, an
  exclusion, a narrowed scope, an exclusion from AutoFill, archiving, a renamed user). Inputs to these requests
  are built only from published identities (`handedBack` in `AutoFillFixtures`).
- *No override.* A look-alike gets the warning in place of a list; repeating the request, raising the presence
  level or omitting the identifier releases nothing (F11.4, F11.7). With no host named, no secret of any kind
  inserts as text, for an item holding a field of every kind, and the host-checked text request without its
  identifiers is refused rather than answered as the hand-picked one.
- *Passkeys.* A relying party ID in any spelling but the canonical one is refused before the vault is read; a
  conditional registration cannot plant an item, and a loop of three hundred of them, each with a fresh user
  handle and any relying party the page could claim, adds one passkey to an item; no registration, silent or
  confirmed, changes an existing item's scopes; a passkey planted in another site's item is asserted for
  neither party.
- *Records no honest client wrote* (a malicious vault member, a crafted import): an over-broad stored scope
  matches nothing; malformed passkey, `otpauth` and recovery-code fields are refused field by field without a
  crash and without taking the item's other fields down; an item ID that two readable items share releases
  nothing on either item's site, through any request, and the twin still ranks.
- *Remote parties.* A randomised run of reports, silent saves and silent registrations, from any party, leaves
  every item, field, secret value and scope in place (the nightly widens it); a report flood adds one version;
  a save cannot widen a scope, pick a title or reach another site's item; hostile `passwordrules` end in a
  refusal or a bounded, conforming password.
- *Locked.* Every request type reports the lock and releases nothing; a lock that lands mid-request wins for a
  write, and for every kind of release when it lands after the items were read (each request type is run
  unlocked, where it must release, and again with the vault locking as its one read returns).
- *Plain `http` pages (F6.9).* An attacker on the network path serves `http://bank.example` (and its
  upper-case and `www.` spellings) for a site with a saved item scoped `bank.example`: the sweep releases
  nothing, by choice included; the credential, one-time code and text lists are `insecurePage`; no save, asked
  or unasked, is made; the same item over `https` is released (`plainHTTPPage`).
- *Excluded from AutoFill (F6.8).* An item excluded on another device is not released for the identities a
  stale store still holds, is not listed, and is not released when chosen.
- *The identity store* learns hosts, user names and opaque IDs only, and nothing of excluded, archived or
  trashed items.

### 6.4 Sync and sharing (milestones 3–4)
- Malicious server mode: substitutes a member's public key → fingerprint mismatch blocks the
  invitation; reorders/duplicates/drops segments → convergence still holds or sync fails closed;
  injects an unsigned or wrongly signed membership record → ignored; serves a stale snapshot →
  Lamport check rejects regression.
- Former member: after revocation, replaying their old wrapped key cannot decrypt new versions;
  their pushed segments are rejected by remaining members.
- Read-only member's writes are rejected by the transport fake and never merged.
- Two admins remove each other concurrently → deterministic outcome, no vault lock-out.
- Vault sharing codes (ADR 0010, its security analysis), "sharing and membership": an adversary in the middle of two
  sessions it runs back to back, in either interleaving, gets codes that do not match and evidences nothing
  (`middle`); a directory that lies to one side (`directoryLiesToOneSide`); a bundle published after a device fixed
  its own (`bundleFetchedLater`); a reply replaced after the reveal, never read and never revealed for
  (`replyReplacedAfterTheReveal`); a reveal planted early (`earlyReveal`); a reply and a commitment with its reveal
  replayed from another session (`replay`); a sniper answering first (`sniping`); three wrong codes and input that
  is not a code (`wrongCodes`); ten minutes without progress (`timing`); the same account on both ends
  (`sameAccount`); a scan of another account or other keys (`wrongScans`); evidence and an invitation used for another
  account or session, forged or altered (`evidenceStaysInItsSession`); junk under a session's names
  (`junkOnTheBoard`). "Shared vaults through the session": a lock while a step waits on the board reveals and pins
  nothing (`lockMidSession`, which failed before the lock was checked ahead of the reveal); two steps at once
  (`oneStepAtATime`); an administrator's invitation accepted only once the owner is checked by the invitee
  (`noVouching`); a directory that changes the invitee's keys after the session (`directoryChangesAfterTheSession`);
  an invitation planted in a session's slot (`plantedInvitation`); a "keys changed" warning settled only to keys the
  chain lists (`keysChangedSettledOnlyToListedKeys`); a joiner's scan pinned only after the starter's reveal and the
  person's yes to the account named, and nothing pinned by an ending, a spoiled reveal or a lock
  (`scannedJoinWaitsForRevealAndYes`, V18; "Screen models: sharing" `scanNamesTheAccountFirst`); a shared vault whose
  ledger no longer restores (the owner's pin deleted) unavailable, never the member's own: no write, rename, share,
  acceptance, publication, snapshot or collection, nothing taken in, restored once the owner is checked
  (`unrestoredSharedVaultIsUnavailable`, V19; "Screen models: sharing" `unrestoredSharedVaultOnScreen`).
  A lock while a joiner waits on the board publishes no reply (`lockWhileJoining`, V9's other half); an end while a
  start or a join waits on the board is not undone (`endWhileStartingOrJoining`, V20), and a step of a replaced session
  reveals nothing (`replacedSessionRevealsNothing`, V20). A taken invitation slot leaves the invitation to hand over
  as text and a retry invites nobody again (`invitationSlotTaken`, V22; "Screen models: sharing"
  `undeliveredInvitationAsText`). A joiner never answers one number twice, across Start Over and a lock, so a fresh
  commit buys the middle no second try (`noSecondAnswerToOneNumber`, V23). No pin is replaced from a session while a
  shared vault here cannot be restored (`noPinReplacedWhileAVaultIsUnrestored`, V28). With no member-key comparison on the current head
  no other member's object verifies (`noComparisonNoVerification`, V29). A shared vault whose `.ledger` and `.owner`
  rows are deleted (A8, after a rotation) stays shared and closed: no write, rename, deletion, move in, share, record
  or publication, nothing sealed under any key, and set up again it seals under the chain's key
  (`deletedLedgerRowsKeepTheVaultShared`, V31, the security-audit branch's Z41 ported); the owner's own deleted state
  (`ownersDeletedSharingState`) and a member's second device (`newDeviceHoldsTheVaultClosed`) likewise; "crypto core"
  `grantedKeyWrapClass` (the wrap authenticates whether a key arrived by grant). Rows planted in the sharing state close
  no vault, the Personal one included (`plantedRowsCloseNothing`, V32). A ledger that does not verify is `notSetUp`
  and set up again from the account's marker with every item kept, and only the owner of an unavailable vault is
  refused a pin replacement (`damagedLedgerIsSetUpAgain`, `pinReplacementScopedToTheOwner`, V33; "Screen models:
  sharing" `damagedSharedVaultSetUpAgainOnScreen`). A load that read the pins before a new pin settles nothing
  (`staleLoadSettlesNothing`, V36). An invitation issued by a session that is then replaced is kept and delivered by a
  later session (`invitationOutlivesItsRun`, V35). "Screen models: sharing" `accountCheckOnEveryStep`: the starter's
  step at the joiner's scan confirmation shows the account check the scan names (V34). UI tests (drafted, not yet run
  on a Mac): `testJoinByScanningTheirScreen` (iOS) reaches the joiner's scan confirmation (V37). After the merge with
  the security-audit branch (V38): `ownersDeletedSharingState` finishes the owner's share from the listed chain (Z50,
  Z122) as well as by invitation; a device enrolled after a rival marker reached the account follows neither owner
  (`laterDeviceFollowsNeitherMarker`, V39, the review's M1); an owner's rotated vault with its marker rows deleted and
  the marker withheld stays shared and closed, and two key IDs mark a vault shared (`rotatedOwnersVaultWithoutMarker`,
  `moreThanOneKeyIDMarksAVaultShared`, V40); a chain that names no granted key held is not joined
  (`stalePrefixIsNotJoined`, V41); with no marker no pin is replaced on a session's word (`noMarkerNoPinReplacement`,
  V42); a kept invitation is delivered only in its role while the chain lists the invitee
  (`keptInvitationFollowsTheChain`, V43). A value no stream will carry here counts for a description only as an administrator's (`uncarriedDescriptionNeedsTheRole`, V48), one who holds the role now: a demoted administrator's does not, even under a key rotated after the cut (`demotedAdministratorsUncarriedDescription`, V50).
- A later format (ownership transfer, `02-architecture.md` §8.9): a record of a later format version, or of this one
  with an unknown operation, signed by the owner as of the record it follows, stops the chain there in every order
  and batching and after a smaller listing, and the device proposes, plans and writes nothing; the same bytes signed
  by an administrator or a writer, unsigned, for another vault or at the wrong epoch change nothing, at one
  signature check each at most (`laterFormatStopsTheChain`, `laterFormatImpostors`, in "sharing and membership").

**Implemented in milestone 3** (`AdversarialSyncTests`, suite "Adversarial: sync log", with the fake keyring):
the server's reorder/duplicate/drop/stale-snapshot cases, a byte flipped anywhere in a segment, objects moved to
another stream, sequence, vault or slot, a withheld or replayed segment (the stream waits at the gap), forgeries
rejected before staging, a former device's segments, a record swap or relabel inside a validly signed segment, a
segment carrying another device's versions, a record ID of another vault, implausible versions (U5), no plaintext
on the transport, a row rolled back or deleted in the local file (A8) restored by reconciling, a tampered staged
download, mutated payloads and containers, sequence numbers and vectors near the integer limit, and symbolic links
planted in a file transport's directory (at the file and higher up). Quarantined versions are kept, not dropped.
Record kinds a device does not know (ADR 0009, `AdversarialSyncUnknownKindTests.swift`, in the same suite): A1
flipping an entry's kind byte, and with it its criticality, in the malleable ciphertext fails authentication and
nothing is skipped or kept (`kindFlip`); an insider filing an item's envelope under an ignorable kind is refused, not
passed over (`itemUnderIgnorableLabel`); an insider flooding ignorable unknown entries hits the stash's caps, stalls
no stream, crowds out honest results only until the upgrade's replay brings them back, and causes one replay, not
one per sync, with one stash write for the pass (`flood`); an entry kept from a device since revoked does not stop
snapshots or the hand-on of its work (`revokedAuthorsStashDoesNotStopSnapshots`), nor does a trusted insider's
(`handOnDespiteStash`); A8 planting a stash row with an item deletion, or one over the caps, erases nothing and the
stash is rebuilt (`plantedStash`). With real keys ("sync with real keys"): a stash row planted in the local state — unsigned, garbage-signed, or another vault's genuine row — is never processed (`plantedStashRow`).
The end-to-end audit of 2026-11-17 (`06-adversarial-review.md` §Z, Z20 to Z29; `AdversarialSyncAuditTests.swift` in
"sync log" unless another suite is named). The state row (A8, "sync with real keys"): a planted erasure signs no
tombstone and erases nothing, and the replay puts the row back (`plantedErasure`); a planted merged vector mutes no
other device (`plantedMergedVector`); a row signed for another vault, or edited after signing, is no state
(`stateRowOfAnotherVault`); every field of the state is in what is signed (`SyncStateAuthenticationTests`). Snapshots
("shared vaults through the session"): a member's snapshot claiming every stream at 2^48 is refused and mutes no device
(`memberSnapshotCoverage`), its tombstone erases nothing (`memberSnapshotTombstone`), and the owner's snapshot's
tombstone is judged like a segment's (`ownerSnapshotTombstoneIsJudged`, `snapshotTombstonesAreJudged`); a vault with a
judge still crosses the gap collection left before it was shared, at a replay too
(`snapshotsBridgeWhatWasCollectedBeforeSharing`); in any vault a snapshot's coverage of the reader's own stream does
not move its numbering (`coverageOfOwnStream`), and a number no reader lists is never published at
(`exhaustedStream`). A device's own stream: an unsigned object named far ahead, or just ahead, in it moves nothing and
loses no edit (`junkFarAheadInOwnStream`, `junkJustAheadInOwnStream`); an own segment that cannot be read yet holds
publishing back and no collected number is reused (`unreadableOwnSegment`); a planted version in the device's own
name does not mark its unpublished edit as sent (`plantedOwnVersionDoesNotSuppressPublishing`). One key space: a record
ID another vault holds costs one entry, in a segment and in a snapshot (`collisionCostsOneEntry`,
`collisionInSnapshot`, `crossVaultRecordID`). The jump ceiling: a device joining from a snapshot is not cut off by a
jump every earlier device accepted (`lateJoinerAcrossAJump`), and a version met before the ones below it is merged
once they have been (`jumpThatIsOnlyAnOrderOfReading`). The quarantine: capped per vault and per writing device, each
entry kept once, at a replay too (`quarantineIsCapped`, `heldAsideSegmentsAreCapped`, and `quarantineLookupAndUsage`
for both stores, the SQLite one on a Mac); a device that kept a version aside writes no snapshot covering it
(`quarantineWithholdsSnapshot`). Version columns at their last value (A8; "account enrolment and device registry" and
"sync with real keys"): typed errors, never a trap (`headerRowAtTheLastVersion`, `directoryRowAtTheLastVersion`,
`fetchedDeletionOverTheLastVersion`, `metadataRowAtTheLastVersion`). Not an adversary's: a lock as a deletion commits
loses no tombstone, and one before it deletes nothing (`DeletionLockRaceTests`).
The review of those fixes (`06-adversarial-review.md` Z30 to Z39; `AdversarialSyncReviewTests.swift` in "sync log",
`AdversarialSharedVaultOwnStreamTests.swift` in "shared vaults through the session"). A device's own stream in a
shared vault: a member's segment far ahead in it, or at the last number, does not move its numbering
(`memberPlantAheadInOwnStream`), and a read-only member's object there holds back nothing, deletions in other vaults
included (`readOnlyMemberPlantInOwnStream`). The hold: an unfetchable name far ahead does not mute a device whose
stream shows its own (`unfetchableNameFarAheadInOwnStream`), and a device whose state is behind its collected stream
does not publish over a collected number while a trusted snapshot covers more of it
(`olderStateUnderACoveringSnapshot`).
A lock before the retry of an out-of-reach version does not leave it out (`lockBeforeTheRetry`); a retried version whose
merge fails stops nothing (`retriedEntryThatDoesNotMerge`). The owner's snapshot's tombstone naming a member's device is
judged against that device's stream (`ownerSnapshotTombstoneNamingAMember`); a planted deletion in the device's own
name marks nothing as sent (`plantedOwnDeletionDoesNotSuppressPublishing`). The quarantine: a version it could not keep
withholds snapshots and is offered again when there is room (`droppedVersionIsRemembered`), sizes near the integer
limit read as full (`quarantineSizesNearTheLimit`), and a failing store stops the sync instead of refusing an object
(`storageFailureStopsTheSync`). The withheld snapshot is combined and worded (`SyncReportCombinationTests`,
`WordingTests.snapshotWithheldForReview`), and the two fields added to the state are signed, and only when set
(`SyncStateAuthenticationTests`).
The review of the second round (`06-adversarial-review.md` Z135 to Z143; `AdversarialSyncFollowUpTests.swift` in "sync
log", `AdversarialSharedVaultFollowUpTests.swift` in "shared vaults through the session"). Collection: a name planted far
ahead in a device's own stream is not kept in place of its head (`plantedNameIsNotTheNewestToKeep`), collection stops at
a segment missing from the listing (`collectionStopsAtAGap`), deletes lowest first and stops at a delete that fails
(`collectionOrderAndAFailedDelete`). The hold: a snapshot's claim about a stream that lists nothing holds nothing back
(`claimAboutAStreamWithNothingListed`), and a claim ends with its signer (`claimEndsWithItsSigner`). Shared vaults: a
deletion claiming the edits of a member who has never published erases nothing, from the owner's snapshot or a writer's
segment (`claimAboutAMemberWhoNeverPublished`); a read-only member's segment in another member's stream is stepped over
and nothing of it kept (`readOnlyMemberPlantIsSteppedOver`), and a taken place is worded
(`WordingTests.ownStreamHeldBack`). What this device published: a planted deletion for a record it does not hold yet
marks nothing as sent (`plantedDeletionBeforeTheRecordExists`). The jump ceiling: failed retries do not lift it
(`failedRetriesDoNotLiftTheCeiling`), and a version a snapshot carries ahead of the ones below it is merged by the retry
(`jumpInsideASnapshot`). The quarantine: a version its store refuses to keep is counted and remembered
(`refusedByTheStoreIsADrop`), a revoked device's dropped version holds no snapshot back
(`droppedVersionOfARevokedDevice`). Local state: a staged object past the listed bounds is dropped
(`stagedPastTheBounds`), and a store that fails while staging stops the sync (`stagingFailureStopsTheSync`).
The review of the third round (`06-adversarial-review.md` Z144 to Z149; `AdversarialSyncEngineReviewTests.swift` in "sync
log", `AdversarialSharedVaultEngineReviewTests.swift` in "shared vaults through the session",
`AdversarialVaultSyncEngineReviewTests.swift` in "sync with real keys"). Shared vaults: the items a revoked device
edited stay visible and converge on a device of its account enrolled after the revocation, on a member who joins after
it and on a device whose stream index was rebuilt (`revokedDeviceWorkStaysVisible`, Z144); a read-only member's segment
at segment 1 of a writer's stream does not take the stream, and the writer is told (`readOnlyMemberPlantAtSegmentOne`,
`WordingTests.ownStreamHeldBack`, Z146). The hold for this device's own stream: a junk name where a snapshot's claim
points does not hold back a device that never published (`junkNameWhereAClaimPoints`), a restored state whose head is
missing from the listing does not publish over a collected number (`restoredStateWithItsHeadMissing`), a store emptied
of the vault publishes on (`emptiedStoreDoesNotHold`), and `claimEndsWithItsSigner` now holds a device whose head is
missing (Z145). The quarantine: a version refused for a crowded digest is not offered again at every sync, only once
something has left the quarantine (`crowdedDigestDoesNotReplayEverySync`, Z147), and the two state fields that carry
this and the collected floor are signed only when set (`SyncStateAuthenticationTests`). The deletion gate: a move's copy
known only by a planted tombstone still holds its original's deletion back (`plantedTombstoneForAMovesCopy`, Z148). A version kept after this device's own deletion holds nothing back; restored and edited it holds the others back where its vault is not published, and goes out behind its tombstone where it is (`keptVersionBehindOwnDeletion`, V44, V46).
Collection: a name planted below what a device collected does not stop it collecting
(`plantedNameBelowTheCollectedRun`, Z149).
The review of the fourth round (`06-adversarial-review.md` Z150 to Z156; `AdversarialSharedVaultEngineRound4Tests.swift`
in "shared vaults through the session", the end of `AdversarialSyncEngineReviewTests.swift` in "sync log", and the
stream index suite `SharedStreamIndexTests`). A read-only and a removed member each revoke a device ID of another
member's, one that has published and one that has not: neither stops being read, nor its own device syncing
(`memberRevokesAnotherMembersDevice`, Z150). An owner's stream whose first segment is withheld from a joiner is not
taken for one collected before sharing, and judging again when it arrives agrees with every other device
(`ownerStreamMissingItsFirstSegment`), while a stream a snapshot covers still is (`collectedOwnerStream`, Z151). A
read-only member's plant at segment 1 of a writer's stream does not take it when the member is promoted, the key is
rotated, and the promoted member's later work counts (`promotionAfterAPlant`; whose segment names a stream, in any
arrival order, `namingSegmentsComeFirst`, Z152). A revocation learnt after a version was held aside for that device
admits it, and the vault settles (`revocationLearntAfterTheHold`, Z153). A segment's acknowledgement does not hold back
a device of a vault that keeps its whole log (`acknowledgementInAWholeLog`, Z154). A read-only member's flood of
segments into its own device's stream is not recorded, and a plant the victim steps over is recorded once the victim
publishes above it (`readOnlyFloodIsNotRecorded`, Z155). The deletion gate of Z148 opens once the copy is published
(`plantedTombstoneForAMovesCopy`, Z156). Since Z157 the Z150, Z152 and Z155 tests check the rule that replaced
theirs: a revocation of another member's device ID retires nothing because no registry but its own account's counts
it; a planted segment verifies nowhere before or after a promotion, and no rotation follows one; a read-only member's
flood is passed over and never recorded.
The review of the fifth round (`06-adversarial-review.md` Z157 to Z161; `AdversarialSharedVaultStreamIdentityTests.swift`
and the end of `AdversarialSharedVaultEngineRound4Tests.swift` in "shared vaults through the session", the end of
`AdversarialSyncEngineReviewTests.swift` in "sync log", `DeviceIdentifierTests` in the crypto tests and the stream index
suite). Device IDs commit to their account: known answers from Python's `hashlib`, and a registry counts in a shared
vault only the devices whose IDs commit to it, another account's listing of one (under its own key or the device's)
counting for nothing (`knownAnswers`, `committedDevicesOnly`, Z157). A stream holds one account's segments in any order
of arrival (`oneAccountPerStream`). A writer's segment in a promoted member's stream verifies nowhere, before and after
a rotation, on the victim's device and others, and versions that saw the victim's edits count there
(`plantInAPromotedMembersStream`, round 5's M1); a removed member's plant at a new device's segment 1 and revocation of
its ID retire it nowhere, and its work arrives once the object is gone (`removedMemberRevokesANewDevice`, M2); the
Z46, Z51, Z120, Z137 and Z146 tests (`segmentsInAnotherMembersStream`, `streamOwnerForSomeoneWhoJoinedAfterARotation`,
`anotherAccountsSegmentIsNeverRecorded`, `replayRequestedDuringAReplay`, `readOnlyMemberPlantIsSteppedOver`,
`readOnlyMemberPlantAtSegmentOne`) check that another account's object squats like junk, says so, loses nothing and is
stepped over by nobody. A device restored to an older state in a vault that keeps its whole log publishes above what
its own account's other device merged, never at a number that device read, and a member's claim moves nothing
(`restoredStateAboveItsOwnAccountsWitness`, Z159). What an owner's collected stream carried of one record bounds no
claim about another (`collectedOwnerStream`, Z160). A registry that cannot be read takes nothing out and settles
nothing (`unreadableRegistrySettlesNothing`, Z161).
The review of the sixth round (`06-adversarial-review.md` Z162 to Z166; `AdversarialSharedVaultDeviceIdentityTests.swift`
in "shared vaults through the session", the end of `AdversarialAccountReviewTests.swift` in "account enrolment and
device registry", the end of `AdversarialSyncEngineReviewTests.swift` in "sync log", `DeviceIdentifierTests` and the
stream index suite). A device whose ID does not commit accepts no invitation, writes and moves nothing into a shared
vault, publishes nothing there and says so (`nonCommittingDeviceTakesNoPart`); a copy an earlier build published there
holds the original's deletion back, so the account's other device keeps the original (`moveByANonCommittingDevice`,
round 6's L-M1); a device of an account from before IDs committed does not share (`legacyDeviceDoesNotShare`); an
identity whose ID does not commit is neither approved nor enrolled as (`approvalRefusesNonCommittingIdentity`,
`enrolmentRefusesNonCommittingIdentity`, Z162). A device that published above a witnessed floor merges its own
segments below it once a lagging listing shows them (`ownSegmentsBelowTheFloorMergeWhenListed`, Z163). The member whose
object holds a device's next number is named, junk names nobody (`plantInAPromotedMembersStream`,
`removedMemberRevokesANewDevice`, Z164). An ID two registries list counts in neither in either order
(`listedTwiceCountsNowhere`), and a stream forgotten leaves the index of a device that never recorded it
(`forgottenStream`, Z165). The review of the seventh round (Z167 to Z169): such a device restored onto other hardware
keeps the move's deletion parked, reported, until the copy is moved out from the new ID, which then goes out first
(`restoredNonCommittingMove`, Z167); the package's test hooks are refused outside their file and test support
(`test_unsafe_tripwire.py`, Z168); a device key that cannot be read for a moment refuses as a retry and publishes
nothing that sync (`unreadableDeviceKey`, `deviceKeyUnreadable`, Z169). The review of the eighth round (Z170 to
Z172): a second restore keeps the deletion parked (`twiceRestoredNonCommittingMove`, Z170); the original deleted again
while its move's deletion is parked does not go out, and the report names the copy (`deletionWhileParked`, Z170,
Z171); the notice names the copy, its vault and the way out (`copiesReachedNobody`, wording, Z171); the tripwire
refuses a hook split over lines, backticked, unapplied, the session's state and the initialiser, and a new line in a
defining file (`test_unsafe_tripwire.py`, Z172). The review of the ninth round (Z173 to Z178): a writing member's
clock claim, or a value relabelled, naming another account's non-committing ID holds none of its deletions back
(`clockClaimHoldsNothingBack`, Z173); a lock while the report is made names no copy, and a directory that cannot be read
then keeps the report (`lockWhileReporting`, `unreadableDirectoryWhileReporting`, "Vault session: the copies nobody
received, in the sync report", Z174, Z175); a lock clears the Devices screen's summary (`syncSummaryClearedOnLock`,
Z176); parked deletions that cannot be read fail a restore's registration rather than stranding
(`parkedDeletionsUnreadableAtRegistration`, Z177); a copy of an allowed line in its file is refused
(`test_unsafe_tripwire.py`, Z178). The review of the tenth round (Z179 to Z184): a writing member's version superseding,
or deletion claiming, the values of a copy under this account's unreceived ID is held aside and the copy and its parked
deletion stay (`supersedingClaimOverAnUnreceivedCopy`, `erasureClaimOverAnUnreceivedCopy`, Z179); a clock claim naming
this device's own non-committing ID holds none of its deletions back (`clockClaimNamingThisDevice`, Z180); a restore's
move of its old ID's deletions that fails once is made again at the next unlock, or at a sync, publishing nothing until
it is complete, and a move record the session did not sign moves nothing (`interruptedDeviceMigration`,
`incompleteMigrationPublishesNothing`, `plantedMigrationMovesNothing`, "account enrolment and device registry", Z181;
`migrationRoundTrip`, store contract); a failed registration leaves no device key behind
(`parkedDeletionsUnreadableAtRegistration`, Z182); a lock after the sync but before its summary is stored leaves none
(`lockBeforeSummaryLeavesNone`, `lockSignalGeneration`, "Screen models: devices", Z183); the empty state the move saves
verifies (`migratedStateIsSigned`, Z184).

**Implemented in milestone 3, the item's own metadata** (`AdversarialItemMergeTests`, suite "Adversarial: sync log,
item metadata"; the adversary is an insider device, or from milestone 4 a vault member, A4, who can seal any payload
that decodes): counts up to `UInt64.max` in stamps, clocks and line IDs (read as at most the record's version, so a
later edit still supersedes); removed note lines planted under the IDs of another device's next edit, made before it
merges the record; canonically equivalent spellings of one value; stamps whose vector omits their own revision; cyclic, dangling,
self-anchored and repeated note lines and a chain thousands deep; values filed under groups they do not belong to,
unknown groups and second spellings; repeated field IDs, devices and stamps, and stamps that claim to supersede each
other; records at the payload limit full of mutually incomparable values, or of copies of one note-line ID, under a
time limit; a clock naming thousands of devices, deleted (the tombstone must still be accepted); the semilattice laws
and "no honest value dropped unless a value of its group claims to supersede it" on randomly corrupted records
(widened nightly); erasure summaries that overflow, lie or do not decode; and records that open to different items.
`mergeOverThePayloadLimit` checks that the engine quarantines a version it cannot merge and carries on with the
stream (Y37). A tombstone whose summary names a far higher row (Y28), passes since the engine gives
the merger the tombstone's stamp.

**Implemented in milestone 3, with real keys** (`AdversarialVaultSyncTests`, suite "Adversarial: sync with real
keys", `VaultSession` as the keyring): a byte flipped anywhere in a segment sealed with AES-GCM and signed with
Ed25519; a genuine envelope signed by a key of the attacker's own, refused locked (Keychain copy) and unlocked
(keyset); a genuine segment moved to another stream or number, refused at download while locked because the name
is signed; an insider's record swap inside a validly sealed and signed segment, refused by the record's own AEAD
context; a locked device with no trusted key in the Keychain, which refuses everything (`trustedKeyUnavailable`)
until the next unlock; pending deletions planted in the local sync state (A8) — unsigned, badly signed, signed by
another key, or another device's — none of which is published; the sync adapter used after `lock()`; and the
keyring refusing to sign as another device. The Keychain item protection suite checks the new `accountSigningKey`
item like the others and that every item has its own account name. With the device registry the same suite
adds: the account key alone, and a device key alone, refused (each object needs both signatures); a registered
device writing in another device's stream; a revoked device's segments and snapshots, refused locked and unlocked
while what it wrote before arrives through a trusted device's snapshot; a registration the store withholds; and
records and a vault's description that do not cross from one vault to another. Member key substitution,
membership records, revocation of members and read-only enforcement are the sharing suite's, below, until sharing
is wired into the session and sync.

`WatchwordSyncTests`, "Sync engine: revoked devices" (fake keyring): a revoked device's objects not read and not
waited for; staged objects dropped; garbage collection resuming (Y6); snapshot election skipping it; what one
device had merged handed on in a snapshot; a revoked device's own engine publishing nothing. "Sync engine:
several erasures of one record": a deletion published although another device's later-stamped erasure is known
(W13), a second deletion by the same device of a version its first had kept, published although its stamp is
the lower (W18), and an erasure already applied not trashing a restored item again. "Item merge audit regressions"
adds the join of a record's erasures itself (`ItemErasures`): commutative, associative and idempotent in one
canonical encoding, an undecodable summary a deletion that had seen nothing, a version erased when the deletions had
between them seen it all, and the same item kept whichever deletion a device learned of first.
`WatchwordKitTests`, "Multi-device vault simulation" (`LongRunningVaultSimulationTests`, nightly at 700 steps):
real sessions over the eventually consistent server, several vaults, moves and copies, vault deletions, a device
enrolling mid-run and a device revoked mid-run with or without a password change; every device left in the
account converges, a device enrolling afterwards sees the same, no value anyone typed is lost unless a person
discarded it, and nothing typed reaches the transport.

**Implemented in milestone 4, session integration** (`AdversarialSharedVaultTests`, suite "Adversarial: shared
vaults through the session", real `VaultSession`s of different accounts over one `InMemorySyncTransport`): a removed
member's late writes, merged by a device the store had not shown the removal, taken out again there and counted by no
device, a member invited afterwards included, while what the cut held counts everywhere (S28); the same for a demoted
member, with no rotation; a grant of a stranger's key filed under the current key's ID, alone and ahead of the genuine
one; segments and membership records copied from one shared vault into another; a stream index altered in the sharing
state, and another account's saved ledger planted there (A8); a removal interrupted by `lock()`
while publishing its grants, resumed and completed by the next sync. From the integration's review
(`AdversarialSharedVaultAttributionTests.swift`): a late value relabelled as a remaining member's revision, and one
back-dated to its author's in-cut revision (S36); a late rename stored again by an unaware member (S37); a late
permanent deletion merged before the removal was known (S40); an invitation whose key ID is another vault's (S38); two
vaults listing one account with different keys (S39); a replay asked for by a late stream, cut short by a lock and
run after a relaunch (S41). From the fourth round (`AdversarialSharedVaultLateWriteTests.swift`): a late removal of a
note line, made through the session and from a modified client that names no writer (S32); a late discard of
retained values, back-dated to an in-cut revision, and a late history entry naming no writer (S43); and a demoted
member's late title, whose knowledge an unaware member's rename on top of it carried (S44). From the fifth round
(`AdversarialSharedVaultLateKnowledgeTests.swift`): a late version claiming the owner's future edits, which an unaware
member's rename on top of it carried (S46), and a permanent deletion of a copy that held a late write (S45); and
(`AdversarialSharedVaultTakeOutHygieneTests.swift`) the hygiene report of an item a take-out rebuilt (S47). Each is merged by a
device the store had not shown the record, written on top of, and counts on no device once it is shown, the two
devices holding the same item. For F4.7 and the review of its rule (`06-adversarial-review.md` §T,
`AdversarialSharedVaultRenameTests.swift`), each failing without its fix: a read-write member's rename, plain, above
the owner's later one and labelled as the owner's revision, held aside everywhere with the name unchanged and the
member's items counting (S53); a demoted administrator's late rename taken out again on the device that merged it and
on their own, the name they chose with the role kept; the same late name stored again by an unaware member's device
as its own row; an owner's, an administrator's and a promoted member's renames converging on every device, with the
session's refusals; a name written before its author's promotion, judged alike on every device at each head (S58);
an older name sealed again above the current one by a member and by a former administrator, and a description dated
above its row (S54); a name labelled as an administrator's revision and sealed by a member for a device that joined
after a rotation (S55); a former author publishing their own name again late to such a device (S56); what such a
device shows across another member's demotion, across the author's, and after the next rotation (S57); a device shown
a demotion before the stream it bounds (`demotionHeardBeforeTheNamesItBounds`); a late name on the device of an
administrator who joined after a rotation and learns of the demotion as it rotates, taken out before the re-seal
(S59, `lateRenameSealedAgainWhileRotating`); a read-write member's re-seal after a rotation, which owes nothing it
never seals (S60, `readWriteMemberResealsWithoutTheDescription`); a member's snapshot carrying a description row
labelled as the owner's rotation re-seal, refused on a newcomer's device (S61, `forgedDescriptionInAMembersSnapshot`),
and S61's second route, the same row one version up in a later segment of the owner's device's stream, published by a
device the member enrolled under that device's ID, which renames the vault everywhere if a segment's signer is not
asked for the role (S67, `forgedDescriptionInALaterSegmentOfTheOwnersStream`);
a forged rename at the version ceiling, after which an administrator's rename and a member's item still land
everywhere (S62, `forgedRenameAtTheCeiling`); a replay that saw the head move settling the head it began with
(S65, `replaySettlesTheHeadItBeganWith`), and the same race through `syncAll` with the head moving between the take-out
and the replay, where a demoted member's late write merged earlier would otherwise stay (S67,
`headMovedBeforeTheReplayThroughSyncAll`); and a member's deletion of the description, which erases it nowhere
(`descriptionDeletedByAMember`, a property that held before the rule). Below them, `ItemMergeWriterTests` (`WatchwordSyncTests`) checks that each of those
parts names its writer and that a merge's attributed parts are exactly its inputs', and
`LongRunningLateWriteSimulationTests` checks, over random histories, that a device that held late versions aside as
they came and devices that merged them and rebuilt from what counts hold the same item, with nothing late in it and
no honest version held aside. Scenarios S3 and S4 through the session are
`SharedVaultScenarioTests` (`WatchwordKitTests`). A chain stopped at a later format (§8.9) through the session is
"Vault session: a shared vault in a later format" (`WatchwordKitTests`): the vault read-only and reported, nothing
published, planned or left, the owner's device stopped too, a member who may still write merged; and, in this suite
(`AdversarialSharedVaultLaterFormatTests.swift`), a later record the store shows before the record it follows, offered
again until it stops the chain, and later records signed by a member or by nobody, which leave the vault writable.
From the end-to-end audit (`AdversarialSharedVaultShownKeysTests.swift`, Z40): a key directory that changes its answer
between the safety number shown and the pin, for each kind of evidence and for each entry point (`verifyContact`,
`invite`, `acceptInvitation` with a chain the store's own bundle signed, and the two screens' full-code fallback, which
replaced the comparison toggle at the merge with ADR 0010: V15, V38);
nothing is pinned, wrapped or joined. A shared vault with no ledger on the device
(`AdversarialSharedVaultWithoutLedgerTests.swift`, Z41): a member's second device after a rotation (no write, rename,
second genesis or vault deletion, nothing of its own in the log, then the invitation accepted there and the next item
sealed under the chain's key); the owner's second device, told by the marker, joining its own chain with the key the
directory gave it; a read-only member's device whose ledger, owner row or owner's pin was deleted; the store
withholding the marker while serving the granted key; a marker row deleted from the file and one planted; a sharing
state that cannot be read at unlock; and an invitation naming another owner refused on a second device. In "crypto
core", that the class of a vault key's wrap is authenticated (`grantedKeyWrapClass`). "Screen models: sharing" has the
vault's label and the accept screen setting it up. Sharing a vault that already holds work
(`AdversarialSharedVaultExistingVaultTests.swift`, Z42): one that two devices of the owner wrote to, where nothing is
held aside on the owner's device or an invitee's; and one whose log was compacted, which is refused. An addition and
the removal that undid it losing a fork together (Z43): through the session
(`AdversarialSharedVaultUndoneAdditionTests.swift`: the addition not replayed, no second grant, nothing sealed again
towards the key the outsider holds, the key reported and then rotated by the administrator's own next syncs, and what
the administrator wrote under the losing branch's key reaching the others, Z47), and in the ledger
(`AdversarialSharingUndoneAdditionTests.swift`, "sharing and membership": order and restart, a routine rotation ending
it, an addition that lost alone, a branch that added the member again); `LongRunningMembershipForkTests` compares
`exposedKeyHolders` across orders and batches with the rest. The deletion paths
(`AdversarialSharedVaultDeletionPathTests.swift`, Z44): a read-only member's permanent deletion, purge and move out,
each refused with nothing queued, then allowed once the member may write; and a move whose copy was written after a
demotion, whose deletion waits until the person discards the held-aside copy. A vault the account left
(`AdversarialSharedVaultFormerMemberTests.swift`, Z45): still a member and still on the share until the rotation, then
listed for what it is, not given to AutoFill, unwritable, and removed from the device by the person without anything
published; and a vault with no ledger not given to AutoFill. A stream's owner
(`AdversarialSharedVaultStreamOwnerTests.swift`, Z46): a member's device enrolled under the owner's device ID writing
into the owner's stream over an unpublished edit, held aside on the owner's device and everyone's, the stream carrying
on. "Screen models: sharing" has the texts (`sharingStatementsAreTrue`) and the left vault on screen.
From the review of those fixes (Z48 to Z59; each failed first unless its row in `06-adversarial-review.md` says
otherwise): a second device that cannot name a vault's owner and is offered an invitation naming someone else, the
held key that stands in for a grant only in one's own vault, and markers that disagree
(`AdversarialSharedVaultOwnerUnknownTests.swift`, which also records Z49's owner's-other-device residual as a known
issue); a share cut short after the marker, a genesis record the store lost, rows planted in the sharing state, and
the owner's other device taking a vault up by sharing it (`AdversarialSharedVaultInterruptedShareTests.swift`); a
stream's owner on a device that joined after a rotation, and the replay when an earlier segment changes it
(`AdversarialSharedVaultStreamOwnerReviewTests.swift`), with "Shared vaults: the stream index"
(`SharedStreamIndexTests`, `WatchwordKitTests`) for the index itself: order of arrival, refiling, unopened segments
and their completion, and the saved form. A key a dead branch says was handed out, a demoted administrator's branch
that removes and re-adds, and what is kept (`AdversarialSharingUndoneAdditionTests.swift`, Z53). The deletion gate
(`AdversarialSharedVaultDeletionGateTests.swift`): an entry planted under this device's name that must not stop its
deletions (Z54), and a second replay in one sync that must not publish the deletion a move's held-aside copy is
waiting on (Z55). A log the account's other device compacted after the vault was shared, which holds nothing of the
owner's aside and stops the first invitation, and the marker published before the chain
(`AdversarialSharedVaultLateCompactionTests.swift`, Z56), with the ledger's "its owner's alone" in "sharing and
membership". A deletion unpublished at a demotion, withdrawn and not published at the promotion
(`AdversarialSharedVaultDeletionGateTests.swift`), and a left vault's removal from a device that holds unsynced work
of its own, refused until the number is acknowledged (`AdversarialSharedVaultFormerMemberTests.swift`), with the
confirmation's text in "Screen models: sharing" (Z57). Claims of rows Z40 to Z47 that had no test of their own (Z58,
which also lists those still without one): every remaining write path under `ledgerUnavailable`, a marker outliving
its device's revocation and a newly enrolled device before its first sync
(`AdversarialSharedVaultClosedWritePathTests.swift`); the whole-log check by the device's own sync state; the
deletion gate's first clause; a key no record introduced; and, in "sharing and membership", both sides of an
invitation refusing evidence for a bundle other than the one shown.
From the second review of those fixes (Z59, then Z120 to Z125; each failed first unless its row says otherwise): a
member's new device led into another owner's chain, which never seals the account's items under that chain's key
whether the store then hands it the directory whole, the real key alone, or the real key alone with the other chain
naming its ID; a vault whose owner the account's devices disagree about held closed on both, ledger or not, across a
restart; and a device whose directory listing names the vault, or that has not listed it yet, refusing a stranger's
invitation (`AdversarialSharedVaultImpostorChainTests.swift`, Z59). A replay asked for during a replaying pass, driven
through sessions with an insider and a withholding store, and a chain that lists only its owner judged on a member's
device (`AdversarialSharedVaultReplayTests.swift`, Z120, Z124). The deletion gate with the saved index, or the set
itself, gone (`AdversarialSharedVaultDeletionGateTests.swift`, Z121), with the rows' saved form in "Shared vaults: the
stream index". The owner's other device taking up the listed chain without a sync, on every platform
(`AdversarialSharedVaultInterruptedShareTests.swift`, Z122). What `unsharedWork` counts, in "Shared vaults through
VaultSession" (`SharedVaultUnsharedWorkTests.swift`, Z123). Z48's `markShared` refusing a second owner and a revoked
device's marker starting no dispute (`AdversarialSharedVaultOwnerUnknownTests.swift`, Z125). Not tested: a quarantine
read that fails at the deletion gate (Z121).

**Implemented in milestone 4, protocol core** (`AdversarialSharingTests`, suite "Adversarial: sharing and
membership", real Ed25519, HPKE and AES-GCM; each test names its adversary):

- *Forged membership*: every single-bit flip of a genuine record; unsigned records, records signed with the
  attacker's key under an administrator's name, by an account that was never a member; a genesis the verified owner
  did not sign; a signature made under another `SignatureDomain`; a copy with a spoilt signature listed ahead of the
  genuine record.
- *Stale administrators and former members*: signing after demotion or removal; going back to an epoch at which
  they were still an administrator with a hash ground down to win (refused on a device that has the real chain, on a
  fresh device in either order, and corrected on a device shown only the attacker's branch); adding themselves back
  with a new record, the owner's old signature, or the old record.
- *Key substitution*: the directory substituting the invitee's key (caught by the comparison; nothing is wrapped),
  substituting a pinned contact's key (refused and reported), returning another account's bundle or a low-order key,
  substituting the owner's key towards an invitee; an administrator putting a key of their own under the invitee's
  account in the chain; an invitation to a vault ID already held under another owner.
- *After revocation*: the old vault key against records sealed since, also relabelled with the new key ID; an old
  grant replayed under the new key's name; a fresh grant of a planted key from a former administrator, from an
  administrator demoted since, and from an administrator of another vault; a former member asking for the new key;
  writes by a former member and by a read-only member reaching the store and counting for no remaining member; a
  write in another member's name.
- *Writes around a revocation* (the write cut, §8.7): a former member's write, and a demoted member's, aimed at a
  device the store has not yet shown the record (merged there, taken out again and held aside once the record
  arrives, never published by that device, read by nobody else); the same write sealed again by that device as a
  version of its own before it knew (refused everywhere for the work it carries); objects claiming places in the
  former member's own stream that the cut covers; a stream prepared in advance of which the removing device was
  shown only the end; part of a stream withheld from a member who joins later (delays, never widens); a cut on a
  record that ends neither a permission nor an administrator's role, a cut altered or over its bound; a removal
  displaced by a fork, whose cut still governs while it is owed; a former administrator's cut on a dead branch built
  from a genuine leave request; and for the vault's name (F4.7), a demoted administrator's branch from before the
  demotion, an altered cut, and an administrator who is not the owner ending another's role, none of which moves
  which descriptions count (`administratorStandingFollowsTheOwnersRecord`).
- *Fork and rollback*: a store serving an older chain; a saved ledger truncated, spliced, altered byte by byte or
  planted; a store showing two halves of a household different branches; a former administrator's rewrite fed a
  page, or an object, at a time in any order; a record signed on a stale head and released after the chain was built
  on (displaces nothing) or before (the removal it displaces is owed, the member's writes stay refused, nothing is
  re-sealed towards their key, and another administrator carries it out again); a stale device of the owner's, one
  record and two; removals a former administrator signs on a dead branch (owed by nobody); a member invited back
  while the store hides everything since their removal.
- *Role escalation*: every way a member or an administrator can sign for more than their role, including roles
  changed on the side inside another operation's member list; an administrator using up the chain's epochs.
- *Leave requests*: replayed after the member was invited back, into another vault, relabelled, or signed by
  someone else; a genuine request behind thousands of junk objects in the leave directory and hundreds filed as the
  member's own.
- *Two administrators*: removing each other at once (nobody is removed, the owner can still act); the owner's
  removal of an administrator against that administrator's own record at the same epoch, in every order.
- *Names and proposals*: a predictable record's object created first with a signature nobody made (a role change
  and a deletion); a change that loses a fork proposed again by its author's device.
- *Pins against the chain*: a member removed and added back under the same account ID with other keys: reported,
  nothing wrapped to them by a rotation or a grant, a stale comparison refused, resolved by removal or by replacing
  the pin.
- *Local state*: pins planted in the contacts store; a rotation plan altered byte by byte, with the departing
  account replaced, or planted (another administrator's, a stranger's, re-signed).
- *Oversized and malformed*: seeded damage to every format (throws, or returns exactly what the bytes say);
  megabyte inputs to every parser; inflated counts; tens of thousands of candidates in one call; thousands of junk
  objects in the membership directory, some shaped like the next record (the next record is still adopted, and the
  flood is paid for once); a flood of unsigned records naming a reused key (one signature check each, no walk); a
  comb of signed branches reusing one key ID (work bounded by each record's own path); grant objects filed in a
  member's own grant directory.

Beside the adversarial suite, `LongRunningMembershipForkTests` holds the property the fork rule is built on: over
randomly generated histories with forks at many depths (stale owner and administrator devices), a ledger fed random
subsets in random order, with repeats, is at every step exactly what a fresh device makes of the same records, and
ends equal to the ledger fed everything at once (`orderAndBatchingDoNotMatter`; the nightly `test:long` widens it).
`SharingScenarioTests` covers what a demoted and a removed member wrote reaching those who remain and a member
invited afterwards, and two concurrent removals ending with both members gone.

Known answers for the formats (records, hashes, a leave request, published bundles, the fingerprint code) come from
an independent Python implementation (`SharingKnownAnswerTests`). Still to come with integration: the same
adversaries against `VaultSession` and `SyncEngine` (a former member's *segments* refused in `SyncKeyring.verify`,
read-only writes refused by the transport fake), and anything that depends on the device registry.

### 6.5 Interchange (milestone 7)
- Zip-slip entry names, nested zip bombs beyond the ratio cap, 1PUX with 10^6 items, CSV cells
  starting with `=`, `+`, `-`, `@`, a tab or a carriage return (imported and exported byte for byte,
  never neutralised: owner decision, 2026-11-16), rows with embedded
  newlines/quotes, invalid UTF-8, BOMs, and a 2 GB declared size → bounded time and memory, no
  crash, clear error.
- CXF payloads with unknown types, duplicate IDs, and oversized blobs.

Done in milestone 7, as "Adversarial: import parsers" (`AdversarialInterchangeTests`, adversary A7), with
every case above and the attacks a parser author would add to them (and, from review §Z, a file whose small rows
store as large items failing on the import-wide stored-size budget, Z81, which the fuzz harness's `check` asserts
too; dates beyond the clock and an archive's AutoFill state, Z85, are in "Adversarial: interchange through the
session"):

- ZIP: twenty-four escaping member names (four of them hiding a separator before a combining mark, which a
  check by characters does not see), in an archive whose wanted member is a good one; undecodable and empty
  names; a bomb that is honest about its size (refused on the declaration), one that lies (stopped at the
  lie) and the bare stream (stopped at the ratio); declared sizes of 2 GB and 4 GB; a nested archive that is
  never opened and a nested bomb; overlapping members; more members than the limit; encryption, ZIP64,
  multi-disk and nine unknown compression methods, each refused by name; archives that can be read two ways
  (repeated names, local headers that disagree, a wrong CRC-32, a directory that is not where the end record
  says, trailing bytes); and every prefix and every single-byte change of a valid archive, each ending in a
  typed error or the true contents.
- DEFLATE: hand-assembled streams for each defect (reserved block type, stored-length mismatch, a distance
  before the start of output, reserved symbols, too many codes, missing, incomplete and over-subscribed code
  sets, a repeat with nothing to repeat, a run past the declared lengths, a block that cannot end), every
  prefix of valid streams, and seeded random damage.
- `www` hosts (owner decision, 2026-11-16): `www.example.com` gains `example.com` beside it, with the same
  subdomain setting, and the report says so; `www.co.uk`, `www.github.io`, `www.1.2.3.4` and `wwwexample.com`
  gain nothing; `www.www.example.com` gains `www.example.com` and nothing more; an apex the entry lists itself is
  not an addition; opting out (`matchApexOfWWWHosts: false`) keeps exactly the recorded host; a merge into an
  item scoped `www.example.com` offers `example.com` as a choice and never adds it unasked (`ImportMappingTests`);
  every apex a random URL yields passes the scope policy (`importedScopesPassPolicy`, and the `host` fuzz target).
- CSV: formula payloads (and values with an apostrophe already in front) imported, exported and imported
  again byte for byte (`formulaInjection`, `formulaCellsAreExact`); record structure hidden inside quoted cells;
  invalid UTF-8 and UTF-16; a byte-order mark before the header; an unterminated quote, an over-long row, too
  many columns and 50,001 rows, each stopped at its limit; a file over 100 MB refused in every format before
  it is parsed.
- 1PUX and CXF: 10^6 items; 200,000 levels of nesting wherever it can sit; oversized items skipped while
  their neighbours import; a flood of warnings capped; repeated keys refused; hostile URLs that never become
  scopes, and the property that every imported scope passes `ScopePolicy`; an entry that names an existing
  item's identifier, another vault, a version or a trash date, none of which reach the draft; unknown
  credential types, repeated identifiers, an oversized key and a bomb in a passkey's large blob; a collection
  tree built to multiply its own size; and one-time passwords that could not work, which never become working
  fields.
- Every parser over seeded random and mutated files: a value or an `InterchangeError`, nothing else.
- Amplification, added after the module's first security review: a CSV file inside every per-entry limit
  stopped at one million fields under the standard limits, and one a thousand columns wide stopped at its
  header; a URL repeated 999 times in each entry parsed once, distinct URLs capped per entry and per file with
  the rest kept as fields and reported; 100,000 empty dynamic DEFLATE blocks (valid to zlib) refused bare
  and as an archive member of any declared size, as is a stream of one literal per block; entries that are
  small as written and megabytes as stored (control characters, quotes, slashes, a quarter of a million
  blank lines, 990 fields, 900 earlier passwords) skipped and listed, with every draft that *is* returned
  stamped by `ItemMerge.stamped` and encoded by `ItemCodec` within its limit; and, as a seeded property,
  the stored-size estimate never below what the vault encodes.
- Duplicates: a hostile entry sharing one host and user name with an existing item, merged, leaves the set of
  hosts on which `AutoFillGate.decide` fills that item unchanged and adds no sign-in field; the match names
  the host the file tried to add, and only a host accepted by name is added. Merging notes built to make a
  string search quadratic completes in one pass.
- Duplicates, through an export (added after the second review): the same entry with URLs an import keeps
  as text (a sign-in page, another port, a look-alike subdomain, a URL the policy refuses, a link in a
  section), merged with nothing accepted, leaves the existing item equal to what it was; merged with every
  URL accepted and no host, it leaves the sign-in URLs of the 1PUX, CXF and CSV exports (read off the files'
  own structure) and the hosts on which `AutoFillGate.decide` offers the real password after export and
  re-import unchanged; with the host accepted by name, every sign-in URL written derives to a scope of the
  item. An item with no site is given none by a merged link, in any export. An item holding a website field
  for a host it is not scoped to (a removed scope, a shared-vault member's write) exports no sign-in URL
  for that host and reports it, in every format, and website fields beyond the per-entry URL count are not
  written as sign-in URLs.

Done with the session wiring (`02-architecture.md` §14.1), as "Adversarial: encrypted Watchword archive"
(`AdversarialArchiveTests`; adversaries A1, holding the archive file, and A7, handing one over) and
"Adversarial: interchange through the session" (`AdversarialSessionInterchangeTests`; A7 and A3):

- An archive cut anywhere, extended by a byte, shortened by a whole entry with its count rewritten, its
  entries reordered or relabelled, an entry spliced from another archive, and a vault item record put where an
  entry goes: each refused by the parser, before any key is derived.
- KDF parameters below the floor and above the ceiling (and a salt below its minimum) refused before
  deriving; a count no file could hold refused before anything is allocated; parameters inside the bounds
  but altered change the key.
- A wrong passphrase, an empty one, a wrong Secret Key, and one changed byte in the creation time, the salt,
  the wrapped key, the manifest or an entry: all one `CryptoError.authenticationFailed`.
- An archive of another account opens only with that account's Secret Key, and cannot be relabelled as this
  account's.
- An archive made under the attacker's own account and handed over with its Secret Key, naming an existing
  item's ID, the victim's vault, huge sync counters, a planted conflict and a scope the policy refuses: imported
  as a new item, with a new ID, in the chosen vault, scoped as the policy allows, stamped by this device alone,
  the existing item untouched.
- A CSV entry matching the bank item, with an attacker's password and a sign-in URL leading to the attacker's
  site, merged without choices, adds nothing that signs in or is offered anywhere, and a later export names no
  other host.
- No plaintext export and no archive without the account password; a preview's drafts gone with a lock, and
  neither `importAdditions` nor `commitImport` reaching them after the next unlock.

- An archive this app wrote restores past 50,000 items and with an item between 768 KiB and 1 MiB stored, and
  what a restore would still not bring back is found when the archive is made (`WatchwordInterchangeTests`: "Items
  from an encrypted Watchword archive"; `WatchwordKitTests`: "the archive's limits are the vault's and the format's
  own", Z82); a staged export left by a process that died is removed by the next launch's sweep, and by every lock
  whatever the model remembers ("Screen models: staged files", Z80); the plaintext export's bytes are the session's
  `SecureBytes` (Z83); only the person's own trash is left out of a plaintext export ("Export reports", Z87).

Still to come: that the file is written with the protection class §14 names (the app's part, *Mac only*), and that
the sweep at termination runs (by hand: stage an export, quit or kill the app with the mover up, relaunch, and list
the container's `tmp`).

### 6.6 Hygiene (milestone 6)
- HIBP responses with padding, missing padding, non-hex lines, huge bodies, HTTP 429/5xx; the
  client never sends more than 5 hex characters and sets the required headers (asserted on the
  fake).
- With keys absent, the scheduler performs no hashing and persists nothing derived from passwords.

**Implemented in milestone 6** (`AdversarialHygieneTests`, suite "Adversarial: hygiene and breach checks"; the
adversaries are in `02-architecture.md` §13.1). Every request is asserted on `FakeHTTPClient`, which records what
a real adapter would have been asked to send:

- *The service and the network path.* Over a full scan, a weekly re-scan and retries after 429, 503 and a
  dropped connection, every request is exactly `GET https://api.pwnedpasswords.com/range/<five hex>` with exactly
  `Add-Padding: true` and the `User-Agent`, and no request contains a sixth character of any digest; redirects and
  URLs in bodies never produce a request to another host; a scan never sends an email address or contacts the
  breached-account API; an API key, address or version string cannot inject a header, a path or a host. A 200
  that cannot be read (empty, HTML, JSON, 60,000 lines) is never "not breached"; a listed suffix is found
  wherever it is in the range and a near miss is not; `Retry-After` of zero, a negative number or 10^12 neither
  spins the scanner nor stops it. An hour of locking and unlocking every minute after a 429 with
  `Retry-After: 3600` sends nothing more, and a lock does not buy a new burst; refusing one range (503, or a
  dropped connection, every time) does not stop the other items being checked, and the refused range is retried
  at the backoff's pace, and the same holds for a vault unlocked for 20, 45 or 300 seconds every ten minutes
  for a day, with the ledger carried by the session and the process either kept or new at each unlock (503, a
  dropped connection, or a page of HTML with status 200): every other item is checked by the second unlock; a breached-account response of 160,000 tiny breaches is refused at entry 2,001, without
  decoding what follows.
- *Readers of the device at rest (A2, A3, A8).* With keys absent the schedule answers `.locked` for any ledger and
  items and does not touch the ledger; the engine refuses every entry point that hashes or hands out derived
  data, touches neither network nor cache, and has zeroised the reuse key; a lock while a request is in flight
  drops the response (nothing cached, ledger untouched), including when the vault is unlocked again before the
  response arrives; the ledger's encoding holds no hash, prefix or token, and the types that do hold
  password-derived material are not `Encodable`; digests, tokens, keys and the API key print as redacted, and so
  do strength estimates (the rank of a common password names it), analyses, range prefixes, cached ranges,
  ledgers, the email address, URLs and header values; a planted cache entry that is misfiled, post-dated or
  stale is not believed. After a lock the default prefix cache holds no prefix, including when the lock lands
  while a range is on its way into the cache. A lock during `unlock` completes after one item's analysis, not
  the vault's (asserted with a gate between items, three items into five hundred), and a cancelled unlock
  leaves the engine locked with the reuse key zeroised; cancelled over an engine that was unlocked, it leaves
  no prefix in the cache either.
- *A malicious household member (A4).* Two thousand new items produce at most the burst and then one request per
  spacing, and a save cannot bypass the limit; one item with 3,000 password fields, megabyte passwords and a
  megabyte title costs sixteen checks and is paid for at the usual rate, and is reported `incomplete`, never
  clear; a breached password cannot hide behind a duplicate field ID or beyond the per-item cap; a stale copy
  of an item cannot mark its newer, breached password as checked; a password of combining marks and look-alike
  digits costs no more dictionary work (counted in table steps) and no more than ten times the time of a
  password of words, measured against it in the same run; text from the breached-account API is stripped of
  control and bidirectional characters and never carries the service's HTML.

**In the session** (`AdversarialSessionHygieneTests`, suite "Adversarial: hygiene in the vault session";
`02-architecture.md` §13.8): after `lock()` the engine holds nothing (ledger, reuse lookups and report refused),
already when `lock()` returns, before any task it queued has run (L2); the
session's device-local key and its record of what the engine saw are gone, the sealed cache answers nothing, and
every byte in the device-local store is ciphertext (no record magic, ledger key, item ID or prefix in hexadecimal),
under names that are keyed digests; a scan whose response is held until after the lock reports `interrupted`,
leaves the device-local store byte for byte as it was, and after the next unlock the item is still due and is
asked for again; the device-local key differs per device of an account and per account, and from a key derived
with this device's ID but another device's secret, is never the raw key, and a sealed record opens neither under
another device's or account's key nor under another name; a ledger and range planted from another account's device
under this device's names, for an item given the same ID and version, are not believed; a holder of the account's
keyset that knows this device's ID can neither open its ledger nor plant one saying a breached password is clear
(L1); an older ledger of this device's own, put back, defers no check (L3); a range cached for one vault does
not answer a check in another, so a member's probe items always go to the network (Z88); and sealed range records
have one length whatever their range holds (Z89). Functional: "Vault session: hygiene" (reports, reuse, an edit due at once, rows the
sync engine wrote reconciled, the ledger and cache surviving a relaunch, eviction and erasure with the account,
the device secret kept in the Keychain and its loss making the sealed records open as nothing).

The functional suites (`WatchwordHygieneTests`) cover: SHA-1 prefix and suffix and the reuse HMAC against
vectors from Python's `hashlib`/`hmac`; the parser on padded, unpadded, malformed, oversized and
line-limit responses; cache expiry, `freshAfter`, the cache codec and its damage cases; every status class;
the schedule's table (create, edit, changed since last scan, weekly, resume after a lock, pacing, jitter,
backoff, per-item retry, clock rollback, a failing item going to the back of the queue, a pass that cannot
finish not blocking the next, a pass start slightly ahead of the clock, pacing handed on across a lock, a
refused range across locks and across restarts, a failure's time of its own holding for its version only, the
bound on failures kept, an interrupted scan paying for its requests, `Retry-After` bounded in the schedule
itself, and after a clock is put back thirty days: a backoff, the weekly jitter and an item's own time each
waited for once and within the policy's bound, and a failure dated ahead not keeping its item at the back) with
`FakeClock`; the ledger's codec, with failures, and its damage cases; the estimator on known-weak and known-strong passwords (including a word, a year and a symbol,
and keyboard columns and zigzags, none of which may score strong), generated passwords and passphrases, each
pattern's explanation, the embedded lists' counts and uniqueness, the word table, and bounded time and
bounded dictionary steps on hostile input; reuse, age, `http` addresses, the site directory; the report's
severities, ordering, determinism and totals, and `incomplete`; the breached-account parser's leniency and
its bounds; and the engine end to end, including stale copies, a save during a scan, a copy from before a
trash or deletion, an unlock still analysing, a second unlock superseding the first, a failed check in the
ledger and out again, twenty scans each interrupted by a lock at one instant sending no more than the burst
(whether the vault is unlocked again before or after the response), a `Retry-After` that arrives just after a
lock still honoured, and an unlock over an unlocked engine locking first (and leaving the engine locked with
an empty cache when it then fails).

**Synced results** (`02-architecture.md` §13.9; ADR 0005, amendment of 2026-11-16; owner decision 10).
Adversarial (`AdversarialSyncedHygieneTests`, suite "Adversarial: synced breach-check results", real sessions of two
accounts sharing a vault): *a current member (A4)*, who can read the password, syncs a "not found" for a password the
owner's device found breached, dated ten years ahead and then fresh every day for forty-five days: the owner's device
shows the breach as its own finding throughout, checks again one pass after its own last check (the far-future time
postponed nothing), and makes its own check within the deferral limit plus a pass; an observation the member forges in
the owner's device's name is held aside by the write judge and changes nothing. *A former member (A5)* whose store
withholds the removal reports a breach after it: the owner's report stays clear and the version is held aside (S28).
*A4 again* trashes and restores the item, or takes its password out and puts it back, and then reports it clear: the
owner's device still shows the breach as its own (review finding N1, `removalCannotEraseAnOwnBreach`).
Functional: "Synced scan results" (`WatchwordHygieneTests`): the binding against Python's `hmac`, and bound to one
item, one password and one key; the record's canonical encoding and every damage case (trailing or missing bytes,
magic, devices out of order, a revision above the record's version, too many results); the join per device and its
laws (commutative, associative, idempotent, bounded) over random records; erasure keeping only later observations;
evidence matched by password, ignoring this device's own observations and keys it cannot derive; and the engine: a
synced check standing in for this device's (nothing asked, the source labelled), a changed password rechecked, an edit
that keeps the password keeping its result, this device's own breach never hidden, a reported breach outlasting a later
synced "not found" until this device's own check, a report older than this device's own clear check not taken in,
future times ignored or counted as now, postponement by at most an interval, the deferral limit under a daily
"not found", that limit and this device's own breach kept through a trash and restore or a password taken out and put
back (N1), no deferral for an item the ledger has no room to mark (N2), the ledger's binding key no reuse token (N3),
and the ledger's new keys round-tripping. "Vault session: synced hygiene" (`WatchwordKitTests`, two
devices of one account): B does not repeat A's check and labels it A's; a breach A found reaches B; a password changed
after A's check is checked again on B and A then takes B's result; checks and their sync add no item version, history
entry or conflict on either device over two passes; deleting an item deletes its results on every device.

The regression tests added after the first review of this module for the scheduling, locking, staleness,
report, parser and rating faults were each checked by putting the fault back and seeing the test fail; the
estimator's cost was measured before and after with the same inputs (`02-architecture.md` §13.4).

Not covered, and why: no test calls the live service, and the fixtures are written to its documented format,
not captured from it (it is not reachable from a cloud session); a capture on a Mac is open in milestone 6.
The comparison's constant-time property is by construction and review, not measured. The `URLSession`
adapter's obligations are §6.10's, run on a Mac only; a compressed body expanding past the limit and "nothing
logged" are not tested (a URL-loading stub bypasses URLSession's own decoding, and logging is by review).

### 6.7 Phishing resistance (PRD F11)

Implemented in `Tests/WatchwordAdversarialTests/AdversarialPhishingTests.swift`. Two distinct
guarantees, tested separately, because passing one and failing the other still harms the person:

*Nothing is released on a look-alike host.* For each of `arnazon.com`, `amaz0n.com`,
`аmazon.com` (Cyrillic), `amazon.com.evil.example`, `secure-amazon.example`,
`amazon-login.example`, `amazom.com`, `xn--mazon-1nf.com`, `firstbank.co.uk.evil.example`,
`firstbamk.co.uk`:
- `AutoFillGate.decide` does not return `.fill`;
- `AutoFillGate.authorize` refuses for *every* item, including when a (hypothetically buggy) UI
  asks for one explicitly;
- `authorizeOneTimeCode` refuses, so a replayable TOTP is never released.

*The person is warned rather than left in silence.* The same hosts must assess as `.suspicious`
with at least one signal; the nine that resemble a specific saved site must also name their target
via `impersonatesSavedSite`, so the warning can say which site is being imitated. Punycode is
flagged with the weaker, unnamed warning because it cannot be decoded without an IDNA table.

*Warnings stay credible.* `example.com`, `wikipedia.org`, `news.bbc.co.uk`, `some-startup.io`
assess as `.unrecognized`; `amazon.de` and `amazon.co.jp` are not flagged against a saved
`amazon.com`. A false-positive regression fails the build just as a false negative does — a
warning people learn to dismiss is not a control.

*Machinery.* Skeleton equivalence for confusables and digraphs; per-label mixed-script detection
(the whole-host version flagged every legitimate IDN and was caught by test, review finding C4);
distinctive-label extraction across public suffixes; bounded edit distance.

*Scope policy.* `com`, `co.uk`, `github.io`, `herokuapp.com`, `localhost`, `appspot.com` refused;
`amazon.com`, `firstbank.co.uk`, `signin.aws.amazon.com`, `tenant.github.io` accepted. One test
asserts the matcher *would* have matched an over-broad scope, so the policy test keeps its meaning
if the matcher changes.

*Normalisation (F11.6).* In `HostNormalizerTests`: ASCII percent-escapes rejected, non-ASCII
escapes accepted, zero-width/bidi/soft-hyphen rejected, over-long hosts and labels rejected,
user-info rejected, and the IDNA compatibility mapping asserted as honoured so a future
"hardening" change cannot silently break legitimate matching. A host normalises alike as a domain and as a
URL (fullwidth, Kelvin sign, ideographic full stop, compatibility characters), a non-ASCII domain the URL
parser cannot read is refused, and the `host` fuzz target checks the same agreement on arbitrary input.

*At the request model (milestone 5):* "no override" is a property of `CredentialProviderModel`'s API, not of a
view: there is no call that releases after a refusal, which `AdversarialAutoFillRequestTests` checks request by
request (§6.3).

*At the session and screen model (review findings Z61, Z62, Z65):* F11.7 is enforced in
`VaultSession.save`, which refuses a host a save adds that resembles a saved site, or cannot be read
by eye, unless the caller names it as confirmed; `AdversarialItemEditorTests` ("Adversarial: account
screens") holds the refusal, the question naming the site and the item, and that an ordinary host asks
nothing. An import entry that would hide or stand beside a saved account, in any vault, or name a
look-alike, is refused at commit without a decision (`AdversarialImportTakeoverTests`, "Adversarial:
interchange through the session"), and `InterchangeScreenTests` drives the screen model. Look-alikes are
judged against `SavedSites`, the gate's own view (`MergeHostTests`: a trashed item, a policy-refused scope
or a member's item scoped to the look-alike recognises nothing).

*From the review of those fixes (Z70 to Z79):* every other write path that adds a host is held the same way, in
the session: a merge's accepted hosts (`AdversarialImportReviewTests`, "a merge that adds a host taking over
another saved login…"; the merge screen's second confirmation in "Adversarial: account screens"), a copy or move
out of a shared vault (`AdversarialSharedVaultTransferTests`), the credential-vault save
(`AdversarialAutoFillPublicSurfaceTests`), trashed import entries and look-alikes within one entry
(`AdversarialImportReviewTests`), and only the item's own trust domain vouches for a host being added
(`AdversarialAutoFillReviewTests`). The keyboard's suggestions are withdrawn where the two trust classes meet at a
host, and a member's passkey beside the person's own is not suggested (`AdversarialAutoFillReviewTests`); every
write made for a remote party has the item budget (`AdversarialLargeBlobTests`, `PasskeyRequestTests`).

*Still to come:* a UI test that the AutoFill extension presents no override affordance on a
suspicious host, and one that drives the editor's F11.7 dialog and the import's concern section on a
Mac (milestone 5). Milestone 2 enforces F11.2 at the vault boundary: `VaultSession.save` refuses
over-broad scopes whatever the UI sends.

### 6.8 Fuzzing (nightly)
- libFuzzer harnesses for the envelope decoder, CBOR item decoder, CSV parser, 1PUX JSON mapper,
  `otpauth://` parser, and `HostMatcher.normalize`.

Done in milestone 7: the `Fuzz/` package builds one executable, `WatchwordFuzz`, with fifteen targets
selected by `WATCHWORD_FUZZ_TARGET`: `csv`, `password-csv`, `inflate`, `zip`, `1pux`, `1pux-archive`, `cxf`,
`amplify`, `envelope` (`Envelope.parse`), `sync-payload`, `signed-object`, `host` (`HostNormalizer` and the
import's scope derivation), `otpauth`, `passkey` and `archive` (`AccountArchive.parse`, everything checked before a key
is derived; its seed is the archive an independent implementation wrote), and since ADR 0010 a sixteenth,
`sharing-code` (what a vault sharing code session reads from the camera, a keyboard or the board: `ScannedSharingCode`,
`FingerprintCode`, typed numbers and codes, and the three board messages, each held to its one spelling). Each target runs a parser over arbitrary bytes and then checks
what must hold of anything it accepted (a CSV file re-reads as itself, an export re-imports and names no
host that no exported item was scoped to, an inflated
stream is within its caps, every imported scope passes `ScopePolicy`, every one-time-password and passkey
field decodes, an accepted envelope serialises to its own bytes); a broken invariant traps, which is a
finding. `mise run fuzz` builds it with `-sanitize=fuzzer`, splits its time budget between the targets,
reads the committed seeds in `Fuzz/Corpus/<target>` and writes findings to `artifacts/`. Built without the
sanitiser the same executable replays inputs (`WatchwordFuzz replay <target> <file>`), which reproduces a
finding on any toolchain, and mutates a corpus blindly; the task falls back to that, with a warning, where
the toolchain has no libFuzzer runtime (`--require` fails instead). Item payloads are JSON decoded by
Foundation after authentication (§5), so there is no CBOR item decoder to fuzz; the canonical CBOR encoder
has no decoder at all.

Those targets run with limits a hundredth of the standard ones and inputs of at most 64 KiB, which keeps a
run in the parsers and means they cannot see cost that only a large file incurs: a file that keeps every
per-entry limit and spends their product (the review finding that led to the import-wide budgets). Two
things address that. `amplify` reads its input as a recipe (a format, a repeat count and a unit) and expands
it to as much as 1 MiB of CSV rows, 1PUX or CXF items, or the URLs or fields of 1PUX items, imported under
the **standard** limits; what comes back must be inside the import-wide budgets and every draft inside the
stored-size bound, and libFuzzer's memory limit and timeout judge the rest. And `mise run fuzz --max-len
<bytes>` lifts the input length for a run aimed at one target.

The harness is a package of its own so that the shipped manifest does not know it exists; the dependency
and unsafe-confinement tripwires cover it (`07-supply-chain.md` §2). The first run found one defect, fixed
with a regression test and a seed: the CSV writer wrote a first cell beginning with U+FEFF bare, and the
reader then took it for a byte-order mark.

### 6.9 Account enrolment and the device registry (milestone 3)

`AdversarialAccountTests`, suite "Adversarial: account enrolment and device registry", real keys throughout.
Adversaries: A1 with the store, A8 with the local file, a revoked device that kept the keyset and its device key,
an insider device in hands that do not know the password.

- The published header (A1): KDF parameters out of bounds on either side refused before any derivation (SEC5,
  SEC9); a byte flipped anywhere stops enrolment; another account's header, as it is or relabelled, enrols
  nobody; an older header replayed beside the current one, in its place, and with the registry's record of the
  change withheld too; planted objects among the headers.
- The local header rolled back to before a password change (A8): refused even with the old password.
- The registry: entries the account key did not sign never admitted; a second genesis entry signed with the real
  account key; a revoked device registering again under its ID, under a new ID with its key, by enrolment with
  the old password, and back-dating a revocation of the device that revoked it — nothing of it counts once the
  password has changed; the stated limit of a revocation that keeps the password; a registered device announcing
  a password change without the password; a revoked device flooding the transport with 4,096 entries the account
  key signed (no parents, back-dated under its own key, in another device's name) — none is stored, the revoking
  device still syncs, a later revocation and password change still spread, a new device still enrols; the same
  flood in the names of puppet devices it registered itself — one registration with a garbage author signature,
  one signed by its own revoked key, and a second puppet registered by the first (`puppetFlood`, W26) — with the
  same outcome; an entry appended after a checkpoint trying to reorder the layer it sealed.
- The vault directory: a wrap copied or re-signed under another vault's name or another key ID, another account's
  wrap, deletions unsigned, by a stranger, copied from another vault, of the Personal vault, or vouched for by a
  revoked device; a vault description that is too large or has an endless name. Vault-key wrap rows edited in
  the local file (A8): one moved under another vault, one deleted, another account's planted with a directory row
  to list it — none opens, no vault is listed or written under a key that is not its own, the items are reported
  unreadable, and the next sync restores the genuine wraps from the transport.

Added by the audit of 2026-11-17 (`AdversarialAccountForkTests.swift`, the same suite; `06-adversarial-review.md` §Z,
Z1 to Z8), the adversary being a device revoked with a password change, a registered device in hands that know a
retired password, and A8:

- Password changes that are not the person's (Z1, Z8): a change made with the retired password under a new salt,
  sealing a back-dated revocation of the revoker, is refused when the retired password is typed, followed by
  nothing under `ignoringPasswordChange`, and described to the person (who made it, what it revokes); a chain of
  four changes under one device's name leaves the genuine one reachable by unlock and by enrolment; a change whose
  own history revokes the device is refused there; with four devices claiming a change, none of them registered
  before the checkpoint the device follows, the unlock reports that and the genuine one is followed by naming its
  device from an unlocked session; a fork made with a retired
  password does not open a device that follows the new one, and is followed only from an unlocked session.
- The list of pending changes (Z2): 96 planted credential entries, half without a valid signature of the previous
  generation's enrolment key, cannot keep the genuine change off it, over four seeds, asserting that sixteen sort
  first.
- A pending change outlives the file (Z3): with the candidate header's row deleted, that and the credential
  entry, a registry row the anchor names, or the header withheld on the transport, the retired password and quick
  unlock are refused; a sync restores what was taken and the new password is followed. The anchor's encoding
  round-trips its pending changes, reads the form from before it recorded any, and refuses anything else.
- Which vault is the Personal one (Z5): the account row redirected to another vault with the real one kept in view
  by a planted directory row, the same with the header row removed, and with the header row replaced by another
  account's, are each refused at a password unlock and at a quick unlock; a key that arrived by grant is never
  the Personal vault's key, on a store with neither header nor anchor.
- Another member's registry (Z6), through two sessions sharing a vault (`AdversarialSharedVaultMemberDevicesTests.swift`,
  suite "shared vaults through the session"): a member's laptop, revoked with a password change, forks the member's
  registry two generations long and writes into the vault as the member; the owner, who had followed the genuine
  change forward from where it first anchored, and another member who sees both branches at once, alike read
  neither contested device (Z12), keep what the laptop wrote while it was the member's and report it; comparing
  safety numbers again settles nothing, and the saved anchor stays where it was (Z11). And as a function over
  `RegistryFixture`: the member's own change followed when it is all there is; a forged branch two generations long
  ignored and reported once the genuine one is anchored at first sight; both arriving together followed by neither,
  with only the uncontested device counting; the forged branch alone followed and then held to, the genuine one
  reported; a disagreement settled by an earlier version not reported again and a new entry reported; a second
  genesis entry neither replacing nor removing the anchored one, and two anchoring neither; the saved anchors
  refused whole on any edit, another vault's ID or another key.

Added by the review of those fixes (`AdversarialAccountReviewTests.swift`, the same suite unless named;
`06-adversarial-review.md` §Z, Z9 to Z17):

- A header ahead of the anchor (Z9): the revoked device's change, made with the retired password and written into a
  laptop's file as its own header, is refused when that password is typed, whether or not the laptop had been told
  of the genuine change; with `ignoringPasswordChange` it opens and follows nothing, a sync moves nothing, and the
  new password still reaches the genuine change. A password change and an adoption interrupted between commit and
  pin are completed from the intent (a fork made with the retired password then stays a fork; a pending list does
  not outlive the adoption that followed it); an intent the file does not bear out is dropped if nothing was
  committed and is no licence if a planted header is there; the anchor's third form round-trips an intent and reads
  its second.
- Another member's registry (Z10, Z12): one refresh follows at most eight of a 20-change chain and the pin carries
  the rest over three refreshes; a lock while the replay is held off the actor takes effect at once and the replay
  is dropped ("shared vaults through the session"); a branch followed forward from the base loses its standing when
  a sibling arrives later beyond the base, the tip being kept; nine competing changes hold every device in question;
  the saved pins' second format carries the base, the first reads with the base at the tip.
- The way out of too many pending changes (Z13): seventeen puppets registered with the retired password, each with
  a two-step chain, neither fill the lock screen's three attempts nor push the genuine change off the list, which
  holds all eighteen authors, sealed first, sixteen described and the rest on request.
- Following a change (Z14): from a quick-unlocked session it takes the password the device follows (a wrong or
  retired one is refused and nothing moves); keys replaced meanwhile end with the new Account Unlock Key resident; a
  lock while a candidate's key is derived, from a follow or at the lock screen, takes effect at once and adopts
  nothing.
- Claims nothing held before (Z17): the flag tries no candidate; a sync keeps one header per author, its newest; a
  follow fetches a header no sync kept; sync's merge-and-publish gate asks the anchor when the file and the
  transport have lost the change (the test fails with that term removed); in "unlock and quick unlock", each quick
  unlock that opens the keyset takes its attempt back, and a released key that opens nothing destroys the
  enrolment.
- Tracked, as known issues: member pins deleted from the file are anchored again from the transport, base and all
  (Z15); a header name created first by someone else keeps the genuine header off the store (Z16).

Registry rules themselves, including the back-dating case the suite found, are in `WatchwordCryptoTests`
"Device registry" (among them `puppets`: entries relying on a registration that can never count — forged, by the
revoked device, sealed as void by a checkpoint, two puppets deep, or an enrolment under the revoked device's own
password change — are void and not retained, at the size limit too, while an honest device added after the
change still writes; and `manyKeysForOneDevice`: 2,048 registrations of one device ID under distinct keys and
2,048 entries descending from them all are void, and the evaluation's signature verifications, counted through
`DeviceRegistry.VerificationCount`, stay within two per entry, W27); P-256 device signatures (low-S only) and the enrolment key have known answers from Python
`cryptography`.

### 6.10 Apple platform adapters (milestones 3 and 6)

The adapters in `WatchwordPlatform` face the same adversaries as the ports they implement; each suite's doc comment
names its threat. One runs everywhere; the rest need Apple frameworks and run on a Mac only, so their lines in
`mise-tasks/test/adversarial-suites.txt` carry a `darwin:` prefix: required on macOS, where a rename fails CI as any
other does, and reported as not required on Linux, where they cannot compile.

- **"Adversarial: device-local store files"** (`AdversarialDeviceLocalStoreTests`, portable, listed). A8 with write
  access to the App Group container: a link planted under a record's name is neither read nor written through (the
  write replaces the link, the target is untouched); a store directory replaced by a link is refused, and erasing the
  account removes only the link; a link anywhere on the path below the container is refused; a record has one file
  name, and a case variant of it is a stray only on a case-sensitive volume (AD10); a sparse 8 GiB file is refused from its size before any byte is read; a planted
  directory is not a record; stray and look-alike names are never records and are erased; a truncated record reads
  back as exactly its bytes, for the session to refuse.
- **"Adversarial: Apple adapters: HTTP client"** (`AdversarialURLSessionHTTPClientTests`, Mac). A1 at the Pwned
  Passwords endpoint, through a real `URLSession` with a URL-loading stub in front of the network: bodies one byte and
  16 MiB over the limit refused; a server that never answers, and one that sends headers and a few bytes, given up
  on at the deadline (injected, already passed, so no test waits on a clock); redirects to another host and to plain
  HTTP never followed; a body that reaches the limit and keeps coming refused; time limits of infinity, NaN or less
  than nothing held to their range. Not covered: a compressed body (a stub bypasses URLSession's decoding).
- **"Adversarial: Apple adapters: iCloud Drive transport"** (`AdversarialCoordinatedFileSyncTransportTests`, Mac). A1
  writing the sync folder: a stream directory replaced by a link is neither listed, read nor written through under
  coordination; planted placeholders outside the layout are not objects, and one beside a present object changes
  nothing; an oversized object is refused. "Coordinated iCloud Drive transport" adds a read held past its deadline by
  another writer, given up as that object's failure alone. Renamed copies (`N 2.wwe`) planted beside an object are
  handed over as bytes, with a link, a directory and an oversized file among them counted and never read or deleted
  through; "Coordinated iCloud Drive transport" runs the copies contract and an engine reading the genuine object
  from behind a junk file under coordination. Not covered: `NSFileVersion` conflict versions and downloads by iCloud
  itself, which need a ubiquity container.
- **Conflict copies** (architecture §7.5; portable, Linux). *Transports* ("Conflict copies: transports"):
  `SyncTransportContract.singleCopies` on every transport and `heldCopies` on the in-memory, directory and simulated
  ones; only an exact `<name> <n>` (2 to 64) is a copy; a copy whose object is gone is still listed; a link or
  directory under a copy's name is counted and never followed; a copy known only by its iCloud placeholder
  (`.N 2.wwe.icloud`) is counted once, with or without its downloaded file, and read as unread, and an inexact one is
  nothing (R18, `duplicatePlaceholder`, `duplicatePlaceholderAlone`, `inexactDuplicatePlaceholders`). *State* ("… what is staged and remembered"): staged
  copies round-trip and a hostile row is no object; "Collecting a device's own objects": a deletion refused for one
  object is reported and tried again, never the sync's end (SR23, `refusedDeletionIsOneObjectsFailure`); the state's new fields (`unreadCopies` and their turns among them, R17, R19) survive encoding and an older row.
  *Engine* ("… the engine"): junk beside an object; the object behind a junk current file; no copy verifying refused
  alone; two verifying copies merged, in either order to the same items; a late copy; the forked author's hand-on;
  acknowledgements by minimum; snapshot copies; both bounds; a judge refusing a fork, at download and from an edited
  staging row; a copy that verifies and does not open stopping the position whole. *Adversarial*: "sync log"
  (`AdversarialSyncConflictCopyTests`: planted junk of five kinds, the genuine object hidden, two verifying forks
  reaching devices past the position, a flood, a shared vault's fork, a copy planted in the staging area, a copy
  that cannot be read yet, read once it can be and never collected before, R11, `unreadableCopyReadLater`; junk under
  names a device waits on, which no longer keeps a late copy from being read, R13,
  `junkUnderWantedNamesStarvesNothing`; copies that never become readable under many merged names, which no longer
  keep a late fork from being read and are still looked at, R17, `unreadableCopiesStarveNothing`; more such names than
  the bound covers, which take turns so a fork under the last of them is read, and whose changing counts bring none
  forward, R19, `unreadNamesTakeTurns`) and "sync
  with real keys" (planted copies while locked and after unlock; a really signed fork merged by every device and
  handed on). `LongRunningSyncSimulationTests` plants junk copies and forked copies of a device's newest segment and
  still converges, loses nothing, and leaves no hand-on owed.
- **Starting again after a reset** (architecture §7.10; portable, Linux). *Engine* ("Store reset: the engine",
  over the fakes): no sync, replay included, uploads again what the store held; a store never set up is not a
  reset; one device hands on everything and a new device reads all of it, with sequence numbers and state kept;
  asked twice it hands on once; a device whose stream another device's snapshot covered still notices its own
  newest segment gone (SR19, `coveredStreamStillNoticesAReset`); a device holding only a revoked device's work,
  handed on in a snapshot the store lost, is asked and writes nothing unasked (SR27, `revokedWorkIsAskedAbout`); an offline device that holds more is asked, and its new edits wait behind a gap
  until it answers; two devices in either order, and at once without seeing each other's snapshot, converge; a
  device whose own stream another device's upload stands for is still asked about a third stream; a second reset is
  noticed by the missing snapshot, and no snapshot name is used twice; a pending deletion and a merged erasure
  travel; the quarantine and the stash stay (a stash narrows the snapshot's coverage to the uploader's own stream);
  a vault that keeps its whole log refuses; an honest store with snapshots, collection and a restored state file
  never raises the question; a snapshot a device owes is never named like one it wrote before (R15,
  `owedSnapshotNamesAreNotReused`); a replay is postponed offline and rebuilds from the snapshot afterwards; the state's
  new fields survive encoding and an older row. *Session* ("Store reset: the session", real sessions, both kinds of
  reset — the transport saying so, and a store merely emptied): nothing uploaded unasked, locked or not, new edits
  included; a store that never held the account publishes; after the call a brand-new device enrols and reads every
  vault, a deleted vault and a trashed item as such; a stale plan, a locked vault and a revoked device are refused;
  two devices in either order converge; an offline device returning is asked and merges; a deletion made before the
  reset is not undone; a shared vault is refused by name and does not keep the question open. *Screens* ("Screen
  models: after the sync storage was reset"): the notice and headline, the question's wording (counts, deleted and
  shared vaults), Not Now, Upload Again, a stale question renewed, a lock dropping the question, the refusals, and a
  success notice that asks only after the vaults the upload was for, so a shared vault waiting for its key does not
  hold it back (SR28, `successAsksOnlyTheUploadedVaults`).
  *Automatic syncing* ("Automatic sync outcome"): at a reset store, of either kind, every sync the policy starts is
  a failure it backs off from, and no number of them uploads anything or starts the store again.
  *Adversarial*: "sync log" (`AdversarialSyncStoreResetTests`: an emptied store with a replay planted in the state
  file; a device's own objects deleted one by one; resets repeated after every upload; a store rolled back to an
  older copy; a whole-log vault with a judge asked to hand on), "sync with real keys"
  (`AdversarialVaultStoreResetTests`: nothing put back unasked under either kind of reset; a reset only claimed;
  repeated resets reusing no name; an old copy of the store put back; the quarantine and an unpublished deletion; a
  shared vault never uploaded from one member's device; a lock while the store is started again, and an upload
  stopped part-way, which asks again until the device has handed on: SR21, `lockWhileStartingAgain`,
  `uploadStoppedPartWay`; and a restore onto other hardware, whose device move keeps what the installation knew, V49:
  into a store the person emptied it asks and publishes nothing, then hands on everything on the yes,
  `restoredIntoEmptiedStoreAsks`; a never-synced installation restored publishes, `neverSyncedRestorePublishes`; an
  upload stopped part-way before the backup still asks after the move, `interruptedUploadAsksAfterMove`) and "account enrolment and device registry"
  (`AdversarialAccountStoreResetTests`: no account on an emptied store until the person says so, then enrolment; a
  revoked device cannot answer and stays revoked; a password change survives). `LongRunningSyncSimulationTests`
  resets the store mid-run and still converges. Mac only, drafted and not compiled: "CloudKit transport" (the zone
  recreated by `startStoreAgain` alone, left alone when it exists and found by a zone fetch and a one-record
  `BEGINSWITH` query, never `TRUEPREDICATE` (SR20), deleted first after a key reset that only the records answer, the
  zone's metadata still fetching as the fake now models it (SR26), under each of three readings of how a query reports
  the reset, for every query, only one asking for encrypted fields, or per record (`ResetReporting`, SR29), saved even
  when that deletion finds no zone (SR20), nothing decided on a probe query that fails after the zone fetched or on an
  empty zone (SR29), nothing created offline) and its adversarial suite (a faked reset repeated; no deletion of a zone
  that answers; a zone another device started again between the two looks, and a reset flag the second look
  contradicts, are not deleted, SR30; a reset reported per record stops a listing, SR29). "Pending downloads"
  (`PendingDownloadsTests`, portable, runs on Linux): a version download is asked for once while it waits and at most
  the capacity at once (R20). Not covered: a
  vault too large for one snapshot (`ReuploadRefusal.tooLarge` needs 64 MiB of records), CloudKit itself, and the
  SwiftUI alert.
- **"Adversarial: Apple adapters: CloudKit transport"** (`AdversarialCloudKitTransportTests`, Mac, over the fake
  database). A1 as the CloudKit store: records whose `name` disagrees with their ID, or whose names are outside the
  layout, are not listed and are refused when fetched; a payload in a plain field is never read, two payloads are
  refused, an oversized one is refused; a listing over the cap, or one of endless cursors of duplicate or invalid
  records, ends in `listingTooLarge`; one record with a missing asset is refused alone and the device still publishes
  (AD4); a stated wait of years is held to the policy's maximum backoff; a refused create is `objectExists`, and no save
  ever uses an overwriting policy. "CloudKit transport" adds the person's deletion of the zone (a reset, never
  recreated) and an unreadable marker (counts as seen). The fake reads the query rather than evaluating it (AD9).
- **"Adversarial: sync log"** gains, portably, one unreadable object (`objectUnreadable`) in another device's stream:
  refused alone, the stream waits, and the device publishes (AD4).
- **Not adversarial, Linux:** "Automatic sync outcome" (a vault throttled is a throttled sync, and one sync asks the
  transport once; the longest wait wins; sharing failures count), "Sync transport failures" (`transportStopped`), "Sync
  store marker".

### 6.11 Manual cases (real devices)

What no runner can check is written down as cases a person runs, in `docs/manual-tests/` (one file per area, each
case a heading and numbered steps whose **Expected** lines are the checks): Face ID and Touch ID with the Secure
Enclave, what the Keychain keeps on one device and a restored backup does not carry, exported files and the
`.watchwordbackup` type as the Files app and Finder treat them, the Emergency Kit on paper, what the app
switcher shows, the camera scanning a vault sharing code on iPhone and iPad (`camera-scanning.md`: the permission,
the live camera only, a code that is not Watchword's, the stand-in absent from a release build), and a vault sharing
code session between two people (`vault-sharing-code.md`: what each reads and types, a wrong code, the ten-minute
limit, a lock mid-session, VoiceOver reading the digits; it needs the sharing board's production adapter, which does
not exist yet, so until then it runs as far as the cases say). A feature that adds something only a person can check adds its cases in the same pull request;
they are run before a release and after any change to the adapters or screens they name. They are not a gate: no
CI job reads them.

## 7. CI implementation

Workflows live in `.github/workflows/` (see `ci.yml` and `security-nightly.yml`). Every step after
checkout and Xcode selection is a `mise run` task (`mise.toml`, `mise-tasks/`), so each job below
reproduces locally with the task named in brackets; `mise run check` runs all of them but the app
tests (its `test` also checks every adversarial suite ran, so it skips the separate adversarial
run, and its strict build skips with a warning on a compiler older than Swift 6.2).

- `package-tests` matrix: `macos-15` with Xcode 16.4 and `xcode-27` (macOS 27) with Xcode 27.0; runs the
  dependency tripwire, `swift build -v` and `swift test --parallel --enable-code-coverage`, fails
  unless both test frameworks and every adversarial area's suite executed tests, and uploads the log and coverage report as artifacts
  [`audit:dependencies`, `build`, `test --coverage`].
- `adversarial-tests`: the adversarial suite alone, so that a regression in the security suite is
  visible as its own red check; fails if any area's suite is missing [`test:adversarial`].
- `strict-memory-safety`: builds with `-Xswiftc -strict-memory-safety -Xswiftc -warnings-as-errors`
  on Xcode 27 (anything from Swift 6.2 on), then runs the unsafe-confinement tripwire, proving no unsafe constructs
  outside `SecureMemory` [`build:strict --require`, `audit:unsafe`].
- `lint`: `swift format lint --strict` with the repository `.swift-format`, then the script tests
  (`Tests/ScriptTests`, Python `unittest`): `screenshots-index.py` over made-up exports (a complete set; a missing,
  blank or non-PNG picture; a tour that stopped; the wrong appearance; names, captions and paths a test run should
  not be able to smuggle through; the BMP reader), the `app:screenshots` task with stand-ins for `mise`, `xcrun`
  and `sips` (what it writes, announces and summarises when a capture fails), and the two inline scripts of
  `screenshots.yml`, read out of the file and run against a stand-in `gh` and `curl` (who can start a capture, what
  the comment job will and will not post or link, and which comment it will overwrite). Since the audit of
  2026-11-17 (`06-adversarial-review.md` §Z) the script tests also hold the supply-chain gates themselves, each run
  as it is in a scratch directory: `audit:actions` over every spelling of `uses:` a grep did not read; the
  adversarial-suite check over logs in which a suite is missing, skipped, or named only inside another's name;
  `audit:mise-pins`; the dependency tripwire with a stand-in `swift` (the `Apps/project.yml` allowlist over each
  planted bypass, and a manifest that reads its environment or leaves Swift 6 mode); the app tasks with a stand-in
  `xcodebuild` that checks packages out with real git (no build unless the checkouts are the pinned commits,
  unchanged; every call given the source-packages directory; a Release product holding a Debug-only marker); and `cloud-setup.sh` with stand-ins for `curl` and `gpg`
  (a tarball that does not verify installs nothing and tries nothing else). The job then runs the two audits that
  need no build [`lint`, `test:scripts`, `audit:actions`, `audit:mise-pins`].
- `app-tests`: `xcodebuild test` for the macOS app and the iOS simulator on `xcode-27`: one leg for macOS, and the
  iOS UI tests split over four legs that run side by side, because one simulator running them all took longer than a
  job may: the tour; `ImportExportTests`; `VaultSharingTests` and `DeviceRevocationTests`; and the rest (the other
  three groups skipped, so a new class lands there), each passed to `app:test` as comma-separated `--only-testing` or
  `--skip-testing` identifiers, each with a job limit of its tests' allowances, a build and headroom. The last leg
  also makes the AutoFill Settings attempt, marked `continue-on-error`. An iOS leg boots its
  simulator and waits for the boot to finish (`simctl bootstatus -b`) before testing, because a UI-test runner
  started on a half-booted device dies before any test runs. When a leg fails, `app:diagnose` prints its
  result bundle's summary, runner logs and crash reports into the job log, and last of all each failed test's
  failure messages and last 30 `STEP` lines (from `app:test`'s copy of xcodebuild's output and the runner's own) and
  one line, `UI-test summary: N passed, N failed: <names>` (`diagnose-summary.py`, tested by `test:scripts` over
  made-up summaries and logs). It no longer skips: a
  missing `Apps/project.yml` fails `app:generate` [`app:test macos`, `app:test ios`]. The macOS scheme includes the app-hosted
  `WatchwordKeychainTests` bundle, unentitled, so it compiles and its round trip skips; the signed
  run is local only (`app:test-keychain`, §6.2), because CI has no provisioning profile.
- `release-build`: both apps in the Release configuration, which no other job compiles, one leg each for macOS and
  the iOS simulator. The task fails on a build error and then if the app bundle or its embedded AutoFill extension
  contains the text of a Debug-only UI-test facility (`--uitest`, `WATCHWORD_UITEST_PASSWORD`, the Settings section
  and the "Lock now" button): the evidence that the `--uitest` switch of §5 does not ship. Each marker must still be
  in the sources, and a script test holds that each is used only inside `#if DEBUG`. The same search must find one
  literal the app always compiles in (the positive control), or it has shown nothing. Not yet run on a Mac
  [`app:release macos`, `app:release ios`].
- `security-nightly.yml`: scheduled fuzzing, long randomised sync simulations and the action
  pinning audit again [`fuzz`, `test:long`, `audit:actions`].

- `required` (`Required checks`): needs every job above and fails unless each succeeded. Branch
  protection requires this one check (`08-repository-hardening.md` §5), so every job above blocks a
  merge, including every package-test, app-test and release-build leg, and a runner bump or a regrouping
  that renames a matrix leg needs no protection change. Legs are judged one by one from the API listing of the run
  attempt's jobs, not from `needs.*.result`, which read `success` for a matrix job with a leg cancelled before it ran
  (`06-adversarial-review.md` Z119); a leg not finished, not listed or not expected fails it. Its inline script is
  tested by `test:scripts` [`Tests/ScriptTests/test_required_checks.py`].

- `screenshots.yml`: not a gate. On the `screenshots` label (and each push while a pull request carries it), a
  same-repository head commit whose message has a line that is exactly `[screenshots]`, or a dispatch, it runs the
  screenshot tour (§5.1) on the iOS simulator and macOS, uploads each set and its one-PNG contact sheet as
  artifacts, writes the index to the job summary, and creates or updates one comment on the pull request linking
  to them [`app:screenshots ios`, `app:screenshots macos`]. Its controls are in `07-supply-chain.md` §3.2, and its
  two inline scripts are tested by `test:scripts` in the `lint` job. It is not part of `required` and must not be
  added to branch protection.
