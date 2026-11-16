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
| CloudKit integration | Swift Testing against a development container | manual `workflow_dispatch` with secrets | < 10 min |
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
| F1.x items/fields | Codable round trips; property test "any item survives encode→decode"; history kept whatever its age or length, with `FakeClock`, and an edit past the payload limit refused rather than pruned |
| F3.x generator | Parameterised tests over all knob combinations; statistical uniformity test (chi-square over 100k samples, seeded); entropy formula tests; site-rule mapping tests |
| F4.x sharing | Scenario S3/S4 over `InMemorySyncTransport`; revoke then verify former member cannot decrypt new versions and remaining members can; read-only client refuses writes (protocol core, milestone 4, `WatchwordSharingTests`: "Membership record format", "Sharing formats: known answers", "Membership chain rules", "Membership ledger", "Fingerprint verification and invitations", "Key grants and rotation", and "Shared vault simulation" — two and three members with real keysets over a hostile store: create, invite, verify, accept, write, role change, removal with rotation, leaving, an interrupted rotation, concurrent administrators, deletion; through `VaultSession` and a real transport: open) |
| F5.x unlock | `UnlockPolicy` table tests for every expiry reason; `FakeKeychain` enrolment change invalidates quick unlock; lock zeroises (inspect `SecureBytes`) |
| F6.x AutoFill | `HostMatcher` tests (S1), IDN/userinfo/port edge cases, and "Public suffix: the broadest site of a host" (the site a QuickType identity is assumed to reach); request-handler tests per request kind; identity publishing diff tests (`WatchwordAutoFillTests`: "One-time codes (TOTP)" — every vector of RFC 6238 appendix B and RFC 4226 appendix D —, "Passkey authenticator" — known answers from an independent Python implementation for the COSE key, authenticator data, attestation object and `prf`, and a signature that implementation verified —, "Site password rules", "Credential identity publishing", "Request model: credential list and passwords", "… one-time codes and text to insert", "… passkeys", "… saving and generating passwords", "… credential-update reports", "Scenarios S1 and S2 through the request model", and "Request model over a real vault session" — S1 and S2 again over a `VaultSession` with a stand-in for its `CredentialVault` conformance; milestone 5) |
| F7.x sync | Convergence under random schedules; offline edits; snapshot GC; locked-device download-only (`WatchwordSyncTests`: "Multi-device sync simulation" — convergence and no lost value —, "Simultaneous edits across devices" — separate fields, separate items, a long note, the same line, one field on three devices, trash or delete against an edit (F7.6), and which trash the 30-day purge may remove (F1.5, F7.7) —, "Sync engine", "Field-level item merge", "Sync review regressions", "Sync payload format", "Sync transport contract", "Sync state store contract", "SQLite sync state store"; `WatchwordKitTests`: "Vault session: sync between devices" — two real sessions, AES-GCM and Ed25519: round trip, ciphertext only (F7.3), a conflict kept on both devices and resolved by the person, locked download, a deletion against an unseen edit, the purge, SQLite stores across a relaunch; XCUITest `SyncConflictTests`; milestone 3) |
| F8.x interchange | Fixture round trips for each format; instruction text snapshot tests |
| F9.x hygiene | HIBP prefix/suffix logic with padded and malformed fixtures; cache TTL; scheduling with keys absent (`WatchwordHygieneTests`: "Pwned Passwords: digest and prefix", "…: range parser", "…: cache entries", "…: client", "Breach scan scheduling", "Scan ledger", "Strength estimator", "Password reuse", "Item checks", "Hygiene report", "Hygiene engine", "Breached-account lookup"; milestone 6) |
| F11.x phishing | Section 6.7: never-release on look-alikes, warn-not-silence, false-positive guards, scope policy, normalisation |
| SEC1–SEC10 | Section 6 below |

## 4. End-to-end scenario tests (normative)

Each test is written once against `VaultSession` and once as an XCUITest where UI is involved.

- **E2E-S1 Amazon vs AWS.** Seed both items. Request credential list for
  `https://signin.aws.amazon.com/signin` → primary list contains only the AWS item, retail is in
  the shadowed list; request for `https://www.amazon.com/ap/signin` → only retail. Assert the
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
- Accessibility audit (`XCUIApplication.performAccessibilityAudit()`) runs on every screen.

### 5.1 The screenshot tour

`ScreenshotTourTests` (`Apps/UITests/Shared`, iOS simulator and macOS) is one pass through every flow the app has
that attaches a picture of each major screen, so the screens can be audited by eye and a pull request that changes
the UI can carry fresh ones. It is an end-to-end test in its own right: `app:test`, and so `ci.yml`'s `app-tests`
job, runs it with the other UI tests, and a flow that breaks fails it there.

- **What is on screen.** The app is launched with `--uitest`: in-memory ports, an account the test creates, and
  `UITestPeer` as the other device. `Screens.capture` refuses any other launch. The Secret Key and the generated
  password in the pictures belong to that throwaway account and differ on every run; no real vault, Keychain item
  or secret can appear. The Settings picture includes the Debug-only "UI test: another device" section, which no
  release build has.
- **The screens today**, in flow order: `onboarding`, `emergency-kit`, `item-list-empty`, `item-edit` (a new item,
  its password filled in by the generator), `item-list`, `item-detail` (password hidden), `item-detail-revealed`,
  `trash-confirmation`, `locked`, `unlock-failed`, `settings`, `item-list-conflict` (the badge after a concurrent
  rename) and `conflict-resolution`. Files are numbered in that order (`01-onboarding.png`).
- **Adding a screen** is one line where the tour reaches it: `Screens.capture("vault-list", in: app, showing:
  "…")`. Names are lower-case words joined by hyphens and unique; the number comes from the order of capture, so a
  screen added in the middle renumbers the later ones. Every milestone that adds a screen adds it to the tour
  (vault list, sharing, AutoFill settings, the hygiene report, import and export are still to come).
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

### 6.3 AutoFill matching (milestone 2/5)
- Service identifiers with user-info (`https://amazon.com@evil.example/`), ports, trailing dots,
  mixed case, IDN homographs (`xn--` forms) and raw Unicode, IPv6 hosts, `file:` and `data:`
  schemes → never match an unrelated item.
- Public-suffix boundaries once PSL is integrated (`co.uk` scope must not match everything).
- Shadowed items are never auto-selected; the request handler refuses to return a credential for a
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

**Implemented in milestone 3** (`AdversarialSyncTests`, suite "Adversarial: sync log", with the fake keyring):
the server's reorder/duplicate/drop/stale-snapshot cases, a byte flipped anywhere in a segment, objects moved to
another stream, sequence, vault or slot, a withheld or replayed segment (the stream waits at the gap), forgeries
rejected before staging, a former device's segments, a record swap or relabel inside a validly signed segment, a
segment carrying another device's versions, a record ID of another vault, implausible versions (U5), no plaintext
on the transport, a row rolled back or deleted in the local file (A8) restored by reconciling, a tampered staged
download, mutated payloads and containers, sequence numbers and vectors near the integer limit, and symbolic links
planted in a file transport's directory (at the file and higher up). Quarantined versions are kept, not dropped.

**Implemented in milestone 3, with real keys** (`AdversarialVaultSyncTests`, suite "Adversarial: sync with real
keys", `VaultSession` as the keyring): a byte flipped anywhere in a segment sealed with AES-GCM and signed with
Ed25519; a genuine envelope signed by a key of the attacker's own, refused locked (Keychain copy) and unlocked
(keyset); a genuine segment moved to another stream or number, refused at download while locked because the name
is signed; an insider's record swap inside a validly sealed and signed segment, refused by the record's own AEAD
context; a locked device with no trusted key in the Keychain, which refuses everything (`trustedKeyUnavailable`)
until the next unlock; pending deletions planted in the local sync state (A8) — unsigned, badly signed, signed by
another key, or another device's — none of which is published; the sync adapter used after `lock()`; and the
keyring refusing to sign as another device. The Keychain item protection suite checks the new `accountSigningKey`
item like the others and that every item has its own account name.

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
  record that ends no permission, a cut altered or over its bound; a removal displaced by a fork, whose cut still
  governs while it is owed; a former administrator's cut on a dead branch built from a genuine leave request.
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
  starting with `=`, `+`, `-`, `@` (export neutralises; import preserves), rows with embedded
  newlines/quotes, invalid UTF-8, BOMs, and a 2 GB declared size → bounded time and memory, no
  crash, clear error.
- CXF payloads with unknown types, duplicate IDs, and oversized blobs.

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

The regression tests added after the first review of this module for the scheduling, locking, staleness,
report, parser and rating faults were each checked by putting the fault back and seeing the test fail; the
estimator's cost was measured before and after with the same inputs (`02-architecture.md` §13.4).

Not covered, and why: no test calls the live service, and the fixtures are written to its documented format,
not captured from it (it is not reachable from a cloud session); a capture on a Mac is open in milestone 6.
The comparison's constant-time property is by construction and review, not measured. The `URLSession`
adapter's obligations (no redirects, size limit on the decoded body, nothing logged) are untested until it
exists.

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
"hardening" change cannot silently break legitimate matching.

*At the request model (milestone 5):* "no override" is a property of `CredentialProviderModel`'s API, not of a
view: there is no call that releases after a refusal, which `AdversarialAutoFillRequestTests` checks request by
request (§6.3).

*Still to come:* a UI test that the AutoFill extension presents no override affordance on a
suspicious host, and that adding a mismatched host as a scope requires the confirmation in F11.7
(both milestone 5; the second was planned for milestone 2, but the mismatch it confirms is first
observable from the extension). Milestone 2 enforces F11.2 at the vault boundary instead:
`VaultSession.save` refuses over-broad scopes whatever the UI sends.

### 6.8 Fuzzing (nightly)
- libFuzzer harnesses for the envelope decoder, CBOR item decoder, CSV parser, 1PUX JSON mapper,
  `otpauth://` parser, and `HostMatcher.normalize`. None exists yet; the envelope decoder
  (`Envelope.parse`) is the first candidate now that it is complete.

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
  the comment job will and will not post or link, and which comment it will overwrite) [`lint`, `test:scripts`].
- `app-tests`: `xcodebuild test` for the macOS app and the iOS simulator, one matrix leg each on
  `xcode-27`, with the AutoFill Settings attempt marked `continue-on-error`. The iOS leg boots its
  simulator and waits for the boot to finish (`simctl bootstatus -b`) before testing, because a UI-test runner
  started on a half-booted device dies before any test runs. When a leg fails, `app:diagnose` prints its
  result bundle's summary, runner logs and crash reports into the job log. It no longer skips: a
  missing `Apps/project.yml` fails `app:generate` [`app:test macos`, `app:test ios`]. The macOS scheme includes the app-hosted
  `WatchwordKeychainTests` bundle, unentitled, so it compiles and its round trip skips; the signed
  run is local only (`app:test-keychain`, §6.2), because CI has no provisioning profile.
- `security-nightly.yml`: scheduled fuzzing, long randomised sync simulations and the action
  pinning audit [`fuzz`, `test:long`, `audit:actions`].

- `required` (`Required checks`): needs every job above and fails unless each succeeded. Branch
  protection requires this one check (`08-repository-hardening.md` §5), so every job above blocks a
  merge, including both app-test legs, and a runner bump that renames a matrix leg needs no
  protection change.

- `screenshots.yml`: not a gate. On the `screenshots` label (and each push while a pull request carries it), a
  same-repository head commit whose message has a line that is exactly `[screenshots]`, or a dispatch, it runs the
  screenshot tour (§5.1) on the iOS simulator and macOS, uploads each set and its one-PNG contact sheet as
  artifacts, writes the index to the job summary, and creates or updates one comment on the pull request linking
  to them [`app:screenshots ios`, `app:screenshots macos`]. Its controls are in `07-supply-chain.md` §3.2, and its
  two inline scripts are tested by `test:scripts` in the `lint` job. It is not part of `required` and must not be
  added to branch protection.
