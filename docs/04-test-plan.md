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
  `FakeHTTP` (recorded HIBP responses), `InMemorySyncTransport` (shared between simulated clients,
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
| F1.x items/fields | Codable round trips; property test "any item survives encode→decode"; history retention with `FakeClock` |
| F3.x generator | Parameterised tests over all knob combinations; statistical uniformity test (chi-square over 100k samples, seeded); entropy formula tests; site-rule mapping tests |
| F4.x sharing | Scenario S3/S4 over `InMemorySyncTransport`; revoke then verify former member cannot decrypt new versions and remaining members can; read-only client refuses writes |
| F5.x unlock | `UnlockPolicy` table tests for every expiry reason; `FakeKeychain` enrolment change invalidates quick unlock; lock zeroises (inspect `SecureBytes`) |
| F6.x AutoFill | `HostMatcher` tests (S1), IDN/userinfo/port edge cases; request-handler tests per request kind; identity publishing diff tests |
| F7.x sync | Convergence under random schedules; offline edits; snapshot GC; locked-device download-only |
| F8.x interchange | Fixture round trips for each format; instruction text snapshot tests |
| F9.x hygiene | HIBP prefix/suffix logic with padded and malformed fixtures; cache TTL; scheduling with keys absent |
| F11.x phishing | Section 6.7: never-release on look-alikes, warn-not-silence, false-positive guards, scope policy, normalisation |
| SEC1–SEC10 | Section 6 below |

## 4. End-to-end scenario tests (normative)

Each test is written once against `VaultSession` and once as an XCUITest where UI is involved.

- **E2E-S1 Amazon vs AWS.** Seed both items. Request credential list for
  `https://signin.aws.amazon.com/signin` → primary list contains only the AWS item, retail is in
  the shadowed list; request for `https://www.amazon.com/ap/signin` → only retail. Assert the
  TOTP returned for each matches the right item. Assert QuickType identities carry distinct ranks.
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
  Emergency Kit confirmation, item creation with a generated password, lock, wrong password, unlock)
  runs on the iOS simulator and macOS from `Apps/UITests/Shared`. `AutoFillSettingsTests` skips
  itself until the extension answers requests (milestone 5). The accessibility audit is not wired
  in yet.
- Accessibility audit (`XCUIApplication.performAccessibilityAudit()`) runs on every screen.

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
- Replay of an *older* version presented as itself → the sync layer's monotonic check
  (milestone 3); presenting it as newer is rejected now.
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

### 6.4 Sync and sharing (milestones 3–4)
- Malicious server mode: substitutes a member's public key → fingerprint mismatch blocks the
  invitation; reorders/duplicates/drops segments → convergence still holds or sync fails closed;
  injects an unsigned or wrongly signed membership record → ignored; serves a stale snapshot →
  Lamport check rejects regression.
- Former member: after revocation, replaying their old wrapped key cannot decrypt new versions;
  their pushed segments are rejected by remaining members.
- Read-only member's writes are rejected by the transport fake and never merged.
- Two admins remove each other concurrently → deterministic outcome, no vault lock-out.

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

- `package-tests` matrix: `macos-15` with Xcode 16.4 and `macos-26` with Xcode 26.x; runs the
  dependency tripwire, `swift build -v` and `swift test --parallel --enable-code-coverage`, fails
  unless both test frameworks and every adversarial area's suite executed tests, and uploads the log and coverage report as artifacts
  [`audit:dependencies`, `build`, `test --coverage`].
- `adversarial-tests`: the adversarial suite alone, so that a regression in the security suite is
  visible as its own red check; fails if any area's suite is missing [`test:adversarial`].
- `strict-memory-safety`: builds with `-Xswiftc -strict-memory-safety -Xswiftc -warnings-as-errors`
  on Xcode 26 (Swift 6.2+), then runs the unsafe-confinement tripwire, proving no unsafe constructs
  outside `SecureMemory` [`build:strict --require`, `audit:unsafe`].
- `lint`: `swift format lint --strict` with the repository `.swift-format` [`lint`].
- `app-tests`: `xcodebuild test` for the macOS app and the iOS simulator, with the AutoFill
  Settings attempt marked `continue-on-error`. The job is skipped until `Apps/project.yml`
  exists [`app:test macos`, `app:test ios`]. The macOS scheme includes the app-hosted
  `WatchwordKeychainTests` bundle, unentitled, so it compiles and its round trip skips; the signed
  run is local only (`app:test-keychain`, §6.2), because CI has no provisioning profile.
- `security-nightly.yml`: scheduled fuzzing, long randomised sync simulations and the action
  pinning audit [`fuzz`, `test:long`, `audit:actions`].

Branch protection should require `package-tests`, `adversarial-tests`, `strict-memory-safety`
and `lint` to pass.
