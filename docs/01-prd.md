# Watchword — Product Requirements Document

Version 0.1 (draft). Companion documents: `00-research.md`, `02-architecture.md`,
`03-implementation-plan.md`, `04-test-plan.md`, `adr/`.

## 1. Summary

Watchword is a native iOS, iPadOS and macOS app that stores web-account authentication material for
a small group of people (a household, a small team) and makes it available where the person needs it:
in Safari and apps through AutoFill, in the app's own UI, and across the person's devices. Every byte
that leaves a device is end-to-end encrypted under keys only the members hold. There is no Watchword
server; synchronisation rides on iCloud (CloudKit) or, optionally, on any file-based cloud the person
already uses.

The security posture deliberately copies the 1Password balance: an account password *and* a
device-held Secret Key are both required to unlock or to sync a vault, biometrics are a convenience
layer on top of (never a replacement for) the password, and the password is re-required on a
schedule.

## 2. Goals and non-goals

### Goals

- G1. Store every credential type a modern account needs (section 5.1) and keep them organised per
  account, not per website, so that two accounts on one domain never get confused.
- G2. End-to-end encryption at rest and in transit, with plaintext existing only transiently in
  client memory while the vault is unlocked.
- G3. Share selected items with selected people and revoke that access later.
- G4. First-class AutoFill for passwords, passkeys and one-time codes on all three platforms.
- G5. Zero-infrastructure sync using the person's existing iCloud account, with a file-based
  alternative for other providers.
- G6. Migration in and out: 1Password and Apple Passwords, plus the FIDO Credential Exchange flow.
- G7. Continuous hygiene: breach scanning, strength assessment, reuse detection.
- G8. A codebase where the security-relevant flows are exercised by automated integration and
  end-to-end tests on every commit.

### Non-goals (v1)

- Windows, Android, Linux, or browser-extension clients.
- A Watchword-operated server, account system, or billing.
- Enterprise features (SSO, SCIM, audit log export, admin policies).
- Storing arbitrary documents or large attachments.
- Cryptographic enforcement of *read-only* access (see 5.4; read-only is transport-enforced).

## 3. Users and scenarios

Primary persona: a technically literate adult who manages their own accounts and a handful of
shared household accounts (bank, utilities, library, streaming) with a partner or family members,
all on Apple devices.

The following scenarios are normative; the test plan derives end-to-end tests from each.

- **S1 Same email, two Amazon accounts.** The person has an Amazon retail account
  (`www.amazon.com`: email, password, TOTP) and a separate AWS root account
  (`signin.aws.amazon.com`: same email, different password, different TOTP). On the AWS console
  sign-in page the app must offer only the AWS credential; on `amazon.com` it must offer only the
  retail credential. Neither may be auto-submitted to the other.
- **S2 Google with passkey and recovery codes.** The person signs in to Google with a passkey stored
  in Watchword and keeps their 2FA backup codes in the same item. AutoFill offers the passkey; the
  backup codes are visible in the item and can be inserted as text on request; used codes can be
  marked as spent.
- **S3 Shared bank account.** A bank item with phone number, password, TOTP and three security
  questions with answers is shared with one other household member. Both can fill the password and
  the TOTP; both can view and insert security answers; either can update the password and the other
  sees it; the owner can revoke the share.
- **S4 Shared library card.** A library item with card number, username, password and PIN is shared
  with one other member. The PIN and card number are insertable as text; the username/password fill
  normally.

Additional scenarios covered by requirements but not enumerated as walkthroughs: moving an item
between a private and a shared vault, leaving a shared vault, onboarding a second device,
recovering from loss of all devices with the Emergency Kit, importing from 1Password, exporting to
Apple Passwords.

## 4. Platform and engineering requirements

- P1. **Memory-safe implementation language.** All first-party code is written in Swift (Swift 6
  language mode). Use of `Unsafe*` APIs and `@unsafe` declarations is permitted only in the
  `SecureMemory` module and must be flagged by the compiler's strict-memory-safety mode. Rust is an
  acceptable alternative for a future shared core but is not used in v1
  (`adr/0001-memory-safe-language.md`).
- P2. **Native UI only.** SwiftUI with AppKit/UIKit where required. No Electron, Tauri, web views for
  UI, or Mac Catalyst (the AutoFill API ignores Catalyst apps) (`adr/0002-native-ui.md`).
- P3. **Platform floor.** iOS/iPadOS 17 and macOS 14 (for HPKE, passkey identities, `CKSyncEngine`).
  Features that depend on newer OS versions (OTP AutoFill on 18/15, Credential Exchange on 26) are
  gated at runtime and degrade gracefully.
- P4. **No third-party cryptography.** Only CryptoKit, Security.framework, and CommonCrypto.
  Third-party Swift packages are limited to non-security utilities and must be pinned and vendored
  or checksum-locked.
- P5. **Testability.** All business and security logic lives in platform-independent Swift packages
  with injected dependencies, so that the full unlock/sync/share/revoke/AutoFill-matching flows run
  in-process in CI without devices (see `04-test-plan.md`).
- P6. **CI.** GitHub Actions on macOS runners runs Swift Testing and XCTest suites, including a
  dedicated adversarial security suite, on every push and pull request.

## 5. Functional requirements

Requirement IDs are stable and referenced from the test plan.

### 5.1 Items and fields

- F1.1 An **item** represents one account. It has a title, zero or more **service scopes**
  (hostnames or hostname patterns with a subdomain flag, plus optional native app identifiers), an
  ordered list of typed fields, tags, notes, a password history, and audit timestamps.
- F1.2 Supported field types: username, email, phone number, password, TOTP secret (stored as an
  `otpauth://` URI with issuer/algorithm/digits/period), passkey (private key, relying-party ID,
  user handle, credential ID, creation date, PRF/largeBlob flags), security question and answer
  (paired, with the answer treated as a secret), API key/token, PIN, 2FA recovery/backup codes (a
  list where each code can be marked used), account/card number (e.g. library card), URL, date,
  free text, and custom labelled secret or non-secret text.
- F1.3 An item may hold any combination and multiplicity of field types (S3 has three security
  questions; S1's AWS item has one password and one TOTP).
- F1.4 Every item version is retained for good ("password history"): a full audit trail, never pruned
  by age or by count. The previous password is always retrievable. An edit that would make an item
  larger than its payload limit (SEC9) is refused, never made room for by dropping history.
- F1.5 Items can be archived and restored, and permanently deleted after a 30-day trash period.

### 5.2 Vaults and organisation

- F2.1 Every item belongs to exactly one **vault**. Each person has a Personal vault that cannot be
  shared. Additional vaults can be created and shared.
- F2.2 Items can be moved or copied between vaults the person can write to.
- F2.3 Search covers title, scopes, usernames/emails, tags and notes; secrets are never indexed in
  plaintext on disk.

### 5.3 Password generation (F3)

- F3.1 Random mode with knobs: length (4–128), lowercase, uppercase, digits, symbols, custom symbol
  set, exclude ambiguous characters (`l1IO0`), require at least one of each selected class, forbid
  repeated adjacent characters, and site rules supplied by AutoFill's generate-password request.
- F3.2 Memorable mode: 3–10 words from the EFF large wordlist, configurable separator, optional
  capitalisation, optional digit and symbol insertion.
- F3.3 PIN mode: 4–12 digits.
- F3.4 The generator shows an entropy estimate derived from the generation process (not from a
  strength guesser) and warns below 64 bits.
- F3.5 All randomness comes from the OS CSPRNG; sampling is rejection-based (no modulo bias).

### 5.4 Sharing and revocation (F4)

- F4.1 A vault owner can invite another Watchword user by Apple ID (CloudKit) to a shared vault with
  `read-write` or `read-only` permission.
- F4.2 On accepting an invitation the invitee must verify the owner's key fingerprint (short safety
  number or QR) out of band before the vault key is accepted; the owner likewise verifies the
  invitee's before wrapping the vault key to them.
- F4.3 The owner (or an admin) can remove a member at any time. Removal happens in this order:
  (a) the member is removed from the transport share, which takes effect immediately server-side;
  (b) the vault key is rotated, all items re-encrypted, and the new key re-wrapped to the remaining
  members. Step (b) requires the owner's device to be online and unlocked, so it may complete later
  than step (a); until it does, the UI shows the vault as pending rotation. The app must state
  plainly that the removed member may have retained copies of items they had already synced.
- F4.4 A member can leave a vault; the same rotation occurs.
- F4.5 Read-only is enforced by the transport (CloudKit `readOnly` participant permission) and by
  the client; it is **not** cryptographic, and the UI must say so.
- F4.6 Per-item sharing is expressed as "move to a shared vault" so that the sharing model has one
  mechanism.

### 5.5 Unlock, lock, and local protection (F5)

- F5.1 Creating an account generates a 128-bit Secret Key on the device and shows an Emergency Kit
  (PDF with the Secret Key and a QR code) that the person must confirm they saved.
- F5.2 Unlocking requires the account password; the Secret Key is read from the device Keychain.
  Enrolling a new device requires entering or scanning the Secret Key, or an authenticated
  device-to-device transfer.
- F5.3 Optional quick unlock with Face ID / Touch ID / Optic ID, and on the Mac with Apple Watch,
  via a Keychain item bound to `biometryCurrentSet` (or `.watch`/`.companion` combined with `.or`).
  Quick unlock is disabled automatically when biometric enrolment changes.
- F5.4 Quick unlock expires and the password is required again: after a configurable interval
  (default 14 days), after a configurable number of failed biometric attempts (default 3), after
  the app is updated, and after the Secret Key or password changes.
- F5.5 Auto-lock after inactivity (default 5 min on iOS, 10 min on macOS, configurable), on
  backgrounding (iOS, configurable grace period), on screen lock/sleep (macOS). Locking zeroises
  key material and decrypted items in memory.
- F5.6 Clipboard copies expire (default 60 s) and use the "local only"/expiry pasteboard options.
- F5.7 Screenshots/screen recording of secret fields are discouraged on iOS by marking secure text
  fields; secrets are hidden from the app switcher snapshot.

### 5.6 AutoFill and platform integration (F6)

- F6.1 Password AutoFill in Safari and apps on iOS, iPadOS and macOS with QuickType suggestions
  from published identities.
- F6.2 Passkey creation and assertion through the credential provider extension, including
  conditional (automatic) passkey upgrade when a site requests it and the PRF extension.
- F6.3 One-time code AutoFill (iOS 18 / macOS 15 and later).
- F6.4 Text insertion for any field (security answers, PINs, card numbers, recovery codes).
- F6.5 Save new logins offered by sites (save-password requests) and honour site password rules in
  generate-password requests.
- F6.6 Matching rule: among items whose scopes match the requested host, the most specific scope
  wins; less specific matches are shown in a secondary "other accounts on this site" list and are
  never pre-selected (S1).
- F6.7 Handle relying-party credential-update reports (unused password, renamed passkey, unknown
  credential) by updating or flagging the item.
- F6.8 A per-item "exclude from AutoFill suggestions" toggle. Publishing an identity hands the
  item's host and username to the OS-managed credential identity store, which is a disclosure
  surface outside the app's control; items the person marks sensitive are reachable only by opening
  the app.

### 5.7 Sync (F7)

- F7.1 Primary transport: CloudKit private database (personal vault, account metadata) and shared
  database (shared vaults, one record zone per vault, zone-wide `CKShare`).
- F7.2 Secondary transport: file-based, over the iCloud Drive container or any Files-app location
  chosen by the person (Dropbox, Google Drive, etc.), with per-device append-only logs and periodic
  snapshots. Sharing over this transport uses the provider's shared-folder feature.
- F7.3 All records carried by either transport are ciphertext produced by the Watchword envelope
  format; transports never see plaintext field values or item titles.
- F7.4 Sync is incremental, resumable, and tolerant of offline edits; conflicts resolve at field
  level by last-writer-wins with a tiebreak on device ID, and the losing version is kept in history.
- F7.5 Sync requires the vault to be unlocked only for *merging*; downloading ciphertext may happen
  while locked.
- F7.6 Simultaneous edits merge: edits to separate fields or separate items all survive; edits to
  different parts of a long text (notes) merge line by line, and two edits of the same line both survive.
  Two concurrent values of the same field are a conflict: every version is kept — one shown, the others
  listed — until the person resolves it. A deletion and a concurrent edit resolve to the deletion with the
  edit kept as the item's last version: trashing and an edit give a trashed item containing the edit; a
  permanent deletion and an edit its author had not seen give the item back, in the trash, with the edit.
- F7.7 Sync never throws away data a person entered or a device received without an explicit action by
  the person: conflicting values, history, notes lines and versions refused as implausible are all kept
  until the person resolves, empties or discards them. History is never pruned (F1.4, decided by the owner
  on 2026-10-23). *Open:* F1.5's 30-day trash purge is still an automatic discard; whether F7.7
  overrides it is a decision for the owner (`06-adversarial-review.md` §H, Y14).

### 5.8 Import and export (F8)

- F8.1 Import from 1Password 1PUX (full fidelity for Login, Password, Secure Note, API Credential,
  Bank Account, Membership categories; others become custom-field items) and 1Password CSV.
- F8.2 Import from Apple Passwords CSV (`Title,URL,Username,Password,Notes,OTPAuth`).
- F8.3 Import via Credential Exchange (iOS 26 / macOS 26) from Apple Passwords, 1Password and any
  CXF-capable app.
- F8.4 Export to Apple Passwords CSV, to 1PUX-compatible JSON (for 1Password import), to CXF via
  Credential Exchange, and to an encrypted Watchword archive. Plaintext exports require re-entering
  the account password, show a persistent warning, and are written with the strongest file
  protection class available.
- F8.5 In-app, step-by-step instructions for exporting from 1Password and Apple Passwords and for
  importing into them, including the caveats discovered in research (passkeys do not survive CSV;
  Wi-Fi items are excluded from CXF).

### 5.9 Hygiene: breaches and strength (F9)

- F9.1 Every password is checked against Have I Been Pwned Pwned Passwords using the k-anonymity
  range API with `Add-Padding: true`, a specific `User-Agent`, and local prefix caching. Only the
  five-character hash prefix leaves the device.
- F9.2 Checks run on item creation/edit, after unlock for items changed since the last scan, and on
  a background schedule (weekly full re-scan) while key material is available.
- F9.3 Strength assessment uses a zxcvbn-class estimator plus checks for reuse across items, age,
  missing TOTP where the site is known to support 2FA (optional dataset), and insecure (`http`)
  scopes. Results surface in a "Watchtower"-style report and per-item badges.
- F9.4 Optional: breached-account lookup by email address with a person-supplied HIBP API key.

### 5.10 Anti-phishing (F11)

Design in `05-anti-phishing.md`. Scope matching alone is insufficient: when the app silently offers
nothing on a look-alike site, the person's workaround is to copy the password by hand, which is
exactly what the attacker wants.

- F11.1 A credential, one-time code, or passkey assertion is released only for a host the item is
  scoped to. Every release passes through one authorization function, which re-checks even when the
  person explicitly selected the item.
- F11.2 Scopes that span unrelated owners cannot be created, edited into existence, or imported:
  single-label hosts and public suffixes (`com`, `co.uk`, `github.io`, `herokuapp.com`) are
  refused with an explanation.
- F11.3 When a host resembles a saved site but does not match it, the app says so — naming the
  resembled site and the reason — instead of showing an empty result. Detection covers visual
  confusables (Cyrillic/Greek/leetspeak), `rn`/`vv` digraphs, edit-distance near-misses,
  the saved site's name in a non-authoritative label, per-label mixed script, and punycode.
- F11.4 One-time codes are withheld on a mismatched host rather than warned about: a TOTP entered
  on a look-alike site is immediately replayable. There is no "copy anyway" affordance in the
  AutoFill extension.
- F11.5 When several items tie as the most specific match, the person chooses; the app never fills
  the first of an ambiguous set.
- F11.6 Host normalisation must never invent a match. Parsing that would widen matching — ASCII
  percent-escapes, zero-width and bidi characters, user-info, trailing-whitespace tricks — is
  rejected rather than normalised away.
- F11.7 Using a mismatched host requires adding it as a scope inside the unlocked app, with a
  confirmation naming the item. The AutoFill extension offers no override.
- F11.8 Passkeys are promoted as the phishing-resistant option: conditional upgrade where a site
  supports it, and password-only items flagged in the hygiene report.

### 5.11 Recovery and account lifecycle (F10)

- F10.1 Changing the account password re-wraps the keyset; changing the Secret Key regenerates the
  Emergency Kit and requires re-enrolling other devices.
- F10.2 Losing both the password and all devices is unrecoverable by design; the UI must say so at
  setup. Losing only devices is recoverable with the Emergency Kit plus the password.
- F10.3 Deleting the account wipes CloudKit zones and local data after confirmation and a
  password check.

## 6. Non-functional requirements

- N1. Unlock to interactive in under 1 s on a 2020-era device after key derivation; key derivation
  itself targets 300–500 ms on the slowest supported hardware.
- N2. AutoFill extension produces a credential list in under 300 ms for 5,000 items.
- N3. Offline-first; every feature except sync, sharing invitations and HIBP works with no network.
- N4. Accessibility: full VoiceOver, Dynamic Type, keyboard navigation on macOS.
- N5. Privacy: no analytics, no crash reporting that could include secrets; the only network
  endpoints are iCloud, the configured file provider, and HIBP.
- N6. Localisation-ready; English at launch.

## 7. Security requirements (summary; threat model in `02-architecture.md`)

- SEC1. All persisted vault data is encrypted with AES-256-GCM under keys derived from the account
  password and Secret Key (2SKD).
- SEC2. Every ciphertext is bound by authenticated data to its record ID, vault ID, schema version
  and key ID so records cannot be swapped, replayed across vaults, or downgraded.
- SEC3. Vault keys are wrapped to members with HPKE (X25519/HKDF-SHA256/AES-256-GCM); member public
  keys are verified out of band.
- SEC4. Key material lives in `SecureMemory` buffers that are zeroised on lock, and nothing in the
  key hierarchy is ever written to disk in plaintext, including logs and crash reports. The
  zeroisation guarantee is scoped to `SecureMemory`: decrypted field values and generated passwords
  become Swift `String`s at the UI boundary, which cannot be reliably zeroised, so copies may
  persist in freed memory while the process lives. Mitigated by short auto-lock timers, not
  eliminated; an adversary with code execution in an unlocked process is out of scope (A8).
- SEC5. KDF parameters are versioned and have enforced minimums; a stored header below the minimum
  is rejected, not silently accepted.
- SEC6. The AutoFill extension never returns a credential to a service identifier the item is not
  scoped to. Enforced by type (matching accepts only a normalised host) and by a single
  authorization chokepoint, not by convention across view controllers.
- SEC7. Import parsers treat input as hostile (size limits, zip-slip and zip-bomb protection,
  CSV formula-injection neutralisation on export).
- SEC8. Host normalisation and scope policy fail closed: an input that cannot be unambiguously
  resolved to a hostname, or a scope that spans unrelated owners, is rejected rather than
  interpreted generously.
- SEC9. Validation bounds are two-sided. A parameter with a security floor (KDF iterations) also
  has a ceiling, because a hostile value at either end is an attack — one on confidentiality, the
  other on availability.
- SEC10. Adversarial tests for SEC1–SEC9 run in CI (`04-test-plan.md`, section 6), as their own
  required check.

## 8. Success metrics (for a first release)

- All four normative scenarios pass as automated end-to-end tests on both platforms.
- Zero plaintext secrets observable in CloudKit Console or in a synced file for a seeded vault
  (verified by the sync-transport contract tests).
- Security review of the key hierarchy by an external reviewer before public release.
