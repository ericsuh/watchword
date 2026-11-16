# Watchword — Adversarial code and design review

Review date: 2026-10-13. Reviewed: `docs/01-prd.md`, `docs/02-architecture.md`,
`docs/03-implementation-plan.md`, `docs/04-test-plan.md`, `docs/adr/*`, and the code under
`Sources/` and `Tests/` at commit `5f9c9c2`.

Method: read the design against the threat model it claims, then attack the code that exists.
Where a claim was checkable on a real toolchain (Swift 6.4 / Xcode 27 locally, Swift 6.0 and 6.2 in
CI) it was checked rather than reasoned about — two findings below (C1, C2) came from running
`URLComponents` against hostile input and were not visible by reading.

Severity: **High** = breaks a stated security guarantee; **Medium** = weakens one, or is a
guarantee the docs claim and the code does not yet keep; **Low** = correctness or robustness.
Disposition is either *fixed in this change*, *accepted with rationale*, or *tracked*.

---

## A. Findings fixed in this change

### C1 (High) — `URLComponents.host` percent-decodes, inventing label boundaries
`HostNormalizer` matched on `components.host`, which Foundation has already percent-decoded. So
`https://x.amazon%2Ecom/` yielded host `x.amazon.com` and matched an `amazon.com` scope with
subdomains enabled. The encoded dot creates a label boundary that does not exist in the address
the person sees. The pre-existing `%` check ran against the *decoded* string, where the escape is
already gone.

Not remotely exploitable on its own (the OS reports the real host of a real page, and such a name
does not resolve), but it is precisely the class of bug — normalisation that invents a match —
that the whole matching design is meant to exclude.

*Fixed:* inspect `percentEncodedHost` and reject any escape in the ASCII range, while still
permitting the non-ASCII escapes that are how Foundation represents an IDN host. Tests:
`testEncodedDotCannotInventALabelBoundary`, `testNonASCIIPercentEscapesAreAccepted`.

### C2 (High) — `trimmingCharacters(in: .whitespacesAndNewlines)` strips U+200B
Foundation's `whitespacesAndNewlines` set includes the zero-width space, so `amazon.com\u{200B}`
was trimmed to `amazon.com` and matched. The `isForbiddenScalar` guard that was supposed to catch
it never saw the character, because trimming had already removed it. Found by a test that was
written expecting a rejection and failed.

*Fixed:* trim ASCII space/tab/CR/LF only, leaving exotic characters in place to be rejected.
Test: `testZeroWidthAndBidiCharactersAreRejected`.

### D1 (High) — No public-suffix guard on scopes
`ScopeMatcher` happily accepts a scope of `com` or `co.uk` with `includeSubdomains`, matching every
host beneath it. On an attacker's domain where the person has nothing specific saved, such a scope
is the top-ranked match and the app offers a real credential. The test plan listed PSL boundaries
as a future test; nothing in the code prevented it. Reachable by hand-editing a scope or by a
sloppy import.

*Fixed:* `ScopePolicy` / `PublicSuffix` refuse single-label hosts and public suffixes at creation
and edit time, with an embedded list covering ccTLD second-levels and shared hosting platforms.
Tests: `overBroadScopesRefused`, `normalScopesAccepted`, `demonstratesWhyPolicyExists` (which
asserts the matcher *would* have matched, so the test still means something if the policy moves).

### C3 (Medium) — No upper bound on KDF iterations
`KDFParameters.validate()` enforced a floor of 650,000 and no ceiling. A compromised sync store
could set `iterations = UInt32.max`; every subsequent unlock attempt would grind for hours. An
availability attack on the one operation the person cannot work around, from an adversary the
threat model explicitly includes (A1).

*Fixed:* `maximumIterations = 25_000_000` (~40× the floor: headroom for calibration on fast
hardware and for raising the floor, while bounding a hostile header to seconds), plus a salt-length
ceiling. Enforced in `validate()` and therefore at `Decodable` init. Test:
`kdfIterationsAboveMaximumRejected`.

### D2 (Medium) — The matching API let callers bypass normalisation
`ItemRanker.rank(items:host: String)` and `isSelectable(_:for: String:among:)` took raw strings.
`ScopeMatcher` lower-cased them but validated nothing, so a UI bug or a future call site could
match against attacker-influenced text and SEC6 would be enforced only by convention. The careful
normaliser sat beside a door that bypassed it.

*Fixed:* `NormalizedHost`, whose initializer is internal to `WatchwordMatching`. Production code
can only obtain one from `HostNormalizer.normalize`, so "matched against a validated host" is a
type-level property. Tests construct them through the normaliser, which means the matching tests
now also exercise normalisation.

### D3 (Medium) — No chokepoint for "may this credential be released"
Refusal was spread across the ranking logic with the extension expected to respect it. Nothing
made a wrong-site fill impossible to express.

*Fixed:* `AutoFillGate.decide` / `.authorize` / `.authorizeOneTimeCode`. `authorize` re-checks
even when the person explicitly selected the item. Also surfaces `ItemRanking.isAmbiguous`, so the
extension cannot auto-fill the first of a tied set — the path by which an AWS root password could
reach a retail login form.

### D4 (Medium) — "No match" was indistinguishable from "look-alike site"
The design treated refusal as sufficient. It is not: silence on `аmazon.com` looks identical to
silence on a genuinely new site, and the person's workaround is to copy the password by hand. This
was the gap behind the phishing request.

*Fixed:* `PhishingDetector`, and `docs/05-anti-phishing.md` for the design. 16 tests in
`AdversarialPhishingTests`.

### C4 (Low) — Mixed-script detection flagged every legitimate IDN
First implementation tested for multiple scripts across the whole host, so `амазон.com` (pure
Cyrillic name, Latin TLD) was "mixed" — i.e. every real internationalised domain. A test written
to assert the opposite caught it.

*Fixed:* per-label testing, as UTS #39 specifies. Test: `mixedScript`.

### C5 (Low) — Unbounded host length
`HostNormalizer` accepted arbitrarily long hosts; an adversarial test asserted only that a 10,000-
label host was processed in bounded *time*. Now rejected at the DNS limits (63-byte label,
253-byte host), which bounds the work rather than measuring it.

---

## B. Findings accepted, with rationale

### D5 (Medium) — Swift `String` cannot be zeroised, so SEC4 is partly unachievable
SEC4 says nothing in the key hierarchy is written to disk in plaintext and key material is
zeroised on lock. Zeroisation is achievable for keys in `SecureBytes`. It is **not** achievable for
anything that becomes a Swift `String`: generated passwords, decrypted field values, and anything
bound into SwiftUI. Strings heap-allocate, copy on assignment, and have no destructive API; copies
may persist in freed memory until reused.

Accepted, because the alternative (a `SecureString` threaded through every view) buys little: while
the vault is unlocked, an adversary with code execution in the process has the keys anyway, and
that adversary is out of scope (A8). What is *not* acceptable is claiming otherwise. SEC4 is
reworded in the PRD to scope the zeroisation guarantee to `SecureMemory`-held key material, and to
state the residual exposure for field values. `PasswordGenerator` returning `String` is noted in
`02-architecture.md` §12 rather than silently contradicting §11.

### D6 (Medium) — Revocation is not instantaneous, and the docs implied it was
F4.3 says removal "rotates the vault key, re-encrypts all items, and re-wraps". All three need the
owner's device online *and unlocked*. Between the decision and the rotation completing, the removed
member can still pull records. The ordering matters: remove from the transport share first (takes
effect server-side immediately), then rotate.

Accepted as a property of a serverless design — there is no always-on component to enforce a cutoff.
Documented: F4.3 now specifies the ordering and states that revocation completes on the owner's
next unlock, with the UI showing a pending-rotation state.

### D7 (Low) — XOR to combine the two secrets (resolved in milestone 1: HKDF, see ADR 0003 amendment)
`AUK = Kp ⊕ Ks` follows 1Password. XOR of two independent secrets is sound here, and neither input
alone yields the AUK. `HKDF(Kp || Ks)` would be marginally more robust against future changes
(e.g. if one input ever became partly predictable) at no cost. Tracked as a milestone-1 decision in
ADR 0003 rather than changed now, because the crypto module does not exist yet and the choice
should be made with its tests.

### D8 (Low) — QuickType identities are a plaintext index outside our control
Publishing to `ASCredentialIdentityStore` hands item hosts and usernames to an OS-managed database.
`02-architecture.md` §5 said "there is no plaintext index on disk", which is true of *our* storage
and misleading overall. Accepted (it is the price of QuickType) but now stated in the threat model,
with a per-item "exclude from QuickType" toggle added as F6.8 for items the person considers
sensitive.

---

## C. Findings tracked, not yet addressed

| ID | Severity | Finding | Plan |
| --- | --- | --- | --- |
| D9 | Medium | Every device holds the account Ed25519 signing key (it is in the AUK-wrapped keyset), so a lost device cannot be excluded without rotating the account key. No device registry. | **Closed for writing** (§J): the device registry, a second signature by a per-device key on everything written, and revocation. **Still tracked as D9b:** a revoked device that held the keyset can still *read* what it reaches; ending that needs an account re-key (new keyset and Secret Key, vault keys rotated), to be decided with vault-key rotation in milestone 4. |
| D10 | Medium | Vault-key rotation re-encrypts every item: O(items) work and O(items) upload on every membership change. | Per-item keys wrapped by the vault key make rotation O(members). Already an open question in §16; promoted to a milestone-4 decision. **Decided in milestone 4, against per-item keys** (ADR 0007): rotation re-encrypts, as resumable data, and the cost was measured. |
| D11 | Medium | Test plan claims AAD-binding and ciphertext-tamper coverage that cannot exist yet — there is no crypto layer. Current envelope tests cover the header only. | **Resolved in milestone 1**: the tests exist (`AdversarialCryptoTests`, §F below). |
| D12 | Medium | No backup story. If CloudKit returns `CKErrorUserDidResetEncryptedDataKey` *and* the only device is lost, data is gone. | Add scheduled encrypted archive export (F8.4 exists; make it schedulable) as a milestone-7 requirement. |
| D13 | Low | KDF calibration to ≥300 ms on the *creating* device can make unlock slow on the person's oldest device. | Calibrate against a floor, cap by the slowest enrolled device class; ADR 0003 note. |
| D14 | Low | N1 says 250–500 ms for derivation; ADR 0003 and §4 say ≥300 ms. | Harmonised to 300–500 ms in the PRD. |
| D15 | Low | `.domain` identifiers containing a port are rejected, which fails *closed* (no AutoFill) rather than open. Usability, not security. | Verify what the OS actually passes on device in milestone 2 before loosening anything. |
| D16 | Low | Entropy's inclusion–exclusion sums terms up to ~1e252; catastrophic cancellation is possible. Clamped by `max(total, 1)` and `min()` against the unconstrained bound, so the reported value stays sane. | Leave; revisit if a policy ever reports an implausible figure. |
| D17 | Info | Trust-on-first-use fingerprint verification will be skipped by most people. | Make the unverified state visibly degraded in the sharing UI (milestone 4). |

---

## D. What the review did not find

Worth recording, so a later reader knows these were examined rather than overlooked:

- **Envelope parse ordering** is correct: magic, version, kind, then length, all before any
  decryption is attempted. Kind confusion is rejected before the payload is touched.
- **`KDFParameters.init(from:)`** validates, so an out-of-policy header cannot be decoded at all
  rather than being caught later by a call site that might forget.
- **Password generation** is unbiased: `Int.random(in:using:)` avoids modulo bias, and the
  `forbidRepeatedAdjacent` redraw keeps the distribution uniform over allowed characters. The
  chi-square test over 200,000 characters passes.
- **Specificity scoring** has no tie that lets a less specific scope outrank a more specific one;
  exact beats subdomain at equal label counts, and the cross-label cases are unreachable.
- **`excludedHosts`** vetoes per scope, not per item, which is the correct granularity.
- **Entropy NaN edge case** (`length == 1` with a one-character alphabet would compute
  `0 * -inf`) is unreachable because `validate()` enforces a minimum length of 4 first.
- **Zero dependencies.** The strongest supply-chain position available, now enforced in CI rather
  than merely stated (`07-supply-chain.md` §2).

## E. Note on validation

Local validation ran on Swift 6.4 / Xcode 27; CI runs Xcode 16.4 (Swift 6.0) and Xcode 26.x.
Green locally is therefore not a substitute for CI — the macro-expansion and `#expect` differences
that produced three of the five CI failures on this branch's history were toolchain-specific. Both
matter; neither alone is sufficient.

---

## F. Milestone 1 review (cryptographic core)

Review date: 2026-10-14, by a separate reviewer of the milestone-1 change (`SecureMemory`,
`WatchwordCrypto`, the full envelope), before the pull request was opened. Method as above: each
claim was reproduced against a toolchain where possible — the bypasses in R1 and the weaknesses in
R2–R7 were demonstrated with probe tests or builds (Swift 6.3.2 and 6.4.1, swift-crypto standing in
for CryptoKit on Linux) before being reported. No Critical or High findings.

| ID | Severity | Finding and threat | Disposition |
| --- | --- | --- | --- |
| R1 | Medium | The unsafe-confinement gate keyed on the token `unsafe`. A malicious contributor could write arbitrary memory with `@_silgen_name("memset")` and integer parameters (compiles under `-strict-memory-safety -warnings-as-errors`), hide marked code behind a symlink (`grep -r` skips symlinks, SwiftPM compiles them), or add a C target or custom `path:`. | **Fixed.** `assert-unsafe-confined.sh` also rejects `@unchecked`, underscored attributes and `@exclusivity`/`@extern` outside `SecureMemory`, hand-bound foreign symbols anywhere, symlinks under `Sources/`/`Tests/`, and non-Swift files under `Sources/`; `assert-no-dependencies.sh` checks the resolved manifest for target types, custom paths and compiler-relaxing settings. Docs say "tripwire", not "proof". Each bypass was re-run against the new checks and fails them. |
| R2 | Medium | `VaultKeyGrant.open` returned the grant's own vault and key IDs. A4 (an admin of vault S1 only) could file a grant labelled S2, carrying a key A4 knows, in S1's table; a caller indexing by the label would install it as S2's key, giving A4 read and inject on S2. The HPKE `info` binding does not help: any legitimate signer can seal a fresh grant under any label. | **Fixed.** `open(as:from:vaultID:keyID:)` takes the storage location and refuses a mismatch before verifying or decrypting. Tests: `grantFiledUnderAnotherVault`, `vaultKeyWrapMoved`. |
| R3 | Medium | The nonce-reuse guard lived in a per-call `RecordSealer` struct, so it never spanned key wraps (each made a fresh sealer) or copies of a sealer. With a repeating RNG, two vault keys wrapped under one Ksym got the same nonce: `ct1 ⊕ ct2 = vk1 ⊕ vk2`, so a former member (A5) holding one learns the other, and GCM's authentication key leaks. | **Fixed.** The ledger belongs to the key (`EncryptionKey.nonceLedger`, a thread-safe `NonceLedger` in `SecureMemory`), shared by every copy and every caller; `RecordSealer` is gone in favour of `RecordCipher.seal`. Test: `nonceReuseAcrossWraps`. A per-record derived key was considered and not adopted: with a repeating RNG the derivation salt repeats too, so it does not remove the dependence on the generator. |
| R4 | Low | Small-order Ed25519 signing keys were accepted. With the identity key, the 64-byte "universal signature" (R = identity, S = 0) verified for every message on swift-crypto/BoringSSL, so a member publishing such a key (it passes fingerprint confirmation, the fingerprint covers it) makes their membership records, log segments and grants forgeable by anyone. | **Fixed.** `Signatures.verify` (and so `PublicKeyBundle.init`) rejects the seven small-order encodings with either sign bit, each checked independently to satisfy 8·P = O. Test: `smallOrderSigningKeys`. |
| R5 | Low | `CBORValue.text` compared by canonical equivalence (`"é" == "e\u{301}"`) but encoded the bytes as given, so "equal values encode equally" was false. Unused today; a trap for item payloads. | **Fixed** by removing `.text`; a future format adds text with an explicit normalisation rule. |
| R6 | Low | `SecureBytes` is a `Collection`, so `Array(s)`, `Data(s)` and the non-constant-time `elementsEqual` compile without any explicit call. | **Partly fixed, partly accepted.** The conformance stays because CryptoKit's sealing APIs take `DataProtocol`, and a separate view type would be equally copyable. Added the named `unprotectedCopy()`, moved the two production copy-outs (salts) to it, and corrected the docs that implied copying out was impossible. |
| R7 | Low | `NSRecursiveLock` let a same-thread `zeroise()` inside a read proceed, so the reader saw zeros instead of a trap. | **Fixed.** A reader count makes that zeroise trap. Exit test (Swift 6.2+): `zeroiseDuringReadTraps`. |
| R8 | Low | Secret Key parsing left unwiped copies (the digit arrays, and freed buffers from array growth). | **Fixed.** Capacity reserved once and never grown; every intermediate array wiped. |
| R9 | Low | One 64 MiB cap for every envelope kind, so a hostile store could make a 113-byte keyset cost ~150–200 MiB of copies to reject, enough to kill a memory-capped AutoFill extension. | **Fixed.** `Envelope.parse`/`RecordCipher.open` take a per-call cap; key wraps use 1 KiB. Test: `perKindSizeCap`. |
| R10 | Low | Nothing enforced "no production target depends on `WatchwordTestSupport`" (seeded and broken RNGs). | **Fixed** in `assert-no-dependencies.sh`. |
| R11 | Low | Adversarial gaps: no tests for moved vault-key wraps, grant location confusion, cross-wrap nonce reuse or weak Ed25519 keys; byte-flip and truncation tests accepted any error, so a regression in *which* layer rejects a flip would pass. | **Fixed.** Tests above, and flips/truncations now assert `EnvelopeError` for header positions and `authenticationFailed` for nonce, ciphertext and tag. |
| R12 | Info | A stray test log was committed; the implementation plan still said "XOR"; dead store in `init(randomCount:)`. NFKD normalisation can differ across OS Unicode versions for code points unassigned on the older one; each `SecureBytes` occupies a whole locked page (16 KiB on Apple silicon); calibration maps a 0 ns probe to the floor but 1 ns to the ceiling. | Log removed and `*.log` ignored; plan and dead store fixed. Unicode-version stability is **tracked** for the password-setting UI (milestone 2: reject unassigned code points, as PRECIS does). Page cost is **accepted** for keys and noted for milestone 2, where decrypted item payloads should not each hold a locked page for long. The calibration asymmetry is **accepted**: both ends stay within the two-sided bounds, and a probe that truly took 1 ns would justify the ceiling. |

Not adopted from the review: a CODEOWNERS entry for `Sources/SecureMemory/`. It belongs with the
other repository-settings steps in `08-repository-hardening.md` §6, which the owner applies; the
suggested line is `/Sources/SecureMemory/ @ericsuh`.


## G. Milestone 2 review (local vault, unlock, apps)

Review date: 2026-10-14, by three independent reviewers of the milestone-2 change before the pull
request was opened, each taking one layer: the unlock and vault-session layer, storage and the unsafe
system bindings, and the app layer with CI and the docs. Method as above: U1, U2, U4 and U5 were
reproduced with probe tests in a scratch copy of the package, S1, S2 and S5 against the system SQLite
with the app's own pragmas; A1–A4 are from reading the SwiftUI, UIKit and AppKit behaviour and were
not run on a device. One High finding (U1), fixed.

| ID | Severity | Finding and threat | Disposition |
| --- | --- | --- | --- |
| U1 | High | `enableQuickUnlock()` needed only an unlocked session, and enrolment writes `lastPasswordUnlockAt = now`. Someone who can present the enrolled biometric but does not know the password (a look-alike, a coerced or sleeping owner) could quick-unlock before day 14 and re-enable, forever, defeating F5.4. Reachable from the Settings toggle. | **Fixed.** `enableQuickUnlock(password:)` re-verifies the password against the stored header; the toggle asks for it. Test: `cannotExtendInterval`. |
| U2 | Medium | `openKeys` failed the whole unlock on the first vault-key row that did not open, after the keyset had already proved the password. One planted row (A8, a restored backup) meant every unlock showed "Incorrect password" and quick unlock was destroyed. | **Fixed.** Only the personal vault's current key is required; other bad rows are skipped. A bad required key is `vaultKeyUnreadable`, never `authenticationFailed`. Quick unlock forgets the enrolment only when the LUK → AUK → keyset chain fails. Test: `plantedKeyWrap`. |
| U3 | Medium | Only `errSecAuthFailed` counted towards the F5.4 limit. With `biometryCurrentSet` and no passcode fallback the system prompt retries internally and a run of failures usually ends in Cancel, so someone who can clear the OS lockout with the device passcode (A3) would never trip it; the fake modelled one error per attempt and hid this. | **Fixed.** Cancels count too (and still surface as cancels). Tests: `failureLimit` over fail and cancel; `cancel`. The real status mapping still needs a device check, carried to milestone 5's on-device QA. |
| U4 | Medium | `changePassword` threw `locked` if a lock landed after the commit, so the UI said "your vault is unchanged" while only the new password worked: a lock-out by misinformation (F10.2). | **Fixed.** Success is reported once the commit lands. Test: `lockDuringPasswordChange`. |
| U5 | Low | One global Lamport high-water mark: one record with a version near `UInt64.max` froze writes to every item. Only a vault-key holder can write one today; any shared-vault member from milestone 4. | **Fixed** (per vault). Quarantining implausible jumps is **tracked** for milestone 3, where versions arrive from other devices. |
| U6 | Low | Permanent deletion and trash purge deleted unconditionally, so a restore interleaved at the store `await` was silently undone. Purge trusts the wall clock. | **Fixed** with `StoreChange.conditionalDeletions` (`versionConflict`). The clock is **accepted**: moving it needs the unlocked device, which can delete directly. |
| U7 | Low | `deleteAccount` stopped at the first Keychain error, possibly leaving the Secret Key behind. | **Fixed.** Every item is attempted; leftovers are reported (`keychainCleanupIncomplete`). |
| U8 | Low | Enrolling quick unlock writes two Keychain items non-atomically; a quick unlock between them fails and forgets the enrolment. | **Accepted**: denial of service only, recovered by re-enabling. |
| U9 | Low | `EmergencyKit`'s default `description` printed the Secret Key; decrypted and encoded item JSON buffers were never wiped; password unlock has no attempt backoff. | Kit **fixed** (redacted description and mirror); buffers **fixed** (`ItemCodec` returns and wipes protected storage). Backoff **tracked** as an ADR candidate: offline guessing is bounded by 2SKD, online guessing needs the unlocked device. |
| S1 | Medium | The store trusted any schema at `user_version = 1`. `trusted_schema = OFF` does not stop plain triggers: a planted `BEFORE DELETE … RAISE(IGNORE)` made deletions and `eraseAll` report success while erasing nothing, and an `AFTER INSERT` trigger turned a one-off rollback into a permanent one. | **Fixed.** On open, `sqlite_schema` must equal exactly what `migrate()` creates (tables, index, autoindex, verbatim SQL), else `unexpectedSchema`. Test: `plantedSchema`. |
| S2 | Low–Medium | `eraseAll` left old pages (envelopes, the pre-change account header) in `-wal`; the connection is never closed cleanly, so they survived on disk. `noPlaintextOnDisk` checkpointed first and hid it. | **Fixed.** `eraseAll` truncates the WAL and fails if a reader blocks it (`checkpointIncomplete`); a password change truncates best-effort. Test: `eraseLeavesNothing`, without a prior checkpoint. |
| S5 | Low | The 64 MiB read cap ran after SQLite had already materialised the value (default limit ~1 GB), so a tampered file could exhaust the AutoFill extension's memory. | **Fixed.** `SQLITE_LIMIT_LENGTH` set at open. Test: `lengthLimit`. |
| S6 | Low | No busy timeout: the app and the extension contending for the file failed at once. | **Fixed** (2 s). |
| S7 | Low | Two tests' names overstated what they asserted ("fails like a wrong password", "any other authentication failure"). | **Fixed.** Exact errors asserted where the behaviour is exact; names describe fail-closed where it is not. |
| A1 | High | On macOS the idle timer and sleep observers lived in the window's view while the unlocked session lived in the app, which keeps running when its window closes; reopening from the Dock showed the vault, and any click reset the timer. | **Fixed.** Monitoring moved to `AppModel`; closing the last window quits; `recordActivity` locks instead of refreshing once the timeout has passed. Test: `lateActivityLocks`. |
| A2 | Medium | The iOS app-switcher cover sat under SwiftUI sheets and skipped the onboarding kit screen, so the snapshot could show the Secret Key or an item being edited. | **Fixed.** A separate window above alert level covers every phase whenever the app resigns active. Not yet verified on a device. |
| A3 | Medium | Emergency Kit confirmation (F5.1) could be skipped by locking on the kit screen, and the kit stayed on screen after a background lock. | **Fixed.** An unconfirmed kit is shown again after every unlock; every lock clears the kit screen. |
| A4 | Medium | A background lock cleared the clipboard, so Copy could not be pasted into Safari, pushing people to select and system-copy the secret (no expiry, Universal Clipboard). On macOS copies reached Universal Clipboard and survived quitting. | **Fixed.** No clear on background lock (the 60 s expiry still applies); secrets are not selectable; macOS uses `.currentHostOnly` and clears on quit. |
| C1 | Medium | `Apps/project.yml` and non-Swift files under `Apps/` bypassed both supply-chain tripwires: a remote package, a build script, a bridging header or `SWIFT_STRICT_MEMORY_SAFETY: NO` would pass CI. | **Fixed.** `assert-no-dependencies.sh` checks the spec; `assert-unsafe-confined.sh` allows only `.swift` and `project.yml` among tracked `Apps/` files. Each planted case was re-run and fails. |
| C2 | Low | Stale comments (CI's "commit a generated project", the tripwire's "Sources/ or Tests/") and an unverified claim that the Emergency Kit PDF never touches the app container (`fileExporter` may stage a copy). | **Fixed** (comments corrected, claim softened). |

Carried from milestone 1, still open: rejecting code points unassigned in older Unicode versions when
a password is set (R12). The onboarding screen accepts any password of ten or more characters.

## H. Milestone 3 review (sync, portable half)

Review date: 2026-10-22. The change was written in a remote Linux session; everything below was reproduced there
with `swift test`. Y1–Y3 came from the randomised multi-device simulation itself (`LongRunning…`, at its nightly
size); Y8–Y13 from an independent review of the engine by a second agent, each with a reproduction test, now kept
as regression tests (`SyncReviewRegressionTests`, and `overflowingNumbers` in the suite "sync log"); Y14 from the
owner's requirement that sync never lose data (PRD F7.6, F7.7), which replaced last-writer-wins with conflict-keeping
merges.

| ID | Severity | Finding and threat | Disposition |
| --- | --- | --- | --- |
| Y1 | High | A save set `modifiedAt` from the saving device's clock, so a version saved on a device with a slower clock than its predecessor's was not "after" it in the merge. A device holding the predecessor kept it while the others adopted the save: silent divergence from ordinary clock skew. | **Fixed.** `ItemMerge.stamped` never moves `modifiedAt` back. Test: `stamping`. |
| Y2 | High | A deletion made on a device but not yet published was not a tombstone during merging, so an older version merged before publishing put the record back on that device only. | **Fixed.** Pending deletions count as erasures in merge. Test: `pendingDeletionBeatsOlderVersions`. |
| Y3 | High | The outbox published rows newer than the highest stamp *seen*; a local version the merge kept over a higher remote one was never published. | **Fixed.** `SyncState.published` records what this device published. Test: `keptLocalVersionIsPublished`. |
| Y4 | Low | Field order is not associative in one corner (a field removed in an intermediate merge and revived later is placed after the ordered ones). | Accepted at first; **fixed** in the audit of the merge (below). The order is stored (`Item.fieldOrder`) as a last-writer-wins register under the order on revisions, and `fields` is a function of it and the fields present, so it is an exact join. Adding or removing a field no longer counts as a reorder. Tests: `fieldOrderIsAJoin`, `fieldOrderLastWriterWins`. |
| Y5 | Medium | Every device holds the account signing key (D9), so a lost device can still write validly signed segments. | **Fixed** (§J): every object needs a registered device's own signature as well; once a device is revoked, each other device refuses its segments and snapshots from the moment it learns of the revocation, locked or unlocked. What a device merged from it before learning is kept and handed on (unavoidable without a clock everyone trusts; stated in architecture §7.8). Tests: `revokedDevice`, `keysetAloneCannotWrite`, `deviceKeyAloneCannotWrite`, suite "Sync engine: revoked devices". |
| Y6 | Low | A device that stops syncing for good blocks garbage collection of other streams (its acknowledgement never arrives); this includes a revoked device's stream known only through a snapshot's coverage. | **Fixed for revoked devices** (§J): a revoked device is retired from garbage collection and from snapshot election (test `collectionResumes`, `snapshotElectionSkipsRevoked`). A device that is merely silent still holds collection back until the person revokes it; that is the intended control, not an oversight. |
| Y7 | Low | The store (A1) can withhold objects. | **Accepted**, unpreventable without a trusted clock: the stream stops at the gap and `SyncReport.waiting` says so. |
| Y8 | High | A device whose sync state was rolled back (a restored backup, A8) took its next sequence number from that state, reused collected numbers no one would fetch — its edits silently lost — and then hit `objectExists` on every sync forever. | **Fixed.** The next number is never below anything its stream has on the transport, and merging its own newest segment or a snapshot's coverage raises it too. Test: `rolledBackState`. |
| Y9 | High | Garbage collection and snapshot choice could strand a device: a snapshot's coverage was consulted only when first applied, so a covered segment that vanished later stalled the stream; and snapshots were chosen by Lamport time, not coverage, so after a partition a joining device could pick one that did not cover what another device had collected. | **Fixed.** Every listed snapshot is merged; streams continue from the highest coverage merged when their next segment is missing or rejected; a segment is collected only once every other stream acknowledges it and a listed snapshot covers it; an own snapshot is deleted only when another covers everything it does. Tests: `gapCoveredBySnapshot`, `incomparableSnapshots`. |
| Y10 | High | A deletion the person made while sync was merging the same record was undone on that device but published to everyone else. | **Fixed.** Before publishing, a row that came back is settled against the deletion exactly as every other device will settle it, and reconciling keeps erasures. Test: `deletionDuringMerge` (with and without reconciling). |
| Y11 | Medium | An insider snapshot whose vector named `UInt64.max`, or an object named with such a number, trapped every reader on arithmetic overflow — a crash loop. | **Fixed.** Vectors above `maximumSequence` (2^48) are rejected, such names ignored, and `nextSequence` is never 0. Test: `overflowingNumbers`. |
| Y12 | Medium | One persistently rejected object anywhere under the vault (a revoked device's segment, a stray or half-uploaded file) stopped every device from writing snapshots, so collection never ran again. | **Fixed.** Snapshots no longer require a clean sync (their coverage is what was merged). Test: `junkDoesNotBlockSnapshots`; the simulation now plants a stray object. |
| Y13 | Low | File transport: `list` followed a symbolic link in an intermediate directory; `create` needed hard links, which some providers lack; a link swapped in between `fetch`'s check and open is followed. | **Fixed**, the first two (test: `plantedSymlinks`, extended). The third is **accepted** and documented: Foundation offers no `O_NOFOLLOW` open; the read stays capped and checked, and the coordinated iCloud Drive wrapper (Mac half) is where it closes. |
| Y14 | High | Requirement, not a defect: concurrent edits of one field kept only the later value (the other in a history capped at 100), notes merged as one value, and a permanent deletion silently discarded an edit its author had not seen. | **Changed.** Multi-value registers per field with version vectors (`Item.conflicts`, kept until the person resolves), notes as a line-level sequence CRDT, erasure summaries so a deletion removes only what its author saw (the rest is kept, trashed), merges never shorten histories, quarantined versions kept. Tests: suite "Simultaneous edits across devices", "Field-level item merge", and the simulation's no-data-loss check. **History decided by the owner (2026-10-23):** a full audit trail, so `VaultSession` no longer prunes history by age (90 days) or count (100 entries); an edit that would outgrow the 1 MiB payload is refused (`ItemCodecError.payloadTooLarge`) and the stored version is left as it was. Tests: `history`, `historyNeverPrunedToFit`. The limit is reached after roughly a thousand field changes of a typical login; moving history into records of its own removes it and is milestone-3 Mac-half work. **Trash decided by the owner (2026-10-24):** the 30-day purge (F1.5) stays, because moving an item to the trash is the person's explicit action; the app now asks for confirmation before it, saying the item is deleted permanently after 30 days (`ItemDetailView`; tested in `OnboardingAndUnlockTests`). The app has no Trash view yet, so `VaultSession.restore` is not reachable from the UI. **Reviewed 2026-10-25:** sync also leaves items in the trash that nobody confirmed, and the purge removed them: a version kept after a deletion (dated to its edit, so possibly purged at the next unlock), a trash merged with an edit it never saw, and a trash shown over a concurrent restore. **Fixed:** the purge removes only `Item.isTrashedByPerson`, and the reference merger marks a deletion's residue `keptAfterDeletion`. Tests: `purgeKeepsTrashSyncLeft`, `trashedByPerson`, `trashEverywhere`, and `trashAndEdit`, `deleteAndEdit` extended. Still open: `trashedAt` comes from the trashing device's clock, which another device's purge trusts once sync is wired (U6). |
| Y16 | High | Found by the long simulation after Y14: an ordinary edit of a field that held a conflict superseded the conflicting value and dropped it — a lost value, against F7.7. | **Fixed.** The edit moves superseded conflicting values to `Item.retainedValues` (union-merged, never pruned); only `ItemMerge.resolve` discards. Test: `editKeepsConflictingValue`; the simulation's no-data-loss check counts retained values. |
| Y17 | High | Found by the long simulation after Y14: each device recorded its own merge write in the item's version vector, so two devices that merged the same edits held different states, and every exchange produced another version: sync never settled. | **Fixed.** The vector records edits only; `ItemMerge.written` sets the version alone, and an item from before sync stands in its row's origin only when it has no vector. Test: `mergeResultsAreTheSameState`, and `conflictsKeepEveryVersion` now requires settling within four rounds. The nightly simulation was reduced to 2,500 steps to fit its budget, and the harness no longer decrypts every item at every step. |

Also recorded: a snapshot may attribute versions to any device (Y15, Low, insider only; documented in §7.5), and
`ItemMerge.merge` traps on versions of different items, so a merger must check identity first, as
`FakeItemMerger` and `VaultSession` do (both open through the row's context) — and, since the audit below, as
`ItemRecordMerger` does itself (`ItemMergeError.identityMismatch`).

### Audit of the item merge as a CRDT

Review date: 2026-11-15, in a remote Linux session. The owner asked that sync be provably correct where it can be.
The merge was restated as a state-based CRDT (`10-sync-correctness.md`: the state, the join, the updates, and the
argument for each component), and checked three ways: against the specification of a multi-value register under
random histories (`LongRunningItemMergeLawTests`), over every history of a small configuration
(`LongRunningItemMergeExhaustiveTests`, counts asserted; 34,933 histories on every push since Y35), and on
arbitrary metadata (suite "Adversarial: sync log, item metadata"). Y18–Y21, Y25, Y26 and the lost place of Y4 were
reproduced by running the previous implementation (a copy of the commit before this change) on the history each test
below uses, and of Y22 the colliding encoding; Y23, Y24 and Y27 were found by reading the code and were not run
against it. Each defence was then removed from the new code in turn to confirm that a test fails without it.
"Insider" below is an account device or, from milestone 4, a member of a shared vault (A4): it holds the vault key,
so it can write any metadata that decodes.

| ID | Severity | Finding and threat | Disposition |
| --- | --- | --- | --- |
| Y18 | High | Not a join. Two devices that concurrently wrote the *same* value of a group were merged into one stamped value. A third write that had seen only the stamp kept then superseded the value outright on devices that merged in one order, and left the other device's write as a conflict on devices that merged in another: `(a ⊔ b) ⊔ c ≠ a ⊔ (b ⊔ c)`, in ordinary use (two people making the same change). | **Fixed.** Every value nothing supersedes is kept, equal or not; only the view (`ItemMerge.conflicts(of:)`, `Item.hasConflicts`) treats equal values as one. Test: `sameValueWrittenTwice`. |
| Y19 | Medium | An update that was not inflationary. `ItemMerge.resolve` discarded the values retained for the group on the resolving device only; merging any other copy — the next sync — brought them back, so a person's explicit discard (F7.7) did not hold. | **Fixed.** `Item.discards` records, per group, the version vector the person had before them; retained values it covers stay discarded in every merge, and values retained by edits it had not seen stay kept. Tests: `resolutionDiscardsEverywhere`, the exploration `twoDevicesWithRetainedValues`. |
| Y20 | High | Insider. A conflicting value was applied by its *type*, not by the group it was filed under: a title planted among the conflicts of a made-up group replaced the honest title **under the honest device's stamp**, so every later merge kept it as that device's own write; one field's contents filed under another field's ID replaced that field. Titles are not in the history, so the honest value was gone. | **Fixed.** A value is read only under the group it belongs to, and only known groups are read (`ItemMerge.belongs`, `ItemGroup.isKnown`). Test: `valuesUnderTheWrongGroup`. |
| Y21 | High | Insider. Note-line IDs are (revision, index), and a device's next revision is predictable. Lines planted under the IDs of the victim's next edit collided with the lines the victim then typed, and of two lines with one ID the first was kept: what the person typed vanished as they saved it. The line merge was also not commutative when one ID had two anchors. | **Fixed.** No ID in a record may be above the record's own version (below, Y23), so a planted ID cannot be one an edit made after merging the record uses (one made before it: Y33); and two lines with one ID are joined, keeping both texts and the later anchor (`NoteText.join`). Tests: `plantedLineIDs`, `noteLineStructure`. |
| Y22 | Medium | Orders that every device must agree on were not total, or not the same everywhere: the shown value among equal revisions fell to `Set` iteration order (which differs between launches); the tie-break encoding was not injective (tags `["a\nb"]` and `["a", "b"]`; scopes) and went through `JSONEncoder`, whose output is not guaranteed across OS releases; a version vector naming one device under two spellings took whichever the dictionary yielded last. Two devices reading the same bytes differently each write "the" merge result and never settle. | **Fixed.** One injective, length-prefixed encoding (`CanonicalWriter`) under every tie-break; orders are total on any input; the vector takes the higher count. Tests: `repeatedIdentifiers`, `lawsOnHostileMetadata`. |
| Y23 | Medium | Insider. "Supersedes" was "has seen the other's revision", which is a partial order only between honest stamps: crafted stamps could each supersede the other (both values dropped) or break transitivity (the result depends on merge order). And counts were unbounded: a value stamped as having seen `UInt64.max` of every device could not be superseded by any later edit or resolution — a conflict for good. | **Fixed.** Supersession is strict coverage of the stamps' vectors, a strict partial order on anything and the same relation between honest stamps (`10-sync-correctness.md` §3.2); and every count in a record is read as at most the record's own version, which the engine has vetted (U5). Tests: `absurdCounters`, `repeatedIdentifiers`, `lawsOnHostileMetadata`. |
| Y24 | High | Insider. `ItemRecordMerger.resolveErasure` computed the version of a kept copy as the highest count in the erasure summary plus two. A tombstone whose summary named `UInt64.max` trapped every device holding an edit the summary did not cover, on every launch (as Y11). | **Fixed.** `ItemErasure(summary:)`: a summary that does not decode, names a version above 2^62, or claims more than the row it erased could hold has seen nothing; arithmetic is checked (`ItemMergeError.versionOverflow`). Test: `hostileErasureSummaries`. |
| Y25 | Medium | A version kept after a deletion was a fresh edit by each device that kept one, so devices that kept the same edit held different items until they exchanged them — and a kept item a person then restored was put back in the trash whenever its device met the tombstone again (a reconciling sync, a device joining from the log), which undid the restore on every device. | **Fixed.** To a version it does not cover, a deletion is one write by the deleting device at the tombstone's revision (`ItemMerge.settle`): the same on every device, superseded by a restore made after it, never applied twice. Tests: `deletionIsOneWrite`, `restoreAfterDeletionStands`. |
| Y26 | Medium | The version of a kept copy was guessed from the summary's highest count. A device that deleted an item whose row was a merge result (a version above every edit in it) wrote a tombstone above the guess; every device holding an unseen edit then offered a copy *below* the tombstone, which the engine refuses (`invalidMergeResult`), stopping the deleting device's stream there until another stream happened to bring the trash. | **Fixed.** The summary names the row erased; the copy is written above the tombstone. Test: `keptVersionIsAboveTheTombstone`. |
| Y27 | Low | Notes split on `"\n"` as a `Character`, which a CR-LF pair is not, so a note with Windows line endings was one line and merged as a whole. `ItemMerge.stamped` trusted its caller to carry the history and creation date forward. | **Fixed.** Every U+000A ends a line; `stamped` takes the union of histories and the earlier creation date itself. Tests: `lineBreaks`, `noteEditsContainTheirPredecessor`, the inflation check in `MergeModel`. |
| Y28 | Medium | Insider; engine. `RecordMerger.resolveErasure` is not given the tombstone's version, so the merger takes the erased row's version from the summary. A tombstone at an ordinary version whose summary names row 2^40 makes every device with an uncovered edit write its copy at 2^40 + 2: versions raised past what the engine lets a *received* version jump (U5). | **Fixed** when the sync-core workstream merged (below, "Integrating the sync-core work"). `SyncEngine.resolve` passes the joined erasure's stamp to `RecordMerger.resolveErasure(_:of:above:)`, a function of the erasures alone; `ItemRecordMerger` believes no deletion whose summary names a row above it (it has then seen nothing) and writes a kept version just above the stamp and the row. The `tombstone:` overload is gone: the protocol carries the version now. Test: `tombstoneNamingAHigherRow`, no longer a known issue; `hostileErasureSummaries` and `keptVersionIsAboveTheTombstone` pass the tombstone too. |
| Y29 | High | Vault, not merge. `VaultSession.save` stamps every group that differs between the draft and the stored version. A draft opened before a sync merged another device's edit differs in the groups *that device* changed too: they are stamped as this device's writes made after seeing the edit, and replace it with no conflict — and, for anything but a field, no history. A lost update in ordinary use (an editor open during a sync). | **Fixed.** `save` refuses a draft whose `version` is not the stored row's with `VaultError.versionConflict`, checked against the row the write read and committed conditionally on it (the compare-and-swap AutoFill's `saveCredentialItem` uses too). A draft of an item no longer stored replaces nothing and is saved as before. Regression: `StaleDraftTests`. |
| Y30 | Low | Insider; vault. A record adopted while the device holds no version of the item is stored as written, and `VaultSession` shows it as stored: `notes`, `fields` and their order as the writer rendered them, which need not be what its metadata says and what every merge and save will make of it. | **Fixed.** `VaultSession.openItem`, which every read goes through (the UI's, AutoFill's, the sealer's), returns `ItemMerge.canonical(item, origin:)` of the row. Regression: `CanonicalReadTests`. |

Also recorded: erasing a covered version whole is not a join with the item merge and cannot be made one without
splitting items (`10-sync-correctness.md` §5 gives the counter-example and what holds instead); a device restored from a backup can reuse a
revision until its next sync (both writes are kept, but a third device that saw the first is taken to have seen the
second); and an insider can fill an item to the payload limit, after which it accepts no edit (as for history).

Also fixed in passing: `StoreFixtures.physicalTemporaryPath` named `SQLiteRecordStore` without a
`canImport(SQLite3)` guard, so the test targets did not build on Linux at all (CI runs only on macOS, so nothing
noticed).

### Integrating the sync-core work

The sync-core workstream (§J) and the audit above were developed independently from one commit, and both changed how
a permanent deletion is settled. Sync-core made the engine remember the join of every erasure of a record (W13, W18)
and pass the merger a version to write above, with an erasure summary that was a bare version vector, joined
pointwise, and a version kept after it re-stamped by *each keeping device* as its own edit (`ItemMerge.stamped`, two
above the base). That was Y25 again: two devices settling the same deletion wrote different items, and the kept item a
person restored could be trashed again by a reconciling sync. The audit's side had one deterministic write per deletion (`ItemMerge.settle`
on an `ItemErasure`) but judged a late version against the latest erasure only, and was not given the tombstone's
version (Y28). The merge keeps each side's half:

- The protocol is sync-core's: `resolveErasure(_:of:above:)` and `joinErasureSummaries`. The engine passes the joined
  erasure's stamp (the later of the joined stamps, a total order, so the same everywhere), not the larger of it and the
  version in question, which differs between devices and so could not be used to judge a summary.
- The join is the set of the deletions (`ItemErasures`): union, in one canonical encoding, an undecodable summary a
  deletion that had seen nothing. Not one erasure with the later revision and the union of what both had seen: that
  is a write no device made, and two devices that learned of the deletions in different orders would hold different
  items until they exchanged them. A join over the tombstone limit (`SyncPayload.maximumErasureLength`, which a
  snapshot must respect) is refused, and the engine keeps the erasure with the later stamp, which erases less.
- `ItemMerge.settle` against the set erases a version the deletions had seen between them, and otherwise applies each
  deletion's own write; the kept item is sealed through `ItemMerge.written` above the stamp and the row. Every device
  that knows the same deletions holds the same item, whatever order it learned them in.

`MergeModel` now settles against the set too, as the engine does. The exhaustive totals did not change: within their
depth no history has a version that two deletions cover only between them (checked by counting them). Tests:
`erasureJoin`, `erasureJoinOverTheLimit`, `deletionsInEitherOrder` (`ItemMergeAuditTests`), `tombstoneNamingAHigherRow`.

### Review of the audit

Review date: 2026-11-16, in a remote Linux session. Two independent reviewers read the audit and reproduced ten
findings with temporary tests and a standalone optimised build of the merge sources; three were raised by both, so
seven entries follow. Each was then reproduced again by a regression test that fails on the audit's code: the
end-to-end ones with three `SyncTestClient`s over `InMemorySyncTransport`. Y37 is the engine's to fix and stays a
known issue; the others are fixed in the merge.

| ID | Severity | Finding and threat | Disposition |
| --- | --- | --- | --- |
| Y31 | Medium | Text was compared with Swift's `String ==`, which is Unicode canonical equivalence: "é" as one scalar equals "e" with a combining accent, but a site hashes the bytes. A save that only respelt a password, title or note line saved the old bytes, with no stamp and no history entry (a regression of the audit: `stamped` rebuilds the item from its registers); two devices saving the two spellings concurrently kept both but showed no conflict, and the next edit dropped the hidden one; and an insider republishing a write respelt under the same stamp left devices holding different bytes for good while `sameState` called them equal. | **Fixed.** `==` on `Field`, `ServiceScope`, `NoteLine`, `ItemGroupValue` and `Item` compares text byte for byte (`ExactEquality.swift`), model-wide so `VaultSession.save` sees a respelt field as an edit too; note lines are compared by UTF-8. Hashing is unchanged and consistent. Tests: `respeltValuesAreSavedAsTyped`, `twoSpellingsAreAConflict`, `oneStampTwoSpellings`, `noteLinesByBytes`, suite "Byte-exact equality of item values", the exploration `twoDevicesWithTwoSpellings`, and two spellings in `lawsOnHostileMetadata`. |
| Y32 | Medium | Insider. Copies of one note-line ID were joined one at a time, re-splitting and re-sorting the accumulated text at each step: quadratic. A 1 MiB record of 8,000 lines under one ID cost every honest device about 13 s of CPU (optimised) each time it read the item, in every merge and save; a few hundred such records keep sync busy for an hour. | **Fixed.** Copies of an ID are gathered and joined in one pass (`NoteText.join(_:)`, the same join). Tests: `linesUnderOneID` (under a time limit), `joiningCopiesOfOneLine`. |
| Y33 | Low | Insider. Y21's fix bounded line IDs by the record's version, but a writer can put its record at or above the victim's next revision (the engine allows a jump of 2^20): removed lines planted under the IDs of an edit the victim makes *before merging that record* joined with what the person typed, and removal won, leaving no conflict, history or trace. Y21's disposition and `10-sync-correctness.md` §6 claimed this was prevented. | **Fixed.** Every edit of an existing item draws a nonce from the injected generator and puts it in the IDs of the lines it inserts (`NoteLine.ID.nonce`; absent in older records, read as zero), so naming a line takes having seen it. The clamp now keeps an anchor's nonce. §6 corrected: removing a line one has seen still leaves no trace of its text, as any writer's edit can. Tests: `plantedLineIDs` (rewritten to plant at the victim's revision), `lineNonces`, `clampingKeepsAnchors`, `lineWithoutNonce`. |
| Y34 | Low | Insider. A stamp decodes as encoded, so its `seen` can omit its own revision; `clamped` returned such a stamp unchanged. A resolution's discard vector then did not cover a retained value it removed, and the next merge brought it back: `merge(resolve(s), s) ≠ resolve(s)`, and the explicit discard (F7.7) did not hold. Relatedly, `settle` took a clock that merely named the tombstone's revision as having met the deletion, so on such metadata settling did not commute with merging. | **Fixed.** Every stamp is read with its revision recorded in `seen`; `settle` decides "met the deletion" from what the version holds. The hostile generator now writes such stamps, and `lawsOnHostileMetadata` checks that every edit, resolution and settlement contains the hostile version it was made on. Tests: `stampsThatOmitTheirRevision`, `resolutionCoversMalformedStamps`, `settlingIsAJoinOnAnyClock`, `stampContainsItsRevision`. |
| Y35 | Low | Test coverage. The exhaustive exploration performed every operation with its first choice only, so no explored history resolved a conflict in favour of a value that was not shown, and edits always acted on the first field or line; `10-sync-correctness.md` §7 called it every history. | **Fixed.** Each step explores every combination of the choices its operation asks for; the asserted totals grew for that reason alone (standard run 34,933 histories, nightly 297,775). |
| Y36 | High | Insider; then every device. `ItemRecordMerger.erasureSummary` encoded the item's whole clock, unbounded, while every reader refuses a summary over 64 KiB (`erasureTooLarge`). An insider publishes an item whose clock names 2,000 made-up devices; when a person deletes it (or the purge does), every other device refuses the deleting device's segment at every sync and that stream stops for good: nothing it writes afterwards, in any item, reaches anyone. | **Fixed** in the merger: a summary that would not fit says the device had seen nothing, so it erases nothing elsewhere and every other copy is kept in the trash, not purgeable — the direction that loses no data. **Tracked** for the engine: it should refuse to publish an over-long erasure. Test: `enormousClockAndDeletion`. |
| Y37 | Medium | Engine. Two versions that each fit the 1 MiB payload limit can have a join that does not (two long concurrent note edits; growing history; or an insider at will). The merger threw, the engine rejected the whole object carrying the remote version as `mergeFailed`, and because a stream is merged in sequence, every later segment from that author never applied on that device: unrelated items stop replicating, silently and permanently. `10-sync-correctness.md` §8 said only that merges of that item are refused. | **Tracked**, with a test recorded as a known issue (`mergeOverThePayloadLimit`). The merger now reports `ItemMergeError.resultNotSealable` for a result it cannot seal, distinct from a record not to be trusted; `SyncEngine` should then keep the local version, quarantine that one entry (F7.7) and continue the stream. §8 states the real blast radius. |

---

## I. Milestone 4 review (sharing protocol core)

Review date: 2026-11-15. The module (`WatchwordSharing`, `02-architecture.md` §8) was written and reviewed in a
remote Linux session by the same agent, with the adversaries of §2 in mind: the sync store and key directory (A1), a
current member (A4), a former member (A5), and someone with this device's files (A8). Everything below was
reproduced there with `swift test` against swift-crypto; nothing has yet run against CryptoKit. S1 to S10 were found
while designing or re-reading the code and are fixed, each with a test in the suite "Adversarial: sharing and
membership" unless noted; S11 to S16 are accepted or tracked. S17 to S27 came from two independent reviews of that
first version (below the table); they changed the fork rule, so S1, S2, S9, S10 and S12 are described as they stand
now. S28 to S31 are the third round, after the table.

| ID | Severity | Finding and threat | Disposition |
| --- | --- | --- | --- |
| S1 | High | A hash-linked chain with "signed by an administrator of the previous state" lets a **former** administrator (A5) go back to any epoch at which they still were one and publish a competing record. Any rule that settles concurrent administrators by the records at the fork alone (lowest hash, seniority), or by length, lets them grind or build a winner and reorganise the chain past their own removal: a former member re-adding themselves. | **Fixed by the fork rule.** The administrator set changes only in owner-signed records, and the accepted chain is the path with the most owner-signed records before length or any hash is compared, so a branch that lacks the owner's record ending their authority never outranks it. Tests: `staleAdministratorRewritesHistory` (ground hash; informed, fresh and misled devices), `rewriteAcrossPages`. |
| S2 | Medium | The same rule trusts every owner-signed record. A store (A1) that isolates one of the owner's devices and shows it only a former administrator's branch can obtain an owner-signed record there; the two paths then tie on owner-signed records, and the former administrator can lengthen theirs to win the tie. Needs A1 and A5 together and the owner acting on the isolated device. | **Reduced, and tracked** with D9. The owner's removal of them is kept, is *owed* (S18), and is planned again by the first of the owner's devices that sees both paths; from then on their path holds one owner-signed record fewer and cannot win. Until then members following it seal to a key the former administrator holds, with that administrator's writes refused. Closing the window needs the owner's devices to refuse to sign while they disagree: device-registry work. §8.8. |
| S3 | Medium | Hashing the whole record, signature included, gives one record as many identities as it has valid signature encodings. CryptoKit's Ed25519 signing is randomised, so the signer could produce them at will, and each would be a "different" record at the same epoch for the fork rule to choose between. | **Fixed.** The hash covers the signed content only. Test: `hash`. |
| S4 | Medium | Consequence of S3 in a first draft: candidates were de-duplicated by hash, so a copy of the next record with a spoilt signature, listed ahead of the genuine one, was examined, refused, and the genuine record never looked at. A store (A1) could freeze a chain without withholding anything. | **Fixed.** Exact copies are dropped; candidates that share a hash are each examined until one verifies. Test: `shadowCopy`. |
| S5 | Medium | "A grant is accepted from an administrator at the epoch that introduced the key" still describes an administrator who was **demoted** afterwards (a demotion does not rotate). They (A4) could wrap a key of their choosing, under the current key's ID, to a member added since, who would then seal new items to it. | **Fixed.** The one entitled sender is the signer of the record through which the recipient became entitled to the key. Test: `demotedAdministratorGrants`, `grantsAfterRevocation`. |
| S6 | High | Vault IDs are not secret. Someone the victim has verified (A4) could send an invitation naming a vault the victim already holds, their own or another owner's; a device that filed the result by vault ID would replace that vault's owner, chain and key with the attacker's. | **Fixed** in the module's half: `IncomingInvitation.begin` takes the owner the device already knows for that vault ID and refuses a different one (`vaultOwnerConflict`). Test: `vaultIDCollision`. The integration must pass that owner, for the account's own vaults too. |
| S7 | Medium | `PublicKeyBundle` equality includes the self-signature, and Ed25519 signing is randomised on CryptoKit: the same keyset yields a different bundle value each time. Comparing bundles with `==` (pin against directory, genesis against pinned owner, the checkpoint's owner) would report a key substitution, or refuse the owner's own chain, on a Mac and never on Linux, where signing is deterministic. | **Fixed.** Bundles are compared by account and keys (`hasSameKeys`), which is what a fingerprint covers. Tests re-derive bundles (`rederivedBundle`, `ownAccount`), but only a macOS run exercises the difference: **not verified here**. |
| S8 | Medium | Epochs are bounded (SEC9), so an administrator (A4) could write records until none were left, and the owner could never sign the one removing them. | **Fixed.** The last 4,096 epochs accept only the owner's signature. Test: `epochExhaustion`. |
| S9 | Low | Work before authentication. Validating every member's key bundle while parsing cost up to 64 signature checks per unsigned junk record; the key-reuse check walked the whole chain per unsigned candidate. | **Fixed**, the second half again by S22. Bundles are validated after the record's signature, and only the new member's; the key history is consulted only after the signature. Test: `reusedKeyFlood`. |
| S10 | Low | Looking for a grant among "the first N objects" under the vault's grant prefix let a member (A4) crowd the real grant out with objects for other keys or recipients. | **Fixed**, completed by S24. Names are filtered first, and no bound is put on how many objects are looked at. Test: `grantFlood`. |
| S11 | Low | The chain names a key ID, not the key. An administrator (A4) can hand one member a different key under the right ID; that member's writes are then unreadable to the others. | **Accepted.** It is denial of service by an insider who has cheaper ones and learns nothing they could not already read. A commitment to the key in the record would close it at the price of a published hash of every vault key; revisit if administrators outside the household are ever a use case. |
| S12 | Low | Write permission is judged against the newest membership a device knows, because a former member can date a write as they please. What a member wrote that the administrator's device had not merged when it signed their removal or demotion counts for nobody, and a write made while read-only counts once its author is promoted. | **Accepted**, as restated by S28: it is the price of F4.5 being a client rule. Such a write is held aside on the devices that have it, not destroyed, and a person who may write can make it their own. Documented in §8.7 and on `writeStanding`. |
| S13 | Low | Local state (A8): a pin can be deleted, putting a contact back to unverified, and an older saved ledger of the device's own restores as that older state. | **Accepted**, as for sync state: signatures stop planting, not rollback. A deleted pin puts the contact in front of the person; an old ledger moves forward at the next ingest. |
| S14 | Info | Membership records are in the clear: the store sees pseudonymous account IDs, public keys, roles and the timing of changes. | **Accepted**, with the reasoning in §8.2: the transport's share list already says more, an invitee must verify before holding a key, and names never enter a record. |
| S15 | Medium | Every administrator device holds the account's signing key (D9), so a lost device can sign membership records. | **Tracked**, as D9, now with a larger consequence than for log segments. |
| S16 | Info | Trust in members other than the owner is transitive through the chain (an administrator vouches for whom they add); most people will compare one fingerprint, or none (D17). | **Tracked** for the sharing UI: unverified members shown as such, `comparedByEye` distinguished from a typed or scanned match (`VerifiedContact.method`). |

**Second round.** Two independent reviews of the version above reported the findings below. S17, S18, S20, S23,
S25 and S27 were reproduced against that version with failing tests before anything was changed; S19, S21, S22, S24
and S26 were confirmed by reading the code against the reviewers' reports. None was rejected. Each test listed is in
the tree. Like the first round, all of it ran on Linux against swift-crypto only.

| ID | Severity | Finding and threat | Disposition |
| --- | --- | --- | --- |
| S17 | High | The ledger kept only the winning path. A valid record that lost a fork was dropped, so a record built on it and offered in a later call was "unconnected" for ever, even when it was the owner's record that should have made its branch win: the fork rule was order-independent only if every record arrived in one call. And one call refused more than 4,096 candidates, which the reference loop exceeded as soon as anyone with create access (A4, A5) put that many objects in the directory. A former administrator's rewrite then stuck on any device fed a page at a time, and a flood froze membership for everyone. | **Fixed.** The ledger holds the tree of valid records, losing branches included (bounded at 1,024, best-ranked kept, persisted), and the accepted chain is a function of that set. `ingest` takes any number of candidates and never throws; junk costs a parse, and what looks like a record one signature check. Tests: `rewriteAcrossPages`, `membershipFlood`, `losingRecordsAreKept`, `LongRunningMembershipForkTests` (a property test over random forked histories), `retentionLimit`. |
| S18 | Medium | "Earliest owner-signed record, then lower hash" gave no weight to what had been built since. The store (A1), by hiding the newest head from an honest administrator's device, obtains a record signed on a stale head; it can read both hashes from the object names, and release that record after every device has accepted a removal and re-sealed, rolling the chain back to a state in which the removed member is listed and their key is current. | **Fixed in two parts.** Between paths with the same owner-signed records the longer wins, so a late record displaces nothing that has been built on. When the paths are equally long the hash still decides and a removal can be displaced; it is then *owed*: kept, reported (`owedRemovals`, `PendingRotation.removalOwed`), the member's writes refused, nothing re-sealed towards their key, and planned again by the next device that may sign it. The documentation no longer claims the store cannot cause a fork. Test: `withheldSiblingReleasedLate`; `deadBranchRemovalsOweNothing` for the abuse this must not open. |
| S19 | Medium | No adversary needed: a second device of the owner's, several records behind, signs an ordinary change on its old head. "Earliest owner-signed record wins" favoured exactly that device, undoing a removal the owner's other device had made, making the old key current, and directing every device to re-seal back under it. | **Fixed.** The rule counts owner-signed records and then length, so one stale record loses. Two stale records can still win; the removal is then owed as in S18, and `recordsToReseal` is empty while it is, so what was written under the newer key is not handed back. The reference loop ingests before it proposes and never publishes a record that is no longer `awaitingPublication`. Test: `staleOwnerDevice`. |
| S20 | Medium | A membership object was named by its record hash, which leaves the signature out (S3). The signed content of a role change, an invitation or a deletion is predictable, so any member (A4) could create the object first with a signature nobody made; a write-once store then never takes the genuine record. | **Fixed.** A membership object's name ends in SHA-256 of the whole object, as a grant's and a leave request's do. A squatted copy is one more object, refused when examined. Tests: `squattedRecordName`, `objectNames`, the known-answer name. |
| S21 | Medium | A pin was checked only against the key directory. An administrator (A4) could remove a member the owner had verified and add the same account ID back with other keys; the owner's device accepted it without a word and wrapped the next vault key to the swapped keys. | **Fixed.** `MembershipLedger.checkMemberKeys` compares every listed member with the device's pins; `RotationPlanner.plan` and `makeGrant` require its result for the current head and refuse a recipient whose keys were swapped (`keySubstituted`). Test: `chainKeyAgainstPin`. |
| S22 | Low | The key-reuse check ran before the signature check and cost (records introducing that key ID anywhere in the tree) × (depth) per candidate. A former administrator (A5) could build a comb of signed branches that made a join take days. | **Fixed.** The signature is checked first, and the key history is a walk over the rotations of the record's own path. `IngestReport` counts both. Tests: `keyReuseComb`, `reusedKeyFlood`. |
| S23 | Low | A saved rotation plan was not authenticated, and the account its first step takes off the transport's share came from an unsigned field. Someone with the device's files (A8) could aim that step at any member. | **Fixed.** A plan is signed by the planner's account and parsed as that account; the departing account is read from the signed record and stored nowhere else; `steps(in:)` asks the ledger, so an old plan put back does not revoke a member invited back since. Tests: `plantedPlan`, `planEncoding`, `planSteps`. |
| S24 | Low | Leave requests were looked for among the first 4,096 objects listed, before any filtering, so junk in the directory (A4, A5) hid a genuine request and the departing member's key stayed current with nothing pending. The same bound, applied after name filtering, let junk filed in a member's own grant directory hide their grant. | **Fixed.** Both look at every object, names and digests first; a signature is checked only for what is filed correctly and says the right things. Tests: `leaveRequestFlood`, `grantFlood`. |
| S25 | High | Judging writes at the current epoch stranded what a member wrote while entitled. After a demotion to read-only (which rotates nothing) every device that had not yet merged their records refused them for good; after a removal, the reference loop's re-seal pass had already refused them and reported the rotation complete. | **Fixed, and the fix replaced by S28's.** The first fix ("what a device has merged stays merged, and is sealed again by a member who may write") opened S28. Now the record that ends a permission to write carries a write cut, and what is inside it counts on every device directly, so nothing is stranded and nothing has to be published again for a demotion. Tests: `demotedMembersData`, `removedMembersData`, `writeStanding`; `demotionSeenLater` for what the cut leaves out. |
| S26 | Medium | Accepting an invitation always built a new ledger from what the store offered. For a member invited back, their earlier membership is a valid prefix, so a store (A1, with a former member, A5) hiding everything since their removal had them rejoin an older state than their own device had verified, sealing new items to a key a former member holds. | **Fixed.** `IncomingInvitation.accept` continues the ledger the device holds for the vault; it must be passed explicitly, `nil` only for a vault never held. Test: `reinvitationRollback` (which also shows what passing `nil` wrongly would do). |
| S27 | Low | A device's own record is not in its chain until it ingests it, so a record that lost to one already on the store was reported `outranked`, never `superseded`, and a loop watching only `superseded` dropped an invitation or a role change silently. | **Fixed.** `MembershipLedger.status(of:)` gives a proposal's status from the ledger, as `RotationPlan.status` did for plans; the reference loop keeps proposals until adopted and proposes a superseded one again. Tests: `proposalStatus`, `lostProposalIsProposedAgain`, `partitionedFork`. |

**Third round.** S28 came from the final verification of the version above, reproduced with a failing test before
anything was changed (`writeAfterUnseenRemoval`, first written against the old rule). S29 and S30 were found while
fixing it, in the fix itself; S31 is what the fix leaves.

| ID | Severity | Finding and threat | Disposition |
| --- | --- | --- | --- |
| S28 | Medium | The acceptance side of S12, opened by S25's fix. Writes were judged against the membership a device knew *when it merged them*, what was merged stayed merged, and `recordsToReseal` listed records whose stored author may no longer write. A former member (A5) with a store that still takes their writes, or a demoted member (A4), for whom there is no transport step at all, and a store (A1) that withholds the membership record from one read-write member's device: that device merges the late write, and once shown the record seals it again under its own name and the new key, and every remaining member reads it. Without that listing it would still travel in the device's next own version of the item. | **Fixed in the module; a condition on integration.** The record that ends an account's permission to write carries a `WriteCut`, the signing device's commitment to what it had merged of that account's work, signed and so the same everywhere. `writeStanding(of:)` gives it to every device: inside counts whenever a device meets it; outside counts on no device, and one that had merged it takes it out and holds it aside. The author rule is gone from `recordsToReseal`, `SealedRecordReference` no longer names an author, and a plan takes its cut before it is signed (the `mergeOutstandingWrites` step is gone). The reference loop derives its record store from its ledger and the objects it has fetched, and a re-sealed version names whose work it carries. Tests: `writeAfterUnseenRemoval`, `writeAfterUnseenDemotion`, `lateWriteSealedAgainByAnother`, `forkedStream`, `misplacedWriteCut`, `writeStanding`, `writeCutRequired`. **Not closed in the product until** sync defines the cut over its own segments and applies it to each value's author (§8.8, `03-implementation-plan.md` milestone 4). |
| S29 | Medium | Found in the fix. A departure on a losing branch is owed whoever carried it out, because the member's own signature asked for it. With cuts believed from an owed record, a former administrator (A5) could take any pending leave request, sign the departure on a branch from before their own removal with a cut of nothing, and have every device set the leaving member's work aside, and the administrator who then carried the departure out sign that. | **Fixed.** What an owed record's branch says about the member's writes is believed only if that record and the one holding the cut are in the accepted chain or were signed by accounts that could sign them on the accepted head; otherwise the member's writes go on counting until the removal is carried out again with a cut. Tests: `deadBranchDepartureCut`, `owedRemovalKeepsItsCut`. |
| S30 | Low | Found in the fix. A cut that is the digest of the last object the signing device had *seen* of a hash-linked stream commits to predecessors it never held. A member who expects removal (A4), with the store, shows the remover only the end of a stream prepared in advance and brings the rest out afterwards, inside the cut. A cut that is only a count per stream fails the other way: a former member can still create an object at a position some device has not filled. | **Fixed** in the reference loop, and written down as what a cut must be (§8.8): the furthest object whose every predecessor the device holds, bound by digest. Tests: `preparedStream`, `forkedStream`. |
| S31 | Low | What the cut leaves. (a) The administrator who signs a removal or demotion chooses the cut; one who signs less than their device holds sets a member's work aside for everyone. (b) A *demotion* displaced by a fork is not owed (§8.3), so until its author proposes it again the member's writes count in full, and the new cut is taken then. (c) While a removal is owed on a branch nobody with standing signed (S29), the same. (d) A store that withholds part of a departed member's stream from a device delays what counts there. | **Accepted.** (a) is within what an administrator who can remove the member can already do, and the work is held aside, not destroyed. (b) and (c) need a fork at the narrowest timing the store has and are bounded by the next record with standing; a read-only role is not a security boundary (F4.5), and a removal that matters is owed with its cut. (d) is withholding, as everywhere. |

Accepted from the second round, beside S2 and S12 as amended: a former administrator who can still write to the store can
publish valid records on dead branches without limit; a device keeps 1,024 and pays a signature check per sync for
each one beyond (§8.8). A fork between honest administrators costs work: what lost is done again, removals by any
device that may and everything else by its author's.

What the review did not find, having looked: a parser that reads past its input or allocates on a count's say-so;
an identity taken from a record rather than from where it was found (vault, key and recipient of a grant, the vault
of a chain, the account of a directory answer); a path from an unverified bundle to a wrapped key; a signature under
`SignatureDomain.membership` that verifies as another kind of message; key material leaving `SecureBytes` (the
planner's new key exists only inside HPKE grants and is zeroised when planning returns).

## J. Milestone 3 review (multiple vaults, enrolment, device registry)

Review date: 2026-11-15. Written and reproduced in a remote Linux session against swift-crypto (ADR 0006); nothing
below has run on a Mac yet. The design was attacked while it was built: W1 and W2 came from the adversarial suite
"account enrolment and device registry", W3 from the first run of the real-enrolment tests, the rest from reading
the design against the adversaries of architecture §2 plus two that this work introduces: **a revoked device that
kept the keyset and its own device key**, and **an insider device in hands that do not know the account password**.

| ID | Severity | Finding and threat | Disposition |
| --- | --- | --- | --- |
| W1 | High | A device that had not yet been given a new password replayed the password change among the entries no checkpoint had sealed. A revoked device holding the account key could sign a *back-dated* revocation of the device that made the change; where its entry ID sorted first, the change was void on that device, which then could never follow it, kept the revoked device, and dropped the one that revoked it. | **Fixed.** A candidate password change is judged by replaying the registry with it as the last checkpoint, never by its place among unsealed entries. Tests: `pendingChangeSurvivesBackdating` (over seeds, asserting the bad order occurs), `revokedDeviceCannotReturn`. |
| W2 | Medium | Entries a device wrote while it was being revoked could be replayed before the revocation (the order among concurrent entries was "revocations first among those ready", and a revocation may become ready late), so a device it added at that moment stayed registered. | **Fixed.** Each revocation is replayed as early as causality allows: what it had seen, the revocation, then everything else. Test: `deterministic`. |
| W3 | Low | Two devices given the same signing key (here: two test devices built from one seed) were both registered. A key that serves two devices makes "which device wrote this" meaningless and lets a revoked key return under another ID. | **Fixed.** No key serves two devices, and a revoked key is refused under any ID. Tests: `keysAreFixed`, `revocationIsFinal`. |
| W4 | Medium | A device whose own header was out of date (the password had been changed elsewhere), or that had been revoked, put its old header back on the transport when it found it missing, undoing the changing device's removal of it. | **Fixed.** A device republishes its header only if it follows the current credentials and is registered. An attacker with store access can still replay an old header; that is `replayedHeader`. |
| W5 | Medium | Enrolment tried the three newest headers by name, so three planted objects under newer names used up the budget without one derivation being worth making. | **Fixed.** Only a header that parses, matches its name and has in-bounds KDF parameters costs a derivation; up to 64 names are looked at. A store that plants three *well-formed* headers still exhausts the budget — it can as easily delete the real one (Y7). Test: `plantedHeaders`. |
| W6 | Medium | Creating the registry for an account that had none (one made before this work) at unlock would have let a database restored without its registry rows start a second registry for an account that already syncs, splitting it. | **Fixed.** The registry is started for such an account only at a sync that finds no account header on the transport. Otherwise the device reports `deviceRegistryUnavailable` and must enrol again. Test: `legacyAccount`. |
| W7 | Medium | Design: what a password change on one device means for the others. Left per-device, a password retired because someone learned it would keep opening every other device. | **Decided.** The change is the account's: a credential entry signed with the previous generation's enrolment key, a new header, and every other device refusing the old password once it holds that header. It needs the current password, so a device in the wrong hands cannot lock the person out (`passwordChangeNeedsThePassword`); if someone who does know it changes it, the person takes the account back from a device they hold (`hostilePasswordChange`). |
| W8 | Medium | Limit, stated rather than fixed: revocation stops writing, not reading (D9b above); a revocation that keeps the password is sound only if the device's holder never had the keyset; and whatever a revoked device wrote before a device learned of the revocation is merged there and handed on. | **Accepted and documented** in architecture §7.8, with the API making the password choice explicit and a test that pins the limit (`revocationKeepingThePassword`). The app must default to changing the password. |
| W9 | Low | A snapshot whose coverage a device had already merged was skipped. After a revocation a device's snapshot may be the only carrier of what it merged from the revoked device, including rows that device attributed to others (Y15). | **Changed.** Snapshot entries are always merged (merging is idempotent). Residual, accepted: rows a revoked insider *fabricated* in a snapshot, merged by one device before it learned of the revocation, reach devices that sync while that device's hand-on snapshot is listed; a device offline for that whole time may never get those fabricated rows. No value a person typed is affected. |
| W10 | Low | A deleted vault's objects stay on the transport, and its key in every device's store, indefinitely: late arrivals must stay readable so that an unseen edit is kept. | **Accepted** for now; collecting them needs every registered device's acknowledgement of the deletion. Tracked in architecture §16. |
| W11 | Info | The software device key is in the Keychain, not hardware-bound: a thief who can read the Keychain has it. It is one of two signatures; the account key still needs the password. | **Tracked**: the Secure Enclave adapter (P-256; verification, with the low-S rule, is built and has a known answer from Python `cryptography`). |
| W12 | High | An account-key holder — a registered insider, or a revoked device that kept the keyset — can fill the registry to its 4,096-entry limit, after which every device refuses to evaluate it and sync stops. Reproduced for a revoked device after a `.change` revocation: entries it signed counted for nothing but were admitted, stored and counted, so the revoking device's sync broke for good, later revocations stopped spreading, and enrolment failed (review "flood", W20); and again, after that fix, with entries in the names of puppet devices it registered itself (W26). | **Fixed for a revoked device once a password change seals its revocation**, in its own name and in its puppets' (W20, W26). **Accepted** for a registered insider, and for a revoked device before a password change: what they sign may count, and the limit refuses the registry rather than evaluate it without bound (SEC9); the same party can delete every object in the store. |
| W13 | High | Found by the vault simulation (`LongRunningVaultSimulationTests`): a deletion made on a device was dropped as "already published" whenever that device knew *any* erasure of the same record with a later stamp, even another device's. That one's author may have seen less — its erasure kept a version this deletion had seen — so the record was erased on the deleting device and kept on every other: divergence, and a deletion the person made that never happened elsewhere. In the engine since milestone 3; moves between vaults (trash, then delete) made it frequent. | **Fixed.** A deletion is done only when *this device* has published it. Erasures of one record are remembered as their join (`RecordMerger.joinErasureSummaries`), and every version is judged against the join, so which of two erasures a device learns of first decides nothing. Tests: `deletionAfterAnotherDevicesErasure`, and the simulation, which failed on roughly one seed in ten before; the one further failure it found afterwards was W18. |
| W14 | Medium | Found by the same simulation: what a vault's deletion left behind was *written* into the trash by each device (a version of its own per device). The next deletion or move of that item, made on one device, had not seen the other devices' versions and so had to keep them: the item kept coming back, kept after deletion, on devices that had done nothing. | **Fixed.** What a deleted vault still holds is *shown* in the trash, as kept after a deletion, and never written that way: derived from the signed directory, the same on every device. |
| W15 | Medium | A header from before a password change, put back in the local file (A8) *together with* deleting the registry's entries from it, unlocked with the retired password: the rollback check needed the registry to tell which credentials the device followed. | **Fixed.** The Keychain anchor records the credential generation, and the keyset's own wrap is bound to the generation it was made for; the check needs nothing else from the file and runs before any key is installed. Test: `localHeaderRollback`, three variants. |
| W16 | Low | With `WATCHWORD_TEST_SEED` set, every `TestVault` took the same seed, so all of an account's test devices had one device key, which the registry refuses (W3): every enrolment in the nightly run would have failed. | **Fixed** in the test support: the nightly seed is added to each vault's own. |
| W17 | Medium | Two smaller faults in the same code, found while fixing W13. (a) A version kept after an erasure was written two above the highest *edit* the erasure's summary named, but had to be above the erasure's *stamp*, which follows the record's version and climbs with every merge; when it was not, the engine refused the merger's result and the object carrying it was rejected at every sync. (b) An erasure a device already held, met again in a later snapshot, was applied to the local version again, putting an item the person had restored back in the trash. | **Fixed.** The engine passes the version to write above (`resolveErasure(_:of:above:)`), and an erasure that adds nothing to what the device holds is not applied again except by a reconciling sync. Tests: `deletionAfterAnotherDevicesErasure`, `restoredItemStaysRestored`. |
| W18 | High | Found by the vault simulation after W13 was fixed: the person deletes a version that this device's own earlier erasure had kept (a trash made elsewhere that the erasure had not seen). A kept version keeps its own number, so the second deletion's stamp was lower than the first, and the outbox dropped it as "already published by this device": erased here, kept on every other device. | **Fixed.** A pending deletion counts as published only if this device published a deletion at or after its stamp *and* the join of the erasures it knows already holds everything this one had seen. Test: `secondDeletionBySameDevice` (fails without the fix); the simulation seed that found it (`WATCHWORD_TEST_SEED=77`) passes, as do 20 seeds of the standard run and 3 of the long one (Linux). |
| W19 | Low | A8 edits a vault-key wrap row in the local file (moves it under another vault, corrupts it). Nothing opened under the wrong key — the wrap's context names its vault — but the vault stayed unreadable for good: the sync fetched only wraps whose row was *missing*. | **Fixed.** While unlocked, a row that does not open counts as missing, and the next sync replaces it (one version up) with the transport's copy, which is checked against its name, its signatures and the keyset first. Test: `localVaultKeyWraps`. |
| W20 | High | The registry flood (W12). Admission checked only the account key's signature, so entries nobody could ever apply — by a device revoked behind a checkpoint, in another device's name, with a superseded enrolment key, with no parents — were stored by every device and counted against the limit, and a sync fetched at most 4,096 names in sorted order. | **Fixed.** `DeviceRegistry.evaluate` names what can never count and retains everything else (`retainedEntries`); devices store, publish and count only that, prune the rest, and fetch in batches judged with what they hold, skipping for the session what they found worthless. A device's entry must descend from its own registration, and that registration must itself count (W26). Test: `registryFlood` (4,096 planted entries of three kinds; fails without the fix in all three ways), `retention`, `sizeLimit`, `evaluationLimit`. |
| W21 | High | Found while fixing W20: an entry appended after a checkpoint could reorder the layer the checkpoint sealed — a revocation pulled forward everything it had seen, in any layer — so a revoked device could move one of its back-dated, sealed entries (a device it added) in front of its own revocation, after the password change. | **Fixed.** A revocation moves only entries of its own layer, and one that can never count moves nothing. Test: `sealedOrder` (over seeds, asserting the bad order occurs; fails without the fix). |
| W22 | High | A `lock()` landing while the account's half of a sync awaited a vault-key fetch, or while the reconciliation after an unlock awaited the store or the Keychain, left key material read after it was zeroised: a trap, so a crash, from an auto-lock. | **Fixed.** Both re-check before touching keys; a lock ends the sync's account half as a download, and the reconciliation quietly. Tests: suite "Vault session: a lock during the account's objects". |
| W23 | Medium | A move publishes its copy and its original's deletion in two vaults' logs, by two engine runs; a sync that wrote the source log and not the destination's removed the item from every other device. | **Fixed.** `syncAll` publishes deletions last, only once every vault's push in that sync succeeded (`SyncEngine.sync(deferringDeletions:)`). Tests: `interruptedMovePublication`, `deferredDeletion`. |
| W24 | Medium | A store restored onto other hardware registers as a new device, but the edits and deletions its old device had not synced still carried the old device's ID, and the engine publishes only its own rows: they reached nobody. | **Fixed.** Registration carries them over to the new ID (rows written again unchanged, pending deletions re-recorded), and each vault's sync state starts over. Test: `restoredStoreCarriesUnsyncedWork`. |
| W25 | Low | A vault deletion's local row kept its author's signature and was judged against the current registry, so revoking the device that deleted a vault brought the vault back on devices that had verified the deletion, until another device's copy arrived. | **Fixed.** A device that has verified a deletion and can sign makes the local row its own (`adoptVerifiedDeletions`). A deletion seen only while locked still rests on its author until then. Test: `deletionOutlivesItsAuthor`. |
| W26 | High | W20's fix could be bypassed with puppets. An entry by a device counted as "might count" if *any* ancestor registered that device under a key that verifies it, whether or not that registration could itself count, and nothing void made its descendants void. So the revoked device, after a `.change` revocation, planted an `add` of a device whose key it made (with a garbage author signature, or signed by its own revoked key, or as an enrolment under a password change of its own) and then any number of entries in the puppet's name: all verified against the void registration, the puppet was never revoked, and all were retained, along with the registration through what they descend from. 100 such entries were 106 retained; 4,096 made every device refuse the registry, so a later revocation's password change never spread and a new device could not enrol. A puppet registering a second puppet, validly signed, went one step further. | **Fixed.** Voidness propagates, in one causal-order pass per replay: past the last checkpoint a device's entry is void unless it descends from a registration of its author, under a key that verifies it, that is not void, and an enrolment is void if the credential entry it cites is; a sealed registration may be relied on only if it counted. The replay applies the same rule (a device's entry needs a registration that counted), so nothing void is ever valid. Each distinct registered key is tried once per entry when the graph is built, not once per replay. Tests: `puppets` (a garbage-signed registration, one signed by the revoked key, one a checkpoint sealed as void, a chain of two puppets, an enrolment under the revoked device's own password change; 64 entries each and one at 4,096; fails without the fix), `puppetFlood` (4,096 entries in three puppets' names at session level; fails without the fix: the next password change never reaches B). |
| W27 | High | Found while fixing W26: the cost of evaluating the registry was quadratic in what a key holder plants. An entry's author signature was tried against every distinct key its ancestors registered its author under, so about 2,000 registrations of one device ID under distinct keys, chained, and 2,000 entries in that ID's name descending from all of them (well within `maximumEvaluated`) were 4,196,360 signature verifications: every device's evaluation hung (31 minutes for the test below, in a debug build on Linux). | **Fixed.** An entry whose ancestors register its author under more than `maximumKeysPerDevice` (2) distinct keys is void without any signature being checked; otherwise each of its at most two keys is tried once, when the graph is built, and replays read the result (an enrolment's signature, too, is checked once there rather than in every replay). Verifications are at most two per entry plus one per credential link replayed. The rule reads ancestry only, so it does not depend on arrival order; honest histories register an ID under one key. Test: `manyKeysForOneDevice` (2,048 registrations and 2,048 entries: 2,056 verifications for 4,102 entries, asserted against a bound of 2 per entry; with the bound removed, 4,196,360 verifications and 1,877 seconds, and the bound fails). |

Also recorded: `UITestPeer` (in `Apps/`, not touched by this work) still enrols its second session by copying the
account header and vault-key wraps, which no longer makes a registered device; it must use `VaultSession.enrol`.
`SystemKeychainStore` gained the two new Keychain item names without being compiled; the "Keychain item protection"
suite now iterates `KeychainItem.all`, also uncompiled here.
