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
| D9 | Medium | Every device holds the account Ed25519 signing key (it is in the AUK-wrapped keyset), so a lost device cannot be excluded without rotating the account key. No device registry. | Add a device registry signed by existing devices; milestone 3, before sync ships. |
| D10 | Medium | Vault-key rotation re-encrypts every item: O(items) work and O(items) upload on every membership change. | Per-item keys wrapped by the vault key make rotation O(members). Already an open question in §16; promoted to a milestone-4 decision. |
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
