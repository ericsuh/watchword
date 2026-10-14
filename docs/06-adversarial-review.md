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

### D7 (Low) — XOR to combine the two secrets
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
| D11 | Medium | Test plan claims AAD-binding and ciphertext-tamper coverage that cannot exist yet — there is no crypto layer. Current envelope tests cover the header only. | `04-test-plan.md` §6.1 now marks which tests arrive with milestone 1. Honest status beats implied coverage. |
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
