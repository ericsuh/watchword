# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Watchword is a native iOS/iPadOS/macOS password manager for a household, end-to-end encrypted and
synced through the user's own iCloud (or any file-based cloud). The repository is in the **design
phase**: `docs/` is the primary deliverable, and `Sources/` holds the milestone-0 pure modules, the
milestone-1 cryptographic core, and milestone 2's local vault (`WatchwordStore`, `WatchwordKit`,
`WatchwordPlatform`). `Apps/project.yml` is the XcodeGen spec for the iOS and macOS apps, their
AutoFill extension shells and the UI tests; the generated `.xcodeproj`, Info.plists and entitlements
are not committed.

## Commands

```sh
swift build
swift test --parallel                                  # runs both Swift Testing and XCTest suites
swift test --filter WatchwordAdversarialTests           # security suite only (its own CI job)
swift test --filter 'Random password generation'        # one Swift Testing @Suite by display name
swift test --filter WatchwordMatchingTests.ItemRankerTests   # one XCTest class
swift format lint --strict --recursive --configuration .swift-format Package.swift Sources Tests
swift format --in-place --recursive --configuration .swift-format Sources Tests
swift build -Xswiftc -strict-memory-safety -Xswiftc -warnings-as-errors   # mirrors the CI gate

# Apps (macOS only; mirrors the app-tests CI job). XcodeGen and gh are pinned in mise.toml, checksums in mise.lock:
mise trust && mise install                             # once per checkout
xcodegen generate --spec Apps/project.yml --project Apps
xcodebuild test -project Apps/Watchword.xcodeproj -scheme Watchword-iOS \
  -destination 'platform=iOS Simulator,name=iPhone 17' CODE_SIGNING_ALLOWED=NO
xcodebuild test -project Apps/Watchword.xcodeproj -scheme Watchword-macOS -destination 'platform=macOS' \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= CODE_SIGN_ENTITLEMENTS=""
```

UI tests launch the app with `--uitest`, which (Debug builds only) swaps in in-memory ports and the KDF floor.
macOS UI tests also need "automation mode" enabled on the machine, which needs an administrator; CI runners
have it. Real Keychain round trips need a signed, entitled process, so `swift test` skips them.

Requires Xcode 16.4+ (Xcode 26 for strict memory safety). Other developer tools come from the project-level
`mise.toml`, never Homebrew or the global mise config; Swift and swift-format come from the selected Xcode. CI runs the same matrix: Xcode 16.4 on
macOS 15 and Xcode 26.6 on macOS 26.

### Xcode MCP server (local macOS sessions only)

In a local macOS CLI session, enable the Xcode MCP server and prefer its tools over shelling out:
`BuildProject`, `RunAllTests` / `RunSomeTests` / `GetTestList`, `GetBuildLog`,
`XcodeListSchemes` / `XcodeListTestPlans` / `XcodeListRunDestinations`, and the simulator and
debugger tools. It drives the same toolchain the CI matrix uses, surfaces structured diagnostics
instead of scraped log text, and will be the only practical way to run the XCUITest and AutoFill
extension suites once `Apps/` exists.

Do **not** rely on it in CI or in hosted/remote sessions — no Xcode GUI, no simulators, and no MCP
server there. Those environments use the plain `swift build` / `swift test` / `xcodebuild` commands
above, which is why every workflow step stays expressible as shell. Keep it that way: an
MCP-only step is a step CI cannot run.

### Cloud sessions run on Linux, so some of this repository is invisible there

A Claude Code cloud session (claude.ai/code, `claude --cloud`, routines) is a fresh **Ubuntu 24.04
x86\_64** VM. `docs/09-cloud-sessions.md` is the setup runbook; the part that matters while working
is what the platform excludes. There is no Xcode, no simulator, no Apple SDK, and no Xcode MCP
server, and the base image cannot be replaced. So in a cloud session:

- `swift build`, `swift test`, the adversarial suite, `-strict-memory-safety` and `swift format`
  all work — four of the five `ci.yml` jobs. Run `.github/scripts/cloud-verify.sh` for the lot.
- The setup script also installs mise and runs `mise trust && mise install` (XcodeGen skipped: macOS
  only). The shims are not on `PATH` in the Bash tool, so run pinned tools as `mise exec -- <tool>`.
- Anything importing CryptoKit, Security.framework, CommonCrypto or LocalAuthentication does not
  compile, and `xcodebuild` is absent. `WatchwordCrypto`, `SecureMemory` and the Keychain adapters
  (`docs/02-architecture.md` §15) can be drafted there but **not** built or tested. Say so rather
  than reporting a layer as verified; the adversarial test such a change owes has to run on macOS.
- The toolchain is Swift 6.4, newer than the Xcode 16.4 CI leg. A clean cloud build is not evidence
  that leg passes.

If an agent needs the real toolchain, the answer is Remote Control on a Mac (`claude
--remote-control`), not a cloud session — that is the only arrangement with `xcodebuild`, a
simulator and the Xcode MCP server.

`WatchwordModel`, `WatchwordMatching`, `WatchwordGenerator` and `WatchwordEnvelope` import only `Foundation`,
`Testing` and `XCTest`, which is the sole reason they are testable on Linux. Treat that portability as a property to
keep. `WatchwordStore`'s port, `InMemoryRecordStore` and `WatchwordKit`'s policies and ports are portable too;
`SQLiteRecordStore` (`#if canImport(SQLite3)`), `VaultSession` (CryptoKit) and all of `WatchwordPlatform` are not.

## Architecture

Read `docs/02-architecture.md` before changing anything security-relevant; its section numbers are
cited throughout the code. `docs/01-prd.md` requirement IDs (`F6.6`, `SEC6`, …) are the other half of
that vocabulary and appear in doc comments.

Nine shipped modules, dependency-ordered, plus test support:

- **`WatchwordModel`** — pure data types (`Item`, `Field`, `ServiceScope`). No dependencies.
- **`WatchwordMatching`** — the AutoFill security boundary. Depends on `WatchwordModel`.
- **`WatchwordGenerator`** — password/passphrase/PIN generation, generic over `RandomNumberGenerator`.
- **`WatchwordEnvelope`** — envelope format, canonical CBOR, `EnvelopeContext` (the AAD), every check that
  can run before decryption, and KDF parameter validation. Does no cryptography itself.
- **`SecureMemory`** — `SecureBytes` (zeroising, page-locked key buffers), `ConstantTime`, the
  CommonCrypto PBKDF2 call, and the four system bindings with pointer-typed signatures (SQLite,
  `SecItemCopyMatching`, `LAContext.canEvaluatePolicy`, the PDF `CGContext`). The only module allowed unsafe
  code (ADR 0001 and its milestone-2 amendment).
- **`WatchwordCrypto`** — Secret Key, 2SKD, KDF calibration, keyset, vault keys, HPKE grants, signatures,
  fingerprints, record sealing. Depends on `SecureMemory` and `WatchwordEnvelope`.
- **`WatchwordStore`** — the `RecordStore` port, `InMemoryRecordStore` and `SQLiteRecordStore` (the App Group
  ciphertext database). Envelopes plus storage locations only; never keys.
- **`WatchwordKit`** — `VaultSession` (the actor every UI calls: create, unlock, quick unlock, lock, items,
  history, trash, password change, deletion), `UnlockPolicy`, `AutoLockPolicy`, `ItemCodec`, `EmergencyKit`, and
  the ports (`KeychainStore`, `BiometricGate`, `WallClock`).
- **`WatchwordPlatform`** — Apple adapters: `SystemKeychainStore`, `LocalAuthenticationGate`, the Emergency Kit
  PDF, the App Group path. In the package rather than `Apps/` so every CI gate covers them.
- **`WatchwordTestSupport`** — `SeededGenerator`, `RepeatingGenerator`, hex helpers, the nightly knobs, and the
  fakes (`FakeKeychain`, `FakeBiometricGate`, `FakeClock`, `TestVault`). Test targets only; not a product, and no
  production target may depend on it.

`docs/02-architecture.md` §15 lists the modules still to come (`WatchwordSync`, `WatchwordSharing`,
`WatchwordHygiene`, `WatchwordInterchange`) and which milestone each belongs to.

### `VaultSession` invariants

- Nothing unlocks on a boolean. `BiometricGate` reports enrolment only; quick unlock needs the Keychain to release
  the Local Unlock Key, that key to open the wrapped AUK, and the AUK to open the keyset. Keep it that way.
- A refused quick unlock *deletes* the Local Unlock Key; it is not merely ignored.
- The actor is re-entrant across `await`: after every suspension, re-check the lock epoch (`requireKeys(since:)`)
  before touching key material, so `lock()` always wins.
- Read contexts come from the store row, and a decrypted item's `id`/`vaultID`/`version` must equal the row's.
- Scopes are checked with `ScopePolicy` in `save`, whatever the UI sends.

### The matching pipeline is the whole point of `WatchwordMatching`

A credential may only reach the OS through one path, and each stage fails closed:

```
ServiceIdentifier (OS-supplied, attacker-influenced)
  → HostNormalizer.normalize   rejects user-info, non-http(s) schemes, ASCII percent-escapes,
                               structural characters, over-long labels → NormalizedHost
  → ScopeMatcher.match         exclusions first; exact = 2·labels+1, subdomain = 2·labels
  → ItemRanker.rank            top specificity wins; less specific matches are *shadowed*
                               (keeps Amazon retail off the AWS console), ties are ambiguous
  → AutoFillGate.decide        .fill / .chooseAmong / .refuse(FillRefusal)
  → AutoFillGate.authorize     re-checks scope even for an explicit user choice (SEC6)
```

Two invariants to preserve when touching this module:

- Comparison functions take `NormalizedHost`, never `String`, so an un-normalised identifier cannot
  reach a match. Keep that typing.
- Normalisation may never *invent* a match. If an input is not unambiguously a hostname, throw.

`PhishingDetector` exists because the above is silent by design: on `аmazon.com` (Cyrillic а) nothing
matches, the UI shows nothing, and the person types the password by hand. It turns that silence into
`PhishingAssessment.suspicious` (visual-skeleton confusables, mixed script, punycode, bounded edit
distance, saved label out of registrable position). `FillRefusal` carries the assessment so the UI can
explain itself. See `docs/05-anti-phishing.md`.

`PublicSuffix` is a deliberately small embedded list, not the full PSL — adopting the ~14,000-entry
file is a supply-chain decision with an open ADR. Don't expand it into a de facto PSL; add the
entry and note the tradeoff, or escalate to the ADR.

### Fail-closed validation in `WatchwordEnvelope`

`EnvelopeHeader` is the authenticated prefix `magic(4) version(2) kind(1) keyID(16) nonce(12)
aadLength(2) aad ciphertext`. Kind, version and magic are checked *before* any payload is touched, so
record-swap and kind-confusion attacks fail without decryption. `Envelope.parse(_:expecting:)` then
checks the key ID and compares the embedded `aad` byte-for-byte with `EnvelopeContext.canonicalAAD()`
re-derived from the storage location (record, vault, schema, kind, key, record version); only then does
`RecordCipher.open` decrypt, with the *whole* serialized header as the AEAD's associated data. Callers
build the expected context from where they found the record, never from the record.

`KDFParameters` enforces two-sided bounds: a floor against downgrade (650k PBKDF2 iterations, 16-byte
salt) and a ceiling against a tampered header turning every unlock into a hang (25M iterations). Both
directions are tested; keep both when adjusting constants.

### The cryptographic core

`docs/02-architecture.md` §4 is the spec; the code cites it. Invariants worth knowing before editing:

- Key bytes live in `SecureBytes`, not in CryptoKit key objects: `EncryptionKey`, `Keyset` and `SecretKey`
  hold `SecureBytes` and build `SymmetricKey`/`Curve25519` keys per operation, so `zeroise()` on lock is
  real. Reading a zeroised buffer traps on purpose (an all-zero key is the worst key). CryptoKit
  plaintext comes back as `Data`; convert with `SecureBytes(wiping:)`.
- Decryption and HPKE failures all surface as `CryptoError.authenticationFailed` — never distinguish a
  wrong password from tampering.
- Every nonce is claimed in the key's `NonceLedger` (shared by all copies of an `EncryptionKey`) and a
  repeat throws `nonceReuseDetected`. Seal only through `RecordCipher.seal`.
- Every signature is domain-separated (`SignatureDomain`), and `Signatures.verify` rejects small-order
  Ed25519 keys; `PublicKeyBundle.init` validates (lengths, low-order X25519, small-order Ed25519,
  self-signature), so a bundle value is always a checked one.
- Anything unwrapped or opened takes its identity (vault ID, key ID, account ID) from the storage
  location the caller passes in, never from the record or grant itself — `VaultKey.unwrap`,
  `Keyset.unwrap` and `VaultKeyGrant.open(as:from:vaultID:keyID:)` all follow this.
- Production code never copies key material out with `Array(secureBytes)`; use `unprotectedCopy()` for
  non-secret values so every escape is searchable.
- Files that need CryptoKit or CommonCrypto are wrapped in `#if canImport(CryptoKit)` (and
  `&& canImport(CommonCrypto)`), so `swift build`/`swift test` still work on Linux; those suites only run
  on the macOS CI matrix. `SecretKey`, `SecureBytes` and the envelope layer are platform-independent and
  run everywhere.

## Conventions

- **Swift 6 language mode**, strict concurrency. Public types are `Sendable` and usually `Hashable`.
- **Errors, not optionals, for security decisions.** Typed error enums (`HostNormalizationError`,
  `FillRefusal`, `KDFValidationError`, `EnvelopeError`) name the reason so tests assert on it.
- **No third-party dependencies, ever, without an ADR.** `.github/scripts/assert-no-dependencies.sh`
  fails CI on any `.package(`, `.binaryTarget`, `.plugin(`, `unsafeFlags`, or non-empty
  `Package.resolved`. Crypto comes only from CryptoKit, Security.framework and CommonCrypto.
- **No unsafe constructs** outside `SecureMemory` — enforced by the `strict-memory-safety` job plus the
  `.github/scripts/assert-unsafe-confined.sh` tripwire (a marked construct would compile anywhere, and
  `@_silgen_name`-style bindings are not flagged by the compiler at all). No symlinks or non-Swift files
  under `Sources/`, no custom target paths, no experimental features (`assert-no-dependencies.sh`). Inside
  `SecureMemory`, every unsafe construct is marked `unsafe (expression)` — **with the space**: Swift 6.2+
  parses it as the keyword, and on Swift 6.0/6.1 it is a call to the stand-in in `UnsafeMarker.swift`.
  An outer `unsafe` does not cover closure bodies; mark each level. Calls to stdlib `withUnsafe*` are
  flagged by Swift 6.3 but not 6.4, so pass a method reference (`src.withUnsafeBytes(dst.copyMemory(from:))`)
  to keep the marker necessary on both.
- `WatchwordMatching` deliberately does not import AuthenticationServices; it mirrors
  `ASCredentialServiceIdentifier` with its own `ServiceIdentifier` so the logic is testable under
  plain `swift test`. Keep core modules platform-independent; adapters belong in `Apps/`.
- Doc comments cite the requirement or architecture section that motivates the code. Follow that —
  the "why" is load-bearing here, and `docs/` is updated in the same PR as the behaviour it describes.
- British spelling in prose and comments (normalisation, zeroisation); American in API names
  (`normalize`, `HostNormalizer`).
- swift-format with `.swift-format` is a CI gate: 120-column lines, 4 spaces, ordered imports,
  no block comments, no semicolons.

## Tests

- **Swift Testing** for new suites: `@Suite("display name")`, `@Test("behaviour sentence", arguments:)`.
  Parameterised tests over two sequences use `zip(a, b)`, not two `arguments:` labels.
- **XCTest** survives in `WatchwordMatchingTests` only. Both frameworks must keep executing tests —
  CI greps `test-output.log` for evidence of each and fails if either produced none.
- **Adversarial suites** live in `Tests/WatchwordAdversarialTests`, are named `Adversarial…`, and
  carry `.tags(.adversarial)`. CI asserts each area's `@Suite` display name is present
  (`"envelope and KDF"`, `"AutoFill service matching"`, `"password generator"`,
  `"phishing resistance"`, `"crypto core"`, `"unlock and quick unlock"`, `"local vault store"`,
  `"Keychain item protection"`), so **renaming a suite breaks CI deliberately** — update the grep list in
  `.github/workflows/ci.yml` alongside it. Each adversarial test's doc comment states the concrete threat
  (which adversary from `docs/02-architecture.md` §2, with what access) it checks.
- Any PR touching crypto, envelope, sharing, `SecureMemory`, or a Keychain/LocalAuthentication
  adapter must add or update an adversarial test (`docs/03-implementation-plan.md`, working
  agreements).
- Randomness is injected: production uses `SystemRandomNumberGenerator`, tests use the SplitMix64
  `SeededGenerator` from `WatchwordTestSupport`. Never make production code reach for a seeded generator, and never sleep in a
  test — time will come from an injected `Clock`.
- `WATCHWORD_LONG_TESTS=1` and `WATCHWORD_TEST_SEED` are the nightly workflow's knobs for extended
  randomised runs; new long-running tests should honour them via `TestEnvironment`.
- Known-answer vectors come from the RFC that defines the primitive, or from an independent
  implementation (Python `hashlib`/`cryptography`), never from round-tripping our own code.

`docs/04-test-plan.md` maps every requirement to its obligated tests and is the place to check before
claiming a layer is covered.

## CI

`.github/workflows/ci.yml` — `package-tests` (2-runner matrix), `adversarial-tests`,
`strict-memory-safety`, `lint`, `app-tests` (self-skipping). `security-nightly.yml` — long randomised
runs, libFuzzer harnesses under `Fuzz/` (self-skipping), and an audit that every `uses:` is a 40-hex
commit SHA.

One check on every PR has **no workflow file**: `Analyze (swift)`, from CodeQL *default setup*,
which GitHub configures in repository settings and runs on a generated workflow you cannot see in
the tree. Don't go looking for it in `.github/`, and don't add a `codeql.yml` to "fix" its absence —
that would run CodeQL twice. Inspect it instead:

```sh
gh api repos/ericsuh/watchword/code-scanning/default-setup   # state, languages, query suite
gh api repos/ericsuh/watchword/code-scanning/alerts --jq '.[] | {rule: .rule.id, state, path: .most_recent_instance.location.path}'
```

Two consequences worth knowing. It is the one piece of CI that does **not** follow the
SHA-pinning rule, because the queries are versioned by GitHub rather than by this repository — an
accepted exception, recorded in `docs/07-supply-chain.md` §3.4, not an oversight. And its check
name is derived from the configured language set, so enabling a second language renames it and
silently drops it from any branch-protection list that named the old one.

Supply-chain rules that apply to edits in `.github/`:

- **Pin actions to full commit SHAs**, never tags; add the `# v4`-style comment and the mapping in the
  header block. The nightly audit fails the build otherwise.
- Keep `permissions: contents: read` at workflow and job level, `persist-credentials: false` on every
  checkout, and the trigger as `pull_request` — never `pull_request_target`.
- Xcode selection goes through `.github/scripts/select-xcode.sh`, not a third-party action.
- Build tools reach CI only through mise with `MISE_LOCKED=1`, so every tool needs a `mise.lock` entry
  (URL and SHA-256). Bump a tool by editing `mise.toml` and running
  `mise lock --platform macos-arm64,linux-x64`; commit both files. mise itself is pinned by version and
  SHA-256 in `ci.yml`, and a bump is reviewed like an action pin.

`.claude/` and other agent/editor configuration is intentionally uncommitted
(`docs/07-supply-chain.md` §5). `docs/08-repository-hardening.md` is the `gh` runbook for branch
protection, signing and rulesets.
