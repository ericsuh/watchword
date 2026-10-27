# ADR 0006: swift-crypto as CryptoKit's stand-in on Linux

Status: proposed. Date: 2026-10-26.

## Context
The flows with the most at stake — account creation, unlock and quick unlock, the key hierarchy, record sealing,
password change — live in `WatchwordCrypto`, the PBKDF2 call in `SecureMemory`, and `VaultSession`. All three need
CryptoKit or CommonCrypto, neither of which exists on Linux, so they were wrapped in `#if canImport(CryptoKit)` and
compiled out there. On Linux, `swift test` went green with 128 of the package's 333 Swift Testing tests absent, among
them two adversarial areas ("crypto core", "unlock and quick unlock") and scenarios S1–S4
(`03-implementation-plan.md`, rule 2: absent, not red). Cloud sessions and any Linux CI could draft that code but not
compile it; every change round-tripped through `mac-run.yml` or a Mac.

The core uses a small, fixed set of primitives: AES-GCM-256, X25519, Ed25519, HKDF-SHA256, HMAC-SHA256, SHA-256, HPKE
(`Curve25519_HKDF_SHA256`, `HKDF_SHA256`, `AES_GCM_256`) and PBKDF2-HMAC-SHA256.

Options considered:

1. **swift-crypto on Linux only** (decided below).
2. **A crypto port, faked on Linux**, as `WatchwordSync` does with `SyncKeyring`. No dependency, but the Linux tests
   would exercise the flow and not the cryptography: the RFC known-answer suites could not run, and production code
   gains a seam whose only purpose is testing.
3. **Our own primitives for Linux.** ADR 0001 forbids self-written cryptography, and HPKE alone rules it out.
4. **A Rust core behind a generated binding** (ADR 0001's deferred path). It answers a different question — non-Apple
   clients — at the cost of a rewrite, an `unsafe` FFI boundary and a crate supply chain.
5. **Status quo**, with `mac-run.yml` for every crypto change. It works, but Linux green says nothing about the layers
   that matter most.

## Decision
- Depend on [apple/swift-crypto](https://github.com/apple/swift-crypto) at **exactly 4.5.2**, products `Crypto` and
  `CryptoExtras` only, **linked on Linux only** (`condition: .when(platforms: [.linux])`). Apple builds — the apps, the
  AutoFill extensions, every macOS CI leg — keep importing CryptoKit and CommonCrypto directly and never compile
  swift-crypto. (On Apple platforms swift-crypto would only re-export CryptoKit anyway; the condition makes that moot.)
- Crypto files are guarded `#if canImport(CryptoKit) || os(Linux)` and import `CryptoKit` where it exists, `Crypto`
  otherwise. `PBKDF2.sha256` keeps its one signature in `SecureMemory`; on Linux it calls
  `KDF.Insecure.PBKDF2` (BoringSSL) and copies the result into `SecureBytes`. The iteration floor stays where it was,
  in `KDFParameters` (SEC5).
- **Pinned, not vendored.** `Package.resolved` is committed, and `assert-no-dependencies.sh` names the one allowed
  package, its exact version, the two allowed products, the Linux-only condition, and the commit of both resolved pins
  (swift-crypto `da9d28d`, and swift-asn1 1.7.3 `3b6410f`, which `CryptoExtras` pulls in). Anything else fails CI, so
  a bump is an edit to that script and an amendment here, reviewed like an action pin. Vendoring was rejected: it
  would put several hundred thousand lines of BoringSSL C under the repository, which the Swift-only rule for
  `Sources/` exists to prevent, and nobody would review it; a pinned commit gives the same integrity.
- **macOS stays the gate.** A Linux pass is evidence about logic (the unlock state machine, AAD binding, the key
  hierarchy, error mapping, zeroisation order), not about the implementation that ships. The known-answer suites run on
  both platforms, so both backends are held to the same RFC outputs.

The three questions `07-supply-chain.md` §2 asks of any dependency:

- *Why no first-party API suffices:* Apple ships no CryptoKit for Linux. swift-crypto is Apple's own: it is
  CryptoKit's API, maintained by Apple's Swift server team, built on Google's BoringSSL.
- *Maintenance and audit:* releases are tagged and changelogged upstream; BoringSSL is vendored there at a recorded
  upstream commit. A bump is reviewed as a diff of those two repositories between pinned commits.
- *Pin-and-vendor plan:* exact version, committed `Package.resolved`, commits checked by the tripwire; not vendored
  (above).

## Consequences
- On Linux, 11 more suites and 90 more tests run (205 → 295 of 333 Swift Testing tests; XCTest unchanged at 21):
  "Adversarial: crypto core", "Adversarial: unlock and quick unlock", "Primitive known answers",
  "PBKDF2-HMAC-SHA256 known answers", "Keyset, vault keys and grants", "Record sealing", the three "Vault session"
  suites, "Scenarios S1–S4 against the vault", and SecureBytes' CryptoKit bridging. Still Mac-only: the SQLite store and
  "local vault store", the Keychain adapter and "Keychain item protection", the Emergency Kit PDF, and the apps.
- **Supply chain (T1, T3).** A compromised swift-crypto release cannot reach a shipped binary. It could make Linux tests
  pass that should fail (the macOS gate catches that), run code in Linux test processes (cloud sessions and any Linux
  CI hold no signing keys or release secrets), and run its manifest wherever the package resolves — every machine,
  macOS CI and Xcode included, sandboxed by SwiftPM on macOS and not on Linux. Pinning commits rules out a moved tag.
- PRD P4 (no third-party cryptography) holds for every build that ships, and now says so. ADR 0001's "cryptography
  comes only from Apple frameworks" is amended to the same effect.
- **Linux builds are test builds.** swift-crypto's BoringSSL PBKDF2 derives into a plain `Data` buffer that is never
  zeroised before it is copied into `SecureBytes`. Acceptable only because no Linux build ships; if one ever does, this
  ADR must be revisited alongside ADR 0001's Rust option.
- A fresh checkout now resolves two packages from github.com before its first build, on every platform, though Apple
  builds compile neither.
- **Toolchain floor.** swift-crypto 4.x declares tools 6.1, within the Xcode 16.4 leg. 5.x declares tools 6.2 and would
  drop that leg; stay on 4.x until the floor moves.

## Verification of the spike
- Linux: `swift build --build-tests` and `swift test` on `swift:6.4-noble` (Ubuntu 24.04, **arm64**, Docker on Apple
  silicon), against the same suites at `HEAD` for the before/after counts. Not yet run on the cloud VM's x86_64 or
  through `cloud-verify.sh`.
- macOS 27, Xcode 27: `mise run test` (333 Swift Testing tests), `build:strict`, `lint`, and `audit` (with negative
  checks: dropping the Linux condition, changing a pin, and a version range each fail it), and `app:build macos`.
  The Xcode 16.4 leg has not been run.
