# ADR 0006: swift-crypto, so the cryptographic core has one code path on every platform

Status: proposed. Date: 2026-10-26.

## Context
The flows with the most at stake — account creation, unlock and quick unlock, the key hierarchy, record sealing,
password change — live in `WatchwordCrypto`, the PBKDF2 call in `SecureMemory`, and `VaultSession`. All three need
CryptoKit or CommonCrypto, neither of which exists on Linux, so they were wrapped in `#if canImport(CryptoKit)` (or
`canImport(CommonCrypto)`) and compiled out there. On Linux, `swift test` went green with 151 of the package's 361
Swift Testing tests absent, among them three adversarial areas ("crypto core", "unlock and quick unlock", "sync with
real keys") and scenarios S1–S4 (`03-implementation-plan.md`, rule 2: absent, not red). Cloud sessions and any Linux CI could draft that code
but not compile it; every change round-tripped through `mac-run.yml` or a Mac.

Guards also cost something on the Mac: each one is a place where the code that ships and the code a reader or a
Linux test sees can drift apart. The goal is one code path for the security logic, with platform differences pushed
below it.

The core uses a small, fixed set of primitives: AES-GCM-256, X25519, Ed25519, HKDF-SHA256, HMAC-SHA256, SHA-256, HPKE
(`Curve25519_HKDF_SHA256`, `HKDF_SHA256`, `AES_GCM_256`) and PBKDF2-HMAC-SHA256.

Options considered:

1. **swift-crypto's `Crypto` everywhere** (decided below).
2. **swift-crypto on Linux only**, behind `#if canImport(CryptoKit) || os(Linux)` in every crypto file (this ADR's
   first revision). Nothing third-party reaches an Apple build, but 18 files keep a guard and a two-way import.
3. **A crypto port, faked on Linux**, as `WatchwordSync` does with `SyncKeyring`. No dependency, but the Linux tests
   would exercise the flow and not the cryptography: the RFC known-answer suites could not run, and production code
   gains a seam whose only purpose is testing.
4. **Our own primitives for Linux.** ADR 0001 forbids self-written cryptography, and HPKE alone rules it out.
5. **A Rust core behind a generated binding** (ADR 0001's deferred path). It answers a different question — non-Apple
   clients — at the cost of a rewrite, an `unsafe` FFI boundary and a crate supply chain.

## Decision
- Depend on [apple/swift-crypto](https://github.com/apple/swift-crypto) at **exactly 4.5.2**, and `import Crypto`
  wherever the code used to import CryptoKit. `Crypto` is linked on every platform. On Apple platforms it compiles no
  cryptography: its manifest builds BoringSSL only for Linux, Android, Windows, WASI and OpenBSD, and its types are
  `@_exported import CryptoKit`, so the app still runs Apple's implementation. On Linux it is the same API over
  BoringSSL. `WatchwordCrypto`, `VaultSession` and their tests contain no platform conditional.
- **One conditional remains, in `SecureMemory/PBKDF2.swift`.** CryptoKit has no PBKDF2. swift-crypto's
  (`KDF.Insecure.PBKDF2`, in `CryptoExtras`) would remove it, but `CryptoExtras` compiles BoringSSL (and swift-asn1)
  into whatever links it, on every platform. So `CryptoExtras` is linked on Linux only, Apple builds keep calling
  CommonCrypto, and the file chooses its backend with `#if canImport(CommonCrypto)`. `PBKDF2.sha256` and its checks are
  outside the conditional; only the call into a backend is inside. The iteration floor stays in `KDFParameters`
  (SEC5).
- Platform conditionals outside cryptography are not this ADR's business and stay: `SecureBytes`' libc differences
  (`memset_s` or `explicit_bzero`, `MADV_DONTDUMP` on Linux), and the Apple-only adapters (Keychain,
  LocalAuthentication, SQLite, Core Graphics).
- **Pinned, not vendored.** `Package.resolved` is committed, and `assert-no-dependencies.sh` names the one allowed
  package, its exact version, the two allowed products, the Linux-only condition on `CryptoExtras`, and the commit of
  both resolved pins (swift-crypto `da9d28d`, and swift-asn1 1.7.3 `3b6410f`, which `CryptoExtras` pulls in). Anything
  else fails CI, so a bump is an edit to that script and an amendment here, reviewed like an action pin. Vendoring was
  rejected: it would put several hundred thousand lines of BoringSSL C under the repository, which the Swift-only rule
  for `Sources/` exists to prevent, and nobody would review it; a pinned commit gives the same integrity.
- **macOS stays the gate.** A Linux pass is evidence about logic (the unlock state machine, AAD binding, the key
  hierarchy, error mapping, zeroisation order), not about the implementation that ships. The known-answer suites run on
  both platforms, so both backends are held to the same RFC outputs.

The three questions `07-supply-chain.md` §2 asks of any dependency:

- *Why no first-party API suffices:* Apple ships no CryptoKit for Linux, and nothing first-party lets one source file
  import the same API on both. swift-crypto is Apple's own: it is CryptoKit's API, maintained by Apple's Swift server
  team, built on Google's BoringSSL where CryptoKit is absent.
- *Maintenance and audit:* releases are tagged and changelogged upstream; BoringSSL is vendored there at a recorded
  upstream commit. A bump is reviewed as a diff of those repositories between pinned commits, with particular attention
  to the Apple-platform side of `Crypto` (below).
- *Pin-and-vendor plan:* exact version, committed `Package.resolved`, commits checked by the tripwire; not vendored
  (above).

## Consequences
- On Linux, 15 more suites and 116 more tests run (210 → 326 of 361 Swift Testing tests; XCTest unchanged at 21):
  "Adversarial: crypto core", "Adversarial: unlock and quick unlock", "Adversarial: sync with real keys",
  "Primitive known answers", "PBKDF2-HMAC-SHA256 known answers", "Two-secret key derivation", "KDF calibration",
  "Keyset, vault keys and grants", "Record sealing", the four "Vault session" suites (account and unlock, items, quick
  unlock, sync between devices), "Scenarios S1–S4 against the vault", and SecureBytes' CryptoKit bridging. Still
  Mac-only: the SQLite stores and "local vault store", the Keychain adapter and "Keychain item protection", the
  Emergency Kit PDF, and the apps.
- **Third-party code now ships (T1).** This is the price of one code path. The apps link swift-crypto's `Crypto`
  module: on Apple platforms, the CryptoKit re-export plus a few non-cryptographic helpers (hex encoding, a resource
  bundle lookup, `Optional.withUnsafeBytes`) and a resource bundle, `swift-crypto_Crypto.bundle`, whose privacy manifest
  declares nothing. No BoringSSL symbol is in either app. But a malicious swift-crypto release could put arbitrary code
  in that module — for instance, replace the re-export with its own implementation — and it would run inside the app
  with vault access. Pinning by commit rules out a moved tag; review of each bump's Apple-platform diff is the control
  that remains. Option 2 avoids this entirely, and is the fallback if the exposure is judged not worth the guards it
  removes.
- swift-crypto's manifest, and swift-asn1's, run wherever the package resolves — every machine, macOS CI and Xcode
  included (sandboxed by SwiftPM on macOS, not on Linux) (T3).
- PRD P4 (no third-party cryptography) holds in substance: every primitive that runs in a shipped build is CryptoKit's
  or CommonCrypto's. P4's limit on third-party packages to "non-security utilities" does not hold, and P4 is amended to
  name this exception. ADR 0001's "cryptography comes only from Apple frameworks" is amended to the same effect.
- **Linux builds are test builds.** swift-crypto's BoringSSL PBKDF2 derives into a plain `Data` buffer that is never
  zeroised before it is copied into `SecureBytes`. Acceptable only because no Linux build ships; if one ever does, this
  ADR must be revisited alongside ADR 0001's Rust option.
- A fresh checkout now resolves two packages from github.com before its first build, on every platform.
- **Toolchain floor.** swift-crypto 4.x declares tools 6.1, within the Xcode 16.4 leg. 5.x declares tools 6.2 and would
  drop that leg; stay on 4.x until the floor moves.

## Verification of the spike
- Linux: `swift build --build-tests` and `swift test` on `swift:6.4-noble` (Ubuntu 24.04, **arm64**, Docker on Apple
  silicon), against the same suites at `main` for the before/after counts. Not yet run on the cloud VM's x86_64 or
  through `cloud-verify.sh`.
- macOS 27, Xcode 27: `mise run test` (361 Swift Testing tests, after merging milestone 3's vault side), `build:strict`, `lint`, `audit` (with negative
  checks: linking `CryptoExtras` unconditionally, changing a pin, and a version range each fail it), and `app:build` for
  iOS and macOS, with the app binaries checked for BoringSSL symbols (none). The Xcode 16.4 leg runs in this PR's CI.
