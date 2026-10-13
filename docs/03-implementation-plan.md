# Watchword — Implementation Plan

Version 0.1 (draft). Milestones are ordered so that every security-relevant layer exists, with its
tests, before any UI depends on it. Each milestone lists its exit criteria; the matching test
obligations are in `04-test-plan.md`.

## Milestone 0 — Repository, toolchain, CI (this change)

- SwiftPM package `Watchword` with the first pure modules (`WatchwordModel`, `WatchwordMatching`,
  `WatchwordGenerator`, `WatchwordEnvelope`) and both Swift Testing and XCTest targets.
- GitHub Actions on macOS runners: `swift build`/`swift test` on Xcode 16.4 (macOS 15) and Xcode 26
  (macOS 26), a dedicated adversarial-suite job, a strict-memory-safety job, formatting lint, and
  an Xcode app-test job that activates when the app project lands.
- Exit: CI green on the pull request; docs in `docs/`.

## Milestone 1 — Cryptographic core

- `SecureMemory`: `SecureBytes` with zeroisation, page locking where available, `@unsafe` marked.
- `WatchwordCrypto`: Secret Key generation/formatting/checksum; 2SKD (`PBKDF2` via CommonCrypto,
  `HKDF` via CryptoKit, XOR); keyset creation and wrapping; vault key creation; HPKE wrap/unwrap;
  Ed25519 signing of membership and log segments; KDF calibration.
- `WatchwordEnvelope`: full encoder/decoder with AAD binding and version/kind/key checks.
- Exit: known-answer tests for every primitive, property tests for round-trips, adversarial tests
  for tamper/swap/replay/downgrade, KDF calibration test (≥300 ms on CI hardware is informational).

## Milestone 2 — Local vault and unlock

- `WatchwordStore` (SQLite ciphertext store in the App Group), `WatchwordKit.VaultSession`
  (create account, unlock, lock, CRUD items, history, trash), `UnlockPolicy`, Keychain and
  LocalAuthentication adapters, Emergency Kit PDF generation.
- `Apps/`: XcodeGen project with iOS and macOS app targets and AutoFill extension targets; minimal
  SwiftUI screens: onboarding (password + Emergency Kit), unlock, item list/detail/edit.
- Exit: scenario tests S1–S4 pass against `VaultSession` with in-memory ports; XCUITest smoke test
  of onboarding and unlock on both platforms; on-device verification of QuickType behaviour with
  overlapping domain identities (document the result in `02-architecture.md` §9).

## Milestone 3 — Sync

- `WatchwordSync`: change-log segments, snapshots, Lamport merge, `SyncTransport` protocol,
  `InMemorySyncTransport` for tests.
- `CloudKitTransport` with `CKSyncEngine`; `FileTransport` for the iCloud Drive container and
  Files-app folders.
- Exit: multi-client simulation tests (N clients, random partitions, concurrent edits) converge;
  CloudKit integration test against a development container runs in a manually triggered
  workflow with repository secrets; transport contract tests prove no plaintext leaves the core.

## Milestone 4 — Sharing

- `WatchwordSharing`: membership chain, invitations, fingerprints, rotation on removal/leave,
  read-only enforcement in the client; CloudKit `CKShare` and `UICloudSharingController`/
  `NSSharingService` integration; folder-share flow for the file transport.
- Exit: S3 and S4 pass end-to-end with two simulated users over `InMemorySyncTransport` and over
  CloudKit (manual workflow); adversarial tests for forged membership, stale-admin signatures,
  key substitution by the server, and post-revocation access.

## Milestone 5 — AutoFill

- `AutoFillExtension` targets for iOS and macOS: credential list, passwords, passkey registration
  and assertion (with `prf`), one-time codes (iOS 18+/macOS 15+), text to insert, save-password
  and generate-password requests, credential-update reports; identity publishing to
  `ASCredentialIdentityStore` with ranks from `WatchwordMatching`.
- Exit: extension view-model tests cover every request type with fakes; manual AutoFill QA
  checklist executed on device for S1 and S2; best-effort XCUITest that enables the provider in
  Settings on the simulator runs as a non-blocking job.

## Milestone 6 — Hygiene

- `WatchwordHygiene`: HIBP range client with padding, caching and lenient parsing; scheduling;
  zxcvbn-class estimator (vendored); reuse/age/2FA checks; Watchtower-style report UI.
- Exit: HIBP client tests against recorded fixtures including padded and malformed responses;
  scheduling tests with a fake clock; UI report snapshot tests.

## Milestone 7 — Interchange

- `WatchwordInterchange`: 1PUX, 1Password CSV, Apple CSV, CXF import/export; Credential Exchange
  integration on iOS 26/macOS 26; encrypted Watchword archive; in-app instructions.
- Exit: fixture-based round-trip tests; adversarial parser tests (zip-slip, bomb, formula
  injection, oversized rows); fuzz targets registered in the nightly workflow.

## Milestone 8 — Hardening and release

- External review of `WatchwordCrypto`, `WatchwordEnvelope`, `WatchwordSharing`.
- Performance (N1, N2) and accessibility (N4) passes; App Store privacy manifest; TestFlight.

## Working agreements

- Every pull request that touches `WatchwordCrypto`, `WatchwordEnvelope`, `WatchwordSharing`,
  `SecureMemory`, or any adapter for Keychain/LocalAuthentication must add or update an adversarial
  test and must be reviewed by a second person.
- No new third-party dependency without an ADR.
- `docs/` is updated in the same pull request as the behaviour it describes.
