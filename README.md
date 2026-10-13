# Watchword

A native iOS, iPadOS and macOS password manager for a household or small group: end-to-end
encrypted, synced through the iCloud account you already have (or any file-based cloud), with
AutoFill for passwords, passkeys and one-time codes.

Status: design phase. The documents below are the deliverable for now; the Swift package holds the
first pure modules and the CI scaffolding that will grow with them.

## Documents

| Document | Purpose |
| --- | --- |
| [docs/00-research.md](docs/00-research.md) | Survey of 1Password, Bitwarden, Apple Passwords, KeePass-family apps; Apple platform APIs for AutoFill, passkeys, Credential Exchange, unlock, CloudKit sharing; HIBP; CI toolchain |
| [docs/01-prd.md](docs/01-prd.md) | Product requirements, scenarios, security requirements |
| [docs/02-architecture.md](docs/02-architecture.md) | Threat model, key hierarchy, envelope format, sync, sharing, AutoFill matching, module layout |
| [docs/03-implementation-plan.md](docs/03-implementation-plan.md) | Milestones and exit criteria |
| [docs/04-test-plan.md](docs/04-test-plan.md) | Test architecture, end-to-end scenarios, mandatory adversarial tests, CI |
| [docs/adr/](docs/adr/) | Architecture decision records |

## Repository layout

```
Package.swift              Swift package (Swift 6 language mode)
Sources/WatchwordModel     item, field and service-scope types
Sources/WatchwordMatching  host normalisation, scope scoring, shadowing (Amazon vs AWS)
Sources/WatchwordGenerator password, passphrase and PIN generation with entropy estimates
Sources/WatchwordEnvelope  envelope header and KDF parameter validation (anti-downgrade)
Tests/                     Swift Testing suites, XCTest suites, adversarial suite
.github/workflows          macOS CI: package tests, adversarial job, strict memory safety, lint
```

## Building and testing

Requires Xcode 16.4 or newer (Xcode 26 for the strict-memory-safety job).

```sh
swift build
swift test --parallel
swift test --filter Adversarial            # security suite only
```

## Principles

- Two secrets (account password + device-held Secret Key) are required to unlock or sync.
- Transports (CloudKit, iCloud Drive, Dropbox via the Files app) carry ciphertext only.
- Native UI, memory-safe Swift, no third-party cryptography.
- Every security flow is testable in-process with injected fakes, and adversarial tests are a
  required part of CI.
