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
| [docs/05-anti-phishing.md](docs/05-anti-phishing.md) | Why refusing to fill is not enough, and the six layers that keep a credential off a look-alike site |
| [docs/06-adversarial-review.md](docs/06-adversarial-review.md) | Adversarial code and design review: findings, severities, and what was fixed, accepted, or tracked |
| [docs/07-supply-chain.md](docs/07-supply-chain.md) | Supply-chain controls for the app code and for the GitHub/tooling/dev layer |
| [docs/08-repository-hardening.md](docs/08-repository-hardening.md) | `gh` runbook for branch protection, actions policy, signing, tag rulesets, and secret scanning |
| [docs/09-cloud-sessions.md](docs/09-cloud-sessions.md) | Running Claude Code cloud sessions against this package: Swift on the Linux VM, and which gates Xcode's absence puts out of reach |
| [docs/adr/](docs/adr/) | Architecture decision records |

## Repository layout

```
Package.swift              Swift package (Swift 6 language mode)
Sources/WatchwordModel     item, field and service-scope types
Sources/WatchwordMatching  host normalisation, scope scoring, shadowing (Amazon vs AWS),
                           scope policy, phishing detection, the AutoFill authorization gate
Sources/WatchwordGenerator password, passphrase and PIN generation with entropy estimates
Sources/WatchwordEnvelope  envelope header and KDF parameter validation (two-sided bounds)
Tests/                     Swift Testing suites, XCTest suites, adversarial + phishing suites
.github/workflows          macOS CI: package tests, adversarial job, strict memory safety, lint
.github/scripts            Xcode selection and the dependency guard (no third-party actions)
mise-tasks/                Build, test, audit and app tasks behind `mise run` (CI calls them too)
```

## Building and testing

Requires Xcode 16.4 or newer (Xcode 26 for the strict-memory-safety job) and
[mise](https://mise.jdx.dev). CI runs these same tasks, so a failing check reproduces locally with
the command in its step name.

```sh
mise trust && mise install      # once per checkout
mise run check                  # lint, supply-chain audits, package and adversarial tests
mise run app:test               # iOS and macOS app suites (generates the Xcode project first)
mise run app:screenshots        # a picture of every major screen, into Screenshots/ with a contact sheet
mise tasks                      # everything else; `mise run <task> --help` for flags
```

## Passkey AAGUID

Watchword's passkeys carry the AAGUID `5B0C7A3E-9D41-4F6C-A2B8-3E1F7C0D9A54`
(`PasskeyAuthenticator.aaguid`). It identifies the authenticator model, Watchword, to relying
parties, so a site can label which provider holds a passkey ("saved in Watchword"). It is the
same for every installation: not a secret, and not per user or per device. With "none"
attestation, which is what passkey providers use, the platform may replace it with zeros, so a
site may never see it.

As of 2026-11-16 it is not registered: it was checked against the community list
[passkeydeveloper/passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids)
(`combined_aaguid.json`, 417 entries) and appears nowhere in it. Registering it there is what
lets sites show Watchword's name and icon.

## Principles

- Two secrets (account password + device-held Secret Key) are required to unlock or sync.
- Transports (CloudKit, iCloud Drive, Dropbox via the Files app) carry ciphertext only.
- Native UI, memory-safe Swift, no third-party cryptography, and one pinned dependency — Apple's swift-crypto, which
  re-exports CryptoKit on Apple platforms (ADR 0006) — enforced in CI.
- A credential is never released on a host an item is not scoped to, and a look-alike site gets a
  warning rather than silence.
- Every security flow is testable in-process with injected fakes, and adversarial tests are a
  required part of CI.
