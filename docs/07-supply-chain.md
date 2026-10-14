# Watchword — Supply-chain controls

Version 0.1 (draft). Covers two layers that are usually treated separately and should not be: what
ends up *inside the app*, and what can execute *in the build and development environment*. For a
password manager the second is at least as dangerous as the first — a compromised CI step can ship
a signed binary that exfiltrates vaults, and no amount of in-app cryptography prevents it.

Controls marked **[enforced]** fail CI. The rest are conventions or planned work, and are labelled
as such so nobody mistakes an intention for a control.

## 1. Threat model for the toolchain

| Adversary | Capability | What it gets them |
| --- | --- | --- |
| T1 Dependency author / account takeover | Publishes a malicious version of a package we depend on | Code inside the app, with vault access at runtime |
| T2 Action author / tag mover | Moves a mutable tag we reference, or takes over the repo | Arbitrary code in CI with the job's token and secrets |
| T3 Build-tool author | Compromises a build plugin, Swift macro, or SwiftPM command plugin | Code execution at *compile* time, on CI and on developer machines |
| T4 Transitive data supplier | Tampers with a bundled data file (wordlist, public-suffix list) | Silently weakens generated passwords or widens scope matching |
| T5 Repository attacker | Pushes to a branch, opens a PR, or edits a workflow | Code execution in CI; a malicious release |
| T6 Signing-key thief | Steals the Developer ID or App Store Connect key | Ships a signed malicious build to real users |
| T7 Developer-machine attacker | Compromises a laptop | Everything above |

## 2. Application code: zero dependencies, enforced

The strongest available position is to have nothing to compromise. The package has no third-party
dependencies, no binary targets, and no build plugins, and that is now checked rather than merely
intended.

- **[enforced]** `.github/scripts/assert-no-dependencies.sh` fails the build if `Package.swift`
  gains a `.package(`, a `.binaryTarget`, a `.plugin(`, or `unsafeFlags`, or if `Package.resolved`
  pins anything. Adding a dependency therefore requires editing the guard in the same pull request,
  which is visible in review.
- **[convention]** Any new dependency requires an ADR covering: why no first-party API suffices,
  the maintenance and audit story, and the pin-and-vendor plan. ADR 0001 already forbids
  third-party cryptography outright.
- **[enforced]** Cryptography comes only from CryptoKit, Security.framework, and CommonCrypto
  (reviewed as part of the no-dependency check: a crypto dependency cannot be added without
  tripping it).

### 2.1 Swift macros and plugins (T3)

Swift macros execute arbitrary code in the compiler's process, on every machine that builds the
project. Swift Testing's `@Test` and `#expect` are macros — acceptable, because they ship with the
Apple toolchain and are already in the trust base. A *third-party* macro package would be
build-time remote code execution, so:

- **[enforced]** no `.plugin(` targets and no third-party macro packages (same guard as above).
- **[convention]** `Package.swift` changes get the same review scrutiny as cryptography changes.

### 2.2 Bundled data files (T4)

Two data files are planned, and both affect security silently if tampered with:

- **EFF large wordlist** feeds passphrase entropy. A list with duplicate entries lowers the real
  entropy while the UI keeps reporting `words × log2(7776)`.
  **[planned, milestone 5]** check the file into the repo, verify a SHA-256 at build time, and add
  a test asserting the exact word count *and* that all entries are unique — the property that
  actually matters, not just the hash.
- **Public Suffix List**, if adopted in full (~14,000 entries) to replace the embedded list in
  `PublicSuffix.swift`. It governs which scopes may be created, so tampering widens matching.
  **[planned]** same treatment, plus an ADR: a list that must be refreshed is a standing
  supply-chain obligation, which is why the current implementation embeds a small curated subset
  instead.

A zxcvbn-class strength estimator is also planned. **[decision]** port a minimal matcher rather
than vendoring a package: the dictionaries are the bulk of the code and can be checked in as
verified data, and the estimator's output drives advice rather than any security boundary.

## 3. GitHub Actions and CI

### 3.1 Actions pinned to commit SHAs (T2)

A tag is mutable. `actions/checkout@v4` is a standing grant of code execution to whoever can move
that tag. Both actions in use are pinned to full 40-hex commit SHAs with the version in a trailing
comment:

```
actions/checkout        v4 -> 11d5960a326750d5838078e36cf38b85af677262
actions/upload-artifact v4 -> ea165f8d65b6e75b540449e92b4886f43607fa02
```

- **[enforced]** the `action-pinning-audit` job in `security-nightly.yml` fails if any `uses:` in
  any workflow is not a 40-hex SHA.
- **[done]** `maxim-lobanov/setup-xcode` was removed entirely and replaced by
  `.github/scripts/select-xcode.sh`. It was the only third-party action in the project, it ran in
  every job, and it did work that is a few lines of `xcode-select`. Fewer actions is a better
  control than a better-pinned action.
- **[convention]** bumping a pin means reading the diff between the old and new SHA, not just
  trusting the tag. Dependabot/Renovate may propose bumps; they are reviewed, not auto-merged.

### 3.2 Token and secret exposure (T5)

- **[done]** `permissions: contents: read` at workflow level and repeated per job. No job needs
  write access.
- **[done]** `persist-credentials: false` on every checkout, so the `GITHUB_TOKEN` is not left in
  `.git/config` for later steps (including any future step that runs third-party code) to read.
- **[done]** the trigger is `pull_request`, never `pull_request_target`, so a fork's code never
  runs with repository secrets.
- **[convention]** the CloudKit integration tests (milestone 3) need an iCloud container and
  therefore secrets. They must stay `workflow_dispatch`-only, in a GitHub Environment with required
  reviewers, and must never be reachable from a `pull_request` trigger.
- **[convention]** no secret is ever `echo`ed; artifact uploads are limited to test logs and
  `.xcresult` bundles, which contain only synthetic fixture data.

### 3.3 Remaining CI exposure, stated honestly

- **Homebrew in `app-tests`.** `brew install xcodegen` fetches an unpinned formula and bottle at
  build time (T3). It is gated behind `Apps/project.yml` existing, so it does not run today.
  **[planned, milestone 2]** commit the generated `.xcodeproj` and delete the step; if XcodeGen is
  kept instead, install a pinned release archive with a verified SHA-256 rather than via Homebrew.
- **The runner image itself** is a large trust base (Xcode, Homebrew, preinstalled tooling) that we
  do not control. Accepted: the alternative is self-hosted runners, which trade this for a
  machine we would have to secure ourselves. Revisit if the project ever signs releases in CI.
- **`continue-on-error` on the AutoFill UI test** can hide a real failure in that one job.
  Accepted deliberately — simulator AutoFill automation is unreliable — and it is scoped to a
  single `-only-testing` invocation so it cannot mask the rest of the suite.

## 4. Repository and release integrity (T5, T6)

**[planned]** — these require repository-admin settings, not code:

- Branch protection on `main`: require `package-tests` (both runners), `adversarial-tests`,
  `strict-memory-safety`, and `lint`; require review; no force-push; no deletion.
- Require signed commits on `main`, so a push with stolen credentials is distinguishable.
- Restrict who may edit `.github/` (a CODEOWNERS entry), because a workflow edit is code execution.
- Tag protection on release tags, with two-person review.
- Release provenance: build from a tagged commit and attach an attestation
  (`actions/attest-build-provenance`, pinned), so a binary can be traced to a reviewed commit.
- Signing keys (T6): Developer ID and App Store Connect API keys live in a dedicated Environment
  with required reviewers, or better, in a hardware-backed keychain used only for release builds —
  never in a secret readable by a PR-triggered workflow.
- Secret scanning and push protection enabled.

## 5. Developer machines (T7)

**[convention]**:

- FileVault required; the repository lives on an encrypted volume.
- `swift build` on an untrusted branch is code execution (macros, plugins, `Package.swift` itself).
  Review `Package.swift` and `.github/` changes *before* building a branch from outside the team.
- Agent and editor configuration (`.claude/`, IDE settings) is not committed, so a committed config
  cannot change what a teammate's tooling does. If any of it is ever shared, it goes through review
  like code.
- No credential helpers that cache tokens in plaintext; no `.netrc` for GitHub.

## 6. Open decisions

| Decision | Why it is open |
| --- | --- |
| Full Public Suffix List vs. the embedded subset | The full list is a recurring third-party data dependency with a refresh obligation (T4). The subset covers the realistic cases with no update process. Needs an ADR before milestone 5. |
| Self-hosted runners | Would shrink the runner trust base but add a machine to secure. Only worth it if releases are ever built in CI. |
| Reproducible builds | Would let a second party verify a release binary against source. Expensive on Apple platforms; worth re-examining at 1.0. |
| Rust core behind a generated binding | ADR 0001 defers it. Note that it would *add* supply-chain surface (crates, `cargo`, the FFI shim), which belongs in that ADR's trade-off. |
