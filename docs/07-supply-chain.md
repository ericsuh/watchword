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
  which is visible in review. It also checks the resolved manifest (`swift package dump-package`):
  only plain Swift source and test targets, each at its conventional path (a custom `path:` could
  compile files no other check scans), no experimental features or C++ interop, and the test-only
  `WatchwordTestSupport` (seeded and deliberately broken RNGs) linked only into test targets.
- **[enforced]** `.github/scripts/assert-unsafe-confined.sh` (strict-memory-safety job) fails on
  unsafe constructs, `@unchecked`, or underscored attributes outside `Sources/SecureMemory`, on
  hand-bound foreign symbols (`@_silgen_name`, `@_cdecl`, `@_extern`) anywhere, and on symlinks or
  non-Swift files under `Sources/`. It is a tripwire for a malicious or careless contribution
  (milestone-1 review finding R1), with review as the backstop.
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
that tag. Every action in use is pinned to a full 40-hex commit SHA with the version in a trailing
comment:

```
actions/checkout              v7.0.1   -> 3d3c42e5aac5ba805825da76410c181273ba90b1
actions/upload-artifact       v7.0.2   -> cf430e030ddbb5b0abf93d22962f4752f3646cd9
anthropics/claude-code-action v1.0.263 -> 8041f1d17e0e7d2f2cfe35002962e9f26237c0bb
```

`anthropics/claude-code-action` (`claude-pr.yml`, §3.2) is the one third-party action. Its pin
covers its own code and its nested `oven-sh/setup-bun`, which it pins to a SHA itself; the Claude
Code CLI it installs is pinned by version inside the action but fetched from `claude.ai/install.sh`
at run time, so that download is trusted the way the runner image is (§3.3).

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
  write access, except the Claude job in `claude-pr.yml` (below).
- **[done]** `persist-credentials: false` on every checkout, so the `GITHUB_TOKEN` is not left in
  `.git/config` for later steps (including any future step that runs third-party code) to read.
- **[done]** the trigger is `pull_request`, never `pull_request_target`, so a fork's code never
  runs with repository secrets.
- **[done]** `mac-run.yml`, the dispatch-only workflow a cloud session uses to run a Mac-only gate on a branch
  (`09-cloud-sessions.md` §5), is held to the same rules. A dispatch runs the workflow file and `mise run ci:gate` as
  they are on the dispatched branch, so anyone who can dispatch it can change what it runs; its controls are that only
  write access can dispatch, it uses no secrets, and its token is read-only (`contents: read`, under the repository's
  read-only default, `08-repository-hardening.md` §1). Two further rules are hygiene rather than a boundary: inputs
  reach the shell only as environment variables (never `${{ }}` inside `run:`), and `ci:gate` refuses an unknown gate,
  a filter that looks like an option or matches no test, and combinations `ci.yml` never runs, so a mistyped or
  prompt-influenced input fails loudly instead of running the wrong thing or passing without testing.
- **[done]** `claude-pr.yml` runs Claude Code on pull requests: a review when an admin opens one
  ready for review or marks it ready, and an answer when an admin writes `@claude` in a PR comment,
  review or review comment. It is the one workflow that holds a secret (`ANTHROPIC_API_KEY` or
  `CLAUDE_CODE_OAUTH_TOKEN`) and a token that can write, and its `issue_comment` trigger runs the
  default branch's copy with secrets even when the pull request comes from a fork. Its controls:
  - **Admin only.** A separate `authorize` job, read-only and without secrets, asks the API for the
    sender's permission; the Claude job runs only on `admin`. Bots never pass. The action also
    requires write access and a human actor. Fork pull requests are skipped on the `pull_request`
    and review triggers, which get no secrets.
  - **One job sees the secret.** The Claude job runs in the `staging` GitHub Environment, so the
    key can be an environment secret that the `authorize` job and every other workflow cannot
    read, and staging's protection rules (required reviewers, deployment branches) gate it.
  - **Comment, not change.** The Claude job has `contents: read` and `pull-requests: write`, and
    uses the job's own `GITHUB_TOKEN` rather than the Claude GitHub App's broader one. The tool
    allowlist admits reading files, `gh pr view`/`diff`/`comment` on that pull request, inline
    review comments, and a reply in the one thread that mentioned Claude. No build, test or other
    command runs, so nothing in the pull request executes. The repository setting that stops
    workflows approving pull requests (`08-repository-hardening.md` §1) still applies.
  - **The pull request's files are never checked out.** Only the base branch is on disk, so the
    CLAUDE.md and `.claude/` that steer Claude are the reviewed ones; Claude reads the change
    through `gh pr diff`. A checkout of the head, even into a subdirectory, would let a CLAUDE.md
    or skill the pull request adds load as instructions when Claude reads files there (CodeQL's
    untrusted-checkout query flags it for that reason).
  - **Event text reaches the shell only through `env:`**, as in `mac-run.yml`.
  - **Allowed by name.** The repository runs GitHub-owned actions only, so the action and its
    nested `oven-sh/setup-bun` each have a SHA-pinned entry in `patterns_allowed`
    (`08-repository-hardening.md` §1); a bump changes those entries with the pin.

  The residual risk is prompt injection: an admin can ask Claude about a pull request written by
  someone else, whose text can try to steer what Claude posts. The tool allowlist bounds what it
  can do to commenting on that one pull request.
- **[convention]** the CloudKit integration tests (milestone 3) need an iCloud container and
  therefore secrets. They must stay `workflow_dispatch`-only, in a GitHub Environment with required
  reviewers, and must never be reachable from a `pull_request` trigger.
- **[convention]** no secret is ever `echo`ed; artifact uploads are limited to test logs and
  `.xcresult` bundles, which contain only synthetic fixture data.

### 3.3 Remaining CI exposure, stated honestly

- **XcodeGen in `app-tests`.** **[done]** closed. Milestone 2 shipped with `brew install
  xcodegen`, an unpinned formula and bottle fetched at build time (T3). XcodeGen now comes from
  the project's `mise.toml` (2.46.0), and `mise.lock` records its download URL and SHA-256. The
  job installs mise from one release tarball (2026.9.11, macOS arm64), fetched over HTTPS only and
  checked against a SHA-256 in `.github/scripts/install-mise.sh` before it runs. It then runs
  `mise install xcodegen` with `MISE_LOCKED=1`, so mise refuses a tool with no lockfile entry and
  checks the archive against the locked checksum. A mismatch at either layer fails the job. The
  `app:generate` task also asserts that `xcodegen --version` matches `mise.toml` before generating.
  `MISE_USE_VERSIONS_HOST=0` keeps mise from contacting `mise-versions.jdx.dev`, and the script
  never runs `mise --version` (which checks `mise.jdx.dev` for a newer release), so the job's only
  fetches are from GitHub releases. Nothing comes from
  Homebrew. Both hashes were checked against an independent download and the digest GitHub
  publishes for the release asset. Each failure path (a bad mise hash, a tampered lock checksum, a
  tool missing from the lock) was exercised and fails the step.

  What remains is trust in two artifacts as their maintainers built them (mise and XcodeGen),
  plus mise's baked-in aqua registry, which maps `xcodegen` to `yonaskolb/XcodeGen`. That is the
  same residual as an action pinned to a SHA. A bump changes version and hash together and is
  reviewed like an action bump (§3.1), by reading the release diff rather than trusting the tag:
  mise in `install-mise.sh`, tools through `mise lock`. The job still has `contents: read` and no
  secrets, and no token is passed to mise, so a bad artifact could at worst falsify that job's own
  result.
- **mise in every job.** **[accepted]** Every CI step past checkout and Xcode selection is now
  `mise run <task>` (`mise.toml`, `mise-tasks/`), so a failure reproduces locally with the same
  command. That puts mise in the trust base of every job, not only `app-tests`: the same pinned
  release, installed by `install-mise.sh` (macOS arm64, and linux x64 for the nightly pinning
  audit, whose digest is the one `cloud-setup.sh` already pins; `mise run audit:mise-pins` fails if
  the two scripts ever disagree). The same script writes mise's CI settings to `$GITHUB_ENV`, so
  every job gets them from one place. Auto-install is off (`MISE_TASK_RUN_AUTO_INSTALL=0`), so a
  job downloads no tool it does not name; only `app-tests` installs one, and the Linux job disables
  the macOS-only XcodeGen outright. The residual is the one above: mise as its maintainers built it, with
  `contents: read` and no secrets in reach. The task scripts are repository files, reviewed like
  the workflow steps they replaced.
- **The runner image itself** is a large trust base (Xcode, Homebrew, preinstalled tooling) that we
  do not control. Accepted: the alternative is self-hosted runners, which trade this for a
  machine we would have to secure ourselves. Revisit if the project ever signs releases in CI.
- **`continue-on-error` on the AutoFill UI test** can hide a real failure in that one job.
  Accepted deliberately — simulator AutoFill automation is unreliable — and it is scoped to a
  single `-only-testing` invocation so it cannot mask the rest of the suite.

### 3.4 CodeQL default setup, and why it is exempt from SHA pinning

Code scanning runs as GitHub's **default setup** rather than a committed workflow: `state:
configured`, `languages: ["swift"]`, `query_suite: default`, `threat_model: remote`, weekly plus
every pull request. The check appears as `Analyze (swift)` and has no file in `.github/workflows/`,
which is worth stating plainly because "every CI step is in the tree" is otherwise true here.

This is a deliberate exception to §3.1. The analysis runs on a GitHub-generated workflow using a
GitHub-versioned query pack, so there is no `uses:` for the nightly audit to check and no SHA for
us to pin; the trust base is the same GitHub-owned surface the actions policy already admits. The
alternative — an advanced-setup `codeql.yml` with pinned `github/codeql-action` SHAs — buys a pin
on the action but not on the queries, and adds a workflow that can drift from the default suite.
Revisit if the repository ever needs custom queries or a pinned query pack version.

Two properties to keep in mind:

- **The check name tracks the language set.** `Analyze (swift)` becomes a different context if a
  second language is enabled, so a branch-protection list naming the old one stops gating without
  failing. Re-verify §9 of `08-repository-hardening.md` after any language change.
- **Default setup can be reconfigured from the web UI** by anyone with admin, including turning it
  off, and that leaves no diff in the repository. Treat `code-scanning/default-setup` as part of
  the settings surface to re-verify, not as something the tree protects.

## 4. Repository and release integrity (T5, T6)

**[planned]** — these require repository-admin settings, not code. The `gh` commands,
in an order that does not lock you out, are in `08-repository-hardening.md`:

- Branch protection on `main`: require `Required checks`, the `ci.yml` job that fails unless
  `package-tests` (both runners), `adversarial-tests`, `strict-memory-safety`, `lint` and both
  `app-tests` legs succeeded; require review; no force-push; no deletion.
- Require signed commits on `main`, so a push with stolen credentials is distinguishable.
- Restrict who may edit `.github/` (a CODEOWNERS entry), because a workflow edit is code execution.
- Tag protection on release tags, with two-person review.
- Release provenance: build from a tagged commit and attach an attestation
  (`actions/attest-build-provenance`, pinned), so a binary can be traced to a reviewed commit.
- Signing keys (T6): Developer ID and App Store Connect API keys live in a dedicated Environment
  with required reviewers, or better, in a hardware-backed keychain used only for release builds —
  never in a secret readable by a PR-triggered workflow.
- Secret scanning and push protection enabled.
- **[done]** CodeQL code scanning enabled via default setup (§3.4). Whether `Analyze (swift)`
  joins the required-check list is an open choice, recorded in `08-repository-hardening.md` §3.1.

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
