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

## 2. Application code: one dependency, enforced

The strongest available position is to have nothing to compromise. The package has one dependency, apple/swift-crypto,
so the cryptographic core has one code path on Apple platforms and Linux (ADR 0006); no binary targets and no build
plugins; and that is checked rather than merely intended. swift-crypto's `Crypto` module ships in the apps: on Apple
platforms it re-exports CryptoKit and compiles no cryptography, but a malicious release could change that, so T1 applies
to it in full and each bump is reviewed accordingly. `CryptoExtras`, which compiles BoringSSL, is linked on Linux only.

- **[enforced]** `.github/scripts/assert-no-dependencies.sh` fails the build if `Package.swift`
  gains a `.binaryTarget`, a `.plugin(`, or `unsafeFlags`; if it depends on any package but swift-crypto at its exact
  version, or on any of its products but `Crypto` and `CryptoExtras`, or links `CryptoExtras` on a platform other
  than Linux; or if `Package.resolved` pins anything but the two commits the script names. Adding or bumping a
  dependency therefore requires editing the guard in the same pull request, which is visible in review. It also checks
  the resolved manifest (`swift package dump-package`):
  only plain Swift source and test targets, each at its conventional path (a custom `path:` could
  compile files no other check scans), no experimental features or C++ interop, the Swift 6
  language mode for the package and no target put back into Swift 5, and the test-only
  `WatchwordTestSupport` (seeded and deliberately broken RNGs) linked only into test targets.
  That dump is what the manifest evaluates to on the machine running the check, and a manifest is
  a program, so the script also holds it to being one value everywhere: it may import
  `PackageDescription` and nothing else, on a line of its own, may contain no block comment, and
  may not name `#if`, `Context`, `ProcessInfo`, `CommandLine`, `getenv`, `#file`, `random`,
  `shuffle`, `hashValue`, `Hasher`, a clock, `MemoryLayout`, `NSHomeDirectory` or `FileManager`.
  Without that, a dependency added only where `GITHUB_ACTIONS` is unset shows CI a clean dump
  (review finding Z104). The words are a tripwire, not a proof that a Swift program is constant,
  and a list of them cannot be complete: the review of the first list found a dozen ways round it
  (Z111), and the order of a `Set` is one that needs no word. **[open]** The check that does not
  depend on a list is to dump the manifest on Linux and on macOS, under more than one
  environment, and compare. Until that exists, §2.1's review of `Package.swift` is the control.
- **[enforced; not yet run on a Mac]** The pin reaches the apps only through a second check. The
  committed `Package.resolved` governs `swift build` and `swift test`, where this package is the
  root. The apps are built by xcodebuild from a generated project that names the package by path,
  and Xcode resolves a local package's dependencies for itself: by the `4.5.2` tag, which can be
  moved, and for swift-asn1 by the newest release in swift-crypto's range. It records the result
  in no file this repository can read: the first Mac run showed that Xcode writes no
  `Package.resolved` inside the generated project for a local package whose dependencies are
  remote, and the first version of this check, which read that file, failed closed on every app
  job. So the evidence is the sources themselves. Every `xcodebuild` call in `app:build`,
  `app:test`, `app:release` and `app:test-keychain` (and in `pick-simulator.sh`) is given one
  `-clonedSourcePackagesDirPath`, `.build/app-source-packages`, which makes each dependency a git
  working copy under `checkouts/` there. The tasks have Xcode resolve first
  (`xcodebuild -resolvePackageDependencies`) and stop, before anything is compiled, unless
  `assert-no-dependencies.sh --checkouts` finds exactly the allowed packages, each a working copy
  of its own with `HEAD` at the commit the script names and no file changed; they check again
  after the build, and no checkouts at all is a failure (`mise-tasks/app/packages.sh`, review
  finding Z102). A failure prints what is in the directory, each checkout's `HEAD` and what Xcode
  recorded in `workspace-state.json`, because nothing but a CI run can look. Until this existed,
  a re-pointed tag left every package gate green and was compiled into the next app build, which
  is the artefact T1 is about. `Tests/ScriptTests/test_app_tasks.py` drives the tasks with a
  stand-in `xcodebuild` that checks packages out with real git, and fails if any call lacks the
  argument: a call without it would compile from Xcode's own DerivedData, which nothing reads.
  That Xcode puts clean working copies in that directory is its documented behaviour and has not
  been seen: this version is unproven until a Mac run passes, and fails closed until then.
  Resolving live and judging the result has a consequence worth knowing before it happens. On a
  fresh runner Xcode takes the newest swift-asn1 in swift-crypto's range, so the day upstream
  releases one, `app-tests` and `release-build` turn red on every pull request, and stay red
  until `ALLOWED_PINS` and the root `Package.resolved` are bumped to it. That is fail-closed, on a
  day upstream chooses; it is the expected trigger for the bump (read the diff between the two
  commits, as for an action pin), not a fault to route round. **[open]** Handing Xcode the
  committed pins, so that it resolves to them rather than to the newest, is to be tried once a
  Mac run shows what it accepts.
- **[enforced]** `Apps/project.yml` can add everything the manifest is forbidden: a remote
  package, shell at generation or build time, prebuilt frameworks, native sources, settings that
  switch off what the compiler enforces. `assert-no-dependencies.sh` hands it to
  `.github/scripts/yaml-audit.py`, which parses it and holds it to an allowlist: the top-level
  keys, option keys, target types, per-target keys, dependency kinds, scheme keys and build
  settings it may contain are each named there, the one package is the repository's own by path,
  every source path stays inside `Apps/` except the one named Keychain test file, and
  `SWIFT_STRICT_MEMORY_SAFETY`, `SWIFT_TREAT_WARNINGS_AS_ERRORS`, `ENABLE_USER_SCRIPT_SANDBOXING`,
  `SWIFT_STRICT_CONCURRENCY` and the Swift 6 language version must be *present* with their values,
  since a setting that is merely deleted is off. No settings per configuration, so nothing can
  define `DEBUG` for Release. It was four `grep`s until review finding Z103, which a flow-style
  package, a quoted key or value, a key they did not list, a dependency written as a list entry
  or a deleted line all passed. A linked product must be `SecureMemory` or a `Watchword` module,
  never swift-crypto's own (Z113), and `Apps/` without its spec fails rather than skipping the
  check (Z118). A tripwire still, with review as the backstop: it reads the spec,
  not the project XcodeGen generates from it, and a new XcodeGen key is refused until it is added
  to the list in the same pull request. Adding a setting or target type is therefore an edit to
  that list, visible in review, like a dependency.
- **[enforced]** `.github/scripts/assert-unsafe-confined.sh` (strict-memory-safety job) fails on
  unsafe constructs, `@unchecked`, or underscored attributes outside `Sources/SecureMemory`, on
  hand-bound foreign symbols (`@_silgen_name`, `@_cdecl`, `@_extern`) anywhere, and on symlinks or
  non-Swift files under `Sources/`. It is a tripwire for a malicious or careless contribution
  (milestone-1 review finding R1), with review as the backstop.
- **[enforced]** The libFuzzer harness is a package of its own, `Fuzz/`, which depends on this repository by
  path; the root `Package.swift` does not mention it, so nothing in it can be linked into an app. libFuzzer
  calls a C function with a pointer and a length, which is the one thing outside `SecureMemory` that must name
  a pointer type; keeping it outside the shipped package keeps "no unsafe code outside `SecureMemory`" true of
  everything that ships. Both scripts cover the harness: `assert-no-dependencies.sh` fails if the root manifest
  refers to `Fuzz/`, if `Fuzz/Package.swift` has any dependency but the repository itself, any product but the
  `WatchwordFuzz` executable, a custom target path, a binary target, a plugin or `unsafeFlags`, or if
  `Fuzz/Package.resolved` pins anything but the commits the root's does; `assert-unsafe-confined.sh` fails on
  non-Swift files under `Fuzz/Sources`, on unsafe constructs or underscored attributes anywhere in `Fuzz/` but
  `LibFuzzerEntry.swift`, and on any attribute there but `@_cdecl("LLVMFuzzerTestOneInput")`. The harness is
  built with `-sanitize=fuzzer` from the command line (`mise run fuzz`), never from a manifest. Its seed
  corpus (`Fuzz/Corpus/`) is data that only the fuzzer reads.
- **[convention]** Any new dependency requires an ADR covering: why no first-party API suffices,
  the maintenance and audit story, and the pin-and-vendor plan. ADR 0001 already forbids
  third-party cryptography outright.
- **[enforced]** Shipped cryptography comes only from CryptoKit, Security.framework, and CommonCrypto
  (reviewed as part of the dependency check: another crypto dependency cannot be added, or BoringSSL linked into an
  Apple build through `CryptoExtras`, without tripping it).

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

**As built (milestone 6).** The estimator is written in `WatchwordHygiene` and its data is embedded as Swift
source, one multi-line string literal per list, so there is still no non-Swift file under `Sources/` and
nothing to load at run time. Each file's header names its source, the commit it was taken at and its licence:

| File | Data | Source and licence |
| --- | --- | --- |
| `WordListCommonPasswords.swift` | 10,000 common passwords | zxcvbn `data/passwords.txt`, commit `67c4ece9`, MIT |
| `WordListEnglish.swift` | 5,000 English words | zxcvbn `data/english_wikipedia.txt`, same commit, MIT |
| `WordListNames.swift` | 500 surnames, 300 + 300 given names | zxcvbn, same commit, MIT (1990 US census) |
| `WordListEFF.swift` | EFF large wordlist, 7,776 words | EFF, CC BY 3.0 US; text from a GitHub mirror (ulif/diceware `b3138e95`, SHA-256 `addd3553…b903e`), compared word for word with a second (redacted/XKCD-password-generator `b9813612`) because eff.org was unreachable; verified against EFF's own `eff_large_wordlist.txt` on 2026-11-16 (same SHA-256, all 7,776 words equal, in order) |
| `SiteDirectoryData.swift` | about 240 domains: TOTP and passkey support | 2factorauth/twofactorauth `9b39477c` (MIT) and 2factorauth/passkeys `ede77017` (CC BY 4.0), retrieved 2026-11-15 |

- **[enforced]** `StrengthEstimatorTests` asserts each list's exact count, that the EFF list has 7,776 unique
  words in its published order from `abacus` to `zoom`, and that every entry is lower-case and 3 to 32
  characters. That is the uniqueness-and-count test asked for above, for the estimator's copy.
- **[convention]** The MIT and Creative Commons notices travel in the file headers; an app release must
  reproduce them in its acknowledgements.
- **[open]** The EFF text has not been compared with EFF's own file. It is used here to *estimate* (where an
  altered list could only misjudge a passphrase), not to *generate*; before the generator draws from it, verify
  it against eff.org and keep a single copy.
- **[decision]** These lists do not refresh. A stale password list only makes the estimator a little generous;
  a stale site directory makes a suggestion late or wrong, which is why `EmbeddedSiteDirectory` is opt-in and
  small. Adopting the full, regularly updated 2fa.directory dataset would be a standing data dependency of the
  same kind as the full Public Suffix List and needs the same ADR.
- The only code that makes network requests for this feature builds them from two constant hosts
  (`HygieneHost`); N5's "only network destinations" is checked by the adversarial suite on the request values.

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

- **[enforced]** `mise run audit:actions` fails if any `uses:` in any workflow (or in a composite
  action kept under `.github/`) is not a 40-hex SHA. It runs on every pull request, in `ci.yml`'s
  `lint` job, which `Required checks` needs, and again in the `action-pinning-audit` job of
  `security-nightly.yml`. It ran nightly only until review finding Z104, so an unpinned action
  merged green and was reported up to a day later. It reads the workflows as YAML
  (`.github/scripts/yaml-audit.py`), because a `grep` for `uses:` reads one spelling and GitHub
  reads several: a quoted or escaped key, a flow mapping, a space before the colon and a value on
  the line after its key all passed the grep. The reader takes the subset of YAML the workflows
  are written in and refuses everything else, so a spelling it does not understand fails the
  audit instead of passing unread; where PyYAML is installed, the script tests compare its
  reading of every workflow with PyYAML's. The residual is the reader itself: it is this
  repository's code, a few hundred lines, and a workflow it accepts but GitHub reads differently
  would be a hole. That is why it refuses rather than interprets.
- **[enforced]** No local action. A `uses:` whose value starts with `.` is a path in the
  checkout, and GitHub reads all of it as that path, so `./ci/build@<40 hex>` is not pinned by
  ending like a commit: the composite action's manifest there is the pull request's own file,
  anywhere in the tree, and its `uses:` lines are whatever it says. The audit refuses every such
  value, pinned-looking or not (review finding Z109: the first version of the parsed audit
  passed that one). The repository has no local action and no reusable workflow of its own, so
  this costs nothing today; if one is ever wanted, the audit has to learn to follow the path
  and read the manifest it finds there first.
- **[done]** `maxim-lobanov/setup-xcode` was removed entirely and replaced by
  `.github/scripts/select-xcode.sh`. It was the only third-party action in the project, it ran in
  every job, and it did work that is a few lines of `xcode-select`. Fewer actions is a better
  control than a better-pinned action.
- **[convention]** bumping a pin means reading the diff between the old and new SHA, not just
  trusting the tag. Dependabot/Renovate may propose bumps; they are reviewed, not auto-merged.

### 3.2 Token and secret exposure (T5)

- **[done]** `permissions: contents: read` at workflow level and repeated per job. No job needs
  write access, except the Claude job in `claude-pr.yml` and the comment job in `screenshots.yml`
  (both below), each `pull-requests: write` and nothing more.
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
  - **Admins only, on the trigger where this file decides.** A separate `authorize` job, read-only
    and without secrets, asks the API for the sender's permission; the Claude job runs only on
    `admin`. Bots never pass. The action also requires write access and a human actor. Fork pull
    requests are skipped on the `pull_request` and review triggers, which get no secrets. This is a
    rule of the default branch's copy of the file, so it binds `issue_comment`, which always runs
    that copy, and nothing else: on `pull_request`, `pull_request_review` and
    `pull_request_review_comment` GitHub runs the pull request's own copy, in which `authorize` is
    whatever the branch says, and a same-repository branch can add any other workflow that names
    `environment: staging`. Against an account that can push (a later collaborator, a stolen
    write-scoped token, a prompt-influenced session acting as the owner, for whom `authorize`
    passes unedited), "admin only" therefore protects nothing. The next control does.
  - **One job sees the secret, and a person releases it.** The Claude job runs in the `staging`
    GitHub Environment, and the key is an environment secret there, never a repository secret, so
    the `authorize` job and every workflow that does not name the environment cannot read it. A
    job that does name it waits for the environment's **required reviewer**, and runs only from a
    ref its deployment-branch rule admits (the default branch and pull-request merge refs: the
    rule cannot be narrower while the pull-request triggers exist). That approval is what stands
    between write access and the secret. Whoever approves checks which workflow is asking and
    whether the pull request touches `.github/`, because an approval on a pull-request trigger
    releases the secret to the pull request's own workflow files. The environment and its rules
    are repository settings, invisible in the tree: `08-repository-hardening.md` §1.2 creates
    them and its §9 prints them. Until that has been run and checked, this control is unverified.
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
  someone else, whose text can try to steer what Claude posts. The tool allowlist bounds what
  Claude can *change* to comments on that one pull request. It does not bound what a comment can
  *say*, and an earlier version of this section claimed it did. **[open]** The action runs Claude
  Code with the job's secrets in its process environment (`ANTHROPIC_API_KEY` or
  `CLAUDE_CODE_OAUTH_TOKEN`, and the job's `pull-requests: write` token; read in the action's
  `action.yml` at the pinned commit). The allowlist grants `Read`, `Glob` and `Grep` with no path
  limit, which reaches `/proc/self/environ`; `Bash(gh pr comment <n>:*)` is a prefix rule that
  also admits `--body-file <path>`, `--edit-last` and `--delete-last`; and the thread reply's
  `gh api` rule admits `--input <file>` and `-F body=@<file>`. A shell variable in a `--body`
  argument is expanded from the same environment. So a review that the pull request's text
  steered could post the Anthropic credential and the job token in a comment on a public
  repository, where the author of that pull request reads them. The token dies with the job (30
  minutes at most) and cannot approve or push; the Anthropic credential does not expire by
  itself. It needs an admin to mention Claude on a hostile pull request and the injection to
  land, which is why it is recorded as medium (review finding Z100) and not fixed by assertion.

  What would narrow it, none of it applied, because none of it can be run from this repository
  and a wrong guess breaks every review without a red check:

  - `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: "1"` in the Claude job's `env:`. The pinned `action.yml`
    passes it to the CLI, and the action's `docs/security.md` describes it as a best-effort scrub
    of Anthropic, cloud and GitHub Actions secrets from the environment of the commands Claude
    runs. Whether `gh` keeps the token it needs under the scrub is the thing to test.
  - Deny rules beside the allowlist (`--disallowedTools`, which the action documents): reading
    under `/proc`, the runner's temporary directory and the home directory, and the file-taking
    and comment-rewriting flags of `gh pr comment` and `gh api`. Rules that constrain a command's
    arguments are pattern matches on the command line and are fragile; they reduce the routes,
    they do not close them. The scrub does not cover `Read` of `/proc/self/environ`, which is the
    CLI's own process, so the deny rule for it is needed as well.
  - Refusing fork pull requests on `issue_comment`, in `authorize`. That removes the outside
    author from the path entirely and also removes the use the trigger exists for, so it is the
    owner's choice.

  The test is the one the finding gives: in a scratch repository with this workflow and a dummy
  secret, an admin asks Claude outright to run `gh pr comment <n> --body-file /proc/self/environ`,
  `gh pr comment <n> --body "$ANTHROPIC_API_KEY"`, `gh api … -F body=@/proc/self/environ` and to
  `Read` `/proc/self/environ`; with the changes in place none posts the dummy, and an ordinary
  review still does its work. Until then the stated bound is this paragraph, and the Anthropic
  credential in `staging` should be one that can be revoked without ceremony.
- **[done]** `screenshots.yml` captures the screenshot tour's pictures (`04-test-plan.md` §5.1) for a pull request
  and attaches them to it. It holds no secret. It runs on the `screenshots` label, on each push while the pull
  request carries the label, on a push to a same-repository branch whose head commit message has a line that is
  exactly `[screenshots]`, and on dispatch. Its controls:
  - **Three jobs, split by what they may touch.** `decide` reads the event and, for the commit marker, one commit
    message through the API: `contents: read`, no checkout. `capture` checks out and runs the pull request's code,
    so it gets exactly what `ci.yml`'s `app-tests` job gets: `contents: read`, no secrets,
    `persist-credentials: false`. `comment` is the only job with `pull-requests: write`; its one other permission
    is `actions: read`, and it has not even `contents: read`.
  - **The job that can write runs nothing from the pull request, and takes one thing from the job that did.**
    `comment` has no checkout step and downloads no artifact. All it receives from `capture` is, per platform, a
    list of screen names as a job output. A list is used only if every name is what `Screens.capture` can produce
    (`NN-` and at most 40 characters of lower-case words joined by single hyphens) and there are at most 99;
    otherwise that platform's line reads "the capture failed or is incomplete". Every other word of the comment is
    the job's own. A build script, a test, or a tool the build fetched can therefore do nothing with the write
    token, and the most it can put into a comment posted in the repository's name is a short list of such names.
  - **The links are the job's own finding, not the build's report.** `comment` does not take artifact ids from
    `capture`. It lists this run's artifacts through the API and links the one named `screenshots-<set>` and the
    one named `watchword-screens-<set>.png`, so a link cannot be pointed at some other run's or some other file.
  - **The one link that opens in the browser is to a picture.** An artifact uploaded unzipped
    (`actions/upload-artifact`'s `archive: false`, read from the action's `action.yml` at the pinned commit) is
    served inline from GitHub's artifact storage, with the content type its uploader declared: the action derives
    it from the file's extension (read in `@actions/artifact` 6.3.1, `getMimeType`), but the declaration is the
    client's, and the client is the job that ran the pull request's code. An HTML contact sheet there would be a
    page of the build's making, script included, one click behind a link the repository's bot posted. So the file
    uploaded unzipped is a PNG (every screen in one picture), and before linking it `comment` asks the API where
    the artifact's download is and reads the type out of the address (`rsct`, which fixes the `Content-Type` of
    the response) without following it: anything but `image/png` is not linked. No browser renders `image/png` as
    a page. The check reads an address format GitHub does not document; if it changes, the sheet link disappears
    from the comment (with a warning in the job log) rather than being posted unchecked. The HTML sheet,
    `index.html`, is inside the zipped set, which downloads as a file.
  - **The comment says what its links are.** It tells the reader that both are files the pull request's build
    produced, served from GitHub's artifact storage and not from github.com, and that nothing behind them should
    ever ask for a password. (It used to say "sign-in needed", which is the wrong expectation to set beside a
    link to a build's output.)
  - **One comment, and only its own.** The comment is updated in place. `github-actions[bot]` is not an identity
    this workflow has to itself: every workflow that comments with the default token is that author, and
    `claude-pr.yml`'s reviews, whose text is model output that a pull request can try to steer, are among them. So
    the comment this job overwrites must be by that author *and* begin with the whole header this job writes: the
    hidden marker, the `### Screenshots` heading, and a first line that names a 40-hex commit and links a run of
    this repository. A comment that merely begins with the marker is left alone, whoever wrote it. If two
    comments pass, the job fails without writing rather than choose. `claude-pr.yml`'s prompt also tells Claude
    never to begin a comment with an HTML comment or a heading copied from another comment. Comment jobs for one
    pull request run one at a time, so two runs cannot each create one.
  - **Who can start it.** Adding a label needs triage access; a dispatch needs write access. The commit marker is
    honoured only when the pull request's branch is in this repository, where pushing needs write access, so it
    gives nobody a capture they could not already start: a fork's author can write the marker in every commit and
    get nothing (the message is not even fetched), and a fork's pull request is captured only when someone with
    triage access labels it. The marker must be a line of its own, so a commit that mentions it in prose, quotes
    it, or reverts one that had it starts nothing. On a fork's pull request GitHub makes the token read-only
    whatever the file says, so the capture and its artifacts are produced and `comment` is skipped. A dispatch may
    name a pull request to attach to only if that pull request is open, in this repository, and its head is the
    dispatched commit.
  - **Event text reaches the shell only through `env:`**, and the commit message is fetched as data and searched
    with a fixed-string, whole-line `grep`, never interpolated.
  - **Inline shell, in two jobs only, and tested.** `decide` and `comment` check nothing out, so they cannot run a
    mise task; their `gh api` calls are in the workflow file, as in `claude-pr.yml`'s `authorize` job. Everything
    that touches the code is `mise run app:screenshots`. `mise run test:scripts`, in `ci.yml`'s `lint` job, reads
    those two `run:` blocks out of the file and runs them against a stand-in `gh` and `curl`
    (`Tests/ScriptTests`): the cases above are its tests.
  - **Pictures are linked, not embedded.** GitHub does not serve artifact files inside a comment. The ways round
    that (committing images to a branch, or an image host) need `contents: write` or a third party, and neither
    is acceptable here.
  - **A set is complete or it is not a set.** A capture that failed, or whose pictures are missing, blank or in
    the wrong appearance, uploads no `screenshots-<set>` artifact and no sheet, and announces no names; what it
    did capture is in the `screenshots-failed-<platform>` artifact with the result bundle, in a directory and
    under an index that say it is incomplete (`04-test-plan.md` §5.1).
  - **Not a gate.** It is not in `ci.yml`'s `required` job and must not be named in branch protection
    (`08-repository-hardening.md` §5): a workflow that most pull requests skip would otherwise report as passing
    without having run, or block the ones it never ran on.

  **No comment command, deliberately.** A `/screenshots` line in a pull-request comment arrives as `issue_comment`,
  which always runs the default branch's copy of the workflow in the base repository's context. Building the pull
  request's head there is the `pull_request_target` pattern this repository rules out: nothing but this file would
  stand between that code and the repository's token, caches and environment, where on `pull_request` GitHub itself
  withholds them from a fork. The safe variant is a relay, in which the comment job runs no pull-request code and
  only dispatches this workflow on the pull request's branch; that needs a second write-scoped job (`actions:
  write`), works for same-repository branches only, and cannot be exercised before it is on the default branch.
  The label does the same for anyone with triage access, and a dispatch for anyone with write access, so the
  relay was not worth a second token. Having the comment job add the label would not work either: events caused by
  the workflow token start no workflows.

  The residual risks. The artifacts and the job summary are whatever the pull request's code produced: they are
  labelled with the commit, and a reviewer reads them as that code's output, as with a test log. The contact
  sheet is a picture, but a picture of the build's choosing, and the zip holds an `index.html` that a hostile
  build can replace with any page, so a downloaded set is opened as one would open any file a stranger's build
  produced. The header check does not make the sticky comment unforgeable: a review that a pull request steered
  into reproducing the whole header would be overwritten in its place (or, beside the real one, would stop the
  job), which is why the prompt forbids it and why this is written down. And a same-repository pull request can
  edit this file, as it can any workflow, so the split protects the write token from the build, not from someone
  who already has write access.
- **[convention]** the CloudKit integration tests (milestone 3) need an iCloud container and
  therefore secrets. They must stay `workflow_dispatch`-only, in a GitHub Environment with required
  reviewers, and must never be reachable from a `pull_request` trigger.
- **[convention]** no secret is ever `echo`ed; artifact uploads are limited to test logs,
  `.xcresult` bundles and the screenshot tour's pictures, which contain only synthetic fixture data
  (the tour refuses to capture anything but a `--uitest` launch).

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
  the two scripts ever disagree, on every pull request since review finding Z104: it used to run in
  no workflow, only in a local `mise run audit`). The same script writes mise's CI settings to `$GITHUB_ENV`, so
  every job gets them from one place. Auto-install is off (`MISE_TASK_RUN_AUTO_INSTALL=0`), so a
  job downloads no tool it does not name; only `app-tests` installs one, and the Linux job disables
  the macOS-only XcodeGen outright. The residual is the one above: mise as its maintainers built it, with
  `contents: read` and no secrets in reach. The task scripts are repository files, reviewed like
  the workflow steps they replaced.
- **The cloud session's toolchain.** **[done]** `cloud-setup.sh` installs Swift as root on the VM that holds a cloud
  session's checkout. The release tarball is verified against a pinned signing key, and a tarball that does not
  verify now ends the attempt. It used to be followed by a second installer, swiftly, downloaded from an
  unversioned URL with no checksum and run as root, so the one check could be failed on purpose to reach the path
  without one (review finding Z106). swiftly is now fetched and run only when the tarball could not be downloaded at
  all *and* `WATCHWORD_ALLOW_UNVERIFIED_SWIFTLY=1` is exported above the pasted script (`09-cloud-sessions.md` §3;
  a setup script is not given the environment's saved variables, Z114). A verified tarball must also report the
  release that was asked for, since the key has signed every release (Z115). **[open]** swiftly itself is
  still unpinned: no published checksum for it is recorded in this repository, and pinning one that was not checked
  against the publisher's would be worse than the opt-in.
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

**Alert dispositions.** An alert closed without a code change is recorded here, with its reason,
so that dismissing it in the web UI is never the only record:

| Alert | Where | Disposition |
| --- | --- | --- |
| Use of a broken or weak cryptographic hashing algorithm (SHA-1) | `PasswordDigest.init(password:)`, `Sources/WatchwordHygiene/PasswordDigest.swift` | **Accepted, won't fix** (owner decision, 2026-11-16). The Have I Been Pwned range API is defined over SHA-1, so no other hash can be asked about, and the hash protects nothing here: only the first five hexadecimal characters (twenty bits) leave the device, and the rest is compared locally (`02-architecture.md` §13.2). Nothing else in the package uses SHA-1 except HMAC-SHA-1 for TOTP, which RFC 6238 defines. Dismiss the alert as "won't fix" with a link to this row. |

## 4. Repository and release integrity (T5, T6)

**[planned]** — these require repository-admin settings, not code. The `gh` commands,
in an order that does not lock you out, are in `08-repository-hardening.md`:

- Branch protection on `main`: require `Required checks`, the `ci.yml` job that fails unless
  `package-tests` (both runners), `adversarial-tests`, `strict-memory-safety`, `lint` (which also
  runs the script tests and the action-pinning and mise-pin audits), every `app-tests` leg and
  both `release-build` legs succeeded; require review; no force-push; no deletion.
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
