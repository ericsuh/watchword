# Watchword — Claude Code cloud sessions

Runbook for running Claude Code *cloud sessions* (claude.ai/code, the mobile and desktop apps,
`claude --cloud`, routines) against this repository with a working Swift toolchain. Verified against
the Claude Code docs on 2026-10-13; the scripts referenced here were exercised against this package
on macOS with Swift 6.4.

The short version: a cloud session gives you `swift build`, `swift test`, the adversarial suite, the
strict-memory-safety gate and `swift format` — four of the five `ci.yml` test jobs. It will never give
you Xcode. §1 is what that costs; §2–§4 is the setup.

## 1. What a cloud VM is, and what it can never be

Every Anthropic-hosted cloud session runs on a fresh VM: **Ubuntu 24.04, x86\_64, root, 4 vCPU,
16 GB RAM, 30 GB disk**, with the repository already cloned. Replacing that base image is not
supported; you add to it with a setup script. There is no macOS option, and self-hosted environments
(Team/Enterprise beta) run a Linux runner image you build, not a Mac.

So the boundary is not a configuration choice, it is the platform:

| Needs | Cloud session | Where it has to run instead |
| --- | --- | --- |
| `swift build`, `swift test`, both test frameworks | Yes, after §2 | — |
| `swift format lint`, `-strict-memory-safety` | Yes, after §2 | — |
| CryptoKit, Security.framework, CommonCrypto | **No** — Apple SDKs only | macOS: local session, CI, or a Mac run (§5) |
| LocalAuthentication, Keychain adapters | **No** | macOS: local session, CI, or a Mac run (§5) |
| `xcodebuild`, simulators, XCUITest, AutoFill extension tests | **No** | macOS: local session, CI, or a Mac run (§5) |
| The Xcode MCP server (`BuildProject`, `RunSomeTests`, …) | **No** — needs an Xcode GUI | Local macOS session |

Two consequences for how this repository is organised, both of which already pointed this way:

- The four milestone-0 modules import nothing but `Foundation`, `Testing` and `XCTest`, which is exactly
  why they build on Linux. Milestone 2 keeps the ports and policies portable too (`RecordStore`,
  `InMemoryRecordStore`, `UnlockPolicy`, `AutoLockPolicy`, `ItemCodec`); `SQLiteRecordStore`, `VaultSession` and
  `WatchwordPlatform` compile out, so their suites are absent rather than red on Linux. Milestone 3's
  `WatchwordSync` is portable in full — keys reach it through ports with fakes — so the sync engine, its N-device
  simulation and the adversarial suite "sync log" run in a cloud session. Its production keyring (`VaultSession`, so
  the suites "Vault session: sync between devices" and "sync with real keys") and `SQLiteSyncStateStore` compile out
  there, and its transports and `SyncConflictTests` need a Mac. That portability is a property worth keeping, not an accident — it is the
  same discipline that keeps `WatchwordMatching` from importing AuthenticationServices.
- The modules still to come that *do* touch Apple frameworks — `WatchwordCrypto`, `SecureMemory`, and
  any Keychain or LocalAuthentication adapter (`02-architecture.md` §15) — are not reviewable in a
  cloud session. A cloud session can draft them; it cannot compile or test them. Any PR touching
  crypto, envelope, sharing or `SecureMemory` still owes an adversarial test
  (`03-implementation-plan.md`, working agreements), and that test has to be run somewhere real: from a
  cloud session, that is a Mac run (§5) on the branch before the pull request.

**If you want Xcode driving an agent, use Remote Control, not a cloud session.** `claude
--remote-control` (or `/remote-control` in a running session) keeps Claude Code on your own Mac with
the full toolchain and the Xcode MCP server, and lets you steer it from claude.ai or the phone. It is
the only arrangement in which an agent works *interactively* with `xcodebuild` and a simulator. Cloud sessions and
Remote Control are different features that solve different halves of this; §5 is the batch middle ground.

## 2. Create the environment

Once, at claude.ai/code → the cloud icon → environment settings.

**Network access: `Custom`**, with **"Also include default list of common package managers"**
checked, plus:

```text
download.swift.org
*.swift.org
mise.jdx.dev
mise-versions.jdx.dev
```

Why each host is there, and which ones the default list already covers:

| Host | Used for | On the default list? |
| --- | --- | --- |
| `download.swift.org` | The swiftly installer and every Swift toolchain tarball and signature | **No** — must be added |
| `*.swift.org` (`www.swift.org`) | The Swift signing-key bundle | `swift.org` and `www.swift.org` are; the wildcard keeps future subdomains working |
| `mise.jdx.dev` | The pinned mise binary (first source tried) | **No** — must be added |
| `mise-versions.jdx.dev` | mise's version index; with exact pins it is rarely consulted, but without it mise falls back to the GitHub API, which the GitHub proxy can refuse (below) | **No** — must be added |
| `github.com`, `api.github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` | The mise fallback download and the release assets of the tools pinned in `mise.toml` | Yes |
| `archive.ubuntu.com`, `security.ubuntu.com`, `*.ubuntu.com` | apt dependencies, and the keyserver GPG may consult | Yes |

The default **Trusted** allowlist contains `swift.org` and `www.swift.org` but *not*
`download.swift.org`, and that host is where both the installer and every toolchain tarball live.
On Trusted alone, setup fails with network errors that look like a broken script.

GitHub traffic is different: it goes through a separate GitHub proxy whatever the allowlist says, and
that proxy serves API requests and source archives only for the repositories attached to the session
(it answers others with a 403 saying access "is not enabled for this session"). The Claude Code docs
do not say whether release downloads from *other* repositories (jdx/mise, cli/cli) are refused the same
way, so the setup script fetches mise from `mise.jdx.dev` first and treats GitHub as the fallback. If
`mise install` fails to fetch a tool, `/var/log/watchword-cloud-setup.log` says so; nothing in the
Swift build depends on it, and `gh` is pre-installed on the VM regardless.

**Setup script:** paste the contents of [`.github/scripts/cloud-setup.sh`](../.github/scripts/cloud-setup.sh).

The field is a free-text box in the web dialog, so the pasted copy is the one that runs. Keeping the
canonical copy in the repository is the point: this is shell that runs as **root on a VM holding this
checkout**, and it gets reviewed like `select-xcode.sh` rather than living only in a textarea
(`07-supply-chain.md` §3). Re-paste it whenever the script changes — nothing syncs it for you.

**Environment variables:**

| Variable | Value | Why |
| --- | --- | --- |
| `BASH_DEFAULT_TIMEOUT_MS` | `600000` | A cold `swift build` or a full `swift test` run exceeds the 2-minute default, and Claude then has to shepherd a backgrounded command. |
| `BASH_MAX_TIMEOUT_MS` | `1800000` | Headroom for `WATCHWORD_LONG_TESTS=1` runs. |
| `WATCHWORD_TEST_SEED` | *(optional)* | Pin the SplitMix64 `SeededGenerator` when reproducing a nightly failure. |
| `MISE_DISABLE_TOOLS` | `xcodegen` | XcodeGen publishes macOS builds only, so a `mise install` run inside a session would otherwise fail on it. The setup script sets this for its own run; this makes sessions match. |

Do not put secrets here: anyone who can use the environment can read the variables and the setup
script. Nothing in this repository needs a secret in a session — there are no dependencies to
authenticate to, and the GitHub proxy handles git.

## 3. What the setup script does

[`.github/scripts/cloud-setup.sh`](../.github/scripts/cloud-setup.sh), in order:

1. Locates the checkout by looking for a `Package.swift` naming `Watchword`, and reads the version
   pin from [`.swift-version`](../.swift-version) (`6.4.1`).
2. Installs the apt dependencies swift.org publishes for Ubuntu 24.04 **and** downloads the
   [swiftly](https://www.swift.org/install/linux/) installer concurrently — the five-minute budget
   below is the reason for the `&`/`wait`.
3. Installs the toolchain, trying two methods in order and judging both by whether a `swift` binary
   actually appears:
   - **The release tarball**, verified with GPG against the pinned Swift signing key
     `52BB7E3D…B47A981F` before anything is extracted. A toolchain is compile-time code execution on
     every later build, so it is verified rather than trusted (`07-supply-chain.md`, T3).
   - **swiftly**, as the second opinion if the URL layout has moved. Both subcommands pass
     `--assume-yes`: a setup script has no TTY, and `swiftly install` prompts.
4. Symlinks `swift`, `swiftc`, `swift-format` and `sourcekit-lsp` into `/usr/local/bin` and writes
   `/etc/profile.d/swift.sh`. The Bash tool does not run a login shell, so the symlinks are what
   actually make the toolchain reachable; only the drivers are linked, because symlinking the whole
   toolchain would shadow the system `clang` for everything else on the VM.
5. In parallel with steps 2–4, installs **mise** `2026.9.11` to `/usr/local/bin/mise` — downloaded from
   `mise.jdx.dev` (GitHub as fallback) and checked against GitHub's published SHA-256 before it is
   unpacked — then runs `mise trust && mise install` in the checkout, with `xcodegen` disabled
   (macOS-only). The tool versions themselves are pinned in [`mise.toml`](../mise.toml). The Bash tool
   does not run a login shell, so mise's shims are not on `PATH`: run pinned tools as
   `mise exec -- <tool>`. A failure here is logged as a warning and never blocks the Swift setup.
6. Warms `.build` with `swift build --build-tests`, bounded by `timeout 150`.
7. Verifies, and **announces its own failure**: everything is logged to
   `/var/log/watchword-cloud-setup.log`, and if no toolchain is present at the end the script appends
   a note to root's `CLAUDE.md`, which the session loads as user instructions. A setup script cannot
   fail a session start, so the alternative is an agent discovering `swift: command not found` much
   later with no idea why — which is precisely what the first version of this script produced.

Two hosting constraints it is written around, and which any edit must preserve:

- **Exit 0 or the session does not start.** Every non-essential step is guarded and the script ends
  with an unconditional `exit 0`. A failed install surfaces as a warning in the startup log and a
  session without `swift`, which is recoverable; a non-zero exit is not.
- **Finish in roughly five minutes or lose the cache.** On success Anthropic snapshots the filesystem
  and later sessions skip setup entirely, starting with the toolchain and `.build` already on disk.
  Overrun that window and every session re-runs the whole thing. The snapshot keeps *files*, not
  processes, and is rebuilt when you edit the script, change the allowlist, or after about seven days.

A setup script is the right home for all of this rather than a `SessionStart` hook: a hook would have
to live in a committed `.claude/settings.json`, and `07-supply-chain.md` §5 keeps agent configuration
out of the repository on purpose — a committed agent config is an instruction channel into every
contributor's tooling. The setup script sits in the environment, not the clone, and costs the
repository nothing. It is also cached, where a hook would re-run on every session. This package has no
dependencies to install per-session, so there is nothing a hook would buy.

## 4. Verify a session

Ask Claude to run:

```sh
.github/scripts/cloud-verify.sh          # build, both test frameworks, adversarial, memory safety, audits, lint
.github/scripts/cloud-verify.sh --quick  # build and test only
```

That script is the honest subset of `ci.yml`: the four jobs that need no Xcode. Each gate is the same
`mise run <task>` the matching `ci.yml` step calls — `build`, `test`, `test:adversarial`, then (without
`--quick`) `build:strict`, `audit:unsafe`, `audit:dependencies`, `audit:actions` and `lint` — so it
cannot drift from CI, and it inherits the tasks' own checks that both test frameworks and every
adversarial suite actually ran. It prints a pass/FAIL line per gate and a summary naming which runner
it used and the Xcode-only gates it did not run, so a green result is never mistaken for a green CI.

Two gates are skipped, with a warning and a `skipped:` line in the summary, rather than failed:
`lint` when the toolchain has no `swift format`, and `audit:dependencies` when `python3` is not on
`PATH` (it parses `swift package dump-package` output with it; Ubuntu 24.04 ships it). `build:strict`
runs: the session's Swift 6.4 supports `-strict-memory-safety`.

mise is installed best-effort (§3, step 5), so when `mise` is not on `PATH`, or `mise tasks info build`
fails (a mise older than `mise.toml`'s `min_version`, or a config it cannot parse), the script warns and
falls back to the plain `swift build` / `swift test` / `swift format lint` commands. That fallback
covers build, both test suites, the strict build and lint, but not the audits or the tasks'
did-it-actually-run checks; the summary header says `(swift)` instead of `(mise)` when it was used.
Fix mise (below) rather than settling for it.

If `swift` is missing, read the log first — it names the failure:

```sh
cat /var/log/watchword-cloud-setup.log
```

A successful run ends with `SUCCESS: swift is on PATH at …`. Note that a setup script that *fails*
still reports success to the session-start UI, because it is required to exit 0; "initialised without
error" is therefore not evidence that anything installed. Causes, in likelihood order:

1. **Network access is `Trusted`, not `Custom`.** The most common cause; `download.swift.org` is
   unreachable and both install methods fail. The log shows the probe failing.
2. **The setup script field is empty**, or holds a stale copy from before an edit. Nothing syncs the
   pasted copy to this file.
3. **A cached snapshot predates your change.** The setup script does not re-run when an idle VM is
   restored, so edits reach only new sessions. Recover in place by running the script from the
   checkout: `.github/scripts/cloud-setup.sh` (it is idempotent and safe to re-run as root).
4. **Setup overran five minutes**, so nothing was cached and every session repeats the whole install.

`mise` problems show up in the same log as `mise could not be installed` (both sources failed or the
checksum did not match), or `mise trust/install FAILED` followed by the tail of
`/tmp/watchword-cloud-setup/mise.log`. The usual cause is `mise.jdx.dev` or `mise-versions.jdx.dev`
missing from the allowlist (§2).

GPG needs `keyserver.ubuntu.com` to fetch the signing key; it is covered by the `*.ubuntu.com` entry
in the Trusted defaults, which is one more reason to keep **"Also include default list of common
package managers"** ticked in step 2.

Mind the compiler-version gap: a cloud session builds with Swift 6.4, while `ci.yml` also runs the
Xcode 16.4 leg on macOS 15. Something can compile cleanly in a cloud session and still fail that
older leg. Cloud-session green is a signal, not the gate — `ci.yml` is the gate.

## 5. Mac-only gates from a cloud session (`mac-run.yml`)

`.github/workflows/mac-run.yml` runs one gate on one branch on a GitHub macOS runner, and does nothing else. A cloud
session pushes its work to a branch, dispatches the workflow on that branch, and reads the job log, so CryptoKit code,
the Keychain adapters and the app's UI tests are compiled and run before anything reaches a pull request. It never
gates a merge; `ci.yml` does.

| Input | Values | Meaning |
| --- | --- | --- |
| `gate` | `test`, `test:adversarial`, `build`, `build:strict`, `lint`, `app:test`, `check` | The steps of the matching `ci.yml` job (below) |
| `filter` | empty, or one line not starting with `-` | `test`: a `swift test --filter` regex. `app:test` with `ios` or `macos`: an `-only-testing` identifier such as `WatchwordMacUITests/OnboardingAndUnlockTests`. Must match at least one test |
| `platform` | `macos`, `ios`, `all` | `app:test` only; `all` runs both schemes in one job (120-minute limit) and takes no filter |
| `xcode` | `27.0`, `16.4` | `xcode-27` (macOS 27), every gate; or `macos-15`, `ci.yml`'s oldest leg, `build` and `test` only |

Each gate runs what its `ci.yml` job runs: `test` is the package-tests job (`audit:dependencies`, `build -v`,
`test --coverage`), `build:strict` is the strict-memory-safety job (`build:strict --require`, then `audit:unsafe`),
and `build`, `test:adversarial`, `lint` and `app:test` are their own job's step. The exceptions: a filtered `test`
runs only the matching tests, without coverage or the audit and build steps; `app:test` omits the iOS leg's
best-effort AutoFill step; and `check` has no `ci.yml` job, being `mise.toml`'s local aggregate. A request that
cannot mean what it says is refused before anything builds: a filter that starts with `-` or is given to a gate
other than `test` and `app:test`, `app:test all` with a filter, and on Xcode 16.4 any gate but `build` and `test`
(16.4 cannot build `-strict-memory-safety` at all, and `ci.yml` runs everything else on 27.0). A filtered run that
executed no test fails too, where `swift test` and `xcodebuild` would report it as passing.

The step is `mise run ci:gate <gate> --platform=<platform> --xcode=<xcode> --filter=<filter>`, which reproduces
locally on a Mac. Each value is written `--flag=value`, because mise reads a separate argument that starts with `-` as
an option: `--filter --help` would print the task's help and pass. A failed run ends its log with a failure summary
(the compiler errors, failing tests and xcodebuild's "Failing tests" list), because a tool reading the log may only
fetch its tail; the full logs, `coverage.txt` and any `.xcresult` bundles are the run's `mac-run-<run id>` artifact.
Runs are named after their gate, platform (for `app:test`), filter, branch and Xcode, and repeats of one request share
a concurrency group: one runs, at most one waits, and a newer dispatch replaces the waiting one. Different requests
never cancel one another.

Starting a run:

- From a session with the GitHub tools: dispatch `mac-run.yml` with `ref` set to the branch and the inputs above,
  then fetch the run's job log once it completes.
- From a terminal: `gh workflow run mac-run.yml --ref <branch> -f gate=app:test -f platform=macos -f
  filter=WatchwordMacUITests/OnboardingAndUnlockTests`, then `gh run watch` and `gh run view --log-failed`.

What it is not:

- **Interactive.** Each run is a fresh runner: minutes per round trip, no debugger, no simulator on screen, no Xcode
  MCP server. For pairing with Xcode, use Remote Control on a Mac (§1).
- **Free on a private repository.** macOS runner minutes count ten times against the plan's included minutes.
- **Available before it is on `main`.** GitHub dispatches only workflows on the default branch, though it runs them
  against any branch, using the workflow file as it is on that branch: a branch cut before `mac-run.yml` merged has
  none, and needs a rebase onto `main` before it can be dispatched.
- **A security boundary.** A dispatch runs `mac-run.yml` and `ci:gate` as they are on the dispatched branch, and
  anyone who can dispatch can push an edited copy of either. The controls are the repository's: only an account with
  write access can dispatch, the workflow holds no secrets, and its token is read-only (`contents: read`, and read is
  the repository default, `08-repository-hardening.md` §1). What the workflow and `ci:gate` add is narrower: inputs
  reach the shell only through `env:`, and `ci:gate`'s refusals stop a mistyped or prompt-influenced request from
  running something other than what was meant, or from passing without testing anything (`07-supply-chain.md` §3.2).

## 6. Related

- [`mise.toml`](../mise.toml) and [`mise-tasks/`](../mise-tasks) — the gates `cloud-verify.sh` runs,
  shared with `ci.yml`; edit a gate there, not in the script.
- `07-supply-chain.md` §3 (operational shell lives in the repository, not in third-party actions),
  §5 (why `.claude/` is not committed).
- `02-architecture.md` §15 — which future modules are Apple-framework-bound, and therefore outside
  what a cloud session can verify.
- `04-test-plan.md` — the requirement-to-test map a cloud session can only partly exercise.
- `03-implementation-plan.md`, "Where each milestone is built" — this boundary applied milestone by
  milestone: which remaining work a remote session can finish and verify, and which needs a Mac.
