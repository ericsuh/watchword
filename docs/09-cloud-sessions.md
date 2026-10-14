# Watchword — Claude Code cloud sessions

Runbook for running Claude Code *cloud sessions* (claude.ai/code, the mobile and desktop apps,
`claude --cloud`, routines) against this repository with a working Swift toolchain. Verified against
the Claude Code docs on 2026-10-13; the scripts referenced here were exercised against this package
on macOS with Swift 6.4.

The short version: a cloud session gives you `swift build`, `swift test`, the adversarial suite, the
strict-memory-safety gate and `swift format` — four of the five `ci.yml` jobs. It will never give
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
| CryptoKit, Security.framework, CommonCrypto | **No** — Apple SDKs only | macOS: local session or CI |
| LocalAuthentication, Keychain adapters | **No** | macOS: local session or CI |
| `xcodebuild`, simulators, XCUITest, AutoFill extension tests | **No** | macOS: local session or CI |
| The Xcode MCP server (`BuildProject`, `RunSomeTests`, …) | **No** — needs an Xcode GUI | Local macOS session |

Two consequences for how this repository is organised, both of which already pointed this way:

- The current four modules import nothing but `Foundation`, `Testing` and `XCTest`, which is exactly
  why they build on Linux. That portability is a property worth keeping, not an accident — it is the
  same discipline that keeps `WatchwordMatching` from importing AuthenticationServices.
- The modules still to come that *do* touch Apple frameworks — `WatchwordCrypto`, `SecureMemory`, and
  any Keychain or LocalAuthentication adapter (`02-architecture.md` §15) — are not reviewable in a
  cloud session. A cloud session can draft them; it cannot compile or test them. Any PR touching
  crypto, envelope, sharing or `SecureMemory` still owes an adversarial test
  (`03-implementation-plan.md`, working agreements), and that test has to be run somewhere real.

**If you want Xcode driving an agent, use Remote Control, not a cloud session.** `claude
--remote-control` (or `/remote-control` in a running session) keeps Claude Code on your own Mac with
the full toolchain and the Xcode MCP server, and lets you steer it from claude.ai or the phone. It is
the only arrangement in which an agent reaches `xcodebuild` and a simulator. Cloud sessions and
Remote Control are different features that solve different halves of this.

## 2. Create the environment

Once, at claude.ai/code → the cloud icon → environment settings.

**Network access: `Custom`**, with **"Also include default list of common package managers"**
checked, plus:

```text
download.swift.org
*.swift.org
```

The default **Trusted** allowlist contains `swift.org` and `www.swift.org` but *not*
`download.swift.org`, and that host is where both the installer and every toolchain tarball live.
On Trusted alone, setup fails with network errors that look like a broken script. GitHub traffic goes
through a separate proxy and needs no entry.

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

Do not put secrets here: anyone who can use the environment can read the variables and the setup
script. Nothing in this repository needs a secret in a session — there are no dependencies to
authenticate to, and the GitHub proxy handles git.

## 3. What the setup script does

[`.github/scripts/cloud-setup.sh`](../.github/scripts/cloud-setup.sh), in order:

1. Locates the checkout by looking for a `Package.swift` naming `Watchword`.
2. Installs the apt dependencies swift.org publishes for Ubuntu 24.04 **and** downloads
   [swiftly](https://www.swift.org/install/linux/) concurrently — the five-minute budget below is the
   reason for the `&`/`wait`.
3. Installs the toolchain with swiftly, pinned to the version in [`.swift-version`](../.swift-version)
   (`6.4.1`). Falls back to the release tarball at `download.swift.org` if swiftly fails.
4. Symlinks `swift`, `swiftc`, `swift-format` and `sourcekit-lsp` into `/usr/local/bin` and writes
   `/etc/profile.d/swift.sh`. The Bash tool does not run a login shell, so the symlinks are what
   actually make the toolchain reachable; only the drivers are linked, because symlinking the whole
   toolchain would shadow the system `clang` for everything else on the VM.
5. Warms `.build` with `swift build --build-tests`, bounded by `timeout 150`.
6. Prints `swift --version` and warns if `swift format` is missing.

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
.github/scripts/cloud-verify.sh          # build, both test frameworks, adversarial, memory safety, lint
.github/scripts/cloud-verify.sh --quick  # build and test only
```

That script is the honest subset of `ci.yml`: the four jobs expressible as plain `swift` commands. It
says so in its own summary line, and it names the Xcode-only gates it did not run, so a green result
is never mistaken for a green CI.

If `swift` is missing, the setup script did not run or did not finish. Check in this order:

1. **Network access is `Trusted`, not `Custom`.** The most common cause; `download.swift.org` is
   unreachable and both the installer and the tarball fallback fail.
2. **The setup script field is empty**, or holds a stale copy from before an edit.
3. **A cached snapshot predates your change.** The setup script does not re-run when an idle VM is
   restored. Start a new session, or ask Claude to run the install commands in the current one.
4. **Setup overran five minutes**, so nothing was cached and a slow session start repeats it.

Mind the compiler-version gap: a cloud session builds with Swift 6.4, while `ci.yml` also runs the
Xcode 16.4 leg on macOS 15. Something can compile cleanly in a cloud session and still fail that
older leg. Cloud-session green is a signal, not the gate — `ci.yml` is the gate.

## 5. Related

- `07-supply-chain.md` §3 (operational shell lives in the repository, not in third-party actions),
  §5 (why `.claude/` is not committed).
- `02-architecture.md` §15 — which future modules are Apple-framework-bound, and therefore outside
  what a cloud session can verify.
- `04-test-plan.md` — the requirement-to-test map a cloud session can only partly exercise.
