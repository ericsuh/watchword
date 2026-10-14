#!/usr/bin/env bash
# Enforces the zero-runtime-dependency invariant (PRD P4, ADR 0001).
#
# The strongest supply-chain position available to this project is to have no third-party package
# to compromise. Adding one is a deliberate decision that needs an ADR, so it must not be
# possible to do it quietly in a pull request.
set -euo pipefail

fail=0

if grep -nE '^[[:space:]]*\.package\(' Package.swift; then
  echo "::error file=Package.swift::A third-party dependency was added. This requires an ADR; see docs/07-supply-chain.md."
  fail=1
fi

if grep -nE 'unsafeFlags|\.binaryTarget|\.plugin\(|packageAccess' Package.swift; then
  echo "::error file=Package.swift::Binary targets, build plugins, and unsafeFlags are not permitted."
  fail=1
fi

if [ -f Package.resolved ]; then
  pins=$(python3 -c 'import json,sys; d=json.load(open("Package.resolved")); print(len(d.get("pins", d.get("object",{}).get("pins",[]))))')
  if [ "$pins" != "0" ]; then
    echo "::error file=Package.resolved::Package.resolved pins $pins dependencies; expected 0."
    fail=1
  fi
fi

# Structural checks on the resolved manifest rather than its text, so formatting cannot hide anything:
# - only plain Swift source and test targets (no binary, plugin, macro, system-library or C targets);
# - every target at its conventional path (a custom `path:`/`sources:` could compile files no other check scans);
# - no settings that change what the compiler enforces (unsafeFlags, experimental features, C++ interop);
# - WatchwordTestSupport (seeded and deliberately broken RNGs) linked only into test targets.
if ! swift package dump-package | python3 -I -c '
import json, sys
manifest = json.load(sys.stdin)
problems = []
forbidden_settings = {"unsafeFlags", "enableExperimentalFeature", "interoperabilityMode"}
for target in manifest["targets"]:
    name, kind = target["name"], target["type"]
    if kind not in ("regular", "test"):
        problems.append(f"{name}: target type {kind} is not permitted")
    if target.get("path") is not None or target.get("sources") is not None:
        problems.append(f"{name}: custom path/sources are not permitted")
    for setting in target.get("settings", []):
        for key in setting.get("kind", {}):
            if key in forbidden_settings:
                problems.append(f"{name}: setting {key} is not permitted")
    for dependency in target["dependencies"]:
        names = [v[0] for v in dependency.values() if isinstance(v, list) and v]
        if kind != "test" and "WatchwordTestSupport" in names:
            problems.append(f"{name}: production target depends on WatchwordTestSupport")
for problem in problems:
    print("::error file=Package.swift::" + problem)
sys.exit(1 if problems else 0)
'; then
  fail=1
fi

# Apps/project.yml can add the same things through XcodeGen: a remote package, a build script that runs arbitrary
# shell, prebuilt frameworks, or settings that switch off what the compiler enforces. Text checks, like the rest of this
# script: a tripwire, with review as the backstop.
if [ -f Apps/project.yml ]; then
  spec=Apps/project.yml
  if grep -nE '^[[:space:]]*(url|github|from|exactVersion|minorVersion|majorVersion|branch|revision):' "$spec"; then
    echo "::error file=$spec::A remote package was added to the app project. This requires an ADR; see docs/07-supply-chain.md."
    fail=1
  fi
  if awk '/^packages:/{p=1;next} /^[^[:space:]#]/{p=0} p && /path:/ && $2 != ".."' "$spec" | grep -q .; then
    echo "::error file=$spec::Local packages other than the repository's own (path: ..) are not permitted."
    fail=1
  fi
  if grep -nE '(pre|post)BuildScripts|postCompileScripts|buildToolPlugins|buildRules|^[[:space:]]*(carthage|framework|sdk|bundle):' "$spec"; then
    echo "::error file=$spec::Build scripts, build rules, plugins and prebuilt or SDK dependencies are not permitted in the app project."
    fail=1
  fi
  if grep -nE 'OTHER_SWIFT_FLAGS|OTHER_LDFLAGS|OTHER_CFLAGS|SWIFT_OBJC_BRIDGING_HEADER|SWIFT_STRICT_MEMORY_SAFETY:[[:space:]]*(NO|false)|SWIFT_TREAT_WARNINGS_AS_ERRORS:[[:space:]]*(NO|false)|unsafeFlags' "$spec"; then
    echo "::error file=$spec::Compiler-relaxing settings and bridging headers are not permitted in the app project."
    fail=1
  fi
fi

if [ "$fail" -eq 0 ]; then
  echo "No third-party dependencies, binary targets, build plugins, custom target paths, or compiler-relaxing settings."
fi
exit "$fail"
