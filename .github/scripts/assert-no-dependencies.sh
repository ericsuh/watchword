#!/usr/bin/env bash
# Enforces the zero-runtime-dependency invariant (PRD P4, ADR 0001).
#
# The strongest supply-chain position available to this project is to have no third-party package
# to compromise. Adding one is a deliberate decision that needs an ADR, so it must not be
# possible to do it quietly in a pull request.
#
# The one exception is swift-crypto (ADR 0006), so the cryptographic core has one code path on every platform. It is
# allowed at exactly the version and commits below. Its `Crypto` product may be linked anywhere: on Apple platforms it
# only re-exports CryptoKit. `CryptoExtras` compiles BoringSSL into whatever links it, so it must stay behind a Linux
# platform condition. Bumping either means editing these lines, like an action pin.
set -euo pipefail

fail=0

export ALLOWED_PACKAGE_URL="https://github.com/apple/swift-crypto.git"
export ALLOWED_PACKAGE_VERSION="4.5.2"
export ALLOWED_PRODUCTS="Crypto CryptoExtras"
export LINUX_ONLY_PRODUCTS="CryptoExtras"
# identity=revision, for Package.resolved. swift-asn1 comes in through CryptoExtras.
export ALLOWED_PINS="swift-crypto=da9d28d69ebe3894b18376c8f2395c2f37b8448f swift-asn1=3b6410f7dee09eb33cdd26260c5fd47fda19b0e2"

if grep -nE 'unsafeFlags|\.binaryTarget|\.plugin\(|packageAccess' Package.swift; then
  echo "::error file=Package.swift::Binary targets, build plugins, and unsafeFlags are not permitted."
  fail=1
fi

if ! python3 -I -c '
import json, os, sys
expected = dict(pin.split("=") for pin in os.environ["ALLOWED_PINS"].split())
try:
    resolved = json.load(open("Package.resolved"))
except FileNotFoundError:
    print("::error::Package.resolved is missing; it must be committed so the pinned commits are the ones built (ADR 0006).")
    sys.exit(1)
pins = {pin["identity"]: pin["state"].get("revision") for pin in resolved.get("pins", [])}
if pins != expected:
    print(f"::error file=Package.resolved::Package.resolved pins {pins}; expected exactly {expected} (ADR 0006).")
    sys.exit(1)
'; then
  fail=1
fi

# Structural checks on the resolved manifest rather than its text, so formatting cannot hide anything:
# - only plain Swift source and test targets (no binary, plugin, macro, system-library or C targets);
# - every target at its conventional path (a custom `path:`/`sources:` could compile files no other check scans);
# - no settings that change what the compiler enforces (unsafeFlags, experimental features, C++ interop);
# - WatchwordTestSupport (seeded and deliberately broken RNGs) linked only into test targets.
if ! swift package dump-package | python3 -I -c '
import json, os, sys
manifest = json.load(sys.stdin)
problems = []
forbidden_settings = {"unsafeFlags", "enableExperimentalFeature", "interoperabilityMode"}
allowed_url, allowed_version = os.environ["ALLOWED_PACKAGE_URL"], os.environ["ALLOWED_PACKAGE_VERSION"]
allowed_products = set(os.environ["ALLOWED_PRODUCTS"].split())
linux_only_products = set(os.environ["LINUX_ONLY_PRODUCTS"].split())
for package in manifest["dependencies"]:
    source = package.get("sourceControl", [{}])[0]
    url = source.get("location", {}).get("remote", [{}])[0].get("urlString")
    if url != allowed_url or source.get("requirement") != {"exact": [allowed_version]}:
        problems.append(f"package {url or package}: only {allowed_url} at exactly {allowed_version} is allowed (ADR 0006)")
if len(manifest["dependencies"]) > 1:
    problems.append("only one package dependency is allowed (ADR 0006)")
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
        if "product" in dependency:
            product, package, _, condition = dependency["product"]
            if package is not None and product not in allowed_products:
                problems.append(f"{name}: product {product} of {package} is not allowed (ADR 0006)")
            if product in linux_only_products and (condition or {}).get("platformNames") != ["linux"]:
                problems.append(f"{name}: {product} compiles BoringSSL and must be linked on Linux only (ADR 0006)")
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
  echo "No third-party dependencies beyond swift-crypto (CryptoExtras on Linux only), binary targets, build plugins, custom target paths, or compiler-relaxing settings."
fi
exit "$fail"
