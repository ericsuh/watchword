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
#
# `assert-no-dependencies.sh --resolved-file <path>` checks one Package.resolved against the same commits and nothing
# else. The app tasks call it on the file Xcode writes inside the generated project: xcodebuild resolves a local
# package's dependencies for itself, so the root Package.resolved says nothing about what an app is built from
# (mise-tasks/app/packages.sh, docs/07-supply-chain.md §2).
set -euo pipefail

fail=0
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export ALLOWED_PACKAGE_URL="https://github.com/apple/swift-crypto.git"
export ALLOWED_PACKAGE_VERSION="4.5.2"
export ALLOWED_PRODUCTS="Crypto CryptoExtras"
export LINUX_ONLY_PRODUCTS="CryptoExtras"
# identity=revision, for Package.resolved. swift-asn1 comes in through CryptoExtras.
export ALLOWED_PINS="swift-crypto=da9d28d69ebe3894b18376c8f2395c2f37b8448f swift-asn1=3b6410f7dee09eb33cdd26260c5fd47fda19b0e2"

# A Package.resolved must pin exactly the allowed commits: no other package, no other revision, none missing. A file
# that is absent, unreadable or in a form this does not know pins nothing it can vouch for, and fails.
check_pins() { # check_pins <Package.resolved> <what to say when it is missing>
  python3 -I -c '
import json, os, sys
path, missing = sys.argv[1], sys.argv[2]
expected = dict(pin.split("=") for pin in os.environ["ALLOWED_PINS"].split())
try:
    with open(path, encoding="utf-8") as handle:
        resolved = json.load(handle)
    pins = {pin["identity"]: pin["state"].get("revision") for pin in resolved["pins"]}
    if len(pins) != len(resolved["pins"]):
        raise ValueError("a package is pinned twice")
except FileNotFoundError:
    print(f"::error::{path} is missing; {missing}")
    sys.exit(1)
except (OSError, ValueError, KeyError, TypeError, AttributeError) as problem:
    print(f"::error file={path}::{path} could not be read as a Package.resolved ({type(problem).__name__}: {problem})")
    sys.exit(1)
if pins != expected:
    print(f"::error file={path}::{path} pins {pins}; expected exactly {expected} (ADR 0006).")
    sys.exit(1)
' "$1" "$2"
}

if [ "${1:-}" = "--resolved-file" ]; then
  if [ "$#" -ne 2 ] || [ -z "$2" ]; then
    echo "::error::usage: assert-no-dependencies.sh --resolved-file <Package.resolved>"
    exit 2
  fi
  check_pins "$2" "nothing shows which commits were resolved (ADR 0006)."
  echo "$2 pins the allowed swift-crypto commits and nothing else."
  exit 0
elif [ "$#" -ne 0 ]; then
  echo "::error::usage: assert-no-dependencies.sh [--resolved-file <Package.resolved>]"
  exit 2
fi

if grep -nE 'unsafeFlags|\.binaryTarget|\.plugin\(|packageAccess' Package.swift; then
  echo "::error file=Package.swift::Binary targets, build plugins, and unsafeFlags are not permitted."
  fail=1
fi

# A manifest is a program, and the structural checks below read what it evaluates to *here*. One that imports
# anything but PackageDescription, or branches on the platform or the environment (`#if`, `Context.environment`,
# `ProcessInfo`, `getenv`), can evaluate to something else on another machine: a dependency or a setting that appears
# only where this script is not running. So the manifest must be the same value everywhere. Comment lines are ignored.
manifest_is_constant() { # manifest_is_constant <Package.swift>
  local found
  found=$(grep -nE '^[[:space:]]*(@[A-Za-z_]+(\([^)]*\))?[[:space:]]+)*import([[:space:]]|$)' "$1" \
    | grep -vE '^[0-9]+:import PackageDescription[[:space:]]*$' || true)
  if [ -n "$found" ]; then
    echo "$found"
    echo "::error file=$1::A manifest may import PackageDescription and nothing else."
    return 1
  fi
  found=$(grep -nE '#(if|elseif|else)|Context[[:space:]]*\.|ProcessInfo|getenv|canImport' "$1" \
    | grep -vE '^[0-9]+:[[:space:]]*//' || true)
  if [ -n "$found" ]; then
    echo "$found"
    echo "::error file=$1::A manifest must not depend on the platform or the environment it is evaluated in."
    return 1
  fi
}
manifest_is_constant Package.swift || fail=1

check_pins Package.resolved "it must be committed so the pinned commits are the ones built (ADR 0006)." || fail=1

# Structural checks on the resolved manifest rather than its text, so formatting cannot hide anything:
# - only plain Swift source and test targets (no binary, plugin, macro, system-library or C targets);
# - every target at its conventional path (a custom `path:`/`sources:` could compile files no other check scans);
# - no settings that change what the compiler enforces (unsafeFlags, experimental features, C++ interop, a target
#   put back into the Swift 5 language mode), and the package as a whole in Swift 6 mode: the actors' invariants rest
#   on the data-race checking that mode turns into errors;
# - WatchwordTestSupport (seeded and deliberately broken RNGs) linked only into test targets.
if ! swift package dump-package | python3 -I -c '
import json, os, sys
manifest = json.load(sys.stdin)
problems = []
forbidden_settings = {"unsafeFlags", "enableExperimentalFeature", "interoperabilityMode", "swiftLanguageMode"}
modes = manifest.get("swiftLanguageVersions")
if modes != ["6"]:
    problems.append(f"swiftLanguageModes must be [.v6], found {modes}")
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

# Fuzz/ is a package of its own (the libFuzzer harness, docs/04-test-plan.md §6.8), so that nothing in it can reach an
# app: the manifest above does not mention it. It is held to the same rules, and to these: its only dependency is this
# repository, by path; its only product is the harness executable; its Package.resolved pins exactly the commits the
# root's does; and the root package depends on nothing in it.
if grep -nE '"Fuzz|Fuzz/' Package.swift; then
  echo "::error file=Package.swift::The shipped package must not refer to Fuzz/."
  fail=1
fi
if [ -d Fuzz ]; then
  if grep -nE 'unsafeFlags|\.binaryTarget|\.plugin\(|packageAccess|url:' Fuzz/Package.swift; then
    echo "::error file=Fuzz/Package.swift::Remote packages, binary targets, build plugins and unsafeFlags are not permitted."
    fail=1
  fi
  manifest_is_constant Fuzz/Package.swift || fail=1
  check_pins Fuzz/Package.resolved "it must be committed so the harness builds the pinned commits." || fail=1
  if ! swift package --package-path Fuzz dump-package | python3 -I -c '
import json, os, sys
manifest = json.load(sys.stdin)
problems = []
forbidden_settings = {"unsafeFlags", "enableExperimentalFeature", "interoperabilityMode", "swiftLanguageMode"}
modes = manifest.get("swiftLanguageVersions")
if modes != ["6"]:
    problems.append(f"swiftLanguageModes must be [.v6], found {modes}")
root = os.path.realpath(os.getcwd())
dependencies = manifest["dependencies"]
paths = [entry.get("path") for package in dependencies for entry in package.get("fileSystem", [])]
if len(dependencies) != 1 or len(paths) != 1 or os.path.realpath(paths[0]) != root:
    problems.append("the only dependency allowed is this repository, by path (..)")
products = [(product["name"], list(product["type"])) for product in manifest["products"]]
if products != [("WatchwordFuzz", ["executable"])]:
    problems.append(f"the only product allowed is the WatchwordFuzz executable, found {products}")
for target in manifest["targets"]:
    name, kind = target["name"], target["type"]
    if kind not in ("regular", "executable"):
        problems.append(f"{name}: target type {kind} is not permitted")
    if target.get("path") is not None or target.get("sources") is not None:
        problems.append(f"{name}: custom path/sources are not permitted")
    for setting in target.get("settings", []):
        for key in setting.get("kind", {}):
            if key in forbidden_settings:
                problems.append(f"{name}: setting {key} is not permitted")
    for dependency in target["dependencies"]:
        if "product" in dependency and dependency["product"][1] != "Watchword":
            product = dependency["product"][0]
            problems.append(f"{name}: product {product} is not from this repository")
for problem in problems:
    print("::error file=Fuzz/Package.swift::" + problem)
sys.exit(1 if problems else 0)
'; then
    fail=1
  fi
fi

# Apps/project.yml can add the same things through XcodeGen: a remote package, a build script that runs arbitrary
# shell, prebuilt frameworks, native sources from outside Apps/, or settings that switch off what the compiler
# enforces. The spec is parsed and held to an allowlist (yaml-audit.py says of what): every key, target type,
# dependency kind and build setting it may hold is named there, the settings the app code is checked under must be
# present with their values, and a file the reader does not understand fails. These were four `grep`s, which a flow
# mapping, a quoted key or value, a key they did not list, or simply deleting a line all passed
# (docs/06-adversarial-review.md Z103). Still a tripwire, with review as the backstop: it reads the spec, not the
# project XcodeGen makes of it.
if [ -f Apps/project.yml ]; then
  python3 -I "$here/yaml-audit.py" app-spec Apps/project.yml || fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "No third-party dependencies beyond swift-crypto (CryptoExtras on Linux only), binary targets, build plugins, custom target paths, or compiler-relaxing settings; Fuzz/ depends on this repository alone."
fi
exit "$fail"
