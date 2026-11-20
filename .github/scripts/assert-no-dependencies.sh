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
# `assert-no-dependencies.sh --checkouts <source packages directory>` checks what an Xcode build compiles against the
# same commits and nothing else. xcodebuild resolves a local package's dependencies for itself, so the root
# Package.resolved says nothing about what an app is built from, and Xcode writes no Package.resolved of its own for
# this project (the first Mac run looked). What it does leave is the sources: with `-clonedSourcePackagesDirPath`,
# each dependency is a git working copy under `<directory>/checkouts`. The app tasks pass that directory to every
# xcodebuild call and hand it here (mise-tasks/app/packages.sh, docs/07-supply-chain.md §2).
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

# The sources an Xcode build compiles must be exactly the allowed commits: under <directory>/checkouts, one git working
# copy per allowed package and nothing else, each with HEAD at its allowed commit and no change to any file. A
# directory that is missing, an entry that is not a working copy of its own (git is not allowed to find a repository
# further up, which here would be this one), a package nobody allowed, another commit and an edited file all fail.
# Nothing here can run Xcode, so a failure prints what is there: the listings, every checkout's HEAD, and what Xcode
# recorded in workspace-state.json, which is read for the log only and never believed.
check_checkouts() { # check_checkouts <source packages directory>
  python3 -I -c '
import json, os, subprocess, sys
root = sys.argv[1]
checkouts = os.path.join(root, "checkouts")
expected = dict(pin.split("=") for pin in os.environ["ALLOWED_PINS"].split())
# No GIT_DIR or GIT_WORK_TREE from outside, and no looking above the checkouts for a repository.
environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
environment["GIT_CEILING_DIRECTORIES"] = os.path.realpath(checkouts)
environment["GIT_OPTIONAL_LOCKS"] = "0"

def git(path, *arguments):
    try:
        done = subprocess.run(["git", "-C", path, *arguments], capture_output=True, text=True, env=environment)
    except OSError as problem:
        return 127, "", str(problem)
    return done.returncode, done.stdout.strip(), done.stderr.strip()

def listing(path):
    print(f"$ ls -la {path}")
    sys.stdout.flush()
    subprocess.run(["ls", "-la", path])

problems, commits = [], {}
# The packages are the directories there (a link counts, and is refused below); a stray file is not a package.
try:
    names = sorted(os.listdir(checkouts)) if os.path.isdir(checkouts) else None
except OSError:
    names = None
if names is not None:
    names = [name for name in names if os.path.isdir(os.path.join(checkouts, name)) or os.path.islink(os.path.join(checkouts, name))]
if names is None:
    problems.append(f"{checkouts} is not a directory: xcodebuild checked no packages out where it was told to")
    names = []
for name in names:
    if name not in expected:
        problems.append(f"{name}: a package that is not allowed was checked out (allowed: {sorted(expected)})")
for name, commit in sorted(expected.items()):
    path = os.path.join(checkouts, name)
    if name not in names:
        problems.append(f"{name}: not checked out")
        continue
    status, top, _ = git(path, "rev-parse", "--show-toplevel")
    if os.path.islink(path) or status != 0 or os.path.realpath(top) != os.path.realpath(path):
        problems.append(f"{name}: {path} is not a git working copy of its own")
        continue
    status, head, error = git(path, "rev-parse", "--verify", "HEAD")
    if status != 0 or head != commit:
        problems.append(f"{name}: checked out at {head or error}, expected {commit}")
        continue
    status, changes, error = git(path, "status", "--porcelain")
    if status != 0 or changes:
        shown = (changes or error).splitlines()[:10]
        problems.append(f"{name}: the checkout differs from commit {commit}: {shown}")
        continue
    commits[name] = head
if not problems:
    for name, commit in sorted(commits.items()):
        print(f"{name} {commit} (clean checkout in {checkouts})")
    sys.exit(0)
for problem in problems:
    print(f"::error::{problem} (ADR 0006)")
print("::group::What xcodebuild left in the source packages directory")
for path in (root, checkouts):
    if os.path.exists(path):
        listing(path)
    else:
        print(f"{path} does not exist")
for name in names:
    path = os.path.join(checkouts, name)
    _, head, error = git(path, "rev-parse", "HEAD")
    _, changes, _ = git(path, "status", "--porcelain")
    print(f"{path}: git rev-parse HEAD: {head or error}; changed files: {len(changes.splitlines())}")
state = os.path.join(root, "workspace-state.json")
if os.path.isfile(state):
    try:
        with open(state, encoding="utf-8") as handle:
            recorded = json.load(handle)
        for dependency in recorded.get("object", recorded).get("dependencies", []):
            reference = dependency.get("packageRef", {})
            print(
                "workspace-state.json:", reference.get("identity"), reference.get("kind"), reference.get("location"),
                json.dumps(dependency.get("state", {}), sort_keys=True), "subpath", dependency.get("subpath"),
            )
    except (OSError, ValueError, AttributeError, TypeError) as problem:
        print(f"workspace-state.json could not be read: {type(problem).__name__}: {problem}")
else:
    print(f"{state} does not exist")
print("::endgroup::")
sys.exit(1)
' "$1"
}

if [ "${1:-}" = "--checkouts" ]; then
  if [ "$#" -ne 2 ] || [ -z "$2" ]; then
    echo "::error::usage: assert-no-dependencies.sh --checkouts <source packages directory>"
    exit 2
  fi
  check_checkouts "$2"
  echo "The package sources in $2 are the allowed swift-crypto commits and nothing else."
  exit 0
elif [ "$#" -ne 0 ]; then
  echo "::error::usage: assert-no-dependencies.sh [--checkouts <source packages directory>]"
  exit 2
fi

if grep -nE 'unsafeFlags|\.binaryTarget|\.plugin\(|packageAccess' Package.swift; then
  echo "::error file=Package.swift::Binary targets, build plugins, and unsafeFlags are not permitted."
  fail=1
fi

# A manifest is a program, and the structural checks below read what it evaluates to *here*. One that imports
# anything but PackageDescription, or branches on the platform, the environment, where it is checked out, how it was
# invoked, the size of a type, the time or chance, can evaluate to something else on another machine: a dependency or
# a setting that appears only where this script is not running. So the manifest must be the same value everywhere.
#
# This is a list of words, and a list of words is a tripwire: it cannot be complete. Swift has more ways to tell two
# machines or two runs apart than can be named (the order of a Set is one that needs no name at all), and the review
# of this change found several the first list missed (docs/06-adversarial-review.md Z111). The check that would not
# depend on a list is to dump the manifest on Linux and on macOS, and under more than one environment, and compare;
# that is tracked there, not built. Package.swift is reviewed like cryptography (docs/07-supply-chain.md §2.1), and
# that review is the control.
#
# Three rules. No block comment anywhere: with `/*` a line can be code to Swift and a comment to a line filter. The
# word `import` on any line that is not a comment must be the whole line `import PackageDescription`: access
# modifiers, attributes and a statement before it on the line are all ways to write another. And none of the names
# below on a line that is not a comment; they are refused as words, so an alias for one is refused where it is made.
manifest_is_constant() { # manifest_is_constant <Package.swift>
  local found word='(^|[^A-Za-z0-9_])' end='([^A-Za-z0-9_]|$)'
  local names='Context|ProcessInfo|CommandLine|getenv|canImport|NSHomeDirectory|FileManager|MemoryLayout'
  names="$names|random[A-Za-z]*|shuffled?|hashValue|Hasher|[A-Za-z]*Clock|[A-Za-z]*RandomNumberGenerator"
  found=$(grep -nF '/*' "$1" || true)
  if [ -n "$found" ]; then
    echo "$found"
    echo "::error file=$1::A manifest may not contain a block comment: a line inside one can still be code."
    return 1
  fi
  found=$(grep -nE "${word}import${end}" "$1" | grep -vE '^[0-9]+:[[:space:]]*//' \
    | grep -vE '^[0-9]+:import PackageDescription[[:space:]]*$' || true)
  if [ -n "$found" ]; then
    echo "$found"
    echo "::error file=$1::A manifest may import PackageDescription and nothing else, on a line of its own."
    return 1
  fi
  found=$(grep -nE "#(if|elseif|else|file)|${word}(${names})${end}" "$1" | grep -vE '^[0-9]+:[[:space:]]*//' || true)
  if [ -n "$found" ]; then
    echo "$found"
    echo "::error file=$1::A manifest must not depend on the platform or the environment it is evaluated in (or on chance)."
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
elif [ -d Apps ]; then
  # A spec that is gone, or was renamed to something XcodeGen is then pointed at, is not a spec that passed.
  echo "::error::Apps/ exists without Apps/project.yml: the app project's allowlist has nothing to read."
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "No third-party dependencies beyond swift-crypto (CryptoExtras on Linux only), binary targets, build plugins, custom target paths, or compiler-relaxing settings; Fuzz/ depends on this repository alone."
fi
exit "$fail"
