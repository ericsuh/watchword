# What an app is built from, checked (sourced by the app tasks; not a task: mise runs only executable files).
#
# ADR 0006 pins swift-crypto by commit: the root Package.resolved is committed and `audit:dependencies` compares it with
# the commits it names. That covers `swift build` and `swift test`, where this package is the root. An app is built by
# xcodebuild from the generated project, which refers to the package by path, and Xcode resolves a local package's
# dependencies for itself: by the version in Package.swift (a tag, which can be moved) and, for swift-asn1, by whatever
# is newest in swift-crypto's range. So the pin says nothing about an app unless what Xcode fetched is read.
#
# The first version of this read the Package.resolved Xcode was expected to write inside the generated project. The
# first Mac run (Xcode 27) showed that it writes none there for this project, a local package whose dependencies are
# remote: the resolution succeeded and the file did not exist. So the evidence is now the sources themselves. Every
# xcodebuild call in every app task is given the same `-clonedSourcePackagesDirPath` (`package_arguments` below), which
# puts each dependency's git working copy at `<directory>/checkouts/<package>`: a place this repository chose, not one
# Xcode did. `resolve_packages` has Xcode resolve before anything is compiled, and `check_resolved_packages` then
# requires those working copies to be exactly the allowed packages, each at its allowed commit with no file changed;
# it is called again after the build or test, in case xcodebuild resolved a second time. The commits are the ones
# `.github/scripts/assert-no-dependencies.sh` names, and it does the comparing (`--checkouts`), so a bump is still one
# edit. No checkouts is not a pass. A call without `package_arguments` would compile from Xcode's own DerivedData,
# which nothing reads: Tests/ScriptTests fails a task that makes one.
#
# Unproven until a Mac run passes (docs/06-adversarial-review.md Z102): that Xcode puts the checkouts there and leaves
# them as clean working copies is its documented behaviour, not something seen. A failure prints what it found.
# shellcheck shell=bash disable=SC2034
source_packages="$PWD/.build/app-source-packages"
package_arguments=(-clonedSourcePackagesDirPath "$source_packages")
dependency_tripwire="$(dirname "${BASH_SOURCE[0]}")/../../.github/scripts/assert-no-dependencies.sh"

check_resolved_packages() { # check_resolved_packages <when, for the message>
  if ! "$dependency_tripwire" --checkouts "$source_packages"; then
    echo "::error::$1, the package sources xcodebuild checked out are not the allowed swift-crypto commits: this app build is not the reviewed dependency (ADR 0006). If the pins were bumped, \`mise run clean\` removes the old checkouts."
    return 1
  fi
}

resolve_packages() {
  xcodebuild -resolvePackageDependencies -project Apps/Watchword.xcodeproj "${package_arguments[@]}"
  check_resolved_packages "Before building"
}
