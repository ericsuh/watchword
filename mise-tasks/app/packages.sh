# What an app is built from, checked (sourced by the app tasks; not a task: mise runs only executable files).
#
# ADR 0006 pins swift-crypto by commit: the root Package.resolved is committed and `audit:dependencies` compares it with
# the commits it names. That covers `swift build` and `swift test`, where this package is the root. An app is built by
# xcodebuild from the generated project, which refers to the package by path, and Xcode resolves a local package's
# dependencies for itself: by the version in Package.swift (a tag, which can be moved) and, for swift-asn1, by whatever
# is newest in swift-crypto's range. It records the result in a Package.resolved of its own inside the project, which is
# generated and never committed. So the pin says nothing about an app unless that file is read.
#
# These two functions read it. `resolve_packages` has Xcode resolve before anything is compiled and fails unless the
# commits are the allowed ones, so a moved tag stops the task before its sources are built into an app; and
# `check_resolved_packages` is called again after the build or test, in case xcodebuild resolved a second time. The
# commits are the ones `.github/scripts/assert-no-dependencies.sh` names, and it does the comparing, so a bump is still
# one edit. A missing file fails: no record is not a pass.
#
# Not run on a Mac yet (docs/06-adversarial-review.md Z102): where Xcode writes the file, and that
# `-resolvePackageDependencies` needs no scheme, are from Xcode's documented behaviour.
# shellcheck shell=bash
resolved_packages="Apps/Watchword.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"
dependency_tripwire="$(dirname "${BASH_SOURCE[0]}")/../../.github/scripts/assert-no-dependencies.sh"

check_resolved_packages() { # check_resolved_packages <when, for the message>
  if ! "$dependency_tripwire" --resolved-file "$resolved_packages"; then
    echo "::error::$1, Xcode's own Package.resolved does not pin the allowed swift-crypto commits: this app build is not the reviewed dependency (ADR 0006). If the pins were bumped, \`mise run clean\` removes a stale project."
    return 1
  fi
}

resolve_packages() {
  xcodebuild -resolvePackageDependencies -project Apps/Watchword.xcodeproj
  check_resolved_packages "Before building"
}
