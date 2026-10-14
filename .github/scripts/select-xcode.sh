#!/usr/bin/env bash
# Selects an Xcode version without a third-party action.
#
# `maxim-lobanov/setup-xcode` did this job, but a third-party action is code execution inside CI,
# and this is a few lines of shell (docs/07-supply-chain.md). Argument is a version such as
# "26.6". Resolution order:
#   1. /Applications/Xcode_<version>.app                      (exact, what CI images provide)
#   2. highest /Applications/Xcode_<major>*.app               (image refreshed; degrade, warn)
#   3. an unversioned /Applications/Xcode.app of that major   (developer machines)
# Anything else is an error, so CI never silently tests on the wrong toolchain.
set -euo pipefail

want="${1:?usage: select-xcode.sh <version>}"
major="${want%%.*}"

major_of() { # major_of <app path> -> major version, or empty
  local plist="$1/Contents/version.plist"
  [ -f "$plist" ] || return 0
  /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist" 2>/dev/null | cut -d. -f1
}

app="/Applications/Xcode_${want}.app"

if [ ! -d "$app" ]; then
  app="$(find /Applications -maxdepth 1 -name "Xcode_${major}*.app" | sort -V | tail -1)"
  [ -n "$app" ] && echo "::warning::Xcode_${want}.app absent; using $app"
fi

if [ -z "$app" ] || [ ! -d "$app" ]; then
  if [ "$(major_of /Applications/Xcode.app)" = "$major" ]; then
    app="/Applications/Xcode.app"
    echo "::warning::No versioned Xcode_${major}*.app; using unversioned $app"
  fi
fi

if [ -z "$app" ] || [ ! -d "$app" ]; then
  echo "::error::No Xcode with major version ${major} found. Available:"
  find /Applications -maxdepth 1 -name 'Xcode*.app' -print
  exit 1
fi

sudo xcode-select -s "$app/Contents/Developer"
echo "Selected $app"
xcodebuild -version
swift --version
