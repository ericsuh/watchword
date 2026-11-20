#!/usr/bin/env bash
# Prints the UDID of an iOS simulator the Watchword-iOS scheme can run on. Argument is a device-name prefix
# ("iPhone", "iPad"). Run from the repository root after `mise run app:generate`.
#
# It asks xcodebuild, not simctl: `simctl list devices available` also lists devices of runtimes the selected Xcode
# cannot load, and a runner image once put such an iPhone (iOS 27.0) first, so xcodebuild found no device with that
# ID. Of the scheme's compatible destinations (printed before the ineligible ones), it takes the newest iOS, and on
# that iOS the first device xcodebuild lists, so repeated runs pick the same model. Exits non-zero if none match.
#
# Listing a scheme's destinations resolves its packages, so this call is given the app tasks' source-packages
# directory like every other (mise-tasks/app/packages.sh): one set of checkouts, in the place that is read.
set -euo pipefail
# shellcheck source=../../mise-tasks/app/packages.sh
source "$(dirname "${BASH_SOURCE[0]}")/../../mise-tasks/app/packages.sh"

prefix="${1:?usage: pick-simulator.sh <device name prefix>}"
xcodebuild -showdestinations -project Apps/Watchword.xcodeproj -scheme Watchword-iOS "${package_arguments[@]}" \
  2>/dev/null |
  python3 -I -c 'import re, sys
prefix = sys.argv[1]
text = sys.stdin.read().split("Ineligible destinations")[0].split("incompatible with")[0]
found = []
for index, line in enumerate(text.splitlines()):
    if "platform:iOS Simulator" not in line or "error:" in line:
        continue
    fields = {key: value.strip() for key, value in re.findall(r"(\w+):([^,}]+)", line)}
    version = fields.get("OS", "")
    if fields.get("name", "").startswith(prefix) and re.fullmatch(r"[0-9]+(\.[0-9]+)*", version):
        found.append((tuple(int(part) for part in version.split(".")), -index, fields["id"]))
if not found:
    sys.exit(f"pick-simulator: no {prefix} simulator among the scheme'"'"'s compatible destinations")
print(max(found)[2])' "$prefix"
