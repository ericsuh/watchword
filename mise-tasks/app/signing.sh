# Build settings shared by `app:build` and `app:test` (sourced, not a task: mise runs only executable files).
#
# CI has no provisioning profile. iOS builds for the simulator without signing. macOS signs ad hoc with the
# entitlements dropped, because a macOS XCUITest runner that is not signed at all hangs before connecting.
# shellcheck shell=bash disable=SC2034
ios_signing=(CODE_SIGNING_ALLOWED=NO)
macos_signing=(CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= CODE_SIGN_ENTITLEMENTS=)
