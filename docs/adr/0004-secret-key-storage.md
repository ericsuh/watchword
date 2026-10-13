# ADR 0004: Where the Secret Key lives

Status: accepted. Date: 2026-10-13.

## Context
The Secret Key must be present on every device the person uses and must not be recoverable from
the sync store. Options: (a) device Keychain only, non-synchronisable, enrolment of new devices by
Emergency Kit or device-to-device transfer; (b) iCloud Keychain (`kSecAttrSynchronizable`), which
Apple end-to-end encrypts, so new devices get it automatically; (c) both, with (b) opt-in.

## Decision
Option (a) by default. The point of the Secret Key is to be independent of the iCloud account that
carries the vault ciphertext; placing it in iCloud Keychain collapses the two secrets into one
Apple account compromise (an attacker with the iCloud account and the account password would have
everything). The app offers an authenticated device-to-device enrolment (QR or proximity, with a
short-lived code) and the Emergency Kit.

Option (c) may be offered later as an explicit opt-in with a clear warning; it is tracked as an
open question in `02-architecture.md` §16.

## Consequences
- Enrolling a new device needs the Emergency Kit or an existing device nearby; onboarding must make
  this obvious.
- Loss of all devices and the Emergency Kit is unrecoverable (PRD F10.2).
