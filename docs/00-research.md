# Research: existing password managers, their security architectures, and Apple platform integration options

Status: informational, October 2026. This document collects the research that the PRD
(`01-prd.md`), the architecture (`02-architecture.md`), and the plans (`03-implementation-plan.md`,
`04-test-plan.md`) build on. Claims are cited; where a primary source could not be fetched from the
build environment, the secondary source is named and the claim is marked as needing confirmation.

## 1. Existing apps and their security architectures

### 1.1 1Password

1Password's design is the reference point for this project because it combines a user password with
a locally held, high-entropy Secret Key ("two-secret key derivation", 2SKD).

- **Two secrets.** The account password and the Secret Key are both needed to derive the key that
  unlocks the account. The Secret Key is generated on the client, never sent to 1Password, and is
  what makes server-side data useless for offline cracking of the account password
  ([1Password security design white paper](https://1passwordstatic.com/files/security/1password-white-paper.pdf),
  [Secret Key security](https://support.1password.com/secret-key-security/)).
- **Secret Key format.** A non-secret version tag (`A3`), a non-secret account ID, and 26 random
  characters drawn from an alphabet of 31 uppercase letters and digits, "just a tad over 128 bits"
  (white paper, as quoted in
  [this comparative analysis](https://eprint.iacr.org/2026/058.pdf)).
- **Key derivation.** PBKDF2-HMAC-SHA256 over the account password with a salt derived with HKDF
  from a stored salt and the email address; 650,000 iterations in current versions
  ([About PBKDF2](https://support.1password.com/pbkdf2/)). The Secret Key is separately expanded with
  HKDF (account ID as salt, version as info) and combined with the password-derived key to produce the
  Account Unlock Key (AUK). A 1Password staff member notes that because the Secret Key contributes
  128 bits, extra PBKDF2 iterations add little against a server-side compromise
  ([1Password community](https://1password.community/discussion/comment/669088/)).
- **Keysets and vault keys.** The AUK encrypts (AES-256-GCM) the symmetric key of the user's
  "keyset", which bundles that symmetric key with an RSA-OAEP (2048-bit) encryption key pair. Each
  vault has its own symmetric vault key; a copy of the vault key is encrypted to the public key of
  every user who has access, which is how vaults are shared (white paper; see also
  [this security engineer's overview](https://medium.com/@cube1214/the-engine-under-the-hood-of-a-password-manager-a-security-engineers-view-f0b6982bd76c)).
- **Authentication.** SRP-6a is used so the account password is never sent to the server, and the
  authentication secret (SRP-x) is derived separately from the encryption key
  ([white paper clarifications thread](https://discussions.agilebits.com/discussion/comment/329659)).
- **Revocation is not cryptographic for past data.** "After read access has been granted to a vault,
  it can't be taken away cryptographically"; revocation is server-enforced and the vendor's own
  guidance is to assume offboarded members copied what they could see
  ([How vault permissions are enforced](https://support.1password.com/permission-enforcement/),
  [Business security practices](https://support.1password.com/business-security-practices/)).
- **Implementation.** 1Password 8 is a Rust core with a SwiftUI/UIKit front end on iOS, and an
  Electron (TypeScript/React) front end on the Mac
  ([1Password community](https://1password.community/discussion/comment/611471),
  [9to5Mac](https://9to5mac.com/2022/04/13/1password-8-beta-for-iphone-and-ipad/)).
  This project explicitly rejects Electron (see `adr/0002-native-ui.md`).
- **Export formats.** 1Password 8 exports 1PUX (a ZIP archive containing JSON) and CSV. The CSV
  carries only Login and Password items with the fields Title, Website/Url, Username, Password,
  One-time password (`OTPAuth`), Favorite, Archived, Tags, and Notes; security questions, linked
  items, and custom fields are not exported to CSV
  ([How to export your data](https://support.1password.com/export/),
  [About the 1PUX format](https://support.1password.com/1pux-format/)). On iOS/iPadOS 26 and later,
  1Password can also export through the system Credential Exchange flow (same export page).

### 1.2 Bitwarden

- Master-password KDF is PBKDF2-SHA256 (600,001 iterations by default) or Argon2id (added in
  2023.2.0) ([What encryption is used](https://bitwarden.com/help/what-encryption-is-used/),
  [Security whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)).
- An organization has one symmetric key, generated with a CSPRNG and encrypted to each member's RSA
  public key; items are shared by encrypting them with that key. There is no supported way to rotate
  the organization key, so a removed member who kept the key can still decrypt anything they had
  synced ([Bitwarden community](https://community.bitwarden.com/t/what-to-do-if-organization-member-is-compromised/86107),
  [CVE-2024-39925 for Vaultwarden](https://nvd.nist.gov/vuln/detail/CVE-2024-39925)).
  Lesson for this project: rotate the vault key on every membership removal.
- Bitwarden has no Secret-Key equivalent; the master password alone protects server-side ciphertext.

### 1.3 Apple Passwords and iCloud Keychain

- Shared groups: anyone in a group can modify or delete any shared entry; joining gives access to
  everything already shared; leaving keeps the entries you contributed and removes access to the
  rest; sharing is end-to-end encrypted and Apple cannot read it; deleted items are recoverable for
  30 days ([Passwords & Privacy](https://www.apple.com/legal/privacy/data/en/passwords/)).
- There is no admin or read-only role in shared groups
  ([TWiT summary](https://twit.tv/posts/tech/apples-passwords-app-enough)).
- CSV export is unencrypted; the community-documented header is
  `Title,URL,Username,Password,Notes,OTPAuth`, UTF-8 without BOM, with `otpauth://totp/...` URIs in
  the last column. Passkeys, shared items, and Wi-Fi credentials do not round-trip through CSV
  ([Apple Community thread](https://discussions.apple.com/thread/255759674),
  [community format notes](https://github.com/rsgill1978/1PasswordExporter/blob/main/docs/ApplePasswords/ApplePasswords.md)).
- On iOS 26 and macOS 26, Apple Passwords supports the FIDO Credential Exchange flow ("Export Data to
  Another App"), which moves logins, passkeys, and verification codes app-to-app without writing a
  file; Wi-Fi items are excluded
  ([Dashlane CXP import notes](https://support.dashlane.com/hc/en-us/articles/32779418812050-Import-your-data-to-Dashlane-using-the-Credential-Exchange-Protocol-CXP)).
  One developer has reported an import that silently delivered nothing on iOS 26.3.1 when the
  receiving app lacked the import activity registration
  ([Strongbox issue #867](https://github.com/strongbox-password-safe/Strongbox/issues/867)).

### 1.4 KeePass-family apps (KeePassium, Strongbox)

These are single-file (`.kdbx`) vaults synced through the Files app, iCloud Drive, Dropbox, and
similar. Their relevance here is as a model for file-based sync.

- KeePassium re-reads the remote file before saving and warns about conflicts, letting the user
  overwrite or save a separate copy ([KeePassium 1.26 release notes](https://keepassium.com/blog/2021/09/keepassium-1.26)).
- Strongbox eventually built its own sync because iCloud Drive proved unreliable for larger
  database files ([ifun.de](https://www.ifun.de/icloud-unzuverlaessig-keepass-app-strongbox-mit-eigener-sync-loesung-235021/)).
- General KeePass guidance is "pull before push" and to rely on the provider's version history as a
  fallback ([ctrl.blog](https://www.ctrl.blog/entry/keepass-file-conflicts-android/)).
- Lesson: a single mutable shared file is the root cause of conflicts. The architecture avoids it by
  giving each device its own append-only change log (see `02-architecture.md`, section 7).

### 1.5 Password-hashing parameter guidance

OWASP's password storage cheat sheet recommends Argon2id with a minimum of 19 MiB memory, 2
iterations and parallelism 1, with equivalent trade-offs such as 46 MiB / 1 iteration
([Wikipedia summary of OWASP guidance](https://en.wikipedia.org/wiki/Argon2)). Argon2id is not in
CryptoKit, which drives the KDF decision in `adr/0003-kdf.md`.

## 2. Apple platform integration options

All API facts below come from Apple's documentation; OS availability is quoted from the
documentation pages.

### 2.1 AutoFill credential provider (passwords, passkeys, one-time codes, arbitrary text)

- A Credential Provider Extension subclasses `ASCredentialProviderViewController`; both the
  extension and its containing app need the
  `com.apple.developer.authentication-services.autofill-credential-provider` entitlement. Available
  on iOS 12+ and macOS 11+. **The class ignores calls from Mac apps built with Mac Catalyst**, so the
  Mac app must be a native AppKit/SwiftUI target
  ([ASCredentialProviderViewController](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)).
- Password and passkey identities are published to `ASCredentialIdentityStore` so they appear
  directly in QuickType; the store supports incremental `saveCredentialIdentities` /
  `removeCredentialIdentities` and is cleared when the user disables the extension
  ([ASCredentialIdentityStore](https://developer.apple.com/documentation/authenticationservices/ascredentialidentitystore)).
- Passkeys: `ASPasskeyCredentialIdentity(relyingPartyIdentifier:userName:credentialID:userHandle:recordIdentifier:)`
  with a `rank` for ordering, iOS 17+/macOS 14+
  ([ASPasskeyCredentialIdentity](https://developer.apple.com/documentation/authenticationservices/aspasskeycredentialidentity)).
  Registration arrives in `prepareInterface(forPasskeyRegistration:)`, assertions in
  `prepareInterfaceToProvideCredential(for:)` / `provideCredentialWithoutUserInteraction(for:)`;
  conditional registration via `performWithoutUserInteractionIfPossible(passkeyRegistration:)`.
  The request carries `clientDataHash`, `relyingPartyIdentifier`, `userVerificationPreference` and
  extension input (`prf`, `largeBlob`) from iOS 18
  ([ASPasskeyCredentialRequestParameters](https://developer.apple.com/documentation/authenticationservices/aspasskeycredentialrequestparameters),
  [AuthenticationServices updates](https://developer.apple.com/documentation/updates/authenticationservices)).
- One-time codes: declare `ProvidesOneTimeCodes` in `ASCredentialProviderExtensionCapabilities`,
  publish `ASOneTimeCodeCredentialIdentity(serviceIdentifier:label:recordIdentifier:)` (iOS 18+/macOS
  15+), handle `ASOneTimeCodeCredentialRequest`, and return via
  `completeOneTimeCodeRequest(using:)`
  ([ASOneTimeCodeCredentialIdentity](https://developer.apple.com/documentation/authenticationservices/asonetimecodecredentialidentity),
  [updates page](https://developer.apple.com/documentation/updates/authenticationservices)).
- Arbitrary text (security answers, PINs, card numbers): declare `ProvidesTextToInsert`, implement
  `prepareInterfaceForUserChoosingTextToInsert()`, return with
  `completeRequest(withTextToInsert:)`. Developers have reported intermittent failures of this path
  on iOS 18 ([Apple forums thread 776124](https://developer.apple.com/forums/thread/776124)).
- Service matching: the system hands the extension `ASCredentialServiceIdentifier` values of type
  `.domain` or `.URL`; `displayName` is only a display hint and "is not used by the system to
  identify the service"
  ([ASCredentialServiceIdentifier](https://developer.apple.com/documentation/authenticationservices/ascredentialserviceidentifier)).
  Deciding which of several same-domain accounts to show (Amazon retail vs. AWS) is therefore the
  app's job; see `02-architecture.md` section 9.
- Save and generate hooks: `prepareInterface(for: ASSavePasswordRequest)` and
  `performWithoutUserInteraction(generatePasswordsRequest:)` let the extension save new logins and
  generate passwords that follow a site's declared rules (same class page).
- Credential update reports from relying parties (`reportUnusedPasswordCredential`,
  `reportPublicKeyCredentialUpdate`, ...) allow the manager to stay consistent with the site
  (same class page).

### 2.2 Credential Exchange (CXP/CXF) on iOS 26 / macOS 26

- `ASCredentialExportManager` and `ASCredentialImportManager` (iOS 26+, macOS 26+) exchange
  credentials app-to-app through a system UI; "this process doesn't write any data to the file
  system". The extension's Info.plist must set
  `ASCredentialProviderExtensionCapabilities > SupportsCredentialExchange = YES` and
  `SupportedCredentialExchangeVersions = ["1.0"]`; the importing app must list
  `ASCredentialExchangeActivityType` in `NSUserActivityTypes` and call
  `importCredentials(token:)` with the UUID from the activity's `userInfo`
  ([ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager),
  [ASCredentialImportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialimportmanager)).
- The payload is the FIDO Credential Exchange Format (CXF) v1.0, a Proposed Standard since
  August 2025, whose credential-type registry includes at least `basic-auth`, `totp`, `api-key`,
  `ssh-key`, `credit-card`, `address`, `person-name`, `custom-fields` and (per the released
  specification and implementations) `passkey` and `note`
  ([CXF v1.0](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-20250814.html),
  [go-cxf](https://pkg.go.dev/github.com/nvinuesa/go-cxf)). The exact enum must be verified
  against the current spec text before implementation (the spec host was unreachable from this
  environment); a 2026-03-09 errata revision is reported
  ([EUDI issue #448](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/issues/448)).

### 2.3 Unlock: LocalAuthentication, Keychain access control, Secure Enclave

- `LAPolicy` offers `deviceOwnerAuthenticationWithBiometrics`, `deviceOwnerAuthenticationWithWatch`,
  `deviceOwnerAuthenticationWithBiometricsOrWatch`, `deviceOwnerAuthentication` (biometry, watch, or
  passcode) and the newer `deviceOwnerAuthenticationWithCompanion` /
  `deviceOwnerAuthenticationWithBiometricsOrCompanion`
  ([LAPolicy](https://developer.apple.com/documentation/localauthentication/lapolicy)).
- Keychain items can be bound to `SecAccessControlCreateFlags` such as `biometryCurrentSet`
  (invalidated when enrolment changes), `biometryAny`, `devicePasscode`, `userPresence`, `watch`,
  `companion`, combined with `.or` / `.and`, plus `privateKeyUsage` for Secure Enclave keys
  ([SecAccessControlCreateFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)).
  A bare `evaluatePolicy` boolean can be bypassed on a jailbroken device; the secret must be gated by
  the keychain access control itself
  ([OWASP MASTG demo](https://mas.owasp.org/MASTG/demos/ios/MASVS-AUTH/MASTG-DEMO-0045/MASTG-DEMO-0045/)).
- CryptoKit `SecureEnclave.P256` provides signing and key agreement keys that never leave the
  Secure Enclave (iOS 13+/macOS 10.15+); newer OS versions add `SecureEnclave.MLKEM768/1024`
  ([SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave)).
- Apple Watch unlock on the Mac is implemented in other open-source managers through
  `kSecAccessControlWatch` and the `...OrWatch` policy
  ([KeePassXC commit](https://git.hackliberty.org/Git-Mirrors/keepassxc/commit/34ed63f49585249f00c99e4048270ed93ba4612c)).

### 2.4 Cryptography available without third-party code

- CryptoKit: AES-GCM, ChaChaPoly, HKDF, SHA-2, HMAC, X25519/Ed25519, P-256/384/521, and HPKE
  (RFC 9180) with DHKEM ciphersuites, base/PSK/auth modes, iOS 17+/macOS 14+
  ([HPKE](https://developer.apple.com/documentation/cryptokit/hpke)).
- PBKDF2 is available from CommonCrypto (`CCKeyDerivationPBKDF`), an Apple-shipped C library.
  Argon2id is not shipped by Apple.

### 2.5 Sync options that need no custom server

| Option | E2EE provided by | Sharing with other users | Push/notify | Notes |
| --- | --- | --- | --- | --- |
| CloudKit private + shared database | Our own envelope encryption, plus CloudKit `encryptedValues` (keys in the user's iCloud Keychain; participants of a `CKShare` can decrypt) | `CKShare`, per-participant `readOnly`/`readWrite`, zone-wide shares | Yes (subscriptions, `CKSyncEngine`) | Free with the developer account; no server to run; encrypted fields cannot be indexed or queried, must be new fields, and are lost if the user resets iCloud Keychain (`CKErrorUserDidResetEncryptedDataKey`) ([Encrypting User Data](https://developer.apple.com/documentation/cloudkit/encrypting-user-data), [CKShare](https://developer.apple.com/documentation/cloudkit/ckshare)) |
| iCloud Drive (ubiquity container) files | Our own envelope encryption only | iCloud Drive folder sharing | File presenter callbacks | Must coordinate every read/write with `NSFileCoordinator`; conflicts surface as `NSFileVersion` unresolved versions; devices can disagree about the "current" version after simultaneous edits ([Resolving Document Version Conflicts](https://developer.apple.com/library/archive/documentation/DataManagement/Conceptual/DocumentBasedAppPGiOS/ResolveVersionConflicts/ResolveVersionConflicts.html), [forum thread 804253](https://developer.apple.com/forums/thread/804253)) |
| Any Files-app provider (Dropbox, Google Drive, OneDrive, Nextcloud) via document picker + security-scoped bookmarks | Our own envelope encryption only | Provider's shared folders | Polling / file presenter where supported | No SDK, no OAuth in our app; provider quality varies |
| Dropbox SDK | Our own envelope encryption only | Dropbox shared folders | Longpoll | Adds OAuth and third-party network code to the trusted computing base |
| iCloud Keychain (`kSecAttrSynchronizable`) | Apple | None across users | None | Not suitable as a vault store; could hold a device-sync copy of small secrets but is intentionally not used for the Secret Key by default (see `adr/0004`) |

### 2.6 Have I Been Pwned

- The Pwned Passwords range API takes the first five hex characters of a SHA-1 (or NTLM) hash and
  returns matching suffixes with prevalence counts; a `User-Agent` is required; sending
  `Add-Padding: true` pads every response to 800–1,000 entries with zero-count filler the client
  must discard; the endpoint needs no API key and is documented as not rate limited (the
  breach/paste/stealer-log endpoints are keyed and rate limited)
  ([HIBP API v3](https://haveibeenpwned.com/API/v3),
  [Cloudflare on padding](https://blog.cloudflare.com/pwned-passwords-padding-ft-lava-lamps-and-workers/),
  [pyhibp notes](https://pypi.org/project/pyhibp/)).
- Checking whether an *email address* appears in breaches requires a paid API key and is rate
  limited (same API page); it is therefore an optional, bring-your-own-key feature.

### 2.7 Password strength estimation

- zxcvbn-style estimators (dictionary, l33t, dates, sequences, keyboard walks) exist as Swift
  packages, e.g. [zxcvbn-swift](https://swiftpackageregistry.com/DeVitoC/zxcvbn-swift) and
  [Zxcvbn (Sameer Totey)](https://github.com/sameertotey-greenwood/zxcvbn). Maintenance status
  varies; the plan is to vendor or port the matcher rather than depend on a binary.

### 2.8 Toolchain and CI

- GitHub-hosted runners: `macos-26` (arm64, also `macos-latest`) ships Xcode 26.0.1 through 26.6
  with 26.6 as default; `macos-15` ships Xcode 16.0–16.4 (default 16.4) plus 26.0.1–26.3; macOS 14
  images are deprecated ([runner-images README](https://github.com/actions/runner-images/blob/main/README.md),
  [macos-26-arm64 README](https://github.com/actions/runner-images/blob/main/images/macos/macos-26-arm64-Readme.md),
  [macos-15-arm64 README](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-arm64-Readme.md)).
  A hang with Xcode 26.0.1 iOS tests on `macos-26` has been reported
  ([runner-images issue #13143](https://github.com/actions/runner-images/issues/13143)), so the
  workflows pin a later Xcode.
- macOS 27 arrived as an image named after Xcode, not the OS: the label is `xcode-27` (arm64 only, or
  `xcode-27-xlarge`), with no `macos-27` label, and runner-images now ships one Xcode major per
  image. As of the 2026-10-12 image it runs macOS 27.0.1 with Xcode 27.0 (default; `Xcode_27.0.app`),
  27.1 RC and 27.2 beta, and iOS 27.0 simulators
  ([xcode-27-arm64 README](https://github.com/actions/runner-images/blob/main/images/macos/xcode-27-arm64-Readme.md),
  [runner-images issue #14404](https://github.com/actions/runner-images/issues/14404)). The
  runner-images README still badges it "preview", which carries no SLA and may queue; that is the
  standing risk of making it a required check.
- Swift Testing and XCTest can coexist in one test target ("don't mix API from the two frameworks
  in the same test"); Swift Testing runs tests in parallel by default and supports tags and traits
  ([Swift Testing](https://developer.apple.com/documentation/testing),
  [Adding tests to your Xcode project](https://developer.apple.com/documentation/xcode/adding-tests-to-your-xcode-project)).
- Swift's opt-in strict memory safety (SE-0458) adds `-strict-memory-safety`, `@unsafe`/`@safe`
  annotations and a `strictMemorySafety()` SwiftPM setting from tools version 6.2
  ([SE-0458 acceptance](https://forums.swift.org/t/accepted-se-0458-opt-in-strict-memory-safety-checking/78116),
  [SwiftPM commit](https://github.com/swiftlang/swift-package-manager/commit/d173ce27f1623c7da23eb7aff6257c147b6a9aab)).

## 3. Conclusions carried into the design

1. Adopt 2SKD (password + device-held Secret Key) as 1Password does; it is the single most
   effective mitigation against compromise of the sync store.
2. Rotate vault keys on every membership change, because revocation of already-seen data cannot be
   cryptographic (1Password's own admission) and failing to rotate is a known weakness (Bitwarden).
3. Use CloudKit as the primary transport because it provides identity, sharing with per-participant
   permissions, push, and a second encryption layer for free; keep a file-based transport for
   Dropbox/other providers behind the same interface, with per-device append-only logs to avoid the
   conflicts that plague single-file vaults.
4. Ship a native AppKit/SwiftUI Mac app, not Catalyst and not Electron, because the AutoFill
   extension API ignores Catalyst and because of the native-UI requirement.
5. Target iOS 17 / macOS 14 as the floor (HPKE, passkey identities, `CKSyncEngine`), with
   iOS 18 / macOS 15 features (OTP AutoFill, text-to-insert) and iOS 26 / macOS 26 features
   (Credential Exchange) gated at runtime.
