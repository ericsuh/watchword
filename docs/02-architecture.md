# Watchword — Architecture Design Document

Version 0.1 (draft). Read `00-research.md` for the evidence behind the choices and `01-prd.md`
for the requirements (IDs such as F4.3 or SEC2 refer to that document).

## 1. Design principles

1. **Two secrets, generated on the client.** Nothing stored outside a device (CloudKit, Dropbox, an
   exported archive) is useful without both the account password and the 128-bit Secret Key that
   never leaves the person's devices except on their Emergency Kit. This is 1Password's two-secret
   key derivation (2SKD) and is the main reason the design is "least risky" for a sync store we do
   not control.
2. **Transports carry ciphertext only.** CloudKit's own field encryption and a file provider's
   TLS are extra layers, never the layer we rely on.
3. **Every ciphertext is bound to its context.** Record ID, vault ID, key ID and schema version are
   authenticated data, so a malicious or buggy sync store cannot swap, replay, or downgrade records.
4. **Biometrics unlock a key, never bypass one.** Quick unlock releases a Keychain item protected by
   `biometryCurrentSet`; it never consults a boolean.
5. **Rotate on every membership change.** We cannot un-share what someone already saw, but we can
   make sure they see nothing new.
6. **Everything security-relevant is testable in-process.** The core is a set of Swift packages
   with injected ports for Keychain, biometrics, randomness, clock, network and sync transport.

## 2. Threat model

### Assets
Field values (passwords, TOTP secrets, passkey private keys, answers, codes), item metadata
(titles, hosts, usernames), vault membership, the account password, the Secret Key, derived keys.

### Adversaries and what they get

| Adversary | Has | Must not get | Primary mitigations |
| --- | --- | --- | --- |
| A1 Sync-store attacker (compromised iCloud account, Apple insider, Dropbox breach) | All ciphertext, record structure, timestamps, sizes | Any field value or title; ability to inject/replay/swap records undetected | 2SKD (128-bit Secret Key makes cracking infeasible), AES-GCM with AAD binding, signed change log, fingerprint-verified member keys |
| A2 Thief with a locked device | Encrypted flash, Keychain items bound to passcode/biometry | Secret Key, derived keys | Keychain classes `WhenPasscodeSetThisDeviceOnly`, Secure Enclave wrapping, no plaintext on disk |
| A3 Thief with an unlocked device, app locked | App sandbox, pasteboard | Vault contents | Auto-lock, zeroised memory, pasteboard expiry, password required after interval |
| A4 Malicious household member (current) | Vault key for shared vaults, their own devices | Items in vaults they are not a member of; ability to impersonate the owner | Per-vault keys, signed membership changes, owner-only admin operations |
| A5 Former member | Old vault key, items synced before removal | Items created/changed after removal | Vault key rotation and re-encryption on removal (F4.3) |
| A6 Malicious web page / app | Control of the page requesting AutoFill | Credentials for a different service | Service-scope matching (SEC6), OS-provided service identifiers, no auto-submit of shadowed matches |
| A7 Malicious import file | Crafted CSV/1PUX/CXF | Code execution, resource exhaustion, data exfiltration | Hardened parsers (SEC7) |
| A8 Local malware with user privileges (macOS) | Can read process memory of unlocked app in the worst case | Long-lived plaintext after lock | Out of scope while unlocked (OS boundary); minimised by zeroisation and short lock timers |

Explicitly out of scope: a compromised OS or jailbroken device while the vault is unlocked,
side-channel attacks on the Secure Enclave, and coercion of the person.

## 3. System overview

```
┌──────────────────────────── Apple device ─────────────────────────────┐
│  SwiftUI/AppKit app      AutoFill extension      (iOS 26+) CX import  │
│      │                          │                        │            │
│      └──────────── WatchwordKit (public API: VaultSession) ───────────┤
│   ┌──────────┬───────────┬──────────┬──────────┬───────────┬────────┐ │
│   │ Crypto   │ Envelope  │ Model    │ Matching │ Generator │ Hygiene│ │
│   │ (2SKD,   │ (record   │ (items,  │ (host    │ (passwords│ (HIBP, │ │
│   │  HPKE,   │  format,  │  vaults, │  scopes, │  phrases) │ zxcvbn)│ │
│   │  wrap)   │  AAD)     │  members)│  ranking)│           │        │ │
│   └──────────┴───────────┴──────────┴──────────┴───────────┴────────┘ │
│   ┌──────────────┬───────────────┬─────────────┬─────────────────────┐ │
│   │ LocalStore   │ SyncEngine    │ Importers/  │ Ports (protocols):  │ │
│   │ (SQLite,     │ (change log,  │ Exporters   │ Keychain, Biometric,│ │
│   │  ciphertext) │  merge)       │ (1PUX, CSV, │ Random, Clock, HTTP,│ │
│   │              │               │  CXF)       │ SyncTransport,      │ │
│   │              │               │             │ IdentityPublisher   │ │
│   └──────────────┴───────────────┴─────────────┴─────────────────────┘ │
│   Adapters: KeychainAdapter · LocalAuthAdapter · CloudKitTransport ·    │
│             FileTransport · URLSessionHTTP · ASCredentialIdentityStore  │
└────────────────────────────────────────────────────────────────────────┘
          │ ciphertext only                       │ ciphertext only
     CloudKit private/shared DB            iCloud Drive / Files provider
```

Three processes share the core: the app, the AutoFill extension (a separate process launched by
the OS), and, on iOS 26+, the same app handling the Credential Exchange activity. They share an
App Group container (SQLite ciphertext store) and a Keychain access group.

## 4. Key hierarchy

Notation: `||` concatenation, `AES-GCM(k, aad, pt)` AES-256-GCM with a random 96-bit nonce stored
alongside the ciphertext.

```
Account password (user)            Secret Key SK (128-bit random, Emergency Kit)
        │                                   │
        │ PBKDF2-HMAC-SHA256                │ HKDF-SHA256
        │ (salt = HKDF(saltA, "WW-salt", accountID), iterations ≥ 650 000)
        ▼                                   ▼
   Kp (256-bit)                         Ks (256-bit) = HKDF(SK, salt = accountID, info = "WW-2SKD-v1")
        └───────────────── XOR ─────────────┘
                           ▼
                 Account Unlock Key AUK (256-bit)
                           │ AES-GCM wrap
                           ▼
                 Keyset {Ksym (256-bit), X25519 private key, Ed25519 private key}
                     │                      ▲                      │
                     │ AES-GCM wrap          │ HPKE unwrap           │ signs membership + change log
                     ▼                      │                      ▼
            Personal vault key  ◄── per-vault VK (256-bit), one per vault, wrapped to each member's X25519 pk
                     │
                     │ AES-GCM(VK, aad = recordID||vaultID||keyID||schemaVersion)
                     ▼
            Item record ciphertext
```

Rationale and parameters:

- **Secret Key.** 128 bits of CSPRNG output, displayed as `WW` + `-` + 26 characters from a
  31-character alphabet (no `0`, `1`, `I`, `O`, `L`), with a checksum group, mirroring 1Password's
  format so that entropy is a "tad over 128 bits". Stored in the Keychain
  (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, non-synchronisable, Keychain access group
  shared with the extension), additionally wrapped by a Secure Enclave P-256 key where available.
  It is never placed in iCloud Keychain by default (`adr/0004-secret-key-storage.md`).
- **KDF.** PBKDF2-HMAC-SHA256 from CommonCrypto with iterations calibrated at account creation to
  ≥650,000 and ≥300 ms on the creating device; parameters are stored in the account header and have
  an enforced floor (`KDFParameters.minimum`), so a tampered header cannot weaken derivation
  (SEC5). Argon2id would be preferable but is not available from Apple frameworks; the header
  carries an algorithm tag so Argon2id can be added when an audited memory-safe implementation is
  adopted (`adr/0003-kdf.md`). Because SK contributes 128 bits, PBKDF2 hardness protects only
  against an attacker who already has SK, i.e. a device-level compromise.
- **Combining.** XOR of two independent 256-bit keys, as in 1Password; neither input alone yields
  AUK.
- **Keyset.** Ksym wraps vault keys the person owns; X25519 receives HPKE-wrapped vault keys from
  others; Ed25519 signs membership records and change-log segments so a sync store cannot forge
  them. Public keys are published in the account record together with a self-signature.
- **Vault keys.** One per vault; the Personal vault key is wrapped with Ksym; shared vault keys are
  wrapped to each member with HPKE base mode, `Curve25519_SHA256_AES_GCM_256`, info =
  `"WW-vaultkey-v1"||vaultID||keyID`, and the wrap is signed by the sender's Ed25519 key.
- **Records.** Each item version is one AES-GCM ciphertext under the current VK with the AAD above.
  A key rotation produces a new `keyID`; old ciphertexts are re-encrypted lazily by the first
  writer and eagerly on membership removal.

## 5. Envelope and record format (`WatchwordEnvelope`)

```
Envelope v1 (binary, little-endian; also expressible as JSON for debugging)
  magic        "WWE1"
  version      u16   = 1
  kind         u8    (0 = item, 1 = vault-key-wrap, 2 = membership, 3 = account-header, 4 = log-segment)
  keyID        16 B  (UUID of the key that encrypted this record)
  nonce        12 B
  aadLength    u16, aad bytes  (canonical CBOR: recordID, vaultID, schemaVersion, kind, keyID)
  ciphertext   remaining bytes (AES-GCM, tag appended)
```

Rules enforced by the decoder (and by adversarial tests): unknown `version` rejected; `kind`
mismatch with the caller's expectation rejected before decryption; AAD fields are re-derived from
the storage location and compared to the embedded AAD before decryption (a record found in vault B
claiming vault A fails closed); nonces are never reused because they are random per encryption and
keys are rotated well before 2^32 encryptions.

Plaintext payloads are canonical CBOR documents with a `schemaVersion`. Item payload:

```
Item { id, vaultID, title, scopes: [ServiceScope], fields: [Field], tags, notes,
       createdAt, modifiedAt, modifiedBy(deviceID), version(lamport), archived, trashedAt?,
       history: [FieldSnapshot] }
ServiceScope { host, includeSubdomains, scheme?, path?, excludedHosts: [host], nativeAppIDs: [bundleID] }
Field { id, kind, label, value(secret or plain), order, meta }   // kinds listed in PRD F1.2
```

Titles and hosts are inside the ciphertext. A separate **index record** per item (also encrypted,
but with a different, smaller payload: `id, vaultID, hosts, usernames, title`) lets the AutoFill
extension build its in-memory index after unlock without decrypting every full item. There is no
plaintext index on disk; AutoFill QuickType suggestions are instead published to the OS-managed
`ASCredentialIdentityStore`, which the OS protects, and which is cleared when the extension is
disabled.

## 6. Local storage

- SQLite in the App Group container, accessed through a thin, audited wrapper (no ORM). Tables:
  `records(recordID, vaultID, kind, keyID, envelope BLOB, lamport, deviceID, deletedAt)`,
  `changelog(deviceID, seq, envelope BLOB, pushed)`, `sync_state`, `hibp_cache(prefix, fetchedAt,
  suffixes BLOB)`.
- File protection: `completeUntilFirstUserAuthentication` for the ciphertext store (needed so the
  AutoFill extension and background sync can read ciphertext while the device is locked after first
  unlock); key material is never in this file.
- Keychain (access group shared with the extension):
  - `secretKey` — `WhenPasscodeSetThisDeviceOnly`, no access-control prompt (unlock already requires
    the password).
  - `quickUnlockKey` — a random 256-bit Local Unlock Key (LUK) that wraps AUK; access control
    `biometryCurrentSet` (iOS) or `biometryCurrentSet .or .watch` / `.companion` (macOS, F5.3),
    `WhenPasscodeSetThisDeviceOnly`. Enrolment change invalidates it automatically. Its creation time
    and failure counter live alongside so F5.4 can expire it.
  - `deviceSigningKey` — Secure Enclave P-256 key used to sign this device's change-log segments
    in addition to the account Ed25519 key (lets other devices distinguish which device wrote what).

## 7. Sync

### 7.1 Model: per-device append-only change logs plus snapshots

Each device appends **log segments** (envelopes of kind 4, each containing one or more item
versions or membership operations, signed with the account Ed25519 key and the device key) to its
own stream `vault/<vaultID>/log/<deviceID>/<seq>`. No two devices ever write the same object, so
the transport never sees a write conflict. Periodically, the device with the lowest device ID among
those online writes a **snapshot** (`vault/<vaultID>/snapshot/<lamport>`) and older segments are
garbage-collected once every known device acknowledges the snapshot.

Merging: item versions carry a Lamport clock and device ID; the highest (lamport, deviceID) wins per
field group; losers are kept in the item's history (F7.4). Membership operations are totally
ordered by the owner's signature chain; a member's device only accepts a membership change signed
by a current admin as of the previous state.

### 7.2 Transport A: CloudKit (primary)

- Container `iCloud.<bundle>`; the private database holds the account header, the personal vault
  zone, and one custom zone per shared vault the person owns; the shared database holds zones
  others shared with them.
- Record types: `WWObject(kind, vaultID, keyID, lamport, deviceID, payload: encrypted bytes)`. The
  payload is our envelope, stored in `encryptedValues` so CloudKit adds its own iCloud-Keychain-based
  layer on top. Fields used for server-side ordering (`lamport`, `deviceID`, `kind`) are
  unencrypted but carry no secrets. (`CKRecord.Reference` cannot be encrypted and is not used.)
- Sharing: a zone-wide `CKShare` per shared vault; invitees are added by Apple ID lookup; the
  transport permission mirrors the vault role (`readWrite` or `readOnly`). The cryptographic grant
  (HPKE-wrapped VK) is a separate membership record, so transport membership without a wrapped key
  yields nothing.
- Engine: `CKSyncEngine` drives upload/download scheduling and push; our merge layer is
  transport-agnostic.
- Failure handling: `CKErrorUserDidResetEncryptedDataKey` / `zoneNotFound` means CloudKit lost its
  own key material; because our envelope is independently decryptable, the client re-uploads from
  local state (the behaviour Apple prescribes) with no data loss. `userDeletedZone` prompts the
  person.
- Observed cost: encrypted fields cannot be queried, which is fine because the change-log model
  only needs ordered fetches by zone.

### 7.3 Transport B: files (iCloud Drive or any Files-app provider)

- Layout mirrors 7.1 as files: `Watchword/<accountID>/vault/<vaultID>/log/<deviceID>/<seq>.wwe`
  and `.../snapshot/<lamport>.wwe`. Files are immutable once written (write to temp, then atomic
  rename), which removes the KeePass single-file conflict problem.
- iCloud Drive: ubiquity container, every access through `NSFileCoordinator`, an `NSFilePresenter`
  for change notification, and a reconciliation pass that lists the directory on each wake. Any
  `NSFileVersion` conflict on an immutable file is treated as corruption and the newer copy is
  discarded after signature verification of the other.
- Other providers: the person picks a folder with the document picker; a security-scoped bookmark
  is stored; polling on foreground and a `BGAppRefreshTask`/`NSBackgroundActivityScheduler` cadence.
- Sharing uses the provider's shared folder; members exchange public keys through the same folder
  (`members/<accountID>.pub`, self-signed) and verify fingerprints out of band as in CloudKit.

### 7.4 Sync while locked

Downloads and uploads of already-encrypted segments need no keys; merging into the item store needs
VK, so merge is deferred until unlock. The AutoFill extension works from the last merged state.

## 8. Sharing protocol

1. Owner O creates vault V, VK, and a membership record `M0 = sign(O, {vaultID, epoch 0, members:
   [O: admin]})`.
2. O invites U: transport share is sent (CloudKit share URL or folder share). O fetches U's
   published X25519/Ed25519 public keys and shows U's fingerprint (`SHA-256(pkX||pkEd)` rendered as
   a 60-digit safety number and QR). U sees O's fingerprint on acceptance. Both must confirm (F4.2).
3. O writes `W = HPKE.seal(pk_U, VK, info)` plus `M1 = sign(O, {epoch 1, members: [O, U(role)]})`.
4. U's device verifies M1's signature against O's verified key, unwraps VK, and stores it wrapped
   under its own Ksym.
5. Removal of U: O generates VK', re-encrypts all live records of V with VK' (new keyID), writes
   wraps for all remaining members, writes `M2` with U removed and `keyID'`, and removes U from the
   transport share. Devices of remaining members accept VK' only if M2 is signed by an admin per M1.
   Records still under the old keyID after M2 are readable by U only if they already had them;
   nothing new is encrypted to the old key.
6. Leaving is the same as removal, initiated by the member; admins perform the rotation on next
   sync (the leaving member cannot generate VK' because it must be signed by an admin).

Admin succession and vault deletion are owner-only operations in v1.

## 9. AutoFill and service matching (`WatchwordMatching`)

Inputs from the OS are `ASCredentialServiceIdentifier` values (domain or URL). Normalisation:
parse as URL when type is `.URL`; take `host`, lowercase, strip trailing dot, IDNA-normalise;
reject identifiers with user-info or non-host content.

Scope matching produces a **specificity** score per (item, scope): exact host match scores
`2 × labelCount + 1`; subdomain match (host ends with `"." + scope.host` and
`includeSubdomains`) scores `2 × scopeLabelCount`; `excludedHosts` veto. An item's score is the
best of its scopes. Ranking then applies **shadowing**: an item is *shadowed* if another matching
item has a strictly higher score. Shadowed items are shown under "Other accounts on this site" and
never pre-selected or auto-filled (F6.6).

Scenario S1: retail item scoped `amazon.com` (subdomains on); AWS item scoped
`signin.aws.amazon.com` and `console.aws.amazon.com`. On `www.amazon.com`, only retail matches. On
`signin.aws.amazon.com`, both match but AWS scores higher and retail is shadowed. The person can add
`aws.amazon.com` to the retail item's `excludedHosts` to hide it entirely.

Published identities: for QuickType we publish one `ASPasswordCredentialIdentity` per
(item, scope host, username) with `rank` set from specificity, one `ASPasskeyCredentialIdentity`
per passkey, and (iOS 18+) one `ASOneTimeCodeCredentialIdentity` per TOTP field. Whether the OS
itself prefers the more specific subdomain identity is not documented and will be verified on
device in the first integration milestone; our in-extension ranking is authoritative regardless.

Passkeys: the extension signs `authenticatorData || clientDataHash` with the item's P-256 key,
increments no counter (Apple's guidance for synced passkeys), supports `prf` (HMAC-secret derived
from a per-passkey 32-byte secret stored in the field) and `largeBlob` storage in the item.

## 10. Unlock state machine

```
Locked ──password ok──▶ Deriving(AUK) ──▶ Unlocked(keys in SecureMemory)
  ▲   ──quick unlock ok (LUK from Keychain, policy ok)──▶ Unlocked
  │                                                        │ idle/background/sleep timer,
  └──────────────── zeroise ◀───────────────────────────────┘ lock command, policy expiry
```

Quick-unlock policy (`UnlockPolicy`) is a pure function of (now, lastPasswordUnlock,
failedAttempts, appVersion, enrolmentChanged, settings) → `.allowed | .requirePassword(reason)`,
which makes F5.4 unit-testable. The extension uses the same policy with its own `LAContext`.

## 11. Secure memory

`SecureMemory` is the only module allowed to use unsafe pointers. It provides `SecureBytes`
(heap buffer, `mlock`-style page locking where permitted, explicit `zeroise()` on `lock()` and in
`deinit`, no `CustomStringConvertible`) and `SymmetricKey` bridging for CryptoKit. All other
modules compile with `-strict-memory-safety` warnings promoted to errors in CI
(`adr/0001-memory-safe-language.md`).

## 12. Password generation (`WatchwordGenerator`)

Uniform sampling with `SystemRandomNumberGenerator` (backed by the OS CSPRNG) via
`Int.random(in:using:)`, which is unbiased. "Require each selected class" is implemented by
rejection sampling (regenerate until satisfied) so the output distribution stays uniform over the
accepted set. Entropy is reported as `length × log2(alphabetSize)` for random mode (conservatively
reduced by the rejection constraint), `words × log2(7776)` for passphrases with the EFF large list,
and `digits × log2(10)` for PINs. Site password rules from `ASGeneratePasswordsRequest` are mapped
to generator options.

## 13. Hygiene (`WatchwordHygiene`)

- HIBP: `SHA1(password)` → prefix 5 hex → `GET https://api.pwnedpasswords.com/range/<prefix>` with
  `Add-Padding: true` and `User-Agent: Watchword/<version>`; the response is parsed leniently,
  zero-count lines are discarded, the suffix set is cached by prefix for 7 days in the ciphertext
  store (it is public data, but caching also hides re-check timing). Plaintext passwords never
  leave `SecureMemory` except as the SHA-1 digest held transiently.
- Scheduling: on item save; on unlock for items modified since `lastScanAt`; weekly full scan via
  `BGProcessingTask` (iOS) / `NSBackgroundActivityScheduler` (macOS) **only while keys are
  resident**; if the vault locks mid-scan the task resumes on next unlock. No hashes are persisted
  to allow scanning while locked (`adr/0005-hibp-while-locked.md`).
- Strength: vendored zxcvbn-class estimator; reuse detection via a per-unlock in-memory map of
  `HMAC(Ksym-derived key, password)` → item IDs (never persisted); age and 2FA-availability checks.

## 14. Import and export (`WatchwordInterchange`)

- Parsers are pure functions `Data → [ImportedItem]` with hard limits (100 MB archive, 50,000
  entries, zip-slip path checks, decompression ratio cap of 100:1).
- 1PUX: unzip `export.data`, walk `accounts[].vaults[].items[]`; map `overview.title`,
  `overview.urls`, `details.loginFields` (username/password designations), `details.sections[]
  .fields[]` by field type (`concealed`, `string`, `totp`, `url`, `email`, `phone`, `date`,
  `creditCardNumber`, ...), `categoryUuid` to item kind. Unknown fields become custom fields.
- CSV: RFC 4180 parser; header mapping tables for 1Password 8 (`Title,Url,Username,Password,OTPAuth,
  Favorite,Archived,Tags,Notes`), 1Password 7 (`URL`), and Apple (`Title,URL,Username,Password,
  Notes,OTPAuth`). Export neutralises formula injection by prefixing `=+-@` cells with `'`.
- CXF: encode/decode CXF v1.0 JSON for `basic-auth`, `passkey`, `totp`, `api-key`, `note`,
  `custom-fields`; security questions and PINs export as `custom-fields`. Credential Exchange on iOS
  26/macOS 26 uses `ASCredentialExportManager`/`ASCredentialImportManager`; on earlier OSes the CXF
  file can still be produced for manual transfer.
- Plaintext exports require password re-entry, display the warning, and are written with
  `completeUnlessOpen` protection to a location the person chooses.

## 15. Module and target layout

```
Package.swift (SwiftPM, tools 6.0, Swift 6 language mode)
  Sources/WatchwordModel        pure data types, Codable/CBOR, scopes, fields
  Sources/WatchwordMatching     host normalisation, scope scoring, shadowing
  Sources/WatchwordGenerator    password / passphrase / PIN generation, entropy
  Sources/WatchwordEnvelope     envelope format, KDF parameter validation
  Sources/WatchwordCrypto       2SKD, keyset, vault keys, HPKE wrap  (CryptoKit)   [milestone 1]
  Sources/SecureMemory          SecureBytes (only unsafe code)                      [milestone 1]
  Sources/WatchwordStore        SQLite ciphertext store                            [milestone 2]
  Sources/WatchwordSync         change log, merge, SyncTransport protocol          [milestone 3]
  Sources/WatchwordSharing      membership, invitations, rotation                  [milestone 4]
  Sources/WatchwordHygiene      HIBP client, strength, reuse                       [milestone 5]
  Sources/WatchwordInterchange  1PUX/CSV/CXF                                       [milestone 6]
  Sources/WatchwordKit          VaultSession façade used by all UI targets         [milestone 2+]
  Sources/WatchwordTestSupport  in-memory fakes for every port, scenario builders
Apps/ (Xcode project generated with XcodeGen from project.yml)
  Watchword (iOS/iPadOS), Watchword (macOS), AutoFillExtension (iOS), AutoFillExtension (macOS)
```

Ports (protocols) injected into the core: `KeychainStore`, `BiometricGate`, `RandomSource`,
`Clock`, `HTTPClient`, `SyncTransport`, `CredentialIdentityPublisher`, `FileAccess`. Production
adapters live in `Apps/`; fakes live in `WatchwordTestSupport`.

## 16. Open questions tracked as ADR candidates

- Whether to offer iCloud Keychain storage of the Secret Key as an opt-in convenience (`adr/0004`).
- Argon2id adoption path (`adr/0003`).
- Whether per-item keys (wrapped by VK) are worth the complexity to make rotation O(members)
  instead of O(items); deferred until vault sizes justify it.
- OS QuickType behaviour with overlapping domain identities (verify on device, milestone 2).
