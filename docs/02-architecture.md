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
| A6 Malicious web page / app | Control of the page requesting AutoFill | Credentials for a different service | Service-scope matching enforced by type and one authorization chokepoint (SEC6), scope policy against over-broad scopes, normalisation that cannot invent a match, no auto-fill of ambiguous or shadowed matches, look-alike warning (§9.1) |
| A7 Malicious import file | Crafted CSV/1PUX/CXF | Code execution, resource exhaustion, data exfiltration | Hardened parsers (SEC7) |
| A8 Local malware with user privileges (macOS) | Can read process memory of unlocked app in the worst case | Long-lived plaintext after lock | Out of scope while unlocked (OS boundary); minimised by zeroisation and short lock timers |

Also disclosed by design, and therefore worth naming rather than discovering later: enabling
QuickType publishes item hosts and usernames to the OS-managed `ASCredentialIdentityStore`. That
is a plaintext index of *metadata* outside this app's control (never secrets), which is the price
of QuickType; F6.8 lets a person exclude an item from it.

Explicitly out of scope: a compromised OS or jailbroken device while the vault is unlocked,
side-channel attacks on the Secure Enclave, and coercion of the person. Also out of scope, but
only because it is unachievable rather than unimportant: zeroising decrypted field values that
have become Swift `String`s (PRD SEC4).

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
        │ PBKDF2-HMAC-SHA256 over NFKD(password)
        │ (salt = HKDF(ikm = saltA, salt = accountID, info = "WW-salt-v1"), iterations ≥ 650 000)
        ▼                                   ▼ HKDF-SHA256
   Kp (256-bit)                         Ks (256-bit) = HKDF(SK, salt = accountID, info = "WW-2SKD-v1")
        └──── HKDF(Kp ‖ Ks, salt = accountID, info = "WW-AUK-v1") ────┘
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

- **Secret Key.** 128 bits of CSPRNG output, displayed as `WW-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-CC`:
  26 data characters from a 31-character alphabet (no `0`, `1`, `I`, `O`, `L`) carrying the value in
  base 31 (31^26 ≈ 2^128.8, so every key fits and anything ≥ 2^128 is rejected), plus a two-character
  check group. The check characters are `c₁ = Σ dᵢ·3^(i+1)` and `c₂ = Σ dᵢ·3^(2(i+1))` mod 31 (3 is a
  primitive root mod 31), which detects every one- or two-character error, including every adjacent
  transposition. It is a typo check, not a MAC. Implemented in `WatchwordCrypto.SecretKey`. Stored in the Keychain
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
- **Combining.** `AUK = HKDF-SHA256(ikm = Kp ‖ Ks, salt = accountID, info = "WW-AUK-v1")`. 1Password
  XORs the two; neither construction lets one input alone yield AUK, but HKDF has no catastrophic case
  if the inputs are ever equal or related (XOR of equal inputs is the all-zero key). Decided in
  milestone 1, settling review finding D7 (ADR 0003). The password is NFKD-normalised and not trimmed.
- **Keyset.** Ksym wraps vault keys the person owns; X25519 receives HPKE-wrapped vault keys from
  others; Ed25519 signs membership records and change-log segments so a sync store cannot forge
  them. Public keys are published in the account record together with a self-signature
  (`PublicKeyBundle`, whose initializer rejects low-order X25519 points, small-order Ed25519 keys —
  for which one signature verifies for every message — and bad self-signatures).
  Every signature covers `"WW-sig-v1" ‖ 0x00 ‖ domain ‖ message`, with one domain per purpose
  (key bundle, key grant, membership, log segment), so no signature verifies for another purpose.
  The keyset is wrapped under AUK as an `accountHeader` envelope bound to the account ID.
- **Device keys.** Each device also has a signing key of its own, registered in the account's device registry
  (§7.8): P-256 in the Secure Enclave where there is one, an Ed25519 key in the Keychain otherwise (the only
  kind built so far). Everything a device writes to the sync store carries the account key's signature *and*
  its own, over `"WW-devsig-v1" ‖ 0x00 ‖ domain ‖ deviceID ‖ message` for the device's, so the keyset alone does
  not make a writer, and a device can be revoked.
- **Enrolment key.** `Ed25519(HKDF-SHA256(ikm = AUK, salt = accountID, info = "WW-enrol-v1"))`: a signing key
  whoever knows the password and the Secret Key can derive, and nobody else. A new device registers itself with
  it; a password change is signed with the key of the password it replaces (§7.8).
- **Vault keys.** One per vault; the Personal vault key, and the key of every other vault the account owns, is
  wrapped with Ksym (a `vaultKeyWrap` record named by the key's ID in its vault); shared vault keys are
  wrapped to each member with HPKE base mode (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM),
  info = `"WW-vaultkey-v1"||vaultID||keyID`, associated data binding sender, recipient and the
  recipient's X25519 key, and the whole wrap (`VaultKeyGrant`) signed by the sender's Ed25519 key.
  The recipient checks, before decrypting, that the grant's vault and key IDs are those of the
  storage location it was found in (entitlement is per vault, so a sender entitled for one vault
  must not be able to install a key into another), then sender, signature and addressing.
- **Records.** Each item version is one AES-GCM ciphertext under the current VK with the AAD above.
  A key rotation produces a new `keyID`; old ciphertexts are re-encrypted lazily by the first
  writer and eagerly on membership removal.

## 5. Envelope and record format (`WatchwordEnvelope`)

```
Envelope v1 (binary, little-endian; also expressible as JSON for debugging)
  magic        "WWE1"
  version      u16   = 1
  kind         u8    (0 = item, 1 = vault-key-wrap, 2 = membership, 3 = account-header, 4 = log-segment,
                    5 = snapshot, 6 = vault-metadata, 7 = vault-directory, 8 = device-registry,
                    9 = archive: everything inside an encrypted Watchword archive, §14.1)
  keyID        16 B  (UUID of the key that encrypted this record)
  nonce        12 B
  aadLength    u16, aad bytes  (canonical CBOR map {1: recordID, 2: vaultID, 3: schemaVersion,
                                4: kind, 5: keyID, 6: recordVersion})
  ciphertext   remaining bytes (AES-GCM, tag appended)
```

The AES-GCM associated data is the **entire serialized header**, not only the `aad` field, so a byte
changed anywhere before the ciphertext fails authentication even if no parser check covers it.
`recordVersion` is the record's Lamport version: binding it means a sync store cannot present an old
ciphertext as a newer version. Presenting it as its true older version is harmless: the sync layer's merge only
moves forward (§7.5), so an old version can never displace newer values.

Rules enforced by the decoder (`Envelope.parse`, then `RecordCipher.open`; all covered by
adversarial tests), in order: envelopes over 64 MiB rejected before any copy; magic; unknown
`version` rejected; `kind` mismatch with the caller's expectation rejected; key ID compared with the
expected key; the AAD re-derived from the storage location and compared byte for byte with the
embedded AAD (a record found in vault B claiming vault A fails closed, as does one relabelled as a
newer version or another schema); a ciphertext shorter than the tag rejected — all before
decryption. Decryption either returns the whole plaintext, into `SecureBytes`, or fails with one
undifferentiated error. Nonces are 96 random bits per encryption. Each key also carries a ledger of
every nonce sealed under it, shared by every copy of the key and every caller (record seals and key
wraps alike), and a repeat is refused: a tripwire for a broken generator. Keys are rotated well
before the 2^32 random-nonce limit. Callers that know their record is small pass a tighter size cap
(wrapped keys use 1 KiB), so a hostile store cannot make a 113-byte keyset cost tens of megabytes to
reject.

Plaintext payloads carry a `schemaVersion` (bound into the AAD, so a record relabelled with another
schema fails closed). The item payload is JSON with sorted keys (`WatchwordKit.ItemCodec`), not
canonical CBOR: it is decrypted and decoded but never signed or compared, so it needs no canonical
form, and decoding it needs a parser for strings and nested structures, which `CBORValue`
deliberately lacks so that attacker-supplied CBOR never reaches a parser of ours. Authentication
proves only that a holder of the vault key wrote the payload — from milestone 4 any member of a
shared vault (A4) — so the decoder still treats it as hostile: a 1 MiB cap before decoding, and the
decoded `id`, `vaultID` and `version` must equal the storage location's or the record is refused
(`VaultError.recordMismatch`). Item payload:

```
Item { id, vaultID, title, scopes: [ServiceScope], fields: [Field], tags, notes,
       createdAt, modifiedAt, version(lamport), archived, trashedAt?, keptAfterDeletion, history: [FieldSnapshot],
       revisions: [group: GroupStamp], conflicts: [group: [ConflictingValue]], clock: VersionVector,
       noteLines: [NoteLine] }          // the last four are sync metadata (§7.5); absent before milestone 3
ServiceScope { host, includeSubdomains, scheme?, path?, excludedHosts: [host], nativeAppIDs: [bundleID] }
Field { id, kind, label, value(secret or plain), order, meta }   // kinds listed in PRD F1.2
```

A vault's own description is a record of kind 6 whose record ID is the vault's ID, sealed under the vault key:
`VaultMetadata { vaultID, name, createdAt, modifiedAt, version, writtenBy? }` (`VaultMetadataCodec`: JSON with
sorted keys, 16 KiB at most, a name of at most 256 characters, and the same identity check against the row).
`writtenBy` is the (version, device) of the write that chose the description, present when a row carries a
description on rather than writing one (§7.7); it is never above the row's own version, or the row does not open.
A vault's name is as private as an item's title. Kinds 7 and 8 are not sealed payloads of their own: they name rows of the
local store that hold a vault's directory entry and a device-registry entry (§6, §7.7, §7.8), and kind 8 is also
the kind under which a device's name is sealed inside its registry entry.

Titles and hosts are inside the ciphertext. A separate **index record** per item (also encrypted,
but with a different, smaller payload: `id, vaultID, hosts, usernames, title`) lets the AutoFill
extension build its in-memory index after unlock without decrypting every full item. Watchword writes no
plaintext index of its own; AutoFill QuickType suggestions are instead published to the OS-managed
`ASCredentialIdentityStore`, which the OS protects and which is cleared when the extension is
disabled. That store is still a metadata disclosure outside our control — see the threat model —
so F6.8 allows per-item exclusion. The index record is built with the AutoFill extension (milestone 5);
milestone 2 stores full item records only.

## 6. Local storage

- SQLite in the App Group container, accessed through a thin, audited wrapper (no ORM;
  `SecureMemory.SQLiteConnection`, which only binds parameters and never interpolates). Milestone 2
  tables, both `STRICT` with length checks on every UUID column: `account` (one row: account ID,
  device ID, personal vault and key IDs, KDF parameters, salt, AUK key ID, the wrapped keyset and
  its version, the credential generation, Emergency Kit confirmation) and `records(record_id, kind,
  vault_id, key_id, version, device_id, envelope BLOB)` keyed by `(record_id, kind)`. The sync layer's
  state, staged downloads, pending deletions and quarantine (`WatchwordSync.SyncStateStore`) are in a second
  database beside it, `sync.sqlite` (`SQLiteSyncStateStore`, milestone 3), opened and schema-checked the
  same way; a separate file keeps `WatchwordStore` ignorant of sync, and nothing needs both in one
  transaction (tombstones are recorded after the deletion commits, and the engine's state can be rebuilt by a
  reconciling sync, so a state row that does not decode is read as no state). Still to come: the breach-check
  prefix cache and scan ledger, as sealed local records rather than a plaintext `hibp_cache` table (§13.2,
  §13.3; milestone 6). The schema version is `PRAGMA user_version`; a newer one is refused, not
  misread. A commit may name the version it read of each record (`StoreChange.expectations`), so a writer
  that awaited something in between — the sync engine waiting on its merger while the person saves the same
  item — fails with `versionConflict` instead of overwriting the newer save.
- Account-level rows live in `records` too, under the account's own ID where a vault's would be, so nothing
  about the schema changed: the published account header (kind 3, record ID the account's; any other record ID
  is a candidate header for a password changed elsewhere), one row per device-registry entry (kind 8, named by
  the first half of the entry's SHA-256), and one directory row per vault (kind 7, record ID the vault's:
  `0x01`, or `0x02` and the signed statement that the vault was deleted). None is trusted for being there: a
  registry entry is re-hashed and its signatures re-checked whenever the registry is evaluated, a candidate
  header and a vault deletion count only if the account key and a registered device signed them, and the
  Keychain anchor below says how far the registry had got (§7.7, §7.8).
- The file is untrusted input (A8 can edit it while the app is locked; a restored backup is anyone's).
  The connection is opened with `SQLITE_OPEN_NOFOLLOW` (the database path is resolved first, since
  `/var` is itself a link), `trusted_schema = OFF`, `cell_size_check = ON` and `secure_delete = ON`;
  every row is re-validated when read and reported as `malformedRow` rather than repaired; SQLite
  itself caps any value near 64 MiB (`SQLITE_LIMIT_LENGTH`). On open the schema must equal exactly
  what this code creates — `trusted_schema = OFF` does not stop plain triggers, and a planted one
  could silently undo writes or deletions. Erasing the account truncates the write-ahead log, which
  otherwise keeps the old pages. Versions only move forward (`versionRegression`), and creating an
  account can never overwrite one.
- Every column except `envelope` is the record's storage location: readers rebuild the expected
  `EnvelopeContext` from the columns, so editing a row's vault, record ID, key ID, kind or version
  makes it unreadable before decryption (adversarial suite "local vault store"). One unreadable
  record is listed as such (`ItemListing.unreadable`), never hidden, repaired or overwritten.
- Rolling a row back: an attacker who can write the file can replace an item with an *older* ciphertext
  together with its older version column, which is self-consistent, or delete the row. Neither is published
  as a change (deletions reach the sync layer only when the session makes them, §7.5), and a reconciling
  sync replays the signed log, which lives outside the file, and restores the newest version (adversarial
  suite "sync log"). A vault that has never synced has no log to restore from.
- File protection: `completeUntilFirstUserAuthentication` for the ciphertext store (needed so the
  AutoFill extension and background sync can read ciphertext while the device is locked after first
  unlock); key material is never in this file. The device's own sealed, unsynced records (the hygiene ledger and
  prefix cache, §13.8) are files beside it, in `DeviceLocal/` (`FileDeviceLocalStore`): the same protection class on
  iOS, excluded from backup, written atomically, and read only as regular files within a size limit.
- Keychain (access group shared with the extension):
  - `secretKey` — `WhenPasscodeSetThisDeviceOnly`, no access-control prompt (unlock already requires
    the password).
  - `quickUnlockKey` — a random 256-bit Local Unlock Key (LUK) that wraps AUK; access control
    `biometryCurrentSet` (iOS) or `biometryCurrentSet .or .companion` (`.watch` before macOS 15)
    (macOS, F5.3), `WhenPasscodeSetThisDeviceOnly`; never `.userPresence`, `.devicePasscode` or
    `.biometryAny`, which would let a known passcode or a newly enrolled face release it. Enrolment
    change invalidates it automatically. A fresh LUK is generated on every password unlock.
  - `quickUnlockState` — the policy inputs of F5.4 (password-unlock time, failure counter, app
    version, credential generation, biometric domain state) and the AUK sealed under the LUK as an
    `.accountHeader` envelope bound to the AUK's key ID and the credential generation. Kept in the
    Keychain rather than the database so the failure counter cannot be reset by editing a file.
  - `accountSigningKey` — the account's Ed25519 *public* key, copied from the keyset at every unlock, so
    sync can check signatures on downloads while the vault is locked (§7.4). Not secret; in the Keychain
    rather than the database so that A8, who can edit the file, cannot substitute a key of their own.
  - All items: `kSecUseDataProtectionKeychain` (iOS semantics on macOS), non-synchronisable,
    accessed through `WatchwordPlatform.SystemKeychainStore`.
  - `deviceSigningKey` — this device's own signing key, with which it signs everything it writes to the sync
    store beside the account Ed25519 key (§7.8). Reached through the `DeviceKeyStore` port: a Secure Enclave
    P-256 key where there is one (that adapter is Apple-only and not built yet), otherwise — and today — a
    software Ed25519 seed stored here with the device ID it belongs to (`KeychainDeviceKeyStore`).
  - `deviceRegistryAnchor` — what this device trusts of the device registry: the genesis entry, the credential
    entry it follows and the newest entries it has applied. Not secret; in the Keychain so that A8 can neither
    substitute a registry nor roll one back to before a revocation.
  - `deviceLocalSecret` — 32 random bytes this device makes for itself, mixed with the keyset into the key that
    seals its unsynced local records (the hygiene ledger and prefix cache, §13.8), so that another device of the
    account, which holds the same keyset, can neither read them nor plant its own.

## 7. Sync

### 7.1 Model: per-device append-only change logs plus snapshots

Each device appends **log segments** (envelopes of kind 4, each containing one or more item
versions or membership operations, signed with the account Ed25519 key and the device key, §7.8) to its
own stream `vault/<vaultID>/log/<deviceID>/<seq>`. No two devices ever write the same object, so
the transport never sees a write conflict. Periodically, the device with the lowest device ID among
those that wrote since the last snapshot writes a **snapshot** (`vault/<vaultID>/snapshot/<lamport>-<deviceID>`;
the device ID keeps two simultaneous snapshots from sharing a name) and older segments are
garbage-collected once every known device acknowledges the snapshot.

Merging: item versions carry a Lamport clock and device ID; the highest (lamport, deviceID) wins per
field group; losers are kept in the item's history (F7.4). §7.5 describes what milestone 3 built. Membership operations
do not travel in log segments: they are a signed chain of their own, beside the log (§8.2, §8.3).

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
  person. As decided on 2026-11-17, every one of these prompts the person first (§7.10).
- Observed cost: encrypted fields cannot be queried, which is fine because the change-log model
  only needs ordered fetches by zone.
- **As built** (`WatchwordPlatform.CloudKitTransport`, milestone 3; not yet run against CloudKit, and not wired into
  the app): one custom zone, `Watchword`, in the private database for the whole account. Each object is a `WWObject`
  record whose record name is the object's name with `/` written `.` (an exact mapping both ways), with two fields: a
  plain, queryable `name` — no more than the record name says — and the bytes in `encryptedValues["payload"]`, or in a
  `CKAsset` (`payloadAsset`) above 512 KiB, since a record's own fields are capped near 1 MB. The `kind`, `lamport`
  and `deviceID` fields above are not written: the name carries them and nothing queries them. A record is saved only
  new, with `.ifServerRecordUnchanged`, so an existing one fails with `serverRecordChanged` (`objectExists`); nothing
  fetched is saved back. A listing queries `name BEGINSWITH` the prefix, fetching the name only, and follows the cursor
  for at most `maximumPages` pages, twice `maximumListedObjects` raw results and `maximumListedObjects` names, past
  which it is `listingTooLarge` and the sync stops (a store answering without end must not keep one running); a record
  counts only if its ID and `name` agree, and a read takes exactly one payload within the reader's limit, never a plain
  field. A missing or unavailable asset is `objectUnreadable`: that object alone is refused and its stream waits at it,
  so one record broken by A1 cannot keep this device from publishing. **The zone and the person's deletion:** the first
  create makes the zone, never a read, and listing or creating it marks it seen in a `SyncStoreMarker` on this device.
  A zone that is missing once seen was deleted (the person's "delete data" in iCloud settings purges it, and CloudKit
  then says only `zoneNotFound`), so it is `SyncTransportError.storeReset` for every operation, as are
  `userDeletedZone` and a reset encryption key; it is never recreated or read as empty by a sync, and only the
  person's choice to start again (`startStoreAgain`, §7.10) recreates it. Errors map to the
  transport's typed errors (`CloudKitErrors`): throttling with CloudKit's `retryAfterSeconds` (`rateLimited`, which
  `AutoSyncPolicy` honours within its bounds, §7.9), `quotaExceeded`, `notAuthenticated`, the network
  (`unavailable`); each stops a sync as being offline does, and the report says which (`transportFailure`). The
  transport reaches CloudKit through `CloudKitDatabase`, a seam over `CKDatabase` that `SystemCloudKitDatabase` only
  forwards, so every decision is tested against a fake. Not built: `CKSyncEngine` (pushes reach the app's
  `AutoSyncDriver` as remote-change hints), per-shared-vault zones and the shared database (milestone 4), and the
  manual integration workflow; an opt-in test runs the transport contract against a development container from a
  signed host (`WATCHWORD_CLOUDKIT_CONTAINER`). The re-upload after a reset that the failure-handling point above
  describes is §7.10: it is never automatic (that point's "prompts the person" holds for every kind of reset, a
  reset encryption key included), and its CloudKit half, `startStoreAgain`, is drafted with the rest.

### 7.3 Transport B: files (iCloud Drive or any Files-app provider)

- Layout mirrors 7.1 as files: `Watchword/<accountID>/vault/<vaultID>/log/<deviceID>/<seq>.wwe`
  and `.../snapshot/<lamport>.wwe`. Files are immutable once written (write to temp, then atomic
  rename), which removes the KeePass single-file conflict problem.
- iCloud Drive: ubiquity container, every access through `NSFileCoordinator`, an `NSFilePresenter`
  for change notification, and a reconciliation pass that lists the directory on each wake. An
  `NSFileVersion` conflict on an immutable file, or a second create that iCloud renamed, means one
  name was written twice. The transport resolves nothing: it hands the engine every copy, and the
  engine keeps what verifies (owner decision, 2026-11-17: "try to detect and merge them"; §7.5,
  "Conflict copies").
- Other providers: the person picks a folder with the document picker; a security-scoped bookmark
  is stored; polling on foreground and a `BGAppRefreshTask`/`NSBackgroundActivityScheduler` cadence.
- Sharing uses the provider's shared folder; members exchange public keys through the same folder
  (`members/<accountID>.pub`, self-signed) and verify fingerprints out of band as in CloudKit.
- **As built for iCloud Drive** (`WatchwordPlatform.CoordinatedFileSyncTransport`, milestone 3; not yet run in a
  ubiquity container, and not wired into the app): the portable `FileSyncTransport`, whose rules (names, no links,
  sizes, create-once by hard link) run inside `NSFileCoordinator` accessors through its synchronous forms. A listing is
  a metadata-only coordinated read of the directory it walks; a fetch a coordinated read without changes; a create a
  coordinated write; a delete one for deleting. Its root is `<ubiquity container>/Watchword/<accountID>`, outside
  `Documents`. A file iCloud has not downloaded — a legacy `.<name>.icloud` placeholder, or a dataless or evicted file
  (`ubiquitousItemDownloadingStatus` `notDownloaded`) — is listed, fetched as absent after
  `startDownloadingUbiquitousItem`, and counts as existing for a create; absence is safe, as a stream waits at its gap.
  The download status is checked before the coordinated read, so a file known to be absent is not waited for, and
  again inside it, so one evicted in between is still read as absent. Each access gives up at a deadline (two minutes, counting only the wait for the grant; once the accessor runs
  nothing gives it up, so a process too busy to schedule its tasks cannot fail a granted access) or on
  cancellation and cancels its coordinator: a fetch so given up is `objectUnreadable` (that object waits, the sync goes
  on), a listing, create or delete `unavailable`. `SyncFolderPresenter` (`NSFilePresenter` on the root) turns changes
  into remote-change hints. **Conflict copies** (drafted with the rest; §7.5 has the rules and the reasons). One name
  can hold several copies: the file, each unresolved `NSFileVersion` conflict version of it, and a second create that
  iCloud renamed (`N 2.wwe` beside `N.wwe`; the portable `FileSyncTransport` attributes `N 2` to `N 64`, and nothing
  else, to `N`). A listing says which names hold more than the one file and how many copies (`listWithCopies`:
  the count of `NSFileVersion.unresolvedConflictVersionsOfItem` per file, and the renamed files the walk sees), and `fetchCopies` reads them
  all under one coordinated read, each within the reader's size limit, at most as many as the engine asks for. The
  transport chooses none and resolves none: it never calls `NSFileVersion`'s resolution, never renames a duplicate
  into place, and a plain `fetch` reads the current file as before. Only `delete` — the author collecting its own
  object, when the engine says it may — removes the copies with the object (`removeOtherVersionsOfItem`, the renamed
  files). The legacy placeholder of a renamed copy (`.N 2.wwe.icloud`) is attributed like the copy itself and
  counted once with it, and `fetchCopies` counts it unread and asks for its download; unattributed, a copy present
  only as a placeholder was seen by nobody, and its author collected the name with it unread (review finding R18). Not built either: other providers with a security-scoped bookmark, and their polling.

### 7.4 Sync while locked

Downloads and uploads of already-encrypted segments need no keys; merging into the item store needs
VK, so merge is deferred until unlock. The AutoFill extension works from the last merged state.

### 7.5 As built in milestone 3 (`WatchwordSync`, the portable half)

`WatchwordSync` imports no Apple framework: sealing, opening, signing and verifying reach it through the
`SyncKeyring` port, and field-level merging through the `RecordMerger` port, both implemented with fakes in
`WatchwordTestSupport`, so the whole engine — including the N-device partition simulation and the adversarial
suite "sync log" — runs under `swift test` on Linux. The production keyring, the persistent state store and the
app's conflict UI are described in §7.6, the account's own objects and enrolment in §7.7, the device registry in
§7.8, automatic syncing in §7.9 and starting again after a reset in §7.10; the CloudKit and iCloud Drive transports are in §7.2 and §7.3, built but not yet
run against iCloud or wired into the app (`03-implementation-plan.md`, milestone 3). One engine runs per vault; a vault's log carries its items, its
description (`vaultMetadata`) and its items' synced breach-check results (`scanStatus`, §13.9), each kind merged by
its own merger (`KindRoutingMerger`).

**Objects.** A transport holds `SignedObject`s: `"WWSO" ‖ version ‖ signature ‖ envelope`, where the envelope
is of kind `logSegment` or `snapshot`, sealed under the vault key, with the object's location bound into its
context (record ID = author device, record version = sequence number or Lamport time). So an object moved to
another name, stream, vault or slot fails before decryption, and the signature over the stored envelope can be
checked with public keys alone. The plaintext (`SyncPayload`) is a canonical binary list of record versions —
`StoredRecord`s, ciphertext still — and deletions, plus a vector: for a segment, the author's acknowledgement of
what it has merged; for a snapshot, what it covers. Object names reveal vault and device IDs, counters and
Lamport times to the transport; nothing else.

**Download** (no keys, §7.4). List the vault, fetch every snapshot not yet merged and every segment past what has been
merged, check each signature against the author named in the location, stage what verifies. A forged, moved or
damaged object is reported and skipped; it never stops other streams.

**Merge** (needs the vault key). Staged objects are verified again (the staging area is in the local file, which
A8 can edit), then checked and opened in the order kind, context, AEAD, payload. Each stream is merged strictly in
sequence; a missing or rejected segment stops that stream (`SyncReport.waiting`) rather than being skipped, unless a
merged snapshot already covers it. Before any entry is applied the whole payload is checked: a segment carries only
its author's versions, every record envelope's own context must match the entry carrying it (no record swaps inside a
validly signed segment), and acknowledgement and coverage values must be plausible sequence numbers. Then, per record
(PRD F7.4, F7.6, F7.7):

- A version the device does not have is stored.
- Two different versions go to the merger, which opens both and calls `ItemMerge.merge`. Each item attribute and each
  field (`ItemGroup`) is a multi-value register: every value carries a `GroupStamp` — who wrote it and the
  `VersionVector` of everything that writer had seen — so the merge can tell an edit made *after seeing* another
  (which replaces it) from a concurrent one. Concurrent values of the same group are all kept: one is shown, chosen
  the same way on every device (a deletion first, then the later revision), the others are kept in `Item.conflicts`
  until the person chooses (`ItemMerge.resolve`); an ordinary edit of the group settles what is shown and moves the
  others to `Item.retainedValues`, still kept. Identical concurrent values are one value. The version vector records
  edits only, never the versions that carry merge results, so devices that merged the same edits hold the same state.
  Notes are a line-level sequence CRDT (`NoteText`, an RGA over lines): concurrent edits to different lines all
  survive, and two edits of the same line both appear. Histories are unioned, never shortened by a merge. The order
  of the fields is a last-writer-wins register of its own (`Item.fieldOrder`, stored, so a field removed and brought
  back returns to its place); it holds no field's contents, so of two concurrent reorders the later stands. A
  resolution records what the person had before them (`Item.discards`), so the values it discards stay discarded
  when a copy that still holds them is merged in. Every part names the write that made it — a line's removal
  (`NoteLine.removedBy`), a history entry (`ItemHistoryEntry.writtenBy`) and a discard (`ItemDiscard`) as values do
  by their stamps — which is what lets a shared vault's judge tell a late write's work from anyone else's (§8.10;
  review findings S32, S43); one that names none is read as the work of the row carrying it. The merge is a join — commutative, associative and idempotent, so
  the same versions in any order, grouping and number give the same item — and every edit contains the version it was
  made on: an item is a state-based CRDT. `10-sync-correctness.md` states the model and the argument, component by
  component, and how it is checked (random histories, every small history, and arbitrary metadata). The merger
  answers keep, adopt, or a new version above both, and the commit names the local version it read
  (`StoreChange.expectations`).
- Sync metadata is a claim by whoever wrote the record (an account device, or from milestone 4 a vault member, A4),
  so every record is read the same bounded way before it is merged (`ItemState.init`, `10-sync-correctness.md` §6):
  no count in it may exceed the record's own version, a value filed under a group it does not belong to is not read,
  and repeated identifiers are joined rather than chosen from. The laws above hold for any metadata, not only for
  honest devices'.
- Moving to the trash is the `trashedAt` group, so trashing and a concurrent edit give a trashed item that contains
  the edit. A permanent deletion is a tombstone carrying an *erasure summary* (`ItemErasure`): the version vector of
  what its author had seen, the version of the row erased, the erasing device and when that row was last modified. A
  version it covers is erased; a version holding an edit its author never saw is kept, in the trash, with that edit
  as its last version and `keptAfterDeletion` set — on the deleting device as on every other. To such a version the
  deletion is *a write by the deleting device at the tombstone's revision* (`ItemMerge.settle`), the same on every
  device, so devices that kept the same edits hold the same item; a restore made after it supersedes it and is not
  undone when the tombstone is met again, and one made without seeing it stays beside it as a conflict. Erasing a
  covered version whole is the one step that is not a join (an item is never split); `10-sync-correctness.md` §5
  says what holds instead: no edit the erasure had not seen is ever lost, and devices cannot end up different.
- A record can be erased more than once, on devices that had each seen something the other had not; a device
  remembers the *join* of every erasure of a record it knows (`RecordMerger.joinErasureSummaries`), stamped with the
  later of their stamps, and judges a version against that, so which erasure arrives first decides nothing. For items
  the join is the set of the deletions (`ItemErasures`, set union in one canonical encoding), not one erasure standing
  for both: a version is erased when the deletions had, between them, seen all of it, and otherwise each deletion is
  its own write as above, so no deletion is credited with what another had seen and a device that learned of them in
  either order holds the same item. A device publishes its own deletion even when it already knows a later erasure of
  the same record by another device: that one's author may have seen less. The same holds for its own earlier
  erasure: the person may delete a version that erasure kept, and a kept version keeps its own number, so the second
  deletion's stamp can be the lower. A pending deletion counts as published only once this device has published a
  deletion of the record at or after its stamp *and* the join it holds already contains everything this one had seen.
  An erasure a device already holds is not applied to its local version a second time (a later snapshot may carry it
  again): it erased the version or the version was kept, and applied again it would put back in the trash an item the
  person has since restored. Only a reconciling sync judges again. The engine passes the merger the joined erasure's
  stamp, which depends on the erasures alone (a record's versions climb with every merge; its edits, which are all a
  summary names, do not): a summary naming a row above it is not believed (review finding Y28), and a version kept is
  written above that stamp and the row, at a version of the keeping device's own — the item it holds is the same on
  every device.
- The 30-day purge (F1.5) removes only what the person who trashed an item had seen, as a deletion does, and never
  splits an item: it skips one kept after a deletion, one whose `trashedAt` group holds a conflicting restore, and one
  whose version vector holds an edit the trash's `GroupStamp.seen` does not (`Item.isTrashedByPerson`, F7.7). Those
  stay in the trash until the person restores or deletes them; moving one to the trash again makes it theirs.
- Versions above 2^62, or more than 2^20 above the vault's highest, are quarantined rather than merged (review
  finding U5) — and kept in the sync state store until the person discards them (F7.7).

This is the monotonic check of §5: an older version, replayed by the store or found in an old snapshot, can never
displace newer values, because a value is only ever replaced by one written knowing about it.

**Publish.** Every row this device wrote that is newer than what it last published, and every pending deletion,
goes into the next segment of its stream. Deletions exist only when the session makes them
(`DeletionRecordingStore` records them as it commits them, with the row deleted, so the erasure summary can be made);
a row that has merely gone missing from the database is damage, repaired by a reconciling sync, and is never
propagated as a deletion. A row that came back while its deletion was being made is settled against the deletion
before publishing. Objects are created, never overwritten, and the next sequence number is never below anything the
stream has on the transport, so a device whose state was rolled back never reuses a collected number.

**Conflict copies** (owner decision, 2026-11-17: "try to detect and merge them"). A provider can hold more than one
copy under one object name although objects are created once: iCloud Drive keeps both when a name is created twice
before it has synced (an `NSFileVersion` conflict, or the second file renamed `N 2.wwe`, §7.3), and whoever holds the
store (A1) can manufacture either. Until this was built the transport refused such an object and its stream waited at
it for good. Now the transport says what it holds and the engine decides, as for everything else:

- *The port.* `SyncTransport.listWithCopies` is `list` plus, for each name the provider holds anything besides the one
  current object under, how many copies it holds in all; `fetchCopies` returns their bytes, the current one first, at
  most `maximumCopies` of them and each within `maximumLength` (a copy over either bound is counted in `omitted`, not
  returned, and never fails the call; one that cannot be read *now*, a conflict version or renamed file iCloud has not
  downloaded or a read that failed, is counted in `unread`, asked for where the provider allows it, and never taken
  for examined: R11). Both default to `list` and `fetch`, so a transport that cannot hold two copies
  (CloudKit saves only new records) implements nothing. `delete` removes every copy under the name. There is still no
  "update", and no call that resolves a conflict.
- *Each copy is checked alone, in the existing order.* Identical bytes are one copy. At download: the container, the
  envelope's kind and context against the name (they need no key, so a genuine object of another name planted as a
  copy is junk before any signature is looked at), then both signatures over `name ‖ 0x00 ‖ envelope` against the
  registry (§7.4). At merge, again for every staged copy: kind, context, the signatures, the AEAD, the payload, its
  location, and every entry's own context. Unsigned junk therefore costs one container parse and at most one
  signature check, and is reported (`SyncReport.copiesRefused`); it is never staged.
- *No copy verifies:* the object is refused alone, as a damaged one is (`SyncReport.rejected`, the stream waits at
  it), and the sync and this device's publishing go on. It is never `unavailable`.
- *Exactly one verifies:* it is used, whichever copy the provider calls current. A junk "current" file in front of
  the genuine object, or junk beside it, changes nothing.
- *Several verify:* the same device signed different bytes under one name, which an honest device does only after
  its state was rolled back (a restored backup, A8) and it wrote again before it had seen what its earlier self
  published. In a vault of one account the engine **merges every verifying copy**: the position holds a set of
  payloads, and the entries of each are applied through the same per-entry path as any segment's. This is sound
  because nothing about applying an entry depends on its being the only one for its stamp: the item merge is a join
  over arbitrary states (`10-sync-correctness.md` §3, §6), so the copies in either order, once or again, give one
  item; two copies may carry the same record *version* by the same device with different contents, and then the
  rows differ in bytes at an equal stamp, which the engine has always sent to the merger rather than treated as "the
  same" (only byte-identical rows are); two tombstones with one stamp and different summaries join
  (`joinErasureSummaries`). It is exactly as sound as a rolled-back device already was without a name collision: the
  two writes under one revision are both kept, and the stated limit of `10-sync-correctness.md` §8 (C1) applies — a
  write that had seen the first is taken to have seen the second. Nothing new is lost by merging; refusing would
  lose the reach of one copy's edits for good.
  - *Sequence.* A stream is still merged strictly in sequence. A position with several copies is one position: all
    its copies are checked and opened before any entry of any is applied, and if one that verified at download does
    not open (a key not yet held, say) nothing is applied and the stream waits there, so the position is never passed
    with part of what it holds.
  - *Acknowledgements.* A segment's vector lets other devices collect their segments, so of several copies the engine
    records the pointwise **minimum**: only what every copy acknowledges.
  - *Snapshots.* Several verifying copies of a snapshot are each merged, and the coverage recorded is the pointwise
    **maximum**: coverage says "the effects of these segments are in the local store", and once every copy's entries
    are applied that holds for each copy's vector.
  - *A copy found late.* A device that merged a position before a second copy appeared never fetches that position
    again, so the listing's count is what tells it: a name whose count differs from the one remembered for it
    (`SyncState.examinedCopies`) is examined again, and its verifying copies are applied *late*, with no change to
    `merged` or the acknowledgements. That is the application of a stale snapshot's entries, which the engine already
    does for every listed snapshot: idempotent, and unable to displace anything written knowing more.
  - *The author hands on.* A device that finds its own stream forked (several verifying copies of one of its own
    names) cannot assume any other device saw both. It owes a snapshot of its own (`SyncState.handOnOwed`), as a
    device owes one for a revoked device's work (below): everything it holds, which now contains both copies. Until
    that snapshot is written it collects nothing.
- *Shared vaults refuse several verifying copies, explicitly* (`SyncTransportError.conflictingVersions` as the
  rejection's reason; the stream waits, as before this was built). A write cut is a chain of segment digests per
  device (`SyncWriteCut`, `SharedStreamIndex`, §8.10): one digest per position. Two verifying copies of one position
  are two chains, and a member whose device signed both could show one to the administrator taking the cut and the
  other to everyone else; which writes are inside the cut would then depend on the copy a device happened to read.
  Nothing here can show that sound, so it is a limit, not a guess: the position is refused until one copy is left (a
  member of the vault, or the provider, removes the other by hand), and a second copy found late at a position
  already merged is reported and not applied. One verifying copy among junk is used in a shared vault as anywhere.
- *Nothing is resolved on the provider; the decision is remembered locally.* Removing a copy deletes bytes another
  device may not have read, and only the engine of a device that has merged a copy knows it is safe to lose there;
  so no device removes another device's copies, ever, and no device "picks a winner" on the provider. Each device
  remembers per name the number of copies it has examined, and looks again only when the provider's count changes,
  or at every sync while one of them could not be read (`unread`); its author does not collect a name of its own
  whose copies it has not examined in full (R11), since `delete` removes every copy. A name whose copies were unread
  at the count listed now (`SyncState.unreadCopies`) is examined after every other name, so copies that never become
  readable, honestly or because A1 withholds them, cannot spend the bound ahead of a late fork (R17); the iCloud
  adapter asks for a conflict version's contents once the copies' read has ended (a detached coordinated read of the
  version's URL, bounded by the coordination deadline).
  The copies go when the object goes: its author collects it under the usual rule (every other stream acknowledges
  the position, a listed snapshot covers it, and it is not the stream's newest), after its hand-on snapshot, and the
  transport's `delete` then removes every copy under the name. Junk copies beside another device's object stay until
  that device collects it.
- *Bounds* (`SyncConfiguration.maximumCopiesPerObject`, 16; `maximumCopiesPerSync`, 512). At most 16 copies of one
  name are fetched, each within the object size limit; more are counted (`SyncReport.copiesNotExamined`) and not
  read. Once one sync has fetched 512 copies of flagged names it looks at no further name's copies (the name it is on
  is finished, so the most is 527), and half of that is kept for names already merged, so that junk under names a
  device still waits for, examined again at every sync, cannot keep a late copy from being read (R13): a flagged name the stream needs is fetched as its current file alone, as before
  this was built (its other copies are examined by a later sync, late), and already-merged names wait for a later
  sync. So a flood of copies costs a bounded number of reads and signature
  checks per sync, stalls no stream whose current file is genuine, and cannot stop this device publishing: rejections
  are per object. What the bound gives up is a genuine copy hidden behind more than 15 planted ones, or a count that
  A1 keeps equal while swapping copies; A1 can delete that copy outright, so this is withholding (Y7), not a new
  capability. Copies of the account's own objects, and of the sharing objects, are not examined: those are named by
  their digests or written once per device, and are read as their current file.

**Record kinds a reader does not know** (ADR 0009, review finding N7). Every kind is critical or ignorable by its raw
value (`EnvelopeKind.criticality(ofRawValue:)`: 10 to 127 ignorable, everything else critical; `scanStatus` is the first
ignorable kind), so the kind byte, bound by the payload's AEAD and signature and by each record envelope's own context,
is also its criticality and cannot be flipped alone. An entry of a critical kind the engine does not carry refuses the
object: the stream stops there and skips nothing, the object stays staged, and `SyncReport.requiresNewerVersion` asks
for an update. An entry of an ignorable kind it does not carry is checked as far as it can be without the kind (its
author's, a positive version, its envelope's header naming the same kind and key), kept byte for byte in the stash
(`SyncStash`) with the device whose object carried it, and the stream merges on; the first engine that carries the
kind processes what was kept, through every context check and the kind's merger, without downloading it again (a
shared vault replays its log, for its judge). The stash is a row of its own in the state store, written once per sync;
`SyncState.stashUnsaved`, saved with each merged segment, makes the sync after a crash replay the log rather than
trust a stash that may lack entries. It holds at most 4,096 entries and 4 MiB per vault, 2,048 and 2 MiB of them from
any one device's objects; past a cap an entry is dropped and its kind recorded against that device, the stream still
merges, and the version that learns the kind replays the log, which still holds it. A row that does not parse (only
ignorable kinds, bounded lengths and counts, within the engine's caps) is dropped and rebuilt the same way. What a
revoked device carried is forgotten, as its objects are no longer read, except its own versions from its own stream,
which nothing else carries: those are kept, across a replay too, and hold nothing back. A device holding entries
carried by a trusted device writes no ordinary snapshot (below).

**Snapshots and garbage collection.** Once the segments not covered by a snapshot reach a threshold (never less
than twice the number of streams, so the acknowledgements a snapshot causes cannot trigger the next), the lowest
active device writes one; any device steps in once four times the threshold is reached. A failure elsewhere in the
sync never stops this. Every device merges *every* listed snapshot, not only the newest — its entries too, even when
its coverage holds nothing new, because merging is idempotent and a snapshot can carry what no accepted segment does
(below) — and continues a stream from
the highest coverage any of them has when its next segment is missing. A device deletes its own segment once every
other known stream has acknowledged merging it and some listed snapshot covers it, always keeping its newest; it
deletes one of its own snapshots only when another listed snapshot covers everything it does. A snapshot's contents
are trusted only as far as their signature: existing devices never delete anything because a snapshot omits it.
Only a device that read everything a trusted device carried to it writes an ordinary one (`SyncReport.snapshotWithheld`
and `snapshotWithheldBy` otherwise, ADR 0009): a snapshot from one that kept entries aside would cover their segments
without being able to carry concurrent versions of one record, and once those segments were collected a device that
reads the kind would never see what it left out. The snapshot a device owes for a revoked device's work is written
all the same, with coverage only of revoked devices' streams, which nobody reads or collects, so it hands that work on
and makes nothing collectable.

**Reconciling** (`sync(reconcile: true)`) forgets everything but pending deletions and the erasures it has merged,
and replays the log. On a healthy device it changes nothing; on one whose file was rolled back it restores the newest
versions. A shared vault's engine, which has a judge and a whole log, rebuilds the erasures from the log as well
(§8.10, S40). A replay is begun only with the log's listing in hand and no sign that the store was reset; otherwise
it is postponed and the state kept (`SyncReport.replayPostponed`, §7.10), since forgetting what was published and
merged in front of a log that is gone would publish every row again and rebuild nothing.

**Revoked devices.** The keyring tells the engine which devices are revoked (`SyncKeyring.retiredAuthors`, §7.8).
From then on the engine does not read their objects at all (`SyncReport.retiredObjects`; staged ones are dropped
unmerged), does not wait for their acknowledgement before collecting garbage (review finding Y6), never waits for
them to write the next snapshot, and stops publishing if the revoked device is itself. What the revoked device
wrote *before* is not lost: a device that had merged any of it that no trusted device's snapshot is known to cover
writes one snapshot of its own, which every other device merges, so an edit made on a phone before it was lost
and received by only one other device still reaches the rest (PRD F7.7), and the devices converge although each
stopped reading the lost device's stream at a different point. The price is stated in §7.8: something a revoked
device wrote after its revocation, but before some device learned of it, is handed on by that device like the
rest.

Known limits, tracked in `06-adversarial-review.md` §H: the store can withhold objects (reported, not prevented); an item's history
lives in its record and is never pruned (F1.4), so an item edited often enough to reach the payload limit (SEC9)
refuses further edits until history moves to records of its own; and a snapshot may attribute versions to any device (its author is
trusted for the vault, so this is an insider's capability). From the audit of the merge (Y36; Y28, the
tombstone's version, Y29, Y30 and Y37 are fixed): the engine does not refuse to publish an over-long erasure
summary (the merger no longer writes one). A version whose merge with the local one is over the payload limit is
quarantined, the local version kept, and the stream goes on (Y37). The session refuses a draft made from another
version than the one stored (`VaultError.versionConflict`, Y29), and every read it hands out, the UI's included, is
`ItemMerge.canonical` of the decrypted item (Y30).

### 7.6 As built in milestone 3 (the vault side, on a Mac)

**Keyring.** `VaultSession` is the production `SyncKeyring` and `ItemSealer`, through `VaultSyncAdapter`, which
holds the session and never a key: every call goes back to the actor, which throws `SyncKeyringError.locked` once
`lock()` has zeroised the keys. Segments and snapshots are sealed with `RecordCipher` under their vault's
current key, in the context `SyncObjectLocation.envelopeContext` gives; items with the same code path as a save.
Every object carries two signatures, domain `logSegment`, over `name ‖ 0x00 ‖ envelope` (`0x02 ‖ account signature
‖ device signature`): the account's Ed25519 key and the writing device's own key. The envelope already
binds the location, but only once the vault key opens it, so binding the name into the signature also refuses a moved
object at download, while locked. `verify` accepts an object only from a device the registry (§7.8) holds as
registered and not revoked, for a vault of the account, with both signatures verifying — the account's against the
keyset's own public key while unlocked and the Keychain copy (`accountSigningKey`, §6) while locked, the device's
against the key the registry gives for it. The registry is evaluated from public keys, so this is the same check
locked and unlocked. With no account key or no registry to trust, every object is refused (`trustedKeyUnavailable`,
so the report says why) rather than trusted, and the next unlock or sync restores them. The keyring signs only as
its own device, and another device signing in its stream is refused by everyone else.

**Vaults.** `VaultSession.syncAll()` syncs the account's own objects first (§7.7), then runs one engine per vault
in the directory — deleted vaults included, so that what a deletion had not seen still arrives — and returns an
`AccountSyncReport`; `sync()` returns the vaults' reports added up. While locked each engine only downloads. The
same holds, unlocked, while this device is not registered, has been revoked, or has seen a password change it
has not been given (§7.8).

**Merger.** `ItemRecordMerger` (in `WatchwordSync`, portable) is the one `RecordMerger` for items: it opens both
versions through an `ItemSealer`, checks that they are versions of one item, calls `ItemMerge.merge` and seals the
result through `ItemMerge.written`; it settles versions against erasures with `ItemMerge.settle`. The app
and the simulations run the same merger; only the sealer differs (`VaultSession` or `FakeSyncKeyring`).

**Saving.** Every write is stamped through `ItemMerge.stamped` with the version the vault assigns, ignoring whatever
sync metadata the caller passed, and is committed conditionally on the row it replaces (`StoreChange.expectations`):
the actor is re-entrant, so a merge can store a newer version while a save waits, and the save then fails with
`versionConflict` instead of overwriting it. With sync configured, the session's own deletions go through
`DeletionRecordingStore`; the engine writes to the base store, so the deletions it applies are not published again.
`resolveConflict` accepts only a value the item holds for that group, shown or conflicting
(`conflictValueNotHeld` otherwise), and checks a chosen scope with `ScopePolicy` like any save.

**State.** `SQLiteSyncStateStore` (§6). Deleting the account erases it with the record store, and the Keychain copy
of the signing key with the other Keychain items. A pending deletion is the one thing in that file sync acts on rather
than rebuilds — it becomes a tombstone that erases the record everywhere — so the session reaches the store through
`AuthenticatedSyncState`: each deletion it commits is signed with the account key (`SignatureDomain.pendingDeletion`,
over every field and the deleted row's envelope), and a pending deletion that is not this device's, or does not verify,
is ignored: never published, never treated as an erasure. A row A8 plants there erases nothing. The stash of entries an
earlier version cannot read (ADR 0009) is signed the same way (`SignatureDomain.syncStash`, bound to the vault, the
device and the state's stash generation), because a kept deletion processed after an update would otherwise erase a
record here and go out in this device's next snapshot; a row that does not verify is refused and the log replayed.
The file is at schema version 2 (the stash's table, migrated from version 1 when it is opened); an older app finds
version 2, throws `unsupportedSchemaVersion` rather than misread it, deletes nothing and syncs nothing until it is
updated again. Downgrading is not supported, and the file is never thrown away to allow it: it holds pending deletions
and the quarantine, which no replay rebuilds. This holds per
vault: a pending deletion counts only for the vault it is filed under.

**App.** Settings has Sync Now and the last report in words; a list row with conflicting values shows a badge, and
the item's detail lists each conflicting group with the shown value first and each alternative after it, every one
behind its own Keep button, secrets hidden until shown. Production builds are built without `SyncSettings`: the
transports exist (§7.2, §7.3), but choosing one, enrolment and the settings for it are a product step not taken yet. UI-test launches (`--uitest`) sync over an in-memory transport with `UITestPeer`, a second session
of the same account in the process, so XCUITest drives a concurrent rename through the real keyring
(`SyncConflictTests`).

### 7.7 Vaults, the account's own objects, and enrolment (as built)

**Vaults** (PRD F2.1–F2.3). An account has the Personal vault and any number of others it owns
(`createVault`, `renameVault`, `deleteVault`, `vaults()`, `items(in:)`; sharing is §8). Each vault has its own
256-bit key, wrapped under Ksym as a `vaultKeyWrap` record whose identity — vault and key ID — comes from where it
is stored, and a sealed description (§5). The Personal vault needs no description to exist (its name defaults
to "Personal"), can be renamed, and can be neither deleted nor shared: the session refuses, and a deletion of it
is ignored whoever signed it. The description merges as a last-writer-wins register (`VaultMetadataMerger`) on
**the stamp of the write that chose it** (`VaultMetadata.descriptionStamp`: `writtenBy`, or the row's own version
and device), not on the stamp of the row that carries it. A row sealed again (the merge of two rows at one
version, a rotation's re-seal, a device registered again) is a carrier: it keeps the description's stamp, and a
carrier at a higher version never brings an older name back over a newer one. Between two carriers of one
description the higher row stamp stands. In a shared vault this is also what keeps the choice of name with its
administrators (§8.10). Every `VaultSession` invariant holds per vault: contexts from the row, identity
checks after decryption, conditional commits, sync metadata owned by the vault. Search (`search`, `ItemSearch`)
runs over decrypted items in memory — titles, scope hosts, usernames and emails, tags, notes, never a secret
field — and nothing is indexed on disk.

**Moving and copying** (F2.2). A copy is a new item with a new ID. A move is a copy under an ID derived from the
version moved and the destination (`SHA-256("WW-move-v1" ‖ item ‖ destination ‖ device ‖ version)`), and the
original put in the trash, **in one commit**; then the original is deleted for good through the path of any
permanent deletion. An interruption therefore leaves either nothing changed or the item in its new vault with
the original at worst still in the trash (where the 30-day purge finds it): never neither, and never a move that
only seems to have happened. Other devices see nothing special — a new item in one vault's log, an item trashed
and then deleted in the other's — so the existing merge rules decide every race: an edit made elsewhere that the
move had not seen is kept, in the trash of the vault it was made in (the deletion removes only what its author had
seen, §7.5), and two devices moving the same version to the same vault create the same item. The two halves are
in two logs, so "never neither" must also hold on the transport: `syncAll` publishes every vault with this
device's deletions held back (`SyncEngine.sync(deferringDeletions:)`; they stay pending and count as erasures
here), and publishes them only once every vault's push in that sync succeeded. A sync that reaches one vault's log
and not another's (offline, locked midway, `ownStreamConflict`) leaves the other devices with the original where it
was until a later sync publishes the copy and then the deletion. An item that holds
values kept for the person to choose between is not moved until they have chosen (`itemHasUnresolvedValues`): the
copy would not carry them and the deletion would discard them, which only the person may do (F7.7).

**Deleting a vault** is explicit, confirmed, signed and never inferred from absence. The caller names how many
items the vault holds (`itemCount(in:)`, shown to the person); if that is no longer true, nothing is deleted. In
one commit the vault's directory row becomes a deletion signed by the account key and the device, and every item
is deleted through the path of a permanent deletion, each tombstone carrying what the deleting device had seen.
On another device an item, or an edit, the deletion had not seen is kept: it stays in the deleted vault and is
*shown* in the trash, as kept after a deletion (so the purge never takes it), listed by `items()` with a vault ID
that `vaults()` no longer lists, from where the person moves it to another vault or deletes it. Shown, not
written: a write would be an edit of each device's own, which the next deletion made elsewhere would not have
seen and would have to keep. Nothing new can be
saved into a deleted vault. Its key is kept, so that what arrives later can still be read; its objects on the
transport are not collected yet.

**Objects on the transport** (`AccountObjectLocation`), beside the per-vault logs, all created once and never
overwritten, all with exact names:

```
account/<accountID>/header/<generation>-<deviceID>             the account header (AccountHeaderObject)
account/<accountID>/registry/<sha256 of the entry, hex>        one device-registry entry (§7.8)
account/<accountID>/vault/<vaultID>/key/<keyID>/<deviceID>     a vault key wrapped under Ksym, vouched for by that device
account/<accountID>/vault/<vaultID>/deleted/<deviceID>         the vault was deleted, as stated by that device
```

- **A store that holds none of them.** Every sync publishes what the store lacks of these objects, so a header or a
  registry entry A1 deletes is put back by any device that holds it. The one exception is a store that lists *no*
  registry entry the device retains while the device's sync state says it has published or merged a vault's log:
  that store was emptied, not never set up, and nothing is published into it, these objects included, until the
  person has answered (§7.10).
- **The header** is everything a new device needs to derive the AUK and open the keyset: KDF algorithm,
  iterations and salt, the AUK's key ID, the wrapped keyset exactly as the local store holds it, the IDs of the
  registry's genesis entry and of the credential entry it belongs to, and a *binding*: an AEAD under the AUK over
  the SHA-256 of all of that, carrying which vault is the personal one. It is signed by the account key and the
  device that wrote it.
- **The vault directory** is a pair of grow-only sets: wraps and deletions, each object a `SignedObject` whose
  two signatures (domain `vaultDirectory`) cover its name and body. A deletion wins for good; vault IDs are never
  reused. Every device vouches, under its own name, for each vault key it has opened and each deletion it has
  verified, so a directory object never depends on the signature of a device that is later revoked. The local
  copy follows the same rule: once a device has verified a deletion and can sign (unlocked, registered), it
  replaces the local row with the deletion signed by itself — at the next sync, at the next unlock, and before it
  revokes a device — so revoking the device that deleted a vault does not bring the vault back there. A deletion
  seen only while locked rests on its author's signature, and on other devices' copies on the transport, until
  then. A wrap is
  accepted only if a registered device vouched for it under that exact name *and* its envelope's own context
  names that vault and key; when unlocked, also only if it opens under the keyset. A wrap row in the local store
  that does not open (edited in the file, A8: moved under another vault, corrupted) counts as missing while
  unlocked, and the next sync replaces it with a copy from the transport that passed those checks; until then the
  vault is not listed or written and its items are reported unreadable, never opened under another key.

Names reveal the account ID, vault, key and device IDs and the credential generation; a device's name is sealed
under Ksym inside its registry entry; vault names are in the vaults' own logs.

**Enrolment** (F5.2, F10.2; `VaultSession.enrol`). A second device joins from nothing but the transport, the
account password and the Secret Key (typed, or the Emergency Kit's setup code, which also names the account):

1. List the account's headers and take the newest first. A header that does not parse, whose name disagrees with
   its contents, or whose KDF parameters are outside the two-sided bounds is skipped before any derivation
   (SEC5, SEC9); at most three that parse are tried, because each costs a derivation.
2. Derive the AUK, open the keyset (bound to the account ID), open the binding. Any failure is the one error a
   wrong password and a wrong Secret Key share. The binding is what authenticates the header to a device that
   holds no key yet: nobody without the password and Secret Key can make one, and it fixes the two things a new
   device must not take from the store on trust — the registry's genesis entry and the personal vault.
3. Fetch the registry, evaluate it from that genesis entry and along that credential entry (§7.8), and check the
   header's signatures against it. If the registry already holds a later password change, the header was an old
   one — replayed by the store, or opened with an old password — and enrolment stops (`passwordSuperseded`).
4. Take a new device ID and device key, and register with the enrolment key the AUK yields.
5. Fetch the vault directory: every key a registered device vouched for that opens under the keyset for the
   vault and key its name says. The personal vault's key must be among them.
6. Commit the account, pin the registry in the Keychain, and leave the vault unlocked. The first sync publishes
   the registration, and the others accept the device's writes from then on.

**A store restored onto other hardware** arrives without its device key (Keychain items never leave a device), so
at its first unlock the installation registers as a new device under a new ID. The engine publishes only its own
device's rows, so what the old ID wrote and never published would otherwise stay on this device alone (F7.7): in
the commit that registers it, every row of the old ID that the restored sync state does not record as published is
written again by the new ID, unchanged (`ItemMerge.written`, one version up), and each of the old ID's verified
pending deletions is recorded again as the new ID's, stamped above it. A vault's name, being last-writer-wins, is
carried over only when the sync state says it was unpublished, so a stale backup cannot override a later rename.
Each vault's sync state then starts over: the old ID's stream is not this device's to continue.

What a store that replays the account's *entire* earlier state can do: show a new device the account as it was
(only with the password of that time, so the person has to type an old password for it to work). That device
then holds nothing newer than that state and none of its writes are accepted by devices that have moved on;
when the store shows it the change, it refuses the old password like every other device. A device that already
has the account is not affected at all: it follows only newer credentials, and remembers which in the Keychain.

**A password change is the account's, not the device's.** `changePassword` re-verifies the current password,
writes a credential entry to the registry (§7.8) and a new header, and deletes the header it replaces from the
transport. Every other device, at its next sync, keeps the new header as a *candidate* — only if the registry
holds its credential entry and the account key and the writing device signed it — and from then on refuses the old
password (`passwordChangedOnAnotherDevice`), refuses quick unlock (and destroys the Local Unlock Key), and neither
merges nor publishes until the person enters the new password there, which adopts the header. The keyset does not
change: a password change does not take the keys away from someone who opened them with the old password (§7.8
says what does). If the change was not the person's, they unlock a device they still hold with the password it
has (`unlock(password:ignoringPasswordChange:)`), revoke the device that made it and set a password of their own;
every other device then follows whichever password the person gives it.

### 7.8 The device registry (as built; review findings D9, Y5, Y6)

Before it, any holder of the account's Ed25519 key could write to every stream, so a lost device could not be
excluded. Now a device writes only if the registry says it may.

**Entries.** The registry is a grow-only set of signed entries on the transport and in each device's store,
named by the SHA-256 of their bytes; each names the entries its author had seen (`parents`), so the set is a
hash-linked graph the store can neither alter nor reorder. Four kinds: *genesis* (the account's first device,
the account's public signing key and the first enrolment key; exactly one), *add* (a device: ID, public key,
sealed name), *revoke*, and *credential* (the account's credentials changed: a new enrolment key, and the entry
it follows). Every entry carries the account key's signature and its author's: a registered device's own key, or
— for a device registering itself — the current enrolment key. A credential entry is signed a third time, by the
enrolment key of the generation it replaces: a device that merely holds the keyset cannot change the password for
everyone. Entries the account key did not sign are never admitted at all.

**Rules** (`DeviceRegistry.evaluate`, a pure function; the merge is set union, so devices that hold the same
entries and follow the same credentials compute the same registry). The entries are replayed in one order:

1. *Credential changes are checkpoints.* Everything a credential change had seen is replayed before anything it
   had not, generation by generation. An entry that arrives later is judged against the state the checkpoint
   left, however old the parents it names, and cannot reorder what the checkpoint sealed: a revocation moves
   only entries of its own layer (otherwise a revoked device could append a revocation naming one of its own
   back-dated, sealed entries, and so move it in front of its own revocation).
2. Between checkpoints: causal order, each revocation as early as that allows (what it had seen, the
   revocation, then what it had not), ties by entry ID. A revocation that can never count (below) moves nothing.

An entry is applied only if, at its place, its author is a registered device not yet revoked — or the current
enrolment key, for an entry written knowing of it — and its signatures verify. A device's entry must also
descend from an entry that registered that device under that key *and that counted* where it stands in the
replay: a device writes only once it is registered, so every honest entry does, and an entry that registered a
device but counted for nothing registers nobody. A revoked device's ID and key are never accepted again; a
registered device's key never changes; no key serves two devices.

*A bounded number of keys per device* (`maximumKeysPerDevice`, 2). An entry whose ancestors register its author
under more than two distinct keys is void, and no signature of it is checked; otherwise its signature is tried
against each of those keys once, when the graph is built, and every replay reads the answer. So evaluating costs
at most two device-signature verifications per entry, plus one per enrolment and one per credential link replayed:
linear in the entries, whatever a key holder plants (without the bound, thousands of registrations of one ID under
distinct keys and thousands of entries descending from them all were millions of verifications, and every device's
evaluation hung; W27). The rule reads ancestry alone, so it is the same whatever order the entries arrived in. An
honest history registers an ID under one key only (a device's key never changes, and an approved device enrols with
the key it was approved with); the second key is margin. Several keys for one ID reach an honest device's ancestry
only through an entry a registered device wrote while it counted — a device that could as well have revoked it.

**What can never count is not kept.** Some entries are void whatever arrives later: past the last checkpoint, one
whose author was revoked before it; one by a device that nothing it descends from registered under a key that
verifies it; one by an enrolment key it does not descend from, that does not verify it, or whose generation was
replaced. Voidness spreads to what relies on a void entry. Past the last checkpoint, a device's entry is void
unless it descends from a registration of its author, under a key that verifies it, that is not void itself, and
an enrolment is void if the credential entry it cites is; a registration the checkpoints sealed counts for good or
for nothing, so behind the last checkpoint "not void" means "counted". Entries are judged in causal order, each
once, so this is one pass over the graph. Without it a revoked device registers a *puppet* — a device whose key
it made — in a void entry (a garbage author signature, or its own revoked key, or an enrolment under a password
change of its own), and floods in the puppet's name: each entry verifies against that registration, and nobody
ever revoked the puppet (review of the device registry, "puppets"; a puppet registering a further puppet is the
same case one step on). The registry does not retain them (`DeviceRegistryState.retainedEntries`: every other connected entry,
and whatever a retained one descends from): a device does not store them, prunes them from its store, does not
publish them, and does not fetch them again in the same session until a sync keeps something new. The size
limit (`maximumEntries`, 4096) counts retained entries only, and a sync fetches in batches evaluated with what
the device holds (at most `maximumEvaluated`, twice that, at once). So a revoked device that kept the account
key can put any number of entries on the transport, but once a password change has sealed its revocation they
fill no device's registry, stop no fetch of the entries that matter, and keep neither the password change from
spreading nor a new device from enrolling (review of the device registry, "flood"), in its own name or in a
puppet's. A registered device in the wrong hands, or a revoked one before a password change, can still sign
entries that might count (and so can puppets it registers before the change); the limit then
refuses the registry rather than evaluate it without bound, as before. A candidate password
change is judged *as if it were followed* (the registry replayed with it as the last checkpoint), never by where
it falls among unsealed entries: otherwise a revoked device could hide the change from a device that has not been
given the new password yet, by back-dating a revocation of the device that made it (found by the adversarial
suite).

**What each device trusts.** The genesis entry and the credential entry it follows, and the newest entries it
has applied, are pinned in the Keychain (`deviceRegistryAnchor`). The genesis entry comes from the account header
the person's password opened; the credential entry moves forward only when this device changes the password or
the person unlocks it with a newer one. So the store cannot forge the registry (no account key), cannot roll a
device back (the local file must still hold everything the anchor names, or nothing verifies until a sync
restores it), and cannot fork it in any way that survives the entries reaching a device (union is the merge). It
can withhold entries, as it can withhold anything (Y7): a device then acts on an older registry until they
arrive. A header older than the pinned credentials is refused at unlock (`accountHeaderRolledBack`).

**Adding a device.** By enrolment with the password and Secret Key (§7.7), or by a registered, unlocked device
vouching for a device's ID and key before it has them (`prepareDeviceIdentity`, `approveDevice`).

**Revoking a device** (`revokeDevice`, which takes the current password): a revoke entry, optionally followed in
the same commit by a credential change that names it as its parent. From the moment a device learns of it:

- `verify` refuses every object of the revoked device, segments and snapshots, locked or unlocked, and the engine
  stops reading its streams (§7.5);
- it is retired from garbage collection and from snapshot election (Y6);
- its ID and its key can never be registered again, by anyone;
- the revoked device itself, if it runs this app, sees its standing, publishes nothing, and should be erased.

**What revocation does not do, and what the person must also do.** State this in the UI; the API makes the
choice explicit (`RevocationPasswordChoice`).

- *It does not take back what the device holds.* A device that someone unlocked — or whose holder knows the
  account password — has the keyset: the account key, Ksym and with it every vault key, including those of vaults
  created later, for as long as it can reach the sync store. Revocation is about **writing**, not reading.
  To stop the reading, the device must lose access to the store (erase it with Find My, remove it from the Apple
  ID, change the file provider's credentials), and the keyset and vault keys must be replaced — an account
  re-key (new keyset, new Secret Key, every vault key rotated and re-encrypted), which is **not built** and is
  tracked with vault-key rotation (milestone 4, F4.3). Until it exists, the app must say so plainly when a device
  is revoked.
- *Keeping the password* (`.keepPassword`) is sound only if the device was locked when it was lost and nobody who
  may hold it knows the account password. Such a device has no account key: it can write nothing, with or without
  the revocation, which then mainly retires it. If that assumption is wrong, its holder can still enrol a new
  device with the password and Secret Key they know — exactly as the person can — and, holding the account key,
  can sign back-dated entries that the devices judge among unsealed ones.
- *Changing the password with the revocation* (`.change`) is what the app should force whenever the person
  cannot vouch for that assumption — in practice, the default, with keeping the password the exception to
  confirm. The revocation is then behind a checkpoint that only someone knowing the *new* password can have
  made: on every device that has been given it, nothing the revoked device signs afterwards counts — not a
  registration under any ID or key, not an enrolment with the old password, not a back-dated revocation of the
  others — and a device that has not been given it yet neither merges nor publishes. What still holds: the
  reading, above; and whatever the revoked device wrote before a given device learned of the revocation, which
  that device merged in good faith and hands on (§7.5).
- *A stolen local header.* A thief with the device's Keychain (the Secret Key) and database can try passwords
  against the header as it was, offline. A password change elsewhere does not change that copy, and the keyset
  it opens is still the account's: again only the re-key ends it. The KDF floor and the Keychain's protection
  class are what stand in the way until then.

**Seam for sharing (milestone 4).** `VaultSession.syncVerify` is the one place that decides whether an author may
write to a vault. For a shared vault it gains a second question before the registry's — is the author's account
a member with a writing role, per the membership chain? — and then asks that account's registry about the
device. `currentKeyID(for:)` is the one place a vault's current key is chosen: a key received through a
member's HPKE grant is stored wrapped under this account's Ksym like any other vault key, and the membership
record's key ID replaces the rule there.

### 7.9 Automatic syncing (`AutoSyncPolicy`)

When to sync is a pure function of the clock and what has happened, in the style of `AutoLockPolicy`: no timers
or threads in the package. The app records events (`unlocked`, `locked`, `localChange`, `remoteChangeHint`,
`syncStarted`, `syncSucceeded`, `syncFailed`), asks `decide(now:state:settings:)`, and arms one timer for the date
a `.wait(until:)` names. The rules (defaults in `AutoSyncSettings`):

- after an unlock, at once, whatever else is pending (what was downloaded while locked can now be merged);
- after a local change, once 5 s have passed without another, and never later than 60 s after the first of a
  burst; a change made while a sync runs is kept for the next;
- on a remote-change hint from the transport (a CloudKit push, a file presenter), after 2 s, coalescing a burst;
- periodically: every 15 minutes while unlocked, hourly while locked;
- never two automatic syncs within 10 s of each other;
- after a failure nothing until a backoff has passed (30 s, doubling per failure in a row, capped at an hour),
  then a retry; any success clears it;
- while locked every sync is download-only (F7.5, §7.4), and local changes wait for the unlock;
- a transport that asks for a wait (`syncThrottled(retryAfter:)`, from `SyncTransportError.rateLimited`) makes that
  failure's backoff at least the wait, never more than the backoff's cap: the store's word is a claim (A1), and a
  stated wait of years must not switch sync off.

`WatchwordPlatform.AutoSyncDriver` is the timer: it records the app's events, asks the policy, starts the sync it
calls for, records the outcome (`AutoSyncOutcome`, from the report or the error), and arms one task for the next date.
The outcome is read from every part of the account's report — its own objects, each vault's log, each shared vault's
pass — so a throttled vault is a throttled sync, with the longest wait asked. Within one sync, the first failure that
stops it stops the rest: `syncAll` hands it to every later vault's engine (`transportStopped`), which merges what it
had downloaded and asks the transport nothing, and the sharing pass stops at its first.
It adds no rule, and takes its clock and its sleep as parameters. Remote-change hints come from `SyncFolderPresenter`
and, once the app registers for them, CloudKit pushes. The app does not create one yet.

A clock that moved backwards cannot show that an interval has not passed, so such a wait is treated as over:
syncing early costs a request, waiting for ever would cost the data.

### 7.10 Starting again after a reset (owner decision, 2026-11-17: re-upload, "but ask the user first")

A store can lose everything it held: the person deletes Watchword's data in their iCloud settings, CloudKit discards
the key that protected a zone, a folder is emptied. Every device still holds all it had, sealed and signed as before,
so the store can be filled again from local state. It is filled again only when the person says so, on each device
that has something to add, because the person on another device may have deleted the data on purpose.

**How a device learns of a reset.** Three signals, and none is trusted for more than stopping and asking:

1. *The transport says so* (`SyncTransportError.storeReset`): a CloudKit zone this device has seen
   (`SyncStoreMarker`) is missing, or CloudKit reports `userDeletedZone` or a reset encryption key (§7.2). The sync
   stops where it stands, as when offline, and creates nothing.
2. *The store holds none of the account's objects, and this device has synced before*
   (`VaultSession.syncAccountObjects`): no device registry entry this device retains is listed, and its sync state
   says it has published or merged some vault's log (`hasSyncedBefore`). This is an emptied folder, or a zone deleted
   on a device whose marker was lost too (A8, a reinstall). The session treats it exactly as the first signal: it
   reports `storeReset` and the sync stops before anything is published, the account's own objects included, in
   every vault and in the sharing pass. A store that never held the account is told apart by what the device
   remembers doing, not by what the store shows: a device that has never published or merged a log publishes as ever.
3. *The engine sees it* (`SyncReport.storeLacksObjects`, `SyncState.storeResetSuspected`): at a listing, before
   anything listed is merged, an object this device wrote and did not delete is missing — a segment past what it may
   have collected (`SyncState.collectedThrough`, which never reaches the newest segment it published, since it never
   collects that one, except after its own hand-on snapshot: SR19), or a snapshot it remembers writing; a device sees its own objects
   at once and nobody else deletes them, so an honest store lists them all — *and* it has merged something of some
   stream that nothing listed stands for (a segment past what the listed snapshots it has merged cover is missing;
   what it merged from a revoked device, whose segments are never listed, unless a listed snapshot covers it: SR27).
   This is what a device that was offline during a reset finds when it returns to a store another device has
   started again. The first half alone is not enough to ask (a device restored from a backup remembers less than its
   later self collected) and the second alone is not either (a provider that lags can show a snapshot's replacement
   late). The suspicion is remembered until everything the device has merged is listed or stood for again, because
   what another device uploads can stand for this device's own stream, and so hide the first half, while this device
   still holds more of a third stream than the store does.

`AccountSyncReport.storeNeedsReupload` is any of the three (the third only for a vault that can be uploaded again).

**Nothing is uploaded again unasked.** At a store that says it was reset, or holds none of the account's objects,
the sync publishes nothing at all, new edits included: they stay local and go out with the upload. In a store
another device has started again, what this device has published is remembered in `SyncState.published`, which a
reset does not change, so the ordinary outbox never re-sends anything; while the engine's suspicion stands and the
person has not answered, the device writes no snapshot (neither elected nor owed: either would carry the whole
vault) and collects nothing. New edits are still published in the device's stream there — they are new, not a
re-upload — and other devices wait at the gap before them until this device's person has answered. **A replay is
postponed** (`SyncReport.replayPostponed`) whenever the log cannot be listed or the suspicion stands: a replay
forgets what the device published and what it merged, and from a log that is gone it would rebuild nothing, publish
every row the device ever wrote, and lose the knowledge of what to hand on. No timer and no policy reaches the call
below: `AutoSyncPolicy` knows two modes, a full sync and a download, `AutoSyncDriver` calls `syncAll` and nothing
else, and a `storeReset` is to it a failed sync that backs off.

**The call** (`VaultSession.reuploadAfterStoreReset(confirming:)`, which only a screen calls, after the person
confirms). `reuploadPlan()` says what would be uploaded — the account's own vaults and how many items each holds,
and the shared vaults that cannot be — for the question; the call takes the plan the person was shown and refuses
(`reuploadNotConfirmed`) if it no longer describes this device, as `deleteVault` does with its count. It needs the
vault unlocked and this device registered, not revoked and following the current password. It holds the session's
sync lock from before the plan is checked, so no ordinary sync merges anything between the answer and the upload,
or runs between the two steps. Then:

1. `SyncTransport.startStoreAgain()`: the one call that may recreate a store this device has seen and found missing.
   CloudKit saves the zone again (deleting it first where CloudKit says its key was reset, and taking a deletion
   answered "no such zone" as done), keeps the marker, and leaves a zone that exists exactly as it is. It learns
   which by fetching the zone and then reading one record with a listing's own `name BEGINSWITH` query, never a
   `TRUEPREDICATE` one (SR20): a zone's metadata is not encrypted and fetches after a key reset, and only its records
   answer the reset (SR26); a transport with no notion of a reset does nothing. Before it,
   each of the account's own vaults that has synced is marked `storeResetSuspected`, which only its hand-on or a
   store standing for everything it holds clears, so an upload stopped part-way (a lock, the network, the app
   killed) asks again; after it, the lock epoch is checked again (SR21).
2. One sync with `reuploadingSince` the epoch of the answer, which counts only while the vault is unlocked at that
   epoch (`reuploadAnswered`): a lock that overtakes it makes it an ordinary sync (SR21). *The account's objects* need no new code beyond skipping the second signal: every
   sync publishes what the listing lacks of the registry entries the device retains, its account header, a wrap
   under its own name of every vault key it has opened, and every vault deletion it has verified (§7.7). They are
   everything enrolment reads: a brand-new device can enrol from one device's upload.
3. *Each of the account's own vaults* runs its engine with `handingOn`. The engine downloads and merges whatever
   the store already holds again (another device may have uploaded first: merges are joins, so this is only more to
   carry), publishes its outbox and pending deletions as the next segments of its stream, and then, if it holds
   something the store lacks, writes **one snapshot of everything it holds**: every row, whoever wrote it, and a
   tombstone for every erasure it remembers, covering what it had merged of each stream. The precedent is the
   snapshot a device owes for a revoked device's work (§7.5): what this device merged from other devices' streams
   exists on the transport nowhere else now, so it hands it on. Every reader merges every listed snapshot, entries
   first, whatever it covers, and continues each stream from the most any snapshot covers.

**Decisions, and why.**

- *Sequence numbers are never restarted, and no snapshot name is used twice.* The device's stream continues at its
  next number. A number once used was read by other devices under other bytes; using it again is the fork of §7.5.
  The snapshot's coverage of the device's own stream is what lets every reader, new or old, pass the gap where its
  segments were. Every snapshot, the hand-on and one owed for a revoked device or a fork alike (R15), is named by a
  number above any this device has used for one (`SyncState.highestOwnSnapshot`): an emptied store would accept an old name again, and a device that had merged
  the earlier snapshot under it would never read the new one.
- *`published`, `known`, `merged`, the erasures and the acknowledgements are kept as they are.* `published` still
  says "on the transport in something this device wrote": the snapshot carries every row. Nothing is forgotten, so
  there is nothing to roll back to: a device that is told of a reset, truthfully or not, is afterwards exactly the
  device it was, plus what it merged.
- *The stash is never dropped and never uploaded.* Kept entries of kinds this version cannot read (ADR 0009) stay in
  the signed stash. A snapshot cannot carry them (one entry per record; the stash may hold several versions of one),
  so the snapshot of a device that holds any covers its own stream and revoked devices' streams and no other: a kept
  entry names the device whose *object* carried it, which for a snapshot is not the device whose segment did, so the
  stash cannot say which streams carried none. A reader passes the gap in the uploader's stream and waits at the
  others until their own devices, which read the kind and hold it as rows, upload again; `snapshotWithheldBy` names
  them. The uploader's snapshot still stands for all it holds (`SyncState.handedOn`), so it is not asked again.
- *Held-aside and quarantined versions stay where they are.* They were refused as implausible or as work that does
  not count; uploading them inside a snapshot would launder them into every device's vault. They are neither
  published nor dropped: only the person discards them (F7.7).
- *Pending deletions* go out as tombstones in the device's next segments, as always (after every vault's other
  writes, §7.7), and the snapshot carries a tombstone for every erasure the device has published or merged: a device
  whose copy predates a deletion does not bring the record back.
- *A device that was offline during the reset* merges the snapshots it finds on the rebuilt store. If they cover
  everything it had merged, its own stream included, it has nothing to add, is asked nothing, and continues at its
  next number. If it holds more — segments of its own that the others had not merged, or more of a third device's
  stream — the engine's signal asks its person, and its own snapshot hands that on. Until they answer, its new edits
  are on the transport behind a gap, where other devices wait (`SyncReport.waiting`); nothing is lost on any device.
  Declining decides nothing for good: the notice stays, and so does the gap.
- *Two devices uploading at once* each write a snapshot under their own name (`<lamport>-<device>`), and each
  merges the other's at its next sync. The item merge is a join and snapshot coverage is a maximum, so either order
  gives the same vault; a device asked twice writes once, because its own listed snapshot stands for what it held.
- *Shared vaults are refused* (`ReuploadRefusal.sharedVault`, reported per vault whether or not the person was
  asked, and worded for them; a shared vault alone never raises the question). A shared vault keeps its whole log
  and writes no snapshots, because a write cut is a chain of digests of a device's own segments and every version is
  judged through the segment that carried its values (`SyncWriteCut`, `SharedStreamIndex`, §8.10). One member's
  device holds the other members' work but not their segments (they are not kept once merged), cannot sign in their
  names, and a snapshot would hand their work on with no segment for any judge to count it by. So nothing is
  uploaded for a shared vault: it stays on each device as that device holds it, readable, with nothing dropped, and
  its log does not sync again (new edits are still published as segments, behind a gap nobody can pass). What a
  sound rebuild would need: every device keeping the signed objects of the shared log byte for byte — they
  authenticate themselves, so any member's device could then create each again under its own name, with every cut
  chain verifying as before — or a membership record that restarts the log under a later format (§8.9). Not
  designed. While a shared vault's log is missing its replays are postponed like any other: a change of head still
  takes out the versions that no longer count, and what a replay would rebuild of such a record stays held aside for
  the person (`06-adversarial-review.md` §S).
- *A vault too large for one snapshot* (the 64 MiB envelope limit, §5) is refused (`ReuploadRefusal.tooLarge`) and
  nothing is written for it; snapshots in parts are not designed, and the question comes back at the next sync.

**Threats.**

- *A1 can fake a reset at will* — delete the zone, empty the folder, delete one device's newest segment, answer
  `zoneNotFound`, or put an old copy of the store back. The device stops or asks; it uploads nothing unasked. If the
  person confirms, the store receives a snapshot of record envelopes it was given before, under the same keys, and
  account objects it held before: it learns nothing new (a store that in fact still holds everything receives
  nothing at all). No device is rolled back: nothing in the path forgets, overwrites or deletes local state (the
  record store, the sync state, the stash, the quarantine and the pending deletions are written only by the ordinary
  merge of verified objects), and every other device merges the snapshot as a join, under the same signature,
  registry, context and version checks as any snapshot. A1 can make the question appear again by deleting again;
  that is withholding (Y7) with a prompt, and declining costs nothing but the sync A1 could stop anyway.
- *A reset must not look like "never set up".* On CloudKit the marker makes a missing zone `storeReset` for every
  operation. Where no transport says so, the second signal does: the account's objects are not put back, and nothing
  else is published. What tells the two apart is the device's own sync state, which the store cannot write. A8, who
  can, can erase it: the device is then a "new" one to itself, and publishes the rows it wrote again, unasked, as
  segments from its first number. The store gains ciphertext it held before, under the same keys; the reused numbers
  are the fork of SR15. A store emptied of everything but one registry entry is not "emptied" either (SR18): the
  account's small objects are put back as ever, and no vault's contents are: a device whose only work in a vault was
  a revoked device's, handed on in a snapshot the store then lost, is asked rather than writing it again (SR27), and a
  snapshot is remembered from the sync that writes it, not only from the next listing.
- *The person deleted the data on purpose, on another device.* Hence the question, and its wording
  (`ReuploadQuestion`): it says the data is gone from the sync storage, that this may have been deliberate, what
  will be uploaded (how many items in how many vaults, and the encrypted keys and device list), that uploading
  undoes a deletion made elsewhere, and what cannot be uploaded (shared vaults). Declining leaves the device as it
  is. **Not undone unasked, but not prevented either:** each device asks its own person, and nothing tells a second
  device that the first person said no.
- *A revoked device* still holds the account key. Its session refuses the call (`deviceRevoked`) and publishes
  nothing. A modified client on such a device could fill an empty store with the registry as it knew it, without its
  own revocation, and a brand-new device enrolling from that store alone would not learn of the revocation until a
  trusted device uploads. That is the limit §7.8 already states for a store that withholds a revocation (A1 can do
  as much without a reset); no existing device is affected, since a registry only grows.

**Limits** (`06-adversarial-review.md` §S). A shared vault's log does not sync again after a reset (SR11). A device
that never published in a vault, was offline during the reset and alone holds more of a stream whose device is gone
is not asked by the engine (SR14). A device whose sync state was rolled back *and* whose store was then reset has no
listing to tell it how far its stream had gone, and can publish under numbers other devices merged under other bytes;
they read its later snapshots, not those segments (SR15). Each device asks its own person, and a refusal on one is not
known to another (SR16).

**Adapters.** `CloudKitTransport.startStoreAgain` is drafted with the rest of that transport (not compiled, not run
against CloudKit; that a zone whose key was reset must be deleted before it is saved again follows Apple's
documentation and is unverified, as are saving a zone again after `userDeletedZone` and a zone fetch succeeding
after a key reset while its records answer the reset, SR26). `CoordinatedFileSyncTransport`
needs nothing: its folder is created by the first write, and an emptied folder is the second signal. The Devices
screen shows the notice, an "Upload Again…" button and the question as an alert (`DevicesModel.askToUploadAgain`,
`confirmUpload`, `declineUpload`; the SwiftUI in `Apps/Shared/DevicesView.swift` is drafted, unbuilt). It says the
upload is done only when every vault the plan named ran and nothing is still asked for
(`DevicesModel.uploadFinished`); a vault outside the plan, a shared one waiting for its key say, does not hold it back
(SR28).

## 8. Sharing protocol

As built in milestone 4's protocol core, `WatchwordSharing`. The module is portable (real cryptography through
`WatchwordCrypto`, the key directory and the contacts store behind ports) and is exercised in-process by simulated
members with real keysets over a hostile store. §8.8 says what an integration calls; §8.10 describes the integration
into `VaultSession` and `SyncEngine` as built. A transport's own sharing (CloudKit `CKShare`, a shared folder) is not
wired yet.

### 8.1 Model

A shared vault has **members**, each an account with a role:

| Role | May |
| --- | --- |
| owner | everything an administrator may; and alone: grant or revoke the administrator role, remove an administrator, delete the vault. Exactly one, fixed for the life of the vault: never removed, never re-roled. |
| administrator | invite and remove members who are not administrators, change them between read-write and read-only, rotate the vault key, rename the vault (§8.7) |
| read-write | read and write items; not the vault's name |
| read-only | read items. They hold the vault key like everyone else: this is a rule the clients keep, **not cryptography** (F4.5, §8.7) |

Membership is a **chain of signed records**, one per change, each naming its epoch (the previous one plus one), the
hash of its predecessor, the operation, the member list and vault key that result, and signed under
`SignatureDomain.membership` by an account that was an administrator in the state before it. Two consequences of the
table carry the rest of the design:

- **The set of accounts that may sign changes only in records the owner signed.** (Everything that adds or removes
  an administrator is the owner's.)
- **The owner can always sign the next record**, so no sequence of records, honest or hostile, leaves a vault that
  nobody can administer. Ownership transfer is not in this version (the owner wants it in a future one; §8.9 is the
  design it must follow, and what this version already does so that it can); the last 4,096 epochs of a chain accept
  only the owner's signature, so an administrator cannot use the chain up either.

### 8.2 Formats, and what is in the clear

Every format is binary, little-endian, with one canonical encoding, a four-byte magic and a version byte, and a
bounded parser: a size is checked before anything is copied, a count before anything is allocated, and bytes that
would not re-encode to themselves are refused (SEC9). Sizes: at most 64 members; epochs up to 65,535; a write cut of
at most 2,048 bytes; a record is at most 12,090 bytes.

| Object | Magic | Contents | Signed by |
| --- | --- | --- | --- |
| Membership record | `WWMR` | vault ID, epoch, previous hash, signer, operation (`createVault`, `addMember`, `removeMember`, `memberLeft`, `changeRole`, `rotateKey`, `deleteVault`) with operands, vault key ID and the epoch that introduced it, a write cut (opaque bytes; empty unless the operation ends an account's permission to write or its administrator role, §8.7), the resulting members (account ID, role, epoch added, X25519 and Ed25519 keys, bundle self-signature) in account order | the signer |
| Key grant | `WWKG` | a `VaultKeyGrant`: vault, key ID, sender, recipient, recipient's X25519 key, HPKE encapsulated key, ciphertext (§4) | the sender (`.vaultKeyGrant`) |
| Leave request | `WWLR` | vault, account, the epoch the member was added | the member |
| Published key bundle | `WWKB` | account ID, X25519 key, Ed25519 key | self-signature (`.publicKeyBundle`) |
| Invitation | `WWIV` | vault ID, owner's account ID | nobody: it only says whose fingerprint to ask about |
| Contact pin (local) | `WWCP` | pinning account, method, time, the contact's bundle | the pinning account |
| Saved ledger (local) | `WWML` | account, vault, digest of the owner's keys, head epoch and hash; then the accepted records, then the records held from losing branches and any later-format records held (§8.9) | the account, over the checkpoint |
| Rotation plan (local) | `WWRP` | planner, vault, base head, new key ID, kind of rotation, the membership record, the grants | the planner's account, over all of it |

Signatures of the membership protocol all use `SignatureDomain.membership`; the leading magic keeps one kind from
verifying as another. A record's **hash** is `SHA-256("WW-membership-hash-v1" ‖ signed content)`: the signature is
left out, so one record has one identity however its signature is encoded.

**Membership records are in the clear, and signed. Nothing of the membership protocol is sealed under the vault
key.** An invitee must check the whole chain back to the owner *before* holding the key, and a member added after a
rotation holds no earlier key at all, so a chain sealed under vault keys could be verified by neither. What the store
(A1) learns is the vault's shape: pseudonymous account IDs and public keys, roles, and when membership changed, which
the transport's own share list (CloudKit participants, a shared folder's members) already tells it by real identity.
What it must not be able to do is *change* membership, which is what the threat model's "vault membership" asset
needs and what the signatures and the hash chain give. Names never enter a record: the label a person sees for a
member is the one they chose when they verified that member's fingerprint, in their own contacts store. The vault key
appears only inside HPKE grants. Envelope kind `membership` (2) stays reserved.

Objects live on the transport under a prefix of their own, beside sync's `vault/<vaultID>/` (§7.1), immutable and
written once like sync's:

```
sharing/<vaultID>/membership/<epoch, 20 digits>-<record hash, hex>-<SHA-256 of the object, hex>
sharing/<vaultID>/grant/<keyID>/<recipient account>/<SHA-256 of the object, hex>
sharing/<vaultID>/leave/<account>/<SHA-256 of the object, hex>
```

Every name ends in a digest of the whole object, so two administrators writing the same epoch write two objects
rather than fight over one, publishing twice is harmless, and **nobody can occupy another writer's name**. That last
property needs the digest and not just the record hash: the signed content of a role change, an invitation or a
deletion is predictable to any member, so a name made of the hash alone could be created first, with a signature that
does not verify, by someone who wants the genuine record never to be published (review finding S20). The record hash
stays in the name because it is the same for every copy of a record, which lets a device skip objects it already
holds (`MembershipLedger.holds`). Names are parsed exactly (`SharingObjectLocation`), as sync's are.

### 8.3 The ledger: verification, forks, rollback

`MembershipLedger` is one device's verified copy of a vault's membership records and the only source of a
`MembershipState`.

**Trust anchor.** Two things, both local: the owner's key bundle, pinned when the vault was created or when the
person accepting an invitation confirmed the owner's fingerprint out of band (§8.4); and every valid record the
device has already seen, which the ledger holds. Everything the store offers is a candidate.

**Verifying a record** against the state before it, cheapest first: the vault, the epoch (exactly the next), the
previous hash; the signer is a member and an administrator of the previous state; the operation is one that signer
may perform (§8.1); the shape of the key change (a removal, a departure and `rotateKey` name a new key, nothing else
changes it); a write cut only where the operation ends an account's permission to write or its administrator role
(§8.7), so that a record has one encoding; the signature, under the key the *previous state* lists for the signer; and only then what costs work or
came with the record: the new key ID must not have been used on this record's own path, a new member's key bundle is
validated, a departure's embedded leave request is checked, and the member list must be exactly the previous list
with the operation applied. Unsigned junk costs exactly one signature check; the key-history check walks the
rotations of the record's own path and nothing else in the tree (S22). Each failure is a typed `MembershipError`; a
refused record changes nothing, and since a record names its predecessor by hash, a refusal is permanent.

**A grow-only set of records, and a function of it.** The ledger holds the *tree* of valid records it has seen: the
accepted chain and the records on branches that lost a fork (`branches`). `ingest` only ever adds valid records to
that set, and the accepted chain is a pure function of the set, the fork rule below. So devices that have seen the
same records agree, whatever the order of arrival and however the records were split across calls; a record that
lost is still there for a later record to connect to, and can then win (S17). This is the same shape as a
state-based CRDT: a set that only grows, merged by union, with the state read off it by a deterministic function.
`ingest` takes any number of candidates and never refuses for count; a flood costs time in proportion to itself (one
parse each, one signature check for what looks like a record) and hides nothing.

The records kept from losing branches are bounded (1,024; only an account that is or was an administrator can sign
one). Past the bound the ledger keeps the best-ranked, removals that are still owed first, says how many it let go
(`IngestReport.forgotten`), and the integrator then offers the whole listing in each call instead of only what is
new, which is always right.

**The fork rule.** Among all paths from the genesis through the valid records held, the accepted chain is the one
with

1. the **most records signed by the owner**; then
2. the **most records**; then
3. at the first record where two such paths part, the **lower hash**.

Why this rule:

- A **former administrator** can go back to an epoch at which they still were one and publish a branch of any
  length, with hashes ground as low as they like. But the accounts that may sign change only in owner-signed records,
  so their removal or demotion is one, and their branch lacks it: it holds fewer owner-signed records and loses on
  every device however it is timed (S1). A device the store showed *only* their branch follows it until the owner's
  record arrives, which is no worse than not having heard of the removal.
- Between paths that hold the same owner-signed records, every signer is an administrator on both, so the choice is
  between equals, and the **longer** one is the one more devices have built on. A single record signed on a stale
  head and released late therefore displaces nothing that has been built on since (S18). Only when two paths are
  equally long does the hash decide.
- A **stale device of the owner's** is not special: one record it signs on an old head ties on owner-signed records
  with the path that holds the owner's later record, and loses on length (S19).
- The owner can always sign the next record, so no outcome leaves a vault that nobody can administer.

**What the store can and cannot do** (A1). It cannot forge (every record is signed back to the owner's pinned
key). Serving an older or partial listing changes nothing, because that is a subset of what the ledger holds. It can
withhold, as everywhere in sync, and the ledger then stays where it is. And by withholding the newest head from an
honest administrator's device it can have that device sign on a stale one, which **creates a fork between two honest
records**; it chooses *when* the fork becomes visible, never which record wins it. What a fork costs is bounded by
the next two paragraphs.

**Removal wins.** A reorganisation can still displace a record that removed a member: two paths of equal standing
(the narrowest timing the store has), or a device of the owner's that signed twice while isolated. The displaced
record is kept, and while its signer may still remove that member in the accepted state (for a departure: while the
member is still in the same stint) the removal is **owed** (`MembershipLedger.owedRemovals`). Until it is carried out
again: `writePermission` refuses the member's writes (`removalPending`), and of what they have written
`writeStanding` counts what the displaced record's own branch said counts, its write cut included (§8.7), so a
device that learns of a removal this way treats the member's later writes as a device that saw it adopted does;
`recordsToReseal` is empty, so nothing written under the newer key is sealed again under one the member holds;
`pendingRotation` reports it; and the next device whose account may sign the removal plans it again, whichever
device signed the first. This is a function of
the records held, like the chain itself. A former administrator's removals on a dead branch owe nothing: their signer
has no standing in the accepted state. Nor does a removal that its own branch went on to take back by adding the
member again. A *departure* is owed whoever carried it out, because the member's own signature asked for it; but
what such a branch says about the member's writes is believed only if the owed record, and the record that holds the
cut, were each signed by an account that could sign the same on the accepted head. Otherwise the member's writes go
on counting until the departure is carried out again with a cut by an account that may: a former administrator cannot
turn a pending leave request into "set this member's work aside" (S29).

**Everything else that loses is proposed again by its author.** `MembershipLedger.status(of:)` says whether a record
this device proposed is `awaitingPublication`, `adopted` or `superseded`. A device keeps what it proposed until it is
adopted, asks after every ingest, and proposes a superseded change again on the new head (the proposing functions
throw if it has meanwhile happened). A device's own record is merely `outranked` in the report of its first ingest,
so the report alone does not say this (S27). And a device ingests before it proposes, and never publishes a record
that is no longer `awaitingPublication`.

**Persistence.** `persisted(signedBy:)` writes a checkpoint (this account, the vault, a digest of the owner's keys,
the head) signed by the account's own key, then the accepted records, then the records held from losing branches.
`restore` trusts none of it: the checkpoint must carry this account's signature and name this vault and owner, every
record is verified again from the genesis and must be valid, and the fork rule applied to them must give exactly the
checkpoint's head (`LedgerError.rolledBack`, `savedRecordInvalid`). A saved ledger that was truncated, altered,
extended or planted fails closed. An older blob of the device's own, put back, restores as that older state; the
next ingest moves it forward.

### 8.4 Fingerprints, verified contacts, invitations (F4.1, F4.2, SEC3)

Accounts publish their `PublicKeyBundle` in a **key directory**, a port (`KeyBundleDirectory`) whose adapter is the
account record on the transport. It is a store like any other: what it returns is parsed, validated, must be for the
account asked about, and is then only a *candidate*.

A bundle's **fingerprint** is `SHA-512("WW-fingerprint-v1" ‖ accountID ‖ pkX ‖ pkEd)` truncated to 60 bytes, shown as
a 60-digit **safety number** in twelve groups of five, and as a QR code carrying
`"WWFP1-" ‖ hex(accountID ‖ fingerprint)` (158 characters; one scan names the account and authenticates its bundle).
A typed number matches only as sixty ASCII digits with ASCII spaces ignored; a scanned payload is parsed exactly;
both comparisons are constant-time.

**Verified contacts** (`VerifiedContacts` over the `VerifiedContactStore` port). Confirming a fingerprint, by typed
number, by scan, or by the person's own comparison, **pins** the bundle: a record signed by the pinning account's own
key. From then on a different bundle for that account is refused and reported (`SharingError.keySubstituted`),
never silently adopted, in the three places the module meets one: the key directory's answer on either side of an
invitation, and the member list of a chain (below). Replacing a pin is a separate, explicit act. A pin that does
not verify is ignored, so an attacker with the file (A8) cannot plant trust, only delete it, which puts the contact
back in front of the person. Bundles are compared by account and keys, not by self-signature, because Ed25519 signing
may be randomised.

A `VerifiedContact` value exists only once a fingerprint was confirmed (or for the account's own bundle), and the two
operations that matter take nothing less: wrapping a vault key to an invitee, and anchoring a chain to an owner.

```
inviter:  begin ─► awaitingVerification ─confirm─► verified ─issue─► issued
                   (show the invitee's number)     (sign addMember, HPKE-wrap the key)
invitee:  begin ─► awaitingVerification ─confirm─► verified ─accept─► accepted
                   (show the owner's number)       (verify the chain, open the grant)
```

- The inviter (owner or administrator) wraps the vault key only from `verified`. A contact pinned earlier starts
  there; one whose published bundle differs from their pin stops at `begin`.
- The invitee verifies the **owner**, whoever invited them: an administrator's key is in the chain under the owner's
  signature, and every other member's under an administrator's. Trust in member keys is therefore transitive through
  the chain, rooted in one out-of-band comparison per person; a member who wants more compares fingerprints with
  another member directly, and the pin then guards that key too (next paragraph). (Review finding D17: the UI must
  show unverified members as such.)
- `accept` builds the ledger from the store's candidates anchored to the verified owner, requires this account to be
  a member **with its own keys** (an administrator who was handed a substituted key for the invitee is caught here:
  `ownKeySubstituted`), and opens the grant of the current key (§8.5).
- An invitation to a vault ID the device already holds under another owner is refused (`vaultOwnerConflict`): vault
  IDs are not secret, and accepting it would let the sender stand in as the owner of someone else's vault.
- A member who was removed and is **invited back** continues the ledger their device already holds
  (`accept(…, continuing:)`); it is not rebuilt from what the store offers. Their earlier membership and the old
  key's grant are a valid prefix of the chain, so a store that hid everything from their removal onwards would
  otherwise have them rejoin a state older than one their own device had verified (S26). A device therefore keeps the
  ledger of a vault it was removed from.

**Pins against the chain.** The chain's rules let an administrator remove a member and add the same account ID back
with other keys, so a ledger accepts that. `MembershipLedger.checkMemberKeys(against:)` compares every member's
listed keys with the device's pins and returns a `MemberKeyCheck` for that head: `substituted` (listed keys differ
from the pinned ones: reported as `keySubstituted`) and `unverified` (no pin; trusted through the chain only).
`RotationPlanner.plan` and `MembershipLedger.makeGrant` *require* that value, made on the current head, and refuse to
wrap a key to a member in `substituted`, so the comparison cannot be left out of anything that wraps a key (S21). The
person resolves it by removing the member (no key goes to the swapped keys) or by verifying the new keys and
replacing the pin.

The session makes the comparison whenever the head changes, **and when it restores a vault at unlock**: a device that
restored the ledger and left the check to the next sync reported nobody as substituted until then, so after a
relaunch the member list called a member with swapped keys verified, and the sync keyring (S39) had no check to refuse
their signatures by (review of the account screens, finding 1). `SharedVaultStatus` carries `verifiedMembers`, the
members the check on the current head found pinned to the keys listed, or `nil` when no such check exists (the vault
locked since the head changed); the member list calls a member verified only from that list, and anyone it does not
name "not checked yet". An empty `unverifiedMembers` is not evidence of anything.

**What the screens accept as a comparison** (`WatchwordPresentation`, `docs/05-anti-phishing.md` §3). The typed
safety number (`.safetyNumber`) or the person's own "the numbers match" (`.comparedByEye`), in that order. A
fingerprint code pasted from a message only names the account to look up: it is not `.scannedCode`, which is for a
code read by the camera from the other person's screen and is never recorded until the app can scan one (finding 2).
`VerifiedContact.method` therefore says what the person did (S16).

**Names of shared vaults.** Only a shared vault's owner or an administrator may rename it (owner decision,
2026-11-17). The review of the account screens (finding 4) had left renaming with every member who may write, for the
owner to confirm, and the owner decided the other way: a name is what a person reads before saving into a vault, and a
member who can call a shared vault "Personal" can have someone's item land where they will read it. A rule kept by the
screens alone would not bind a client that does not ask, so this is a rule of the protocol: every device's write judge
refuses a description that is not an administrator's work, the same on every device whenever it heard of the
membership records. §8.7 says which descriptions count and why the rule is the one it is; §8.10 how the session, the
merge and the judge apply it. The screens still never let a name stand alone, because an administrator can choose any
name: every list and the item editor label a vault by ownership and role (`VaultRow.badge`: "Your own vault", "Shared
by you", "Shared with you · Can edit"), and the editor says where a new item goes, with "everyone in this vault can
see it" for a shared one (finding 4). A vault's own screen offers a rename only to an account that may
(`VaultRow.mayRename`, from `SharedVaultStatus.mayRename`), and says why to everyone else (`renameRefusal`).

### 8.5 Key grants

A grant is found at `(vault, key ID, recipient)` and those come from its storage location, never from the grant
(§4). The chain then names **the one account entitled to have sent it**: the signer of the record through which the
recipient became entitled to that key, which is the record that introduced the key if the recipient was a member
then (the genesis, a rotation, a removal), or else the record that added the recipient while the key was current.
That signer was an administrator in the verified chain at that epoch by the chain's own rules, and their key comes
from the chain. Nobody else's grant is accepted (`MembershipLedger.grantSender`, `openGrant`): not a former member's
or former administrator's, not an administrator of another vault's, not one from an administrator demoted since
(a demotion does not rotate, so "an administrator when the key was introduced" alone would still let them plant a
key on a member added later). Only then does `VaultKeyGrant.open` check signature, addressing and ciphertext. A
member is entitled only to keys that were current while they were a member; a newcomer reads older records because
rotation re-seals them (§8.6), not by being given old keys. Looking for a grant, every object listed is considered,
names first; there is no bound on how many, because a bound is something junk filed in the right place can fill
(S10, S24).

### 8.6 Removal, leaving and rotation (F4.3, F4.4)

Removing a member or carrying out a departure **always rotates** (the verifier refuses a removal that keeps the
key). Before planning, the device checks that its account may remove the member (`mayRemove`), takes them off the
transport's share (F4.3a: at once, so that a store which honours its share list holds nothing more of theirs
afterwards), syncs, merges what the account has written, and takes the **write cut** (§8.7): the record that ends a member's permission to write says which of their
writes count, and the cut is signed into the record when the plan is made. `RotationPlanner.plan` then produces a
`RotationPlan`, pure data the integrator executes, in this order:

1. **Revoke transport access** for the departing account, again: a resumed plan starts here, and it is the signed
   plan that says whom.
2. **Publish the grants**: the new key wrapped to every remaining member, the planner's own account included.
3. **Publish the membership record** that removes the member, names the new key and carries the cut, after one more
   look at the store: a record that can no longer be adopted is not published, the plan is superseded, and it is
   planned again, with a cut taken again.
4. **Re-seal** every record `MembershipLedger.recordsToReseal(in:)` lists, as new versions through the ordinary
   save path, repeating until the list is empty. A re-sealed version still says whose work it carries.

The plan holds no key in the clear: the new key exists only inside the grants, and the planning device obtains it
like everyone else, by opening its own grant once the record is in its chain. So the plan can be saved and resumed
after any interruption; every step is safe to repeat; its status is read from what the device sees
(`awaitingPublication`, `resealing(remaining:)`, `complete`, `superseded`), not from a counter; and what is left to
do is asked of the ledger (`steps(in:)`), so that once the record is in the chain nothing is published again and the
share is revoked again only while the account is still not a member.

A saved plan is local state and is **signed by the planner's account**, like a pin or the saved ledger: its first
step takes an account off the transport's share, and a file altered or planted on the device must not be able to aim
that at a member of its choosing (S23). The account that leaves is not stored; it is read from the signed record.

The planner needs a `MemberKeyCheck` made on the current head (§8.4) and wraps the new key to nobody whose keys in
the chain are not the ones this device's person verified.

**Pending rotation** (F4.3) is observable on every device, `MembershipLedger.pendingRotation`: a departure
requested and not yet carried out, a removal that is owed (§8.3), a plan of this device's not yet in the chain, the
current key not yet held, and records still to be sealed again.

**Leaving.** The member's device publishes a signed `LeaveRequest` and leaves the transport share; it cannot write
the record itself, which names a key it must not hold. The next unlocked device of an administrator (the owner, if
the leaver is an administrator) turns the request into a rotation whose record carries the request's signature, so
"left" in the chain always means the member said so. A request is bound to the vault and to one stint of membership
(the epoch the member was added), so replaying it after the member has been invited back, or into another vault,
does nothing. Requests are found by name (the vault, a current member's account, the object's own digest) and then
by signature, with no bound on how many objects are looked at: junk filed in the leave directory cannot hide a
request, and so cannot keep a departing member's key current unnoticed (S24).

**Per-item keys** were considered and rejected (`adr/0007-rotation-reencrypts-records.md`): rotation re-encrypts.

### 8.7 Permissions (F4.5)

Two questions, both answered from a verified ledger.

**May this account write now?** `MembershipLedger.writePermission(for:)` (over
`MembershipState.writePermission(for:)`): allowed for the owner, administrators and read-write members of a vault
that has not been deleted, unless their removal is owed (§8.3). The client asks it before its own writes.
(`writePermission(for:atEpoch:)` answers for an earlier epoch of the accepted chain; that is for showing history.)

**Which of this account's writes count?** `MembershipLedger.writeStanding(of:)`, asked before merging anything
another account wrote, and again about everything already merged whenever the ledger's head has changed:

| Standing | What counts |
| --- | --- |
| `mayWrite` | everything the account signed. Judged *now*, not at the time a write claims: a former member holds the keys of their time and can date a write as they please. So a write made while read-only counts once its author is made read-write. |
| `ended(cut:author:refusal:)`: could write once, may not now | exactly the writes inside the **write cut** of the record that ended it (the latest such record of the accepted chain; for an owed removal, §8.3). `author` is the member as the chain listed them then, for checking signatures. |
| `nothingCounts` | nothing: the account never could write here, or the vault was deleted |

It is **not cryptographic**: a read-only member holds the vault key, and a former member holds every key of their
time, so either can produce a ciphertext that decrypts. What stops it counting is every remaining member's client
asking, and the transport's own permission where it has one (CloudKit's read-only participant).

**The write cut.** A record that ends an account's permission to write (the removal or departure of a member who
could write, a change of role to read-only) carries a `WriteCut`: the signing administrator's device, after one more
sync pass, commits to what it has merged of that account's work. So does a record that ends an administrator's role
without ending their permission to write, a demotion to read-write (below, "Who may name the vault"). The verifier
refuses a cut on any other record. To
this module the cut is at most 2,048 opaque bytes, signed with the rest of the record and therefore the same on every
device; what it must let the integrator do is decide, from the cut and a write alone, whether the write is inside,
with the same answer everywhere and no way for the account to add to the set afterwards (§8.8 says what that means
for sync's logs). Then:

- **A write inside the cut counts on every device, whenever it meets it.** A member invited later, or a device
  that was offline, accepts it directly. Nothing has to be published again for a demotion, which rotates nothing; a
  removal re-seals for the key's sake (§8.6), and a re-sealed version says whose work it carries.
- **A write outside the cut counts on no device, including one that merged it before it had seen the record.**
  That device takes it out again and holds it aside for its person (never destroyed, never merged, never published
  again by the device on its own, alone or inside a version of its own). The person may write it again as their own;
  that is then their write.

The second rule is what a per-device rule cannot give. Judging a write only against the membership a device knows
*when it merges it*, and keeping what was merged, lets a former member with a store that still takes their writes
(or a demoted member, for whom there is no transport step at all) aim one write at a device that has not yet been
shown the record: that device merges it, later seals it again under its own name, and everyone accepts it (review
finding S28). With the cut, when a device hears of the record changes nothing about which writes count.

What is still lost, in the sense of set aside on the devices that hold it rather than merged: whatever the account
wrote that the signing device had not merged when it took the cut. That is the price of F4.5 being a rule the
clients keep (S12), and why the device syncs first and, for a removal, takes the member off the transport before
anything else. An administrator chooses the cut they sign; one who signs less than they hold sets a member's work
aside for everyone, which is within what an administrator who can remove the member can already do.

**Who may name the vault** (owner decision, 2026-11-17: only the owner or an administrator renames a shared vault;
§8.4). The vault's description (§5) is the one record a member who may write may not. The session refuses its own
account (`SharedVaultError.renameRefused`), and for anyone else's description every device asks
`MembershipLedger.administratorStanding(of:)`, beside `writeStanding(of:)`, before merging it and again about the one
it holds whenever the head has changed. A description counts only if its writer's writes count *and* this says so:

| Standing | Which of the account's descriptions count |
| --- | --- |
| `holdsRole`: the owner, or an administrator on the accepted head | every one the account signed. Judged *now*, like `mayWrite`, and for the same reason: nothing in a write says when it was made that its writer could not have chosen. So a name an account wrote before it was made an administrator counts once it is one. |
| `ended(cut:author:)`: an administrator once, not now | exactly those inside the write cut of the record that ended the role (the latest such record of the accepted chain; for an owed removal, what the displaced record's branch said, §8.3). That record is a removal, a departure or a change of role, **to read-write as to read-only**. |
| `neverHeld` | none: the account never was an administrator here, or the vault was deleted |

Like read-only it is **not cryptographic**: every member holds the vault key and can seal a description. What stops
it counting is every other member's client asking.

Three rules were weighed.

- *By current role alone*: a description counts while its author is the owner or an administrator. The smallest
  rule, sound, and it needs no cut. What it admits: nothing of a former administrator's, early or late. What it
  costs: the name an administrator gave the vault lapses on every device the day their role ends, by an act nobody
  meant as a rename, with the version held aside on each of them, and comes back if they are promoted again.
  Rejected: "a write inside the cut counts on every device, whenever it meets it" should hold for a name as for an
  item, and a rename made with the role was a permitted write.
- *By the role at the time the description claims* (a version, a date, or a membership record it names): a writer
  chooses what a write claims, so a former administrator would name an epoch at which they held the role. Nothing
  binds a writer except a commitment made by someone else.
- *The cut* (chosen): that commitment already exists for writes, and three of the four ways a role ends already
  carry it (a removal, a departure, a change to read-only: an administrator can always write). The fourth, a
  demotion to read-write, ended no permission and carried none; it now carries one, taken the same way (§8.8,
  `requiresWriteCut(changingRoleOf:to:)`), which bounds the former administrator's descriptions and says nothing
  about their items: their `writeStanding` stays `mayWrite`. Only the owner signs such a record (§8.1).

A fourth, the cut where a record already carried one and the current role for a demotion to read-write, needs no
change to the verifier, and was rejected for what a person would see: the names of an administrator who was removed
would stand while those of one merely demoted lapsed. "By current role alone" keeps the same adversaries out and
admits less, and what it changes is visible to a person, so the choice of the cut over it is recorded for the owner
(`06-adversarial-review.md` §T, K10); going from the cut to the role alone later only narrows what counts.

The record's layout is unchanged: the field was always there, and what changed is which records the verifier lets
carry a cut, and what an empty one on a demotion to read-write means (none of that account's names count). Nothing
is released at format 2, so the version byte stays. After a release this would have to be a later format (§8.9): a
device on the old rule would refuse the new record as invalid, for good, and carry on without it.

What that comes to, case by case:

- **The owner, or an administrator on the head**: their rename counts on every device.
- **An administrator demoted to read-write**: the names they chose before the owner's device took the cut count for
  good; one written after it counts on no device, and a device that merged it before it heard of the record takes it
  out again and holds it aside. Their items are untouched.
- **Demoted to read-only, removed, or gone by their own leave request**: the same, by the one cut that also bounds
  their items.
- **A read-write member whose client does not keep the rule**: never. Not a late one; not one written above an
  administrator's description (a higher version changes nothing about whose work it is); not one labelled as an
  administrator's revision (a description is judged by its bytes in the stream of the device its stamp names, S36);
  and not one that an unaware member's device stored again as a row of its own (it is judged by the write that chose
  it, `VaultMetadata.writtenBy`, S37).
- **A member promoted to administrator after writing a name while read-write**: it counts from the promotion on.
  Deliberately, as a write made while read-only counts once its author may write (S12): the alternative would need
  to know when a write was made, which only its writer says; and it would bind nobody, because the account can write
  the same name again the moment it holds the role. Every device changes its answer at the same head.
- **A demotion displaced by a fork** is not owed (§8.3): until the owner's device proposes it again the account is
  an administrator and its names count, and the new record's cut, taken then, decides.

**A name is chosen, not only written.** Whoever may write can seal a version that carries a description on (the
merge of two rows at one version does, on any device), so with descriptions ordered by their *row's* version a
member could have chosen the vault's name without writing one: by sealing an old description again, genuine to the
byte, above the current one (review finding S54). The description is therefore a last-writer-wins register on the
stamp of the write that chose it (§7.7), which the judge checks with the rest of its bytes; a carrier's version
decides only between carriers of the same description. A description dated above the row that carries it does not
open at all, or an administrator who expects to lose the role could date a name above every rename to come.

### 8.8 What integration calls, and what is not solved

For each shared vault a session keeps a `MembershipLedger` (saved after every ingest that adopted, outranked or
forgot a record, and kept after the account is removed from the vault), the vault's keys, at most one `RotationPlan`,
and the records it has proposed and not yet seen adopted. `SimulatedMember` in `WatchwordTestSupport` is this loop,
written out against a hostile store. One sync pass, in this order:

1. **Membership.** List `sharing/<vaultID>/membership/`; skip names that are not a membership object's, that carry a
   hash the ledger `holds`, or whose contents were refused as `malformed` or `invalid` before (both are permanent,
   except `malformed(.unsupportedFormatVersion)` and `malformed(.unknownOperation)`: a later format, §8.9, which is
   offered again until the ledger holds it in `laterFormatRecords`);
   fetch the rest, drop any whose contents are not what the name commits to (`SharingObjectLocation.isName(of:)`),
   and `ingest` what remains. Offer `unconnected` objects again next time. Persist.
2. **Member keys.** `checkMemberKeys` against the verified contacts; report `substituted` members to the person.
3. **Proposals.** For each record this device proposed: `status(of:)`. Adopted: forget it. Awaiting publication:
   publish it again. Superseded: propose the change again on the new head, if it is still wanted and still possible.
   A record of this account's in `IngestReport.superseded` is a proposal again.
4. **Key.** Fetch the grant of the current key if it is not held (`openGrant(of:from:as:)`) and store the key
   wrapped under Ksym.
5. **Items.** Judge every account whose work the device holds or is offered with `writeStanding(of:)` (§8.7):
   merge what counts, and take out and hold aside what was merged and no longer counts (after any change of head, not
   only for new objects). `SyncKeyring.verify` is where the author's signing key plugs in, from the ledger's state
   or from the standing. The account judged is the one whose *work* it is: a member's version of an item that
   carries another account's edits is judged for both (below).
6. **Rotation.** Continue any saved plan (`RotationPlan.parse(_:account:)`, `steps(in:)`); a superseded removal or
   departure is planned again. Plan each of `owedRemovals` this account may sign. As an administrator, plan a
   rotation for each of `pendingLeaveRequests`. Every plan that removes a member who can write, and every change of
   role to read-only or away from administrator, needs a write cut (`requiresWriteCut`), taken after step 5 of the
   same pass. Then, as a member
   who may write, seal again whatever `recordsToReseal` lists, from an inventory that holds only what counts; a
   re-seal is the same item state at a higher version (`ItemMerge.written`), not an edit, so two devices doing it at
   once converge, and it keeps every value's own author. The vault's description is sealed again only by an
   administrator's device (§8.10). Planning and carrying out a rotation ingest membership again, so the head may have
   moved since step 5 by someone else's record as well as this device's own: what no longer counts under the head is
   taken out once more before anything is sealed again (S59), because a version sealed under the new key is believed
   by a member who joins later to have been judged with every record up to that key in hand.

Accepting an invitation passes the ledger the device already holds for that vault ID, if it ever held one
(`continuing:`), and the owner it knows for it (`knownOwner:`).

**What a write cut must be for sync's logs.** `SimulatedMember` shows one that works for its model, and the
integration has to give the same three properties over `SyncEngine`'s objects and `ItemMerge`'s values:

- *Bound to objects, not to positions.* The simulation's cut is the digest of the last object of the account's
  hash-linked stream that the signing device held with every predecessor; an object is inside it if walking back
  from that digest reaches it. A count per device log would not do: a former member with a helpful store can still
  create an object at a position some device has not filled (`forkedStream`). Nor would the digest of the last
  object *seen*: it commits to predecessors the device never held, which could be brought out later
  (`preparedStream`). `SyncEngine` merges a log strictly in sequence, so "how far this device has merged each of the
  account's device logs, and a digest binding those segments" is the natural cut; 2,048 bytes is room for 32 devices.
- *Applied to work, not to envelopes.* A device that merged a late write before it knew publishes that write on in
  its own next version of the item, signed by a member in good standing. In the simulation a version sealed again
  names the account and the object its text came from, and every reader judges that too
  (`lateWriteSealedAgainByAnother`). In `ItemMerge` every value already carries the revision that wrote it
  (`GroupStamp`, device and counter): the integration maps devices to accounts (the device registry) and drops, on
  every device, values whose revision is outside their account's cut, wherever they arrive from.
- *Taken out, not only kept out.* A device recomputes what counts when its head changes. The simulation keeps
  every object it has fetched and derives its record store from them; `SyncEngine` keeps item history and
  quarantines rather than deletes (§7.5), and needs the equivalent: the item as it was without the values that no
  longer count, and those values held aside for the person.

These are conditions of wiring sharing into sync, not refinements of it. The module signs the cut, gives every
device the same one and says whose writes it governs; the reference loop shows the rest for its own item model, and
§8.10 how the integration gives the three properties over `SyncEngine` and `ItemMerge`.

Not solved here, and to be decided with integration:

- **One signing key per account** (review finding D9). A lost device of an administrator can sign membership records
  until the account key is replaced. The device registry belongs in front of this module's signature checks.
- **An isolated owner device.** A store that shows one of the owner's devices only a former administrator's branch
  can obtain an owner-signed record on it; the two paths then tie on owner-signed records and the former
  administrator, who can lengthen theirs, wins the tie. The owner's removal of them is then *owed* and is planned
  again by the first device of the owner's that sees both paths, after which their path can never win again; until
  then members who follow it seal to a key the former administrator holds. Closing the window needs the owner's
  devices to refuse to sign while they disagree, which is device-registry work. A displaced *demotion* is not owed;
  the owner's device proposes it again (step 3).
- **Forks cost work.** Whatever lost a fork is done again: removals by any device that may, everything else by its
  author's device when it next syncs. Until then an invitee waits, a role change is not in effect, and a removed
  member is listed (with their writes counted only as far as the displaced record's cut). A displaced *demotion* is
  not owed, so until its author proposes it again the member's writes count in full, the later ones included; the
  new record's cut then decides.
- **A departed account's log.** What is inside a cut can be checked only against the objects it names, so a
  departed account's segments must not be collected while a device may still need them to judge a cut, or the cut
  must carry what is needed to judge without them.
- **A former administrator who can still write to the store** can publish valid records on dead branches without
  limit. They change nothing and owe nothing, but a device keeps only 1,024 of them, and each one beyond that costs
  it a signature check on every sync. Taking them off the transport's share (step 1 of a removal) is what stops it.
- **Account key replacement.** A member with new account keys is removed and invited again; there is no record that
  replaces a member's bundle in place.
- **A deleted or exhausted chain.** After `deleteVault`, or at epoch 65,535, membership is frozen; items move to a new
  vault (F4.6's "move to a shared vault" is that mechanism).
- **Keys from a superseded record.** A device that followed a losing branch may have sealed records under its key;
  it keeps that key until nothing it holds is sealed under it (`recordsToReseal` lists them). A device that never
  held that key cannot read those records until one that did has sealed them again.

### 8.9 Ownership transfer (future)

The owner is fixed **in this version**: no record removes, re-roles or replaces the owner (`MembershipRules.authorise`
throws `ownerIsFixed`). The owner wants a way to hand a vault to another member (owner decision, 2026-11-16) and has
deferred it to a future version. This is how it plugs in, checked against the module as built; nothing in the record
format, the rules or the fork rule precludes it, and the one thing that was missing, how a device on this version
behaves when the vault goes on without it, is now built (below).

**The record.** A new operation, `transferOwnership(to: account)`, in a later format version of `WWMR` (version 3;
the operation byte and the version byte both leave room). Signed by the current owner, the account that is the
owner in the state before it, and carrying the new owner's own signature over the same content (an acceptance, as a
departure carries the member's leave request), so nobody becomes owner without asking to. The new owner must be a
member, and an administrator, in the state before it; the old owner stays a member as an administrator (or as the
record says), and their key bundle stays in the list. It does not change the vault key: nobody leaves.

**The rules.** `MembershipRules.authorise` gains the case: the owner alone may sign it, its target must be an
administrator, the acceptance must verify under the target's key from the state before it. Everything that today
says "the owner" means "the member whose role is owner in the state before this record", which is already how the
signer's key is found (§8.3: the signer's key comes from that state, never from the record). The genesis check alone
stays anchored on the pinned owner (`VerifiedContact`), because the genesis has no state before it; an invitation
then names the *current* owner, whose fingerprint the invitee verifies, and the invitee checks the chain back to a
genesis whose owner is reached from the current one by transfers each signed by its predecessor.

**The fork rule must then count transfers first.** Today it prefers the path with the most records signed by the
owner, computed against the pinned owner (`MembershipLedger.resolve`, `signedByOwner`); in this version the two are
the same account. With transfers, two things change:

1. *Owner-signed is judged per record*: a record counts if its signer is the owner **in the state before it**. That
   is computable for every node from its parent's state, which the ledger already holds.
2. *Transfers come before owner-signed counts.* Otherwise the former owner, who signed records as owner before the
   transfer, could fork from just before it and outsign the new owner, which is S1 again with the owner as the
   former administrator. The order becomes: the most transfers on the path, then the most records signed by the
   owner of their time, then the most records, then the lower hash. A former owner cannot add a transfer without the
   new owner's acceptance, and a transfer needs both signatures, so the path with the transfer wins on every device
   however the records are timed.

The same reasoning carries the other rules: the administrator set changes only in records signed by the owner of
their time, and the owner of every state can sign the next record, so nobody is locked out. `owedRemovals` and
`hasStanding` ask "may this signer do this on the accepted head", which a transfer answers like any role change.

**Devices on an older version must fail closed, and this one does.** A device that cannot read the transfer must not
take it for junk: it would carry on with the former owner as owner and split from every updated device. So every later
format keeps this version's prefix (magic, version, vault ID, epoch, previous hash, signer) and a trailing 64-byte
signature under `SignatureDomain.membership` over everything before it, and fits `MembershipRecord.maximumLength`.
This version reads that much of any record it cannot parse (`MembershipRecord.laterFormat`): a later format version,
or this one with an operation it does not know. If such a record extends a record the ledger holds, is in its place
(epoch next, same vault) and verifies under the key of the account that is the owner in the state it follows, the
ledger **stops there**: the accepted chain is the path to that record and nothing after it, whatever else is offered
and in whatever order (`continuesInLaterFormat`, `laterFormatRecords`, held so that serving less rolls nothing back);
the device proposes nothing and plans no rotation (`SharingError.requiresNewerVersion`) and may not write
(`WriteRefusal.requiresNewerVersion`). Other members' writes are judged on the stopped chain and merged, read-only,
until the update; an updated device re-judges everything against the full chain (§8.7's "taken out, not only kept
out"). Anything else in a later format's clothing (unsigned, signed by an administrator, misplaced) is junk: one
signature check at most, and nothing changes. Only the owner can stop the chain, and the owner can already delete the
vault. The held records are saved with the ledger (`WWML`, after the branch records; `restore` accepts them as the
one kind of saved record this version cannot parse, and only if they still stop the chain), and §8.8's step 1 offers
a later-format object again until the ledger holds it. The adversarial tests are `laterFormatStopsTheChain` and
`laterFormatImpostors`.

**What the future version still has to do:** the operation and its acceptance; the rule changes above (and
`LongRunningMembershipForkTests` extended with transfers); the invitation naming the current owner and the
genesis-to-current-owner check; the UI (offer, accept, and what each member is told); and a minimum version, so that
a transfer is offered only once the version that fails closed (this one) is what members run, which it is from the
first release with sharing.

### 8.10 As integrated (`VaultSession`, `SyncEngine`)

`VaultSession+Sharing.swift` holds the session's side and `VaultSession+SharingSync.swift` the sync pass and the
judge; `SyncEngine` asks a `WriteJudge` port (`WriteJudge.swift`) and stays free of cryptography. Everything here was
built and tested on Linux against swift-crypto; the SQLite adapter (`SQLiteSharingStore`) compiles only on a Mac and
has not been run.

**What the session keeps** per shared vault: the `MembershipLedger`, at most one saved `RotationPlan`, the records it
proposed and has not seen adopted, and a **stream index** (`SharedStreamIndex`): for every segment of every device's
stream in the vault, the digest of the object (SHA-256 of its name and envelope), the account whose keys signed it,
the record versions it carried, and the digest of every value it carried that its stream had not carried before and
whose stamp names that stream's device (format 2, S36; format 3 since note-line removals, discards and history
entries are values too, S32 and S43, so an older index is refused and rebuilt by a replay); and the devices a version
is waiting on. All of it goes through the `SharingStateStore` port as blobs, each signed by the
account (`WWML`, `WWRP`, and `WWSI` for the index) or re-checked on load (proposals are records, filtered to this
account's own), so a planted file can delete trust and never add it; the owner's account ID only says which pin
anchors the ledger, and a ledger whose owner's pin is gone is not loaded. Pins live behind `VerifiedContactStore`.
In-memory implementations serve tests; `SQLiteSharingStore` (`sharing.sqlite`, both ports) is the production one.
A vault key received through a grant is stored like any other, as a `vaultKeyWrap` row under the keyset, with a
directory row when the vault is new on the device; a key whose ID the device already holds for another vault is
refused (`keyIDInUse`, S38), because key IDs are public and a shared vault's owner chooses them; the key a shared vault's records are sealed under is the one the
chain names (`currentVaultKey`, the seam §7.7 left), and a write the person makes needs `writePermission` (in
`writableVaultKey`, so every write path asks: save, move, copy, rename, conflict resolution). A rename also needs the
owner's or an administrator's role (`checkSharedRename`, `SharedVaultError.renameRefused`; §8.7), asked before
anything is sealed; vaults that are not shared, and the Personal vault, are renamed as before. Deleting a shared vault
is the owner's and also proposes `deleteVault`; a member leaves instead.

**The session's API** (what a UI calls): `configureSharing`, `publicKeyBundle` (for the directory, and the person's
own safety number), `contactCandidate` and `verifyContact` (fingerprint by typed number, scanned code or comparison;
a different pinned bundle is `keySubstituted` unless the person replaces the pin), `shareVault` (the genesis
record), `invite` (needs a verified contact: wraps the current key and proposes the addition), `acceptInvitation`
(confirms the owner's fingerprint if not pinned, continues any ledger the device ever held for the vault, S26, and
passes the owner it knows for the vault ID, the account itself for its own vaults, S6), `leaveSharedVault`,
`changeRole`, `removeMember`, `rotateVaultKey`, `sharedVaultIDs` and `sharedVaultStatus`. Each is checked by
`MembershipRules` (through the ledger's proposing functions and `RotationPlanner`) before anything is signed.

**One sync** (`syncAll`) runs §8.8's pass around the logs. Before any vault's log: membership ingested (names first,
refused names remembered), member keys compared with the pins, proposals settled, the current key fetched if the
chain entitles this account to it, and the device registry of every account the chains list or listed fetched from
`account/<id>/registry/` and evaluated from the one genesis entry signed by the key the chain gives for that account,
following its newest password change. A registry is evaluated once per signing key the chains give an account, and
each vault uses the one its own chain anchors (S39). Then each shared vault's log runs with the judge, publishing only if this
account may write (a read-only or former member merges and publishes nothing, `sync(publishing:)`), and with
`maintainsLog` off: a shared vault writes no snapshots and collects no segments, because a cut is judged against the
departing account's own segments (§8.8, "a departed account's log"). After the logs: a saved plan continued, owed
removals this account may sign planned, leave requests turned into rotations by an administrator, and what
`recordsToReseal` lists sealed again through `ItemMerge.written` (the description only by an administrator's device,
below), after what no longer counts under the head has been taken out again (`resealSharedVault`, S59). While locked
only membership is ingested and the logs download.

**Verifying** (`SyncKeyring.verify`, `sharedVerify`): an object of a shared vault must carry the dual signature of a
device in the registry of an account the chain lists, under that account's key as the chain lists it (for an account
whose permission ended, the key in the record that ended it), and that account's standing must not be
`nothingCounts`, nor that account one whose chain keys differ from this device's pin (`MemberKeyCheck.substituted`).
A snapshot needs an account that may write now. Devices revoked from a member's account, as the vault's chain anchors
it, are not read.

**The write cut over sync's objects** (S28). The cut a removal, departure or demotion carries is, for each device
whose segments the departing account's keys signed, the furthest sequence through which the signing device holds every
segment of that stream and the chain `H_n = SHA-256("WW-cut-v1" ‖ H_{n-1} ‖ n ‖ digest_n)` through it
(`SyncWriteCut`: at most 36 devices in 2,018 bytes; a cut that does not parse holds nothing). It is taken after a
sync, from the stream index and the vault's merged positions. The judge then gives the three properties:

- *Bound to objects.* Before a pass judges anything, every segment it is about to merge is recorded in the index
  (`WriteJudge.record`; a device's own segments as it publishes them), the first copy of a name kept. A segment of an
  account whose permission ended is merged only if it is inside the cut: at or below the cut's sequence for its device,
  with the chain through that sequence equal to the cut's. One beyond it is held aside; one whose chain cannot be
  checked yet (the stream is not all here) makes the stream wait, as at a gap.
- *Applied to work.* Every remote version, from a segment or a snapshot and whoever sealed it, is admitted only if
  its own revision counts (the segment of its writer's stream that first carried it, for the account that signed
  that segment) and every value it holds counts: each group's values, kept and retained values, the field order,
  each note line, each removal of a line, each resolution's discard and each history entry once per write that
  recorded it (S32, S43), read through `ItemMerge.canonical`, and the vault's description, attributed to the write that
  chose it (`VaultMetadata.writtenBy`, kept by every re-seal, S37) and counted only as an administrator's work
  ("The vault's description", below). A removal, discard or entry that names no writer is
  the work of the row carrying it. And every edit the version's clock says it contains, of any device but its own
  writer's, must have been published in a segment of that device's stream that counts (a version of the record at or
  above that count, `knowledgeCounts`): a version built on a late write holds what that write had seen, and an edit
  made on it supersedes what its writer was shown only through it, so it is held aside like the write (S44); and a
  claim to have seen a current member's edits that their stream has not published is a claim about edits that do not
  exist yet, which would supersede them when they are made, so the version waits for that stream (S46; one about this
  device's own edits is refused). A current member's device whose stream this device cannot read from its first
  segment is not checked. A tombstone is judged the same way before it is applied or remembered
  (`WriteJudge.admitsErasure`): its erasure summary is its author's clock, and one built on a late write would erase
  what its author was shown only through it, so it is held aside and the item stays (S45; `10-sync-correctness.md`
  §9). A value is judged by its **bytes, stamp included**
  (`ItemMerge.attributedValues`), never by the revision its stamp names, which its writer chose (S36): it counts
  through a segment of the stream of the device its stamp names that carried those exact bytes, if that segment
  counts (its signer may write, or it is inside the cut). A value naming this device that none of its segments
  carried counts only if its own copy of the record holds it: a device knows what it wrote, so a value relabelled
  with its revision is refused there at once. A value carried by no segment held here waits: the version is held
  aside and the device its stamp names is remembered (`SharedStreamIndex.awaiting`), and a new segment of that
  device's stream replays the log. The one exception is a member who joined after a rotation, who cannot open the
  segments that carried older values: for them a version sealed under a key introduced at or after the latest record
  that ended anyone's permission to write vouches for such values (its sealer held that record and every earlier
  segment, and judged them), provided the device is listed by an account whose work can count. Segments sealed under a
  key this account was never entitled to are passed over for that reason (`WriteJudge.passesOverSegment`). A tombstone's
  segment carries what applying it writes (`ItemMerge.attributedSettlement`), so a version kept after a deletion is
  judged like any other.
- *Taken out.* When the head changes, every local version of the vault that no longer counts is held aside and taken
  out of the store, and the log is replayed with the judge (a reconciling sync), so that each record is rebuilt from
  the versions that count. The replay rebuilds the engine's erasures from the log too, so a deletion whose segment no
  longer counts erases nothing (S40). Receiving a key, a segment inside a cut that was missing, or a new segment of a
  device a version is waiting on replays it again; the need is written down by clearing the saved index's head, and the
  index is saved before anything a recorded segment lets count is merged, so a restart in between still replays (S41).
  An index refused on load is rebuilt by a replay before anything is taken out against it.

**The vault's description** (§8.7, "Who may name the vault"). The judge asks more of a `vaultMetadata` version than of
an item's, and the three properties above carry over:

- *Whose work.* The description is one value, its bytes the vault, the name, the creation date and the stamp of the
  write that chose it (`VaultMetadata.descriptionStamp`: `writtenBy`, kept by every path that stores a description
  again — the merge of two rows, a rotation's re-seal, a device registered again — or else the row's own). It counts
  through a segment of the stream of the device that stamp names which carried those bytes, if that segment counts
  as a write (above) **and as an administrator's** (`administratorSegmentCounts`): its signer is the owner or an
  administrator on the head, or was one and the segment is inside the cut of the record that ended the role. A
  read-write member's segment therefore carries no description that counts, whatever the description claims; a
  version of anyone's that carries such a description on is held aside with it; and a description this device wrote
  and has not published counts only while its own account holds the role, so a rename made before the device heard
  of its demotion is taken out before it is ever published.
- *Which one.* Among the descriptions that count, the one with the highest stamp is the vault's (§7.7), whatever
  version the row carrying it has reached. A member who may write can seal carriers, and so could otherwise choose
  between names administrators once wrote (S54).
- *Taken out.* `takeOutWhatNoLongerCounts` judges the description like every other record at each change of head,
  and the replay rebuilds it from the versions that count: a promotion makes held-aside names count, a demotion
  takes late ones out, on every device at the same head. A segment at or below a former administrator's cut that
  arrives later asks for a replay, as one inside a write cut does.
- *A member who joined after a rotation* cannot open the segment that first carried an older name, and takes it on
  the word of the version that carries it on. For a description that word must be an administrator's
  (`vouchesForDescriptions`): the version's own writer is the owner or an administrator (its segment counts as
  one's), and for each account that could be the name's author, either it holds the role now or the version is
  sealed under a key introduced at or after the record that ended its role, so that its sealer held that record and
  judged the name by its cut. A member's version vouches for no name (S55), which is why only an administrator's
  device seals the description again after a rotation (the device that planned the rotation is one). A device whose
  account may not name the vault leaves the description out of what it counts as its own to seal again
  (`sharedInventory(_:resealableBy:)`), so its `pendingRotation` does not report it as owed for as long as no
  administrator's re-seal has reached it (S60). That word is judged by the row's bytes: each segment files the
  digest of every description row it carried, and a row counts, and vouches, only through the segment of its
  device's stream that carried those bytes (`descriptionCarriage`), never by its version alone, which a snapshot
  can deliver under any device's name with other bytes (S61). The same word
  stands when the only carrier of the name that such a member can read is a late copy its former author published
  again (S56). Holding the record is not having judged by it: a device that learns of a demotion while it plans a
  rotation of its own holds, for a moment, a late name it merged before and a key newer than the demotion. So
  `resealSharedVault` takes out what no longer counts under the head before it seals anything again, items as well
  as the description, and seals nothing while it cannot (S59); without that such a device, if its own account had
  joined after a rotation, kept the late name as a row of its own and handed it to every member who joined since.

What is held aside is kept in the sync state's quarantine (`quarantinedVersions`, `SyncReport.heldAside`), never
merged, never published by the device and discarded only by the person; the objects it came from are judged again
on every replay of the log, so a write made while read-only counts once its author may write. A version that cannot be merged because the join would be
over the payload limit is quarantined the same way (Y37).

**A chain stopped at a later format** (§8.9) makes the vault read-only on this device, whatever its role, and says so:
`SharedVaultStatus.requiresNewerVersion` for the UI (the person is told to update the app) and
`SharedVaultSyncReport.requiresNewerVersion` for each sync. The ledger already refuses proposals, plans and the
device's own writes (`writePermission` is `.refused(.requiresNewerVersion)`, so every write path and the engine's
publishing stop); the session adds what the ledger cannot see: waiting proposals are kept and not published again, a
saved rotation plan is not carried on (`resumeRotation` throws `SharingError.requiresNewerVersion`), nothing is
planned or sealed again after the logs, and no leave request is published. Membership is still ingested, the log
downloaded, and the writes of members who may write on the stopped chain judged and merged. A membership object
refused as `malformed(.unsupportedFormatVersion)` or `malformed(.unknownOperation)` is not remembered as refused until
the ledger holds it in `laterFormatRecords` (§8.8 step 1): one that arrives before the record it follows stops the
chain once that record is here. Tests: "Vault session: a shared vault in a later format", and
`laterFormatBeforeItsParent` and `laterFormatImpostorsThroughTheSession` in "shared vaults through the session".

**Limits** (also `06-adversarial-review.md` §I, S33 to S35, S42, S45 and S46, and §T, S57 and S58):

- A device ID listed by more than one member's registry makes values stamped with it that reached a newcomer only
  through vouching count only while every listing account's work can count (S33, insider denial of service like S11).
- Vouching is for a member who joined after a rotation, and only under a key introduced at or after the latest record
  that ended a permission: a member invited after a demotion, with no rotation since, holds aside versions carrying
  values from before the last rotation until the next one seals them again, and a store withholding one device's
  stream from another delays every version carrying that device's values there (S42). Rotate after a demotion before
  inviting.
- A permanent deletion's erasure summary is the deleting device's clock, and tombstones are judged by their segment
  only: a device that merged a late version and then deleted the item claims what the late writer had seen (S45). A
  late version's vectors can claim edits of a current member that do not exist yet, which a device merging it carries
  on (S46). Both tracked, neither reproduced.
- A name chosen by an administrator whose role ended after the last rotation cannot be checked by a member who joined
  after that rotation: the version carrying it on was sealed under a key older than the record, so nothing says its
  sealer had judged it by the cut. That member's device shows no name for the vault (the row's badge still says whose
  vault it is) and holds the version aside until the next rotation seals the name again or an administrator renames
  the vault; every other device shows the name throughout (S57). The same word is missing from a carrier that a
  read-write member's device stored when two rows met at one version: a member who joined since holds that row aside
  and keeps the administrator's own row of the same name. Rotate after demoting an administrator, as after any
  demotion (S42).
- An administrator's choice of name is bounded only by the role: one who holds it can write any name, date it up to
  the version jump the engine allows, and seal another's description again; a name written before a promotion counts
  from the promotion on (§8.7). `modifiedAt` is not part of what the judge attributes, so a carrier can state another
  time for a name it carries; nothing reads it (S58).
- A member who joined after a rotation reads records sealed before it only once a device that holds the old key has
  sealed them again (rotation does so for every record a member who may write holds), and a version of a shared vault
  that does not open here is held aside, not merged (S34).
- Another device of a member's account receives the vault's keys through the account's own vault directory but no
  ledger and no pins: it accepts the invitation itself. The ledger, pins and plans are per device (S35).
- The transports' own sharing (`ShareAccessControl` is the port), the key directory's adapter, and the UI are open
  (`03-implementation-plan.md` milestone 4).

## 9. AutoFill and service matching (`WatchwordMatching`)

Inputs from the OS are `ASCredentialServiceIdentifier` values (domain or URL). Normalisation:
parse as URL when type is `.URL`; take `host`, lowercase, strip trailing dot, IDNA-normalise;
reject identifiers with user-info or non-host content.

Scope matching produces a **specificity** score per (item, scope): exact host match scores
`2 × labelCount + 1`; subdomain match (host ends with `"." + scope.host` and
`includeSubdomains`) scores `2 × scopeLabelCount`; `excludedHosts` veto. An item's score is the
best of its scopes. Ranking then applies **shadowing**: an item is *shadowed* if another matching
item has a strictly higher score. Shadowed items are never offered, listed, pre-selected or filled
on that host by the extension; they are reachable in the app only (F6.6; the extension's "other
accounts on this site" list was removed by owner decision, 2026-11-16).

Scenario S1: retail item scoped `amazon.com` (subdomains on); AWS item scoped
`signin.aws.amazon.com` and `console.aws.amazon.com`. On `www.amazon.com`, only retail matches. On
`signin.aws.amazon.com`, both match but AWS scores higher and retail is shadowed. The person can add
`aws.amazon.com` to the retail item's `excludedHosts` to hide it entirely.

Normalisation is stricter than "lower-case and compare", because two Foundation behaviours
verified against the real toolchain would otherwise widen matching:

- `URLComponents.host` returns a **percent-decoded** host, so `https://x.amazon%2Ecom/` yields
  `x.amazon.com` and would match an `amazon.com` scope. The normaliser inspects
  `percentEncodedHost` and rejects ASCII escapes, while allowing the non-ASCII escapes that
  represent an IDN host.
- `trimmingCharacters(in: .whitespacesAndNewlines)` strips U+200B, so `amazon.com\u{200B}` was
  trimmed into a match. Trimming is ASCII-only.

Conversely, Foundation's IDNA compatibility mapping is *honoured*: fullwidth `ＡMAZON.com` and
Kelvin-sign `amazonK.com` arrive folded to `amazon.com`, which is what a browser resolves.
Characters IDNA keeps distinct (Cyrillic `а`) stay distinct and never match an ASCII scope. A bare
domain is mapped the same way, by parsing it as `https://<domain>/` once its own checks have passed, so one
host has one normalised form whichever kind of identifier carries it. Until the import fuzzer found it, a
domain was only lower-cased: `ＡMAZON.com` was `ａmazon.com` as a domain and `amazon.com` as a URL, so a
scope saved from one never matched the other, and a bare-host scope an import made came back from its own
export as a different host. Where Foundation finds no host, an ASCII domain keeps its checked form (malformed
punycode stays visible to the phishing checks, and matches nothing that arrives as a URL) and a non-ASCII
one is refused.

Types carry the guarantee: `ScopeMatcher` and `ItemRanker` accept only a `NormalizedHost`, whose
initializer is internal to the module, so the only way to obtain one is through the normaliser.
`AutoFillGate` is the single function through which a secret may reach the OS, and it re-checks
`isSelectable` even when the person chose the item explicitly.

**Only `https` pages (F6.9, owner decision 2026-11-16).** Before anything is matched, the gate refuses a
URL identifier whose scheme is `http` (`AutoFillGate.page`, `HostNormalizer.isPlainHTTPPage`), with
`FillRefusal.insecurePage(host)`, in `decide` and in `authorize`, so an explicit choice cannot get past it.
What it stops: a person on a network an attacker controls (adversary A2 on the path) being given a fill
into a page whose content, scripts and form the attacker can read and rewrite. A domain identifier carries
no scheme (an app's associated domain, a published identity) and is judged on its host as before. Two
halves of the owner's request cannot be enforced in the extension, and are stated plainly rather than
approximated:

- *Forms that submit to `http`.* The credential provider API gives the extension the page's service
  identifier, never the form's action, so an `https` page whose form posts to `http://` is filled like any
  other. The browser's own mixed-form warning is the only control there.
- *QuickType on an `http` page.* A tap hands back the identity Watchword published, which is a domain, and
  not the page (§9.2, "The page, or nothing"). `ServiceScope` records no scheme: a scope is a host. An
  imported item does keep an `http://` URL it came with, as a website field beside the scope, but that is
  not evidence about the page the system offers the identity on (an item saved from `https` is offered on
  that site's `http` pages too), so identities are published as before and such a fill is not refused. The
  hygiene report flags every saved `http://` address (`ItemAnalysis.insecureURLFields`, §13.5), and a
  login made on an `http` page is never saved, so nothing would offer it there again.

### 9.1 Anti-phishing

Full design in `05-anti-phishing.md`. Three additions beyond matching:

1. **Scope policy.** `ScopePolicy`/`PublicSuffix` refuse single-label and public-suffix scopes at
   creation, edit, and import. Without this, a `com` scope becomes the top-ranked match on an
   attacker's domain.
2. **Look-alike warning.** `PhishingDetector` turns "no match" into a named warning for hosts that
   resemble a saved scope — visual skeleton, edit-distance near-miss, saved name out of position,
   per-label mixed script, punycode. Silence is what pushes a person to copy a password by hand.
3. **Ambiguity is surfaced, not resolved.** `ItemRanking.isAmbiguous` forces a choice when items
   tie, so the extension never fills the first of a tied set.

Published identities: for QuickType we publish `ASPasswordCredentialIdentity` values (item, scope
host, username, with `rank` set from specificity), one `ASPasskeyCredentialIdentity` per passkey,
and (iOS 18+) `ASOneTimeCodeCredentialIdentity` values for TOTP fields. Two facts about the system
decide *which* identities:

- A tap on a password or code suggestion hands the stored identity back
  (`provideCredentialWithoutUserInteraction(for:)`, then `prepareInterfaceToProvideCredential(for:)`).
  The extension is **not told the page**. Only `prepareCredentialList(for:)` carries the page's
  service identifiers.
- Which pages a stored identity is suggested on is the system's own matching. It is undocumented,
  and as far as other providers have observed it is by registrable domain: an `amazon.com`
  identity can be suggested on `signin.aws.amazon.com`, and an identity for one subdomain on a
  sibling.

So on the QuickType path `AutoFillGate` cannot be asked about the page, and our in-extension
ranking is **not** authoritative there: nothing of F6.6's shadowing, a scope's `excludedHosts` or
`includeSubdomains == false` would be applied to a tap. The rule that follows is that an identity
is published, and answered, only if the item is the right answer on *every* page the system might
offer it on. `CredentialIdentityPlanner` (§9.2) is the pure function from the vault's items to the
identities, and it gives an item a password or code identity for a scope host only when

1. the scope covers the whole site: its host is the site's root, subdomains are included and no
   host is excluded. The root is `PublicSuffix.broadestSite(of:)`, which errs wide on purpose: the
   last two labels, three under a country-code second-level domain, and a shared-hosting suffix is
   *not* honoured, because whether the system treats `zendesk.com` as a suffix is not ours to
   know. A tenant's login (`acme.zendesk.com`) is therefore never suggested by the keyboard;
2. no other item outside the trash holds a scope below that host, so there is no page of the site
   where another account is more specific (S1: once the AWS item exists, the retail login has no
   identity, and the AWS login never had one); and
3. no other item scoped to that same host shares the name the suggestion shows, so accounts that
   tie are told apart by what the person tapped (F11.5), and two accounts under one email are not
   suggested at all.

Everything else is reached through the keyboard's key icon, which opens the extension's list:
that request names the page and goes through the gate. The cost is real and deliberate: a login
saved from the extension is scoped to one exact host and has no QuickType identity until the
person widens its scope in the app. A passkey identity is published exactly when the gate would
release the passkey for its relying party, which every passkey request names. Because of rules 2
and 3 one item's identities depend on the others, so a change to one item is published as the
difference between the whole sets before and after.

Nothing is published for an item that is excluded from AutoFill (F6.8), archived or in the trash,
for an item whose ID another item shares, for a scope the scope policy refuses, for a login with
no user name, for a second code field of one item, or for a passkey its relying party reported
unknown; and one item publishes at most 64 identities. The rank is the specificity an exact match
on the host scores (`2 × labels + 1`). An identity carries a host, a user name, the passkey's
credential ID and user handle, and a record identifier made of the item's and field's random
UUIDs. Nothing else of the item leaves: no title, note, tag, field label or secret.

The first on-device question for milestone 5 is therefore what the system hands back and where it
offers an identity; if it turns out to match exact hosts only, rule 1 can be relaxed, and nothing
else in the model changes.

Passkeys: the extension signs `authenticatorData || clientDataHash` with the item's P-256 key,
increments no counter (Apple's guidance for synced passkeys), supports `prf` (HMAC-secret derived
from a per-passkey 32-byte secret stored in the field) and `largeBlob` storage in the item.
`PasskeyAuthenticator` (§9.2) is that authenticator, in software: ES256 only, attestation format
`none`, credential IDs of 32 random bytes, the signature DER-encoded. The flags say what happened
rather than what a relying party would like to hear: UP and UV come from what the extension
reports about the person in *this* request, BE is always set, and BS is set only when the vault
syncs. `prf` is evaluated as CTAP's `hmac-secret`:
`HMAC-SHA-256(prfSecret, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input))`; every credential gets a secret
at creation whether or not the registration asked for the extension, and since there is one secret
where CTAP keeps a second for unverified requests, `prf` is evaluated only for a verified person.
A passkey is bound twice:
the credential stores its relying party ID and signs for no other, and the item holding it must
pass `AutoFillGate` for that relying party as a host, like any release. A relying party ID is a
`RelyingPartyID` value, which exists only after `HostNormalizer` and `ScopePolicy` have accepted
the string in its one canonical spelling, so `com`, `Google.com` and `google.com.` are never
hashed, stored or signed for. That spelling is lower-case ASCII, with A-labels for an
internationalised name, and it is what is hashed and stored; matching uses the ID as `HostNormalizer`
gives it (`RelyingPartyID.host`), which since a domain normalises as its URL does (§9.1's pipeline) can
be the Unicode form, so a new passkey item's scope is in that form too and matches its own relying
party on any platform's Foundation.

### 9.2 As built in milestone 5 (`WatchwordAutoFill`, the portable core)

The credential provider extension is an adapter. Every decision it makes and every byte it
returns comes from `WatchwordAutoFill`, which imports no Apple framework and mirrors the
AuthenticationServices request and result types with its own values, as `WatchwordMatching`
mirrors `ASCredentialServiceIdentifier`. It reaches the vault through one port:

```
protocol CredentialVault            (VaultSession conforms; FakeCredentialVault in tests)
  credentialItems()                 every readable item, archived and trashed included
  confirmUnlocked()                 throws `locked` unless unlocked now; the last call before a release
  defaultVaultID()                  where a new item goes
  isBackedUp()                      whether items reach the sync store (the BS flag)
  saveCredentialItem(_:replacingVersion:)   create, or compare-and-swap on the version read
```

Every method throws `CredentialVaultError`, and `locked` whenever there are no keys. The vault
keeps owning versions, timestamps, history, sync metadata and the scope policy check. Item IDs
should be unique in what `credentialItems()` returns, and the model does not rely on it: an ID two
items share (a member of a shared vault choosing a record ID, an item mid-move between vaults)
names neither, so both keep ranking and neither is listed, released, written or published.

`CredentialProviderModel` is the actor behind the extension. One method per request:

| Request (AuthenticationServices entry point) | Method | Answer |
| --- | --- | --- |
| Credential list (`prepareCredentialList`) | `credentialList(for:passkey:)` | passwords of the most specific matches and passkeys of the relying party (never the accounts they shadow), a suggestion only for a sole match; or `LookAlikeWarning` |
| Password, chosen in the list | `password(for:identifiers:)` | `PasswordCredential` |
| Password, QuickType (`provideCredentialWithoutUserInteraction`) | `passwordWithoutInteraction(for:)` | the credential for an identity the planner would publish now; otherwise `requiresInteraction` or a refusal |
| One-time codes (iOS 18) | `oneTimeCodeList`, `oneTimeCode`, `oneTimeCodeWithoutInteraction` | `OneTimeCode` with the seconds remaining |
| Text to insert, host named | `textInsertionList(for:)`, `textToInsert(for:identifiers:)` | the field's text, one recovery code, or a code field's current code |
| Text to insert, no host (iOS 18's `prepareInterfaceForUserChoosingTextToInsert()`) | `textInsertionListWithoutHost()`, `textToInsertWithoutHost(for:)` | a hand-picked field that is not a secret |
| Passkey assertion | `passkeyAssertion`, `passkeyAssertionWithoutInteraction` | `PasskeyAssertionResult` with `prf` and `largeBlob` output |
| Passkey registration | `passkeyRegistrationOptions`, `registerPasskey` | attestation object, and where the credential was stored |
| Conditional registration (iOS 18) | `registerPasskeyWithoutInteraction` | as above, or `noItemToUpgrade` |
| Save password | `savePasswordPlan`, `savePassword`, `savePasswordWithoutInteraction` | create (alone, or beside the accounts already there), offer an update, or already saved |
| Generate password | `generatePassword(for:)` | a password obeying the site's `passwordrules`, with its entropy; refused for a page loaded over `http` when the request names one |
| Credential-update reports | `handle(_:)` | which fields were flagged or renamed |
| Identity publishing | `publishAllIdentities()`, and after every write | through `CredentialIdentityPublisher` |

Which system version first makes each request is the adapter's concern; the model answers any of
them whenever it is asked.

What holds across all of them:

- **One gate, by construction.** A secret is read out of an item only through an `Authorization`,
  whose initialiser is private to `ReleaseGate.swift` and is called in one place, after
  `AutoFillGate.authorize` (or `authorizeOneTimeCode`) accepted that item for a host the system
  named. A choice the person made in a list is authorised again; what a list showed is not
  evidence (SEC6, F11.1).
- **No override.** There is no parameter, mode or second call that releases after a refusal
  (F11.4, F11.7). A look-alike host gets a `LookAlikeWarning` *instead of* a list (F11.3).
- **Only `https` pages (F6.9).** A page loaded over plain `http` gets nothing: lists name nothing for
  it (and with nothing else named are `refused(.gate(.insecurePage))`), a password, code or text is
  refused even when chosen, no login is saved from it, and no password is generated for it. The gate
  decides it (§9 above); the lists read the page through `AutoFillGate.page`, as a release does. Domain
  identifiers and passkeys are unchanged, and a QuickType fill on an `http` page cannot be refused,
  since the tap does not name the page.
- **Shadowed accounts are neither listed nor released.** An item that matches the host less
  specifically than another (F6.6) is not in the list (there is no "other accounts" part: listing
  what cannot be used served nothing; owner decision, 2026-11-16), and the gate refuses it even
  when chosen, as it always has; to use one on that host the person adds the host to the item, in
  the app. A new item that would outrank accounts already offered still says how many it would
  hide (`NewItemProposal.hiddenAccounts`).
- **Archived and excluded items rank but are not released; trashed items do neither.** An archived
  AWS item still keeps the retail login off the console. An item marked "exclude from AutoFill
  suggestions" is reachable only by opening the app (F6.8): the extension does not list it, does
  not release it by choice or for an identity the store still holds, and does not write to it.
- **Stored scopes are checked again.** The gate ranks among items with only the scopes
  `ScopePolicy` accepts, so a `com` scope written by another vault member or an import matches
  nothing (F11.2). The stored item is not rewritten.
- **The page, or nothing.** The gate is asked about a host only when the system named it for
  *this* request: the identifiers of a list request, the relying party of a passkey request, the
  identifier of a save. A QuickType tap names no page (§9.1, "Published identities"), so
  `passwordWithoutInteraction` and `oneTimeCodeWithoutInteraction` treat the identity's identifier
  as a lookup key and answer only an identity `CredentialIdentityPlanner` would publish for the
  vault as it is now: host, user name (or code label) and record all as planned. Anything else is
  `requiresInteraction(.ambiguousMatch)` when other items are the reason and `.staleIdentity`
  when the item itself changed, and the person chooses from the list, which is told the page. The
  gate is still asked, about the identity's own host. A passkey chosen in the system's sheet is a
  choice of one credential for a relying party the request names, and needs only the gate.
- **No host, no secret.** With no service identifier a password, a one-time code, a passkey
  assertion and host-checked text are refused. Text insertion is the one request the system makes
  without naming a site, and it is a separate pair of methods, not the gated ones with an empty
  list, so an adapter that lost the identifiers gets a refusal. Without a host the person picks an
  item by hand, as in the app, and can insert only fields that are **not secrets**: user names,
  emails, phone, account and card numbers, dates. A recovery code is a one-time code that needs no
  device and an API key is a bearer credential; a security answer and a PIN each sign someone in
  or recover an account somewhere. Typed into a look-alike they are replayed at once, and with no
  host there is no mismatch to detect, so F11.4's rule for codes holds for all of them. This
  narrows PRD F6.4 as written (S2's recovery codes, S3's answers and S4's PIN insert as text only
  where the system names the host, which iOS 18's request does not; otherwise they are copied
  from the app, where the item's scopes are in view). Which of those kinds, if any, may leave
  without a host is the owner's decision; the predicate is `ManualChoice.isInsertable`.
- **A page cannot plant, widen or hide.** A new login is scoped to the exact host it was made on,
  without subdomains, titled by that host (never by the page), and goes through `ScopePolicy`. An
  update touches the password of an item the gate would fill on that host and never its scopes.
  Without UI a login is saved only for a host nothing is saved for. Where accounts are already
  offered on the host, an item scoped to the exact host (or, for a passkey, to the relying party)
  would outrank them, and the gate would then refuse them there even when chosen: right for a
  different service under the same domain (S1), wrong for a second account on the same one, and
  the request cannot say which. So `NewItemProposal` reports `hiddenAccounts` and offers
  `besideExisting`, the scope of the accounts already there (one the person gave an item), and the
  person picks `newItem` or `newItemBesideExisting`. The passkey sheet's suggestion never hides
  an account.
- **A registration never adds a scope.** A passkey joins an existing item only if the gate
  already authorises that item for the relying party, and an item holds at most eight. A login
  saved for `www.shop.example` is not for the relying party `shop.example`; the sheet names it
  under `relatedLogins`, the passkey goes to an item of its own, and joining the two means adding
  `shop.example` to the login in the app (F11.7). A conditional registration only ever adds a
  passkey to the one saved password login for that relying party and user, and only to an item
  that holds no passkey yet: every field of that request, the user handle included, is the
  page's, so "one per account" would be no bound at all.
- **A remote party never deletes.** A report sets or clears a flag in `Field.meta`
  (`reportedUnusedAt`, `reportedUnknownAt`) or changes a passkey's account name, only on items the
  gate would release to the reporter, and at most once per field per day, because every change is
  a version in a history that is never pruned (F1.4).
- **Locked is a state.** `vaultLocked`, or `requiresInteraction(.vaultLocked)` for a request made
  without UI. Each request reads the items once; each step of an interactive flow reads them
  again; writes are compare-and-swap. A lock that lands mid-request wins: a write fails in the
  vault, and every request that hands a secret back calls `confirmUnlocked()` as its last
  suspension, so plaintext read before the lock is not released after it.
- **The page is not trusted.** Identifiers, relying party IDs, user names, allow and exclude
  lists, `prf` inputs, blobs, password rules and reports are bounded and validated here, whatever
  the system checked first.

Also in the module: `TOTP` (RFC 6238 over an injected instant), `PasswordRules` (a strict parser
for the page's `passwordrules` and its mapping to `RandomPasswordPolicy`; the generated password
is checked against the parsed rules before it is returned), and `CredentialIdentityPublishing`.

**`VaultSession` is the `CredentialVault`** (`VaultSession+AutoFill.swift`; `WatchwordKit` depends on
`WatchwordAutoFill`, never the reverse). `credentialItems()` is every vault's items as `items()`
presents them (read through their rows, canonical, what a vault's deletion left shown trashed). The
store keeps one row per item ID whatever its vault and sync refuses a record naming an ID another
vault holds, so an ID occurs once; a move is a copy under a derived ID and the original trashed in
one commit, so the original is never fillable beside its copy. `saveCredentialItem` is a
compare-and-swap inside the session's own `write`: the expectation (absent, or the version read) is
checked against the row the write read, and the commit is conditional on that row, so a save or a
merge landing in between is refused with `versionConflict`; the session stamps the edit
(`ItemMerge.stamped`) and runs every scope through `ScopePolicy`, as `save` does. `isBackedUp()` is
whether the session syncs. `confirmUnlocked()` is the actor's own check that keys are resident.
The extension process builds a session over the App Group store and the shared Keychain and
unlocks it with `quickUnlock(prompt:)` (the Local Unlock Key the Keychain releases after biometric
authentication, then the AUK, then the keyset) or the password; nothing else is exposed for it.

Still open for milestone 5, all on a Mac: the extension targets' adapter over this model, the
encrypted index record that lets the extension list without decrypting every item, and on-device
QA (first, what the system hands back for a QuickType tap and on which hosts it offers an identity,
§9.1; then what it passes as `prf` salts, and how it treats UP = 0 on a conditional registration).

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

As built in milestone 2 (`WatchwordKit.VaultSession`):

- **No boolean anywhere.** `BiometricGate` reports only enrolment; it cannot authorise. The
  biometric check *is* the Keychain read of the LUK, and unlocking needs that LUK to open the wrapped
  AUK, and the AUK to open the keyset. A gate that says yes without the Keychain releasing the key
  unlocks nothing (adversarial suite "unlock and quick unlock").
- **Refusal destroys.** When the policy refuses, the LUK is deleted rather than merely ignored, so a
  later bug cannot revive an expired enrolment; a biometric re-enrolment also forgets the state.
  After `maximumFailedAttempts` prompts that did not end in the key — cancels included, because the
  system prompt retries internally and a run of failures usually ends in Cancel — the LUK is deleted
  and no further prompt is shown. Bytes from the Keychain that fail to open the wrapped AUK, or an
  AUK that fails to open the keyset, destroy the enrolment; a bad vault-key row does not.
- **Enrolment needs the password.** `enableQuickUnlock(password:)` re-verifies the password against
  the stored header, because enrolment starts the 14-day interval: a quick-unlocked session must not
  be able to restart it.
- **Clock.** Elapsed time is wall-clock; a clock that reads earlier than the last password unlock
  is treated as expired, not as zero. Winding the clock back *within* the window is not detected
  (no trusted time source); it still needs the enrolled biometric, so the interval is about
  re-practising the password, not about stopping a thief.
- **Lock wins.** `VaultSession` is an actor and actors are re-entrant across `await`. A lock epoch
  is checked after every suspension, so a `lock()` that lands during an unlock discards the derived
  keys (`lockedDuringUnlock`) and one that lands during a save fails it (`locked`) instead of sealing
  with a zeroised key.
- **Auto-lock** (`AutoLockPolicy`, F5.5) is likewise pure: idle timeout, background grace (default
  zero: backgrounding locks at once), screen lock/sleep, and a clock that moved backwards locks.

## 11. Secure memory

`SecureMemory` is the only module allowed to use unsafe pointers. It provides `SecureBytes`, the
`SymmetricKey` bridging for CryptoKit, `ConstantTime` comparison, and the CommonCrypto PBKDF2 call
(which needs raw pointers, and reads the password from and writes the key into protected storage).
From milestone 2 it also holds the four system bindings whose signatures are pointer-typed
(ADR 0001, milestone 2 amendment): the SQLite wrapper, `SecItemCopyMatching` (which returns
Keychain data straight into `SecureBytes`), `LAContext.canEvaluatePolicy` and the PDF
`CGContext` initializer. Each is one small file with a safe API.
`SecureBytes`:

- heap storage that is page-aligned and a whole number of pages, so `mlock` (best effort; the result
  is reported, not assumed) never shares a page between two buffers — `mlock` does not nest, so a
  shared page would be unlocked when either buffer was released;
- `zeroise()` with `memset_s`/`explicit_bzero`, which the optimiser may not elide, on lock and in
  `deinit`; reading a zeroised buffer **traps**, because an all-zero key read back by a racing
  encryption would seal records under a key everyone knows;
- excluded from core dumps on Linux (`MADV_DONTDUMP`);
- a zeroise during a read on the same thread (the lock is recursive) traps rather than wiping the
  bytes under the reader;
- redacted `description`, `debugDescription` and reflection mirror, and no `Codable`, `Hashable` or
  `Equatable`. It is a `Collection`, because CryptoKit's sealing APIs take `DataProtocol`, so
  `Array(bytes)` and the non-constant-time `elementsEqual` compile; production code uses the named
  `unprotectedCopy()` for the rare non-secret copy-out and `constantTimeEquals` to compare.

Every unsafe construct in the module is marked with an `unsafe` expression, and the
`strict-memory-safety` CI job builds all modules with warnings as errors, so any construct the
compiler classifies as unsafe must be marked. The compiler does not classify everything: an
`@_silgen_name` declaration with integer parameters binds `memset` with no pointer type in sight.
So a separate CI tripwire (`assert-unsafe-confined.sh`) fails on `unsafe` in any form, `@unchecked`
and underscored attributes outside `SecureMemory`, on hand-bound foreign symbols anywhere, and on
symlinks or non-Swift files under `Sources/`; and `assert-no-dependencies.sh` rejects custom target
paths, non-Swift target types and compiler-relaxing settings in the manifest. These are tripwires,
not proofs; review of `Sources/SecureMemory` is the backstop (`adr/0001-memory-safe-language.md`).

## 12. Password generation (`WatchwordGenerator`)

Uniform sampling with `SystemRandomNumberGenerator` (backed by the OS CSPRNG) via
`Int.random(in:using:)`, which is unbiased. "Require each selected class" is implemented by
rejection sampling (regenerate until satisfied) so the output distribution stays uniform over the
accepted set. Entropy is reported as `length × log2(alphabetSize)` for random mode (conservatively
reduced by the rejection constraint), `words × log2(7776)` for passphrases with the EFF large list,
and `digits × log2(10)` for PINs. Site password rules from `ASGeneratePasswordsRequest` are mapped
to generator options.

The generator returns a Swift `String`, which cannot be zeroised; see PRD SEC4 for why that is
accepted and what bounds the exposure. A `SecureBytes`-returning variant is worth adding if a
future flow needs a generated password to outlive a single UI interaction.

## 13. Hygiene (`WatchwordHygiene`)

The portable core is built (milestone 6), and so is its wiring into `VaultSession` (§13.8), with results synced
through the vault (§13.9); the `URLSession`
adapter, the file adapter for the device-local store, the background-task glue and the report UI are not. The module depends on `WatchwordModel`,
`SecureMemory` and `Crypto` (SHA-1 for the range API, HMAC-SHA-256 for reuse and for result bindings) and on nothing else: it does
not know the session, the store or any Apple framework, takes the time as a parameter and randomness as a
generator, and reaches the network only through the `HTTPClient` port. Everything below runs under
`swift test` on Linux.

### 13.1 Who hygiene defends against

Hygiene is the one feature that talks to a third party, so it adds two positions to §2:

- **The service and the network path** (the Have I Been Pwned operator, its CDN, a TLS-intercepting proxy
  the device trusts). Sees every request and chooses every response. It learns five hexadecimal characters
  of a password's SHA-1 per check and the times of the checks, and nothing else; it cannot move a request
  to another host, exhaust the device with a response, or switch the scanner off. It can always lie by
  omission (leave a breached suffix out of a range), which nothing on the device can detect.
- **Whoever reads the device at rest** (A2, A3, A8). Finds nothing derived from a password in the clear:
  no hash, no prefix, no reuse token, no breach result (ADR 0005).
- **A malicious household member** (A4) chooses the items a victim's device analyses, so the cost of one
  item, and the request rate whatever the items, are bounded.

### 13.2 Pwned Passwords (F9.1)

`PasswordDigest` is SHA-1 of the password's UTF-8 bytes as typed, split into `PwnedRangePrefix` (twenty
bits, held as a number, so the type cannot carry more of the hash; it prints as redacted, and `hex` is the
accessor the request path is built from) and the other 35 hexadecimal characters, packed into 18 bytes of
`SecureBytes`. It is not `Codable`, `Hashable` or printable. Item fields are Swift
`String`s (PRD SEC4), so `init(utf8Of:)` takes one; the copy fed to the hash is in `SecureBytes` and wiped,
and `init(password:)` takes `SecureBytes` for callers that have it.

SHA-1 is the API's, not a choice: the range API is defined over SHA-1 and only the five-character prefix leaves
the device, so the hash's weakness protects nothing here. CodeQL's weak-hash alert on this call is **accepted, won't
fix** (owner decision, 2026-11-16; `07-supply-chain.md` §3.4).

`PwnedPasswordsClient.check` sends at most one request per check:
`GET https://api.pwnedpasswords.com/range/<PREFIX>` with `Add-Padding: true` and
`User-Agent: Watchword/<version>`, and no other header. The host and scheme are constants (`HygieneHost` has
no public initialiser; `HTTPSURL` is built only by two factories from typed values), so no parameter, setting
or response can redirect a request, and a 3xx is an error (`unexpectedStatus`), never followed.

`PwnedRangeParser` is lenient about what a well-meaning server or proxy might do (either line ending, either
case, stray white space, blank lines, a byte-order mark; lines that are not `SUFFIX:COUNT` are skipped and
counted) and bounded about the rest: 2 MiB, 50,000 lines, counts saturating at `UInt32.max`. Zero-count
lines are padding and are dropped. Exceeding a bound, or a body with no range line at all (an error page, a
proxy's block page), is an error, not an empty range: a response that could not be read is never "not
breached". `PwnedRange.result(for:)` compares the digest with every entry, in full, and selects the count
without a branch, so neither the result nor the time taken says which other suffixes the range holds or
where a match was.

Outcomes are typed (`PwnedPasswordsError`): 429 and 5xx are retryable and carry `Retry-After` clamped to
1 s…1 h (so a server can neither make the scanner spin nor switch it off), a thrown transport error is
retryable, and everything else (other statuses, oversized or malformed bodies) is not.

**Prefix cache.** `PwnedRangeCache` is a port; the client applies the 7-day expiry against the `now` it is
given, ignores an entry dated in the future or filed under the wrong prefix, and stores only parsed 200
responses. `InMemoryPwnedRangeCache` (512 prefixes, 32 MiB, oldest out) is the default. The ranges are
public data, but *which prefixes a device holds* is not: each is twenty bits of the SHA-1 of one of the
person's passwords, enough to discard all but one in a million guesses offline. So the set does not outlive
the keys, in memory or at rest: `HygieneEngine.lock()` calls the port's `lock()`, after which no prefix may
be readable without the vault's keys. The in-memory cache empties itself. A persisting implementation must
seal what it writes under a key that is gone when the vault locks, drop its plaintext copies at `lock()`,
read and write nothing while locked, and keep it on the device; `CachedPwnedRange.encoded()` is the
plaintext to seal (ADR 0005, amendment). The client asks "still unlocked?" both before storing a range and
after, and removes the entry if the answer has changed, so a lock that lands while an entry is on its way
into the cache still wins. This replaces the earlier plan of a plaintext `hibp_cache` table.

### 13.3 Scheduling (F9.2, ADR 0005)

`ScanSchedule` is a value: given the candidates (items with a password, not trashed), the `ScanLedger` and
the time, `decide` returns `.locked`, `.scan(item, reason)`, `.wait(until, why)` or `.idle(nextFullScanAt)`.
It owns no timer, thread or clock.

- An item with no ledger entry (`created`) or an entry for another version (`changed`) is due at once and
  first. That one rule covers creation, edit, and "changed since the last scan" after an unlock.
- A weekly pass begins when the previous one *began* at least seven days ago, whether or not that one
  finished. An item is due in a pass until it has been scanned since the pass began; the pass's checks pass
  `freshAfter` to the client, so the pass really asks again, once per prefix. A pass a lock interrupts is
  still in progress in the ledger (`fullScanCompletedAt == nil`), so the next unlock resumes it. A pass that
  cannot finish, because one item's range keeps failing, is still in progress a week later and the next one
  begins all the same; it is never called complete while an item in it is unchecked.
- With `keysResident` false the answer is `.locked` and the ledger is untouched.
- Rate: a token bucket (five requests at once, then one per two seconds; every request is paid for, so an
  item with several passwords buys a proportionate wait), plus up to three seconds of injected jitter in the
  weekly pass. Any failure backs every request off, doubling from one minute to one hour and never less than
  `Retry-After`. Checks answered from the cache cost nothing.
- The rate limit and the backoff are a value, `ScanPacing`, that **outlives a lock**: none of it is derived
  from a password, and a phone locks and unlocks many times a day, so a scanner that forgot a `Retry-After`
  or was handed a fresh burst at each unlock would hammer the API exactly when asked not to. The engine keeps
  it across `lock()` and `unlock()`; it is not persisted, so a new process starts with a full burst. A scan
  that a lock interrupts still pays into it: the requests it sent are charged, and a refusal that came back
  after the lock still backs the scanner off (`recordInterrupted`), so locking during each request buys
  neither extra requests nor a way round `Retry-After`. It names no item.
- No item blocks the rest. An item whose check failed goes to the back of the queue, behind every item that
  has not failed and those that failed longer ago, so the backoff paces requests but the next one is for a
  different item; otherwise whoever controls the path could stop the whole vault being checked by refusing
  one range. An item whose range cannot be used at all (too large, malformed, an unexpected status) is also
  set aside for a time of its own (ten minutes, doubling to a day), and a wait for such an item never sleeps
  past the start of the next pass. **Which items failed, and when, is in the ledger** (`ScanLedger.Failure`:
  item, version, count, time), not in the schedule's memory, so it lasts as long as the results do: across a
  lock, and across a restart. It has to outlast the backoff it goes with. Kept only for the unlocked period,
  it left the refused item the most urgent again at every unlock; it was asked for first, failed, and set a
  backoff longer than the unlock, so a vault unlocked for twenty seconds every ten minutes never had another
  item checked. Keeping it in the ledger also means no item ID stays in memory while the vault is locked. The
  time of its own holds for the version that failed (an edit may have changed the password); the place at
  the back of the queue holds whatever the version, so an edit cannot buy the front.
- Times ahead of the clock (a clock put back) are treated as wrong, not waited for, and that is true of the
  total wait and not only of each answer: a backoff, the weekly pass's jitter time, or an item's time of its
  own that is further ahead than this policy could have set it is *overwritten* with the furthest it could
  have set, once (an hour, five seconds and a day with the standard policy), and a failure dated after now
  is dated now, since otherwise it would sort behind every later failure and its item would never come round.
  A pass in progress whose start is ahead of the clock by any amount is taken to have begun now: left in the
  future, every scan would predate the pass and every item would be due again the moment it was scanned.

`ScanLedger` records, per item, the version scanned, when, and the result and the binding (§13.9) per password
field; per item whose last check failed, the version, when and how often in a row; the breaches other devices
reported and when this device began letting synced checks stand in for its own (§13.9); and the pass times. It is
`Codable` with explicit, bounded shapes (a ledger with no failures, reports or deferrals encodes without those keys),
and it is **derived from passwords** (a breach count all but names one; a binding is a keyed digest of one): the
session persists it only sealed, as a local record that is not synced. It holds no hash or prefix. A result counts for
the password it judged, by binding, at whatever version the item is now; an entry from before bindings were kept
counts for its version only.

A candidate may carry `coveredAt`: when every password it holds now was last checked by anything besides the entry
for this very version (the same passwords at an earlier version, or synced checks, as the engine bounds them). It
counts for a weekly pass if it is from since the pass began or from within the last interval.

### 13.4 Strength (F9.3)

`StrengthEstimator` is a zxcvbn-class estimator written here (Wheeler, USENIX Security 2016 is the
description it follows; no code is shared with any implementation). `StrengthMatcher` finds every stretch
explained by a ranked word list (plain, reversed, and with look-alike substitutions and capitalisation
variations), a keyboard walk (US QWERTY and a keypad, built from the printed rows), a repeat (its unit
analysed recursively, two levels), a sequence, a recent year or a date; `cheapestCover` is the
minimum-guesses search over those matches, with brute force between them. The result is a `StrengthScore`
(0–4 at 10^3, 10^6, 10^8 and 10^10 guesses), the estimate's order of magnitude (`guessesMagnitude`), and a
`StrengthWeakness` with one plain sentence that never quotes the password. The exact estimate stays inside
the module, and an assessment prints as its score only: for a password that is one entry of a public list
the exact figure is the entry's rank, which names it. The item's own title, usernames and hosts are passed
as personal inputs and rank ahead of every list.

Two deliberate differences from the paper, both because the reference design rated guessable passwords
strong:

- **No bonus for having parts.** A cover of `k` matches costs `k! × g1 × … × gk`. The paper adds
  `10000^(k-1)`, which alone lifts any three cheap patterns to 10^8 and any four to 10^12: `Spring2026!` (a
  word, a year, a symbol) scored strong, and the search preferred "a word and eight random characters" to
  "two words and two symbols". Guessing programs order candidates by likelihood, not by the number of parts,
  so a password is as strong as its parts multiply out to and no stronger. When a strong password's cover
  does contain patterns (a passphrase), the explanation says it is built from recognisable parts, not that
  no pattern was found.
- **Keyboard shapes, not only strokes.** A walk whose directions repeat with a short period (a zigzag such
  as `2w3e4r5t6y`) is worth the turns of one period, and walks of the same shape side by side
  (`1qaz2wsx3edc`, `rfvtgbyhn`, `!QAZ@WSX#EDC`) are one pattern: a walk, a direction to step in, and a count.
  Counted stroke by stroke, each of these came out stronger than random characters of the same length.

Three common passwords in a row (`password1qwerty1dragon1`) still score strong: that is what `3! ×` the
product of three ranks in the hundreds comes to, and the scale says so honestly.

Bounded: only the first 64 scalars are analysed (`truncated` says so). What follows can only add guesses, so
the estimate for a longer password is a lower bound, and an assessment costs the same for 64 characters or
ten thousand. One match is kept per stretch, so the search sees at most `n(n+1)/2`. The word lists are held
as one sorted table of scalar arrays (`WordTable`) and a stretch is looked up by narrowing a range of it one
scalar at a time, abandoning the stretch at the first scalar no word continues with; nothing is built or
hashed per stretch, so the cost does not depend on the script the password is in. (Looking each stretch up
as a `String` cost a password of combining marks several hundred times an ordinary one, because hashing a
non-ASCII string normalises it: 26 to 33 ms against 0.2 ms now, compiled with `-O` on Linux; not measured on
Apple hardware.) The price is that a word from the item's own title matches by exact scalars, not by
canonical equivalence.

The word lists are Swift source (one multi-line literal each; about 300 kB in all), each file carrying its
source, commit and licence (`07-supply-chain.md` §2.2):

| List | Entries | Source |
| --- | --- | --- |
| Common passwords | 10,000 | zxcvbn `data/passwords.txt` (MIT), most common first |
| English words | 5,000 | zxcvbn `data/english_wikipedia.txt` (MIT) |
| Surnames, female and male given names | 500 + 300 + 300 | zxcvbn (MIT; 1990 US census) |
| EFF large wordlist | 7,776 | EFF (CC BY 3.0 US), via a mirror, cross-checked against a second and verified against EFF's own file (2026-11-16) |

A word's cost is its rank in its list. The EFF list is not a frequency list, so every word in it costs
7,776: a generated passphrase of `n` words is estimated at about `7776^n`, the figure §12 reports.

### 13.5 Reuse and the other checks (F9.3, F11.8)

- **Reuse.** `ReuseKey` (32 bytes or more, derived by the session from `Ksym` for this purpose, zeroised on
  lock) gives `ReuseToken = HMAC-SHA-256(key, password)`; `ReuseIndex` maps tokens to item IDs. Tokens and
  the index are not `Codable`, print as redacted, and live only between unlock and lock.
- **Age.** A password has been current since the latest time the item's history shows a different value of
  that field being replaced, or since creation. Asking for the latest differing entry is independent of the
  order a merge left the history in. Older than three years (configurable, or off) is reported as
  information only; an item with no timestamps has no age.
- **Insecure addresses.** `url` fields that start `http://`, loopback excepted. (Scopes are hostnames and
  carry no scheme, so "insecure scopes" in F9.3 can only mean these.)
- **Two-step verification and passkeys.** `SiteDirectory` is the seam. The default, `NoSiteDirectory`, knows
  nothing, and then a password-only item is merely noted (`passwordOnly`, information; F11.8).
  `EmbeddedSiteDirectory` is an opt-in selection of about 240 domains of well-known services from the
  2factorauth directories, retrieved 2026-11-15; with it, an item with no one-time code on a site listed as
  supporting TOTP gets `twoFactorAvailable`, and one with no passkey on a site listed as supporting
  passkey sign-in gets `passkeyAvailable`. It is off by default because such a list ages; its answers are
  advice in the report and feed no decision about a secret.
- Security answers and PINs are not checked.

### 13.6 Breached-account lookup (F9.4)

`BreachedAccountClient.breaches(disclosing:apiKey:)` sends
`GET https://haveibeenpwned.com/api/v3/breachedaccount/<address>?truncateResponse=false` with the person's
key in `hibp-api-key`. Unlike the range API this sends an identifier, so it is opt-in per call: the only
argument that names the address is an `IdentifierDisclosure`, made by
`.confirmedByPerson(sending:)` at the UI action in which the person asks, and nothing in the module makes
one or looks an address up on a schedule. `EmailAddress` and `HIBPAPIKey` refuse anything that could add a
header or change the path (the address is one percent-encoded segment). The key, the address, the
disclosure, a URL (its path is the address, or twenty bits of a hash) and a request's headers all print as
redacted or as names only; `HTTPSURL.absoluteString` and `HTTPHeaders.fields` are the two accessors an
adapter sends from, and the two to search for. The response is bounded (2 MiB, 2,000 breaches, 64 data
classes each) and the bounds apply *while reading*: the array is read one entry at a time and entry 2,001
ends the read, so a body of 160,000 minimal objects is refused without decoding them. It is reduced to
plain text: control and bidirectional-formatting characters are removed, and the service's HTML description
and logo URL are not carried. Nothing is cached or stored.

### 13.7 The report and the engine

`HygieneReport.make(analyses:ledger:now:policy:)` is pure. Per item it gives findings (kind, severity, field,
a summary, a plain-language explanation, and the facts behind it for a UI that words things itself), badges
(one per kind at `low` or above), and a breach status (`notApplicable`, `notChecked`, `clear`, `breached`,
`incomplete`, with the check time); and vault-wide totals, including how many items await a check and the
oldest check, so stale results are visible (ADR 0005). Order is fixed: items worst first, then by
lower-cased title bytes, then ID; findings by severity, kind, field. A breach result counts for the password it
judged (its binding), and synced results are weighed as §13.9 says; each item's `breachSource` says whether its status
rests on this device's checks alone or on another device's too, and a breach found only elsewhere says so in its
explanation. The report holds titles, so it is as private as the vault; it holds no password, hash or token.

`clear` is a statement about every password in the item, and it is not made on less. An item with more
passwords than are analysed in one item (16) is `incomplete` once the sixteen are checked, with a finding
that says how many were not looked at. Field IDs are whatever the item says and nothing makes them distinct,
so two password fields that share an ID share one result, the worse of the two: a breached password cannot
be overwritten by the clean one that follows it.

| Finding | Severity |
| --- | --- |
| Password found in a data breach | critical |
| Password reused on another item | high |
| Weak password (score 0–1) / could be stronger (score 2) | high / medium |
| Two-step verification available, none set up (directory) | medium |
| Unencrypted web address | low |
| Passkey available, none set up (directory) | low |
| More passwords than are checked in one item | low |
| Password only | info |
| Old password | info |

`HygieneEngine` is the actor the session drives between unlock and lock: `unlock(reuseKey:ledger:items:now:)`,
`update`/`remove` as items change, `next(now:)` and `scan(_:now:)` in a loop, `report(now:)`, `ledger()` to
persist, `lock()`. It keeps an `ItemAnalysis` per item (strength, token, flags; never the password; it prints
as an ID and counts) and reads passwords only from the item handed to `scan`. Its invariants:

- Everything derived from a password lives in one optional that `lock()` clears after zeroising the reuse
  key, and `lock()` then has the prefix cache forget what it holds (§13.2). Every entry point that hashes
  checks the optional first; while locked `scan` returns `.locked`, and `update`, `report`, `ledger` and
  `items(using:)` throw. What survives a lock is `ScanPacing` and nothing else (§13.3).
- **Unlocked to locked always empties the prefix cache**, whichever call did it. An `unlock` over an engine
  that is already unlocked is a lock first, exactly as `lock()` does it (old reuse key zeroised, state
  dropped, cache emptied), before anything of the new unlock exists; so an unlock that then fails (the same
  key buffer handed in again is zeroised by then) or is cancelled leaves what a lock leaves, and a caller
  need not follow it with `lock()` for the cache's sake.
- A scan re-checks the lock epoch after every suspension, and the client asks again before storing and
  after: a lock that lands while a request, or a cache write, is in flight wins. The response is dropped,
  nothing stays cached, the ledger is untouched, and a scan from before a lock cannot write into the session
  after it. The one thing an interrupted scan does write is the pacing (§13.3): requests sent are paid for.
- **`lock()` never waits long.** An actor runs one call at a time. `unlock` is `async`: it analyses one item,
  suspends, and stops as soon as it finds the vault locked or its task cancelled (a cancelled unlock leaves
  the engine locked and the cache empty). Until it returns, `next` answers `.wait(…, .analysing)`, `scan` answers `.busy` and
  `report` throws `.analysing`, because deciding or reporting on part of a vault would call it cleaner than
  it is; `update` and `remove` work, and what they say about an item outranks unlock's older copy of it.
  Every other call does a bounded amount of work on one item.
- **Stale copies are refused.** The session fetches an item and then calls `update` or `scan`, and the actor
  is re-entrant, so a save can land in between. The engine remembers the highest version of each item it has
  been shown; an older copy, or a copy from before the item was trashed or deleted, changes nothing
  (`update` returns `false`, `scan` returns `.stale`), and a scan whose item was saved while its ranges were
  being fetched records nothing. So a stale copy can neither replace a newer analysis nor mark a newer
  password as checked.
- One scan at a time; a check requested by a save obeys the same rate limit and backoff as the loop.
- At most 16 passwords per item are analysed and checked, and the report says when there were more.

### 13.8 In the session, and what is still to come

**Session wiring, as built** (`VaultSession+Hygiene.swift`). `VaultConfiguration.hygiene` (`HygieneSettings`)
turns it on and carries the `HTTPClient` port, the user agent, the policies and the `DeviceLocalStore` port;
there is no host to configure. The session owns one `HygieneEngine` for its lifetime, so pacing survives a lock.

- **Keys.** At every unlock, on the actor, the session derives two keys of its own (`DeviceLocalKeys`, in
  `WatchwordCrypto`, `package` access): the reuse key, `HKDF-SHA256(Ksym, salt: accountID,
  "WW-hygiene-reuse-v1")`, handed to the engine, which zeroises it at its lock; and the device-local key,
  `HKDF-SHA256(Ksym ‖ device secret, salt: accountID ‖ deviceID, "WW-device-local-v1")` (32 bytes of key and 16
  of key ID), which seals this device's records and never leaves the actor. The **device secret** is 32 random
  bytes this device makes at its first unlock and keeps in its Keychain (`deviceLocalSecret`, §6): device-only,
  never synced, never on a transport. It is there because the keyset is not this device's alone: every device of
  the account holds it, a revoked one included (§7.8), and a device ID is on every row and stream the device
  writes, so a key derived from those two alone could be derived by any of them, which could then read this
  device's ledger and plant one of its own (docs/06 L1). With the secret, another device of the account derives a
  different key even when it claims this device's ID, and the secret alone (someone reading the Keychain without
  the password) opens nothing either. Neither key is the raw key, and a password change keeps both (the keyset and
  the secret are kept). A store restored onto other hardware arrives without the secret: its records open as
  nothing and everything is due again. The secret is read in the engine's unlock task; until it is, and if the
  Keychain refuses it, there is no local key, so nothing is read or stored and the engine starts from an empty
  ledger.
- **Unlock.** The engine's `unlock` runs in a task of its own (utility priority) with the decrypted items and
  the unsealed ledger, after any engine lock still in flight. Every query waits for it, then reconciles.
- **Lock.** `lock()` zeroises the keyset, then drops the engine's reuse key and everything derived from a password
  (`HygieneEngine.dropKeys()`), then zeroises the local key and cancels the unlock task, all before it returns;
  only the engine's `lock()`, which empties the prefix cache, runs in a task afterwards. The drop is synchronous
  because the engine runs on the session's own serial executor (both conform to `SecureMemory.SharesExecutor` over
  one `SerialExecutorOwner`; ADR 0001's amendment of 2026-11-16 says why that lives in `SecureMemory`), so the
  session's `lock()`, already on that executor, calls it through `assumeIsolated`. With
  the drop in that task instead, the reuse key, the reuse tokens and every analysis stayed resident for as long as
  the session was busy after `lock()`, or the process was suspended in the background (docs/06 L2). Nothing the
  engine does can keep the vault's keys resident. A scan in flight finds the engine locked and records nothing; the
  engine drops its answers.
- **Changes.** Every commit of an item (`commitItem`) updates the engine at once, so an edit is due for a check
  (reason `changed`); a sync, and every query, reconciles the engine with the store first: rows whose version (or
  whose vault's deletion) changed are decrypted and shown to it, and rows that are gone are removed. So a merge, a
  deletion or anything a later path writes is in the report the person is shown.
- **Scans.** Nothing runs by itself: the UI or a background task calls `runHygieneStep()`, which asks
  `next(now:)` with the session's clock, checks the item it names (fetched through `item(id:)`), and seals and
  stores `ledger()` after a check that completed **or failed** (§13.3), and returns when to call again. The
  stored ledger goes to the next `unlock`; a ledger that does not open is an empty one (everything is due).
- **Persisted only sealed, per device, unsynced.** (Breach results and scan times are *also* synced, as a record of
  their own in each item's vault, §13.9; the ledger and the cache themselves never are.) The ledger and the prefix
  cache are records in the
  `DeviceLocalStore` port, never in the record store the sync engine reads and never on a transport: sealed under
  the device-local key with a context binding the record's name and the account
  (`EnvelopeKind.accountHeader`, as for quick unlock's wrapped AUK), and named by
  `HMAC(local key, label ‖ message)`, so a name says nothing about the prefix it holds. The cache
  (`SealedPwnedRangeCache`) holds nothing in memory: each lookup and store goes through the session, which
  refuses while locked, so its `lock()` has nothing to drop. One record per prefix (`CachedPwnedRange.encoded()`)
  and a sealed index (prefix, fetch time, size) bound it to 512 prefixes and 32 MiB by default, expired ranges
  first, then the oldest. The index lists at most 4,096 prefixes and one listing more does not decode, so
  `HygieneSettings.cacheCapacity` is clamped to that (`maximumCacheCapacity`): above it, the index would be read as
  empty and every record it named left on disk, never evicted. A record planted from another account, or sealed by another device of this account (which has the
  keyset and this device's ID but not its secret), does not open and answers nothing. An older ledger of this
  device's own, put back by someone who can write the files (A8), does open: it is accepted as what it is, an
  authentic earlier reading, whose every check is older than the one it replaces, so nothing becomes due later than
  it was on this device's own checks (docs/06 L3). With synced results it can also drop a deferral mark or a reported
  breach taken in since; a mark dropped starts the deferral limit again, so A8 together with a member reporting
  "not found" (A4) can postpone this device's check further (docs/06 N6). Deleting the account erases the store and the secret.
- **What the UI calls:** `hygieneReport()`, `itemsUsingPassword(_:)` for the editor's reuse warning, and
  `runHygieneStep()`. All throw `locked` while locked and `hygieneNotConfigured` without settings.

**Adapters, as built** (`WatchwordPlatform`; not yet compiled or run on a Mac, and not yet configured by the app,
which builds its session without `HygieneSettings`):

- **`URLSessionHTTPClient`**: an ephemeral session with no cookie, credential or cache storage, cookies neither sent
  nor accepted, the system's TLS validation with TLS 1.2 at least; every redirect refused by the session's and the
  task's delegate, so the 3xx is the answer, and a response from any URL but the one asked refused; the decoded body
  counted as it arrives and cut one byte past `maximumResponseBytes`; an idle timeout, a resource timeout and an
  overall deadline of its own, each held to 1 ms to 600 s whatever is configured; exactly the request's headers, with
  `User-Agent: Watchword` if none is named and a fixed `Accept-Language: *` in place of the device's languages
  (URLSession still adds `Accept` and `Accept-Encoding`); nothing logged, and errors carry no URL. A proxy the system or
  a device-management profile sets is used like any app's: it sees the host, and one the device trusts to intercept
  TLS also sees the five-character prefix (and, for the opt-in breached-account lookup, the address). The limit on the
  decoded body is untested against a compressed response: the tests' URL-loading stub bypasses URLSession's decoding.
- **`FileDeviceLocalStore`**: one file per record in `DeviceLocal/` beside the database (`AppContainer.
  deviceLocalStoreURL`), owner-only, excluded from backup (the directory and every file),
  `completeUntilFirstUserAuthentication` on iOS (macOS has no per-file class for this; FileVault protects it). The
  store is a path of `components` below a trusted ancestor, the App Group container (`AppContainer.deviceLocalStore`),
  and every component is checked at every operation, so a link anywhere below the container is refused. Writes go to an
  exclusively created temporary file (`withoutOverwriting`) moved into place after whatever was under the name is
  removed, so no write follows a link; a crash in between leaves no record, which reads as none. 0700 and the
  directory's backup exclusion are set again before every write. Reads fail closed against A8: only a regular file,
  never through a link, never past the size limit, checked before reading; `deleteAll` removes a link in the
  directory's place without touching its target. Portable apart from the backup flag and protection class, so it is
  tested on Linux too.

Still to come:

- **Background glue**: `BGProcessingTask` (iOS) and `NSBackgroundActivityScheduler` (macOS) only wake the
  loop; whether anything runs is `next(now:)`'s decision, so a wake while locked does nothing.
- **The report UI** and its snapshot tests, and the settings for the site directory and the API key.

### 13.9 Synced results (owner decision 10; ADR 0005, amendment of 2026-11-16)

"Store and sync them with the items, with scan times synced", with the rule that **a synced "clear" only postpones
this device's next check, and never hides a breach this device has seen.** So that a household's devices do not each
check every password every week, each completed check is written into the vault, and each device takes the others'
into account. The prefix cache is not synced; nor is the ledger.

- **The record.** `SyncedScanRecord`, sealed under the vault key as `EnvelopeKind.scanStatus` (10) with the item's
  record ID, in the item's vault, with the context every record has (record, vault, schema, kind, key, version), and
  checked against its row when opened (item, vault and version inside must equal the row's). It maps each device to
  its latest observation: the revision at which it wrote it, the vault key its bindings are under, when it checked
  (whole seconds, its clock), and per password binding the count found (zero is "not found"). At most 32 observations
  of at most 16 results; one canonical binary encoding (`"WWSR"`), decoded exactly (ascending devices and bindings, no
  observation above the record's version, nothing trailing). It is not an item version: no history entry, no
  conflict, never `ItemMerge`. Sync carries it like any record (`SyncConfiguration.schemaVersions`), merged by
  `ScanStatusMerger` through `KindRoutingMerger`.
- **The merge is a join.** Per device the observation with the higher revision (then the later encoding); beyond 32
  devices the highest (revision, device) are kept. Neither side → written by this device above both, as items are.
  A deletion (the record goes with its item, explicitly: permanent deletion, purge, a move's original, a vault's
  deletion) erases the observations at or below the tombstone and keeps later ones, so an item kept after a deletion
  keeps what was checked since.
- **Bindings.** `ScanBinding = HMAC-SHA-256(K, "WW-scan-binding-v1" ‖ 0x00 ‖ itemID ‖ password UTF-8)`. In a synced
  record `K = HKDF-SHA256(vault key, salt: vaultID ‖ keyID, "WW-hygiene-scan-binding-v1")` (`HygieneKeys`,
  `WatchwordCrypto`, `package`), under the key the observation names; a reader derives it from that key only if it
  holds it for the item's own vault, so results survive a rotation's re-seal and say nothing to anyone without the
  key. In this device's ledger `K = HMAC(reuse key, 0xFF ‖ "WW-ledger-binding-key-v1")`, which no vault rotation
  changes; the `0xFF`, a byte no UTF-8 text holds, keeps `K` from being the reuse token of any password (N3). A
  changed password has a new binding; an edit that leaves it leaves its result.
- **Writing.** After a check completes (`runHygieneStep`), and only with sync configured, where this device may write
  (`writableVaultKey`: not a read-only member, not a deleted vault), for the version checked and while unlocked, the
  session writes this device's observation under the vault's current key, conditionally on the row it read.
- **Reading.** At unlock, at every reconcile (a changed item or scan-status row) and after every save, the session
  matches each other device's observation against the item's current passwords (`SyncedScanEvidence.matching`) and
  hands the engine `SyncedScanEvidence` for that item version (`HygieneEngine.updateSynced`): in memory only, dropped
  at lock. This device's own observations are never read back from the record: its results are its sealed ledger's.
- **What it is worth** (`PasswordBreachEvidence`, the one place the report and the schedule read results from):
  - a synced time more than `clockTolerance` (five minutes) ahead is ignored; the rest count as no later than now;
  - a synced check counts as a check: an item whose passwords are all covered is not due, which postpones this
    device's own check by at most an interval from the check; and synced checks stand in for its own check of an item
    for at most `ScanPolicy.maximumSyncDeferral` (28 days) from the first time they did (`ScanLedger.deferred`; only
    this device's own check ends it), then for the pass that ends in. So a member who reports "not found" every day
    delays this device's own check by weeks, never for good;
  - a breach is a breach if this device found it, or another device reported it and this device has no newer check
    of its own that found the password clear. A reported breach is remembered in the ledger (`ScanLedger.reported`)
    when taken in, so a later synced "not found", even from the device that reported it, does not remove it: only
    this device's own later check of that password does. A synced "not found" never outweighs any breach;
  - an item that leaves the candidates but still exists (trashed, or without a password) keeps its results, reports
    and deferral mark (`ScanSchedule.setAside`): they are about its passwords, which a restore or an edit can bring
    back. Only a permanent deletion forgets them, and an unlock prunes only items that no longer exist. Otherwise a
    trash and restore, or a password taken out and put back, would erase a breach this device saw and restart the
    deferral limit (N1). An item the ledger has no room to mark is not deferred at all (N2);
  - the report labels each status's source (`ItemHygiene.breachSource`).
- **Shared vaults.** The write judge attributes each observation to its device and revision
  (`attributedValues`, one value per observation), so a removed member's late observation counts nowhere (S28) and
  one forged in another device's name is held aside; a rotation re-seals the records (the observations keep their
  devices, revisions and keys); a change of head takes out what no longer counts, records included.

What this leaves (`06-adversarial-review.md` §N): a current member (A4) can make a breached password look clear on a
device that has not checked it itself, for up to the deferral limit; they can read and change the password, so this is
no new power, and they cannot hide a breach that device saw while the item holds that password. The ledger keeps one
check per item, so a breach of a password the item no longer holds is forgotten once this device checks the new one; a
member who changes the password back and reports it clear then has it shown clear for up to the limit again (N4).
Two devices checking at once both write; the join keeps both, and a check that races the item's permanent deletion
leaves a record with no item, which nothing collects (N5). A client that does not know the kind refuses every segment
and snapshot that carries it and, merging each stream strictly in sequence, merges nothing more from that device (N7).

## 14. Import and export (`WatchwordInterchange`)

Built in milestone 7 as a portable module: it imports `Foundation`, `WatchwordModel` and `WatchwordMatching`
and nothing else, so every line of it runs under `swift test` on Linux. Parsers are pure functions from bytes
to item drafts and a report; exporters are pure functions from items to bytes. Nothing in it reads a key, a
file or a clock.

**Limits (`InterchangeLimits`, SEC7, SEC9).** Checked before or while the cost is incurred, never after:
100 MB for any input file and for the one decompressed document, 50,000 archive members and 50,000 entries
(every array element walked counts, imported or not), a decompression ratio of 100:1 enforced *while*
inflating, 512 KiB for one CSV row or one item as written, 256 KiB for one cell or field value, 1,000 fields
(or members of a walked JSON object) per item, 100 columns in a CSV file, 64 levels of JSON nesting, 1,024
bytes for an archive member's name. Those bound one entry and one file, not their product: fifty thousand
entries of a thousand two-byte fields fit in 100 MB and would be fifty million `Field`s. So the import as a
whole has budgets too. **One million fields** (fields, URLs, tags and earlier passwords, counted as each
entry is about to be built; reaching it fails the file), which measured comes to about 100 MB of drafts
from CSV and 250 MB from 1PUX; CSV rows are streamed into the assembler, never held beside the drafts.
**Thirty-two URLs an entry and 100,000 a file** are considered as scopes, each distinct URL once (parsing a
URL is the most expensive thing an import does per byte, and a 1.4 MB archive of repeated URLs used to buy a
minute of it); further URLs are kept as `url` fields with a warning. And each draft is measured **as the
vault will store it** (`StoredItemSize`, at most 768 KiB against `ItemCodec`'s 1 MiB): JSON escaping writes
a control character as six bytes, every field carries a sync stamp, and every line of the notes is stored
again with two identifiers, so 512 KiB as written can be megabytes as stored; an entry over the bound is
skipped and listed, never reported as imported and then refused by the vault. The estimate is an upper
bound by construction and the adversarial suite checks it against `ItemMerge.stamped` and `ItemCodec`.
`InterchangeLimits.standard` holds these ceilings; an initialiser can tighten any of them and clamps each
argument to `1...ceiling`, so no caller can loosen one. A file that cannot be read as
what it claims to be ends in exactly one `InterchangeError`; a problem with one entry (too large, a repeated
identifier, an unknown credential type) skips or degrades that entry and is listed in the `ImportReport`.
The report's own warning list is capped at 10,000 with a count of the rest, because a refused URL of a few
bytes earns a warning.

**ZIP and DEFLATE (`ZIPArchive`, `Inflater`, `CRC32`, `ZIPWriter`).** Written here in safe Swift, because
the input is hostile and the module may not use unsafe code or an Apple framework. The reader parses the
central directory, validates *every* member, and decompresses only the one member asked for; nothing is
extracted to disk and a nested archive is never opened. It refuses, each with a typed error: a member name
that could escape a directory (absolute, drive letter, `.`/`..`/empty component, backslash, control
character; judged on the name's bytes, since by characters a slash followed by a combining mark is not a
slash) even though no name becomes a path; encryption, ZIP64 (sentinel sizes, the extra field, the
locator, a streaming writer's local header), multi-disk archives, and every compression method but stored
and deflate; members whose data overlaps another member's or the directory (the non-recursive bomb); and
any archive with two readings (an end record that is not the last thing in the file, a directory that does
not end where the end record begins, counts that disagree, a local header that disagrees with the directory,
a repeated name, a wrong CRC-32). A declared size is checked against the document and ratio caps before any
work, and bounds the inflater, so a member that lies about its size stops at the lie. The inflater follows
zlib's strictness (over-subscribed and incomplete code sets, a block with no end code, a distance before the
start of output, symbols the format reserves) and also refuses bytes after the final block. One thing zlib
accepts is refused: more than 1,024 blocks averaging under 256 bytes of output each
(`DeflateDefect.excessiveBlocks`). A block header is a fixed amount of work whatever the block emits, an
empty dynamic block is under twelve bytes, and without the rule 100 MB of them was half a minute of work
for no output, unseen by the ratio and document caps. With it the work is linear in the compressed and
decompressed sizes with a small constant. `ZIPWriter` writes stored members only, deterministically,
under the reader's own rules.

**JSON (`JSONReader`).** Not `JSONSerialization`: that behaves differently on Linux and Apple platforms,
resolves a repeated key by position and materialises the whole document. The reader is strict RFC 8259,
refuses repeated keys, lone surrogates and NUL, bounds its recursion, and walks a document member by member:
`skipValue` checks syntax without allocating and reports a value's extent, and only a value already measured
to be within one entry's size is materialised. Memory is therefore proportional to one item, not to the file.
Input must be valid UTF-8 (an optional byte-order mark is skipped); invalid UTF-8 and UTF-16 are refused, never
repaired, because a replacement character inside a password is a different password. Wherever the module
trims or searches text from a file it does so on bytes or scalars with its own code (`UTF8Text.trimmed`
removes ASCII white space only): Foundation's white-space sets and string searches differ between Linux and
Apple platforms, and a difference there is a difference in what becomes a scope.

**CSV (`CSVReader`, `CSVWriter`, `PasswordCSV`).** An RFC 4180 reader that also accepts LF line ends and
blank lines, and refuses a quote inside an unquoted cell, text after a closing quote, a bare carriage return,
NUL, and a quote that never closes (which the per-cell and per-row caps stop from swallowing the file). The
header row decides the mapping: 1Password 8 (`Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,
Notes`), 1Password 7 (`URL`) and Apple Passwords (`Title,URL,Username,Password,Notes,OTPAuth`) are detected
from it, unknown columns become concealed custom fields, and a first row naming fewer than two known columns
is refused rather than guessed at. Cells are data in both directions, formula characters included: an
import takes each cell exactly as written (an apostrophe in front of `=` is part of the value, not a mark
to remove), and the Apple Passwords CSV export writes every stored value unaltered, with RFC 4180 quoting
only (`CSVWriter`), so a file reads back byte for byte. Nothing neutralises spreadsheet formulas: the file
is for another password manager's importer, not a spreadsheet, and an apostrophe in front of a password
that begins with `-` is a different password there (owner decision, 2026-11-16; SEC7). What a spreadsheet
might do with such a file is answered by the export screen's warning instead (`InterchangeGuide`'s
`notForSpreadsheets` caveat: every password in plain text, not meant for spreadsheets).
That prefix is part of the value to whatever imports the file, and generated passwords often begin with `-`
or `+`, so `.preserve` exists for a file that goes straight into another password manager; which to offer,
and how to warn, is the UI's decision. A passkey is left out of a CSV export and reported; fields with no
column are written into the notes and reported; an item with several websites becomes one row for each.
The URL column holds the item's sign-in URLs and nothing else: a `url` field that is not one of them (a
link, a website the item is not scoped to) is a line of the notes, because whatever reads the file offers
the row's password on that column's host.

**1PUX (`OnePUX`).** Import reads `export.data` and walks `accounts[].vaults[].items[]`: `overview` (title,
URLs, tags), `details.loginFields` by designation, `details.sections[].fields[]` by value type (`concealed`,
`string`, `totp`, `url`, `email`, `phone`, `date`, `monthYear`, `creditCardNumber`, `address`, `sshKey`,
`menu`, …), `notesPlain`, `passwordHistory`, `state` (active, archived, trashed) and `categoryUuid`. Login,
Password, Secure Note, API Credential, Bank Account and Membership keep their shape through the field
identifiers 1Password's templates use (`credential`, `accountNo`, `routingNo`, `membership_no`, `pin`, …);
every other category becomes an item of custom fields. Attachments and links between items are reported,
not imported. Nothing else is passed over without a line in the report, with one stated exception: the
checkboxes, radio buttons and buttons of a saved web form (`fieldType` `C`, `R`, `B`), which are a page's
state. Every other saved-form entry is kept as text; a number or boolean where text was expected is kept as
its text; a value that is not of its type (a string under `date`) is kept as text with a warning. A `date`
may be any day of the years 1 to 9999, since a date of birth is before 1970 (timestamps keep the narrower
range), and one outside it is kept as its number with a warning. A sign-in name typed as an email address
(`fieldType` `E`) is an `email` field. Watchword items have no category, so each field's section, source
type, source identifier and the entry's category are kept in `Field.meta` (`InterchangeMeta`); the export
uses the category the fields agree on, unless the item has since become a login, and otherwise reads one
off the fields (a note with a field is a Secure Note, a membership is known by its template's field names).
Export writes `export.attributes` and `export.data` into a stored archive, with the first user name or,
failing that, the first email address as the login's username; passkeys are left out and reported.

**CXF (`CredentialExchange`).** Reads and writes Credential Exchange Format 1.0 JSON: `basic-auth`,
`passkey`, `totp`, `api-key`, `note` and `custom-fields`. Security questions, PINs, recovery codes and every
field with no credential type of its own are written as `custom-fields`. On import, a credential of any other
type is kept as concealed custom fields and reported; an item repeating an earlier identifier is skipped and
reported; a passkey outside `PasskeyCredential`'s bounds (identifier, handle, key, large blob) is refused
alone and reported, and the rest of its item is imported; an account's collections become tags on the items
they list (a path longer than a kilobyte is passed over, so nesting cannot multiply the file's size); an
`EditableField` whose value is a JSON number or boolean is kept as its text, and one with no text at all is
reported; a subtitle is kept, as a text field, when it says something the title and fields do not; Android
app scopes are reported; the version is judged once the whole document has been read, since JSON members
come in any order. The same bytes are the payload of the OS Credential
Exchange APIs (`ASCredentialExportManager`/`ASCredentialImportManager`, iOS 26 and macOS 26) and a file that
can be moved by hand. The field names follow the published 1.0 specification as recorded in
`00-research.md` §2.2; they were not re-verified against the specification text when this was written (the
host was unreachable), which the integration step must do against a real export before shipping.

**Into the vault (`ImportAssembler`).** Every format hands its entries to one assembler, so no format can
skip a rule. A draft gets its `id` from an injected `RandomNumberGenerator` (never from the file) and the
`vaultID` the caller names. A URL becomes a scope only through `ScopeDerivation`: `HostNormalizer`, then
`ScopePolicy`, and one check stricter than the policy (a host with ASCII punctuation such as `*` is refused,
so a file cannot plant a scope that reads as a wildcard); a refused URL is kept as a `url` field with a
warning (F11.2). **A `www` host also matches its apex** (owner decision, 2026-11-16): a scope derived for
`www.<apex>` gets a further scope for `<apex>` beside it, with the same subdomain setting, and keeps its own
(`ScopeDerivation.apexScope(beside:)`). Exactly one leading `www` label is removed (`www.www.example.com`
adds `www.example.com`), the apex must pass `ScopePolicy` (`www.co.uk` adds nothing) and not be an address,
an apex the entry lists for itself is its own scope rather than an addition, and each addition is a line of
the report (`ImportWarning.apexScopeAdded`) so the preview can show it. It is on by default and opt-out
(`ImportOptions.matchApexOfWWWHosts`); it replaces the earlier opt-in `stripsLeadingWWW`, which *replaced*
the `www` scope by the apex. The added scope is a scope the file brought like any other: a merge into an
existing item adds it only through `MergeChoices` (below). A scope is a host and nothing more, so a URL that
says more than `https://host/` (another scheme, a port, the sign-in page) is *also* kept as a `url` field, and every
exporter writes that text back in place of the URL it would otherwise synthesise for the scope; which
field stands for which scope is decided on export by deriving the host again, never from a hint. **No
exporter writes a sign-in URL for a host the item is not scoped to** (`ExportSupport.websites`): whatever
reads the file offers the item's secrets on every URL in that position, so a website field whose URL
derives to some other host (the person removed the scope and the field stayed, or the field arrived by a
road that never checked) is written as an ordinary field and reported (`ExportWarning.websiteNotScoped`),
as is one beyond the number of URLs an import considers for an entry. A URL the policy refused, from which
no scope can come, is still written where it was found. A one-time-password value is validated through `OTPParameters` and stored as a canonical
`otpauth://totp/` URI; an unusable one is kept as a concealed custom field with a warning. A passkey goes
through `PasskeyCredential`. Entries in the source's trash are skipped unless the caller asks for them, and
are then marked, not trashed: only the vault moves an item to the trash.

**Duplicates (`DuplicateDetector`).** Compares drafts with existing items (identical, or the same account:
one shared host and login name) and computes what skip, keep both or merge would save; nothing is ever
dropped or merged without the person's choice. A match is made on one host and one name, and the file
controls everything else about its entry, so merge is where a hostile file would reach an existing secret:
an entry listing the bank's URL and the attacker's, merged into the bank's item, would have AutoFill offer
the real password on the attacker's site. The rule is that **a merge never changes where an existing item
is offered or what it signs in with, in this app or in a file exported from it**. `merged` adds tags, notes
(unless every line is already there; one linear pass, not a string search) and fields other than sign-in
fields and URLs. New scopes, new user names, email addresses, passwords, one-time passwords and passkeys,
and new `url` fields are *reported* (`DuplicateMatch.newHosts`, `hasNewSignInFields` and `hasNewURLFields`,
`additions(of:to:)`) and added only when `MergeChoices` names the host or the field the person accepted;
there is no "accept all". Field values are compared as bytes.

URLs are in that list because of what an export does with them. An entry's URL that says more than its
host is kept as a website field, and a second review found the consequence: merged by default, the
attacker's `https://evil.example/login` became a field of the bank's item, widened nothing in this app, and
was then written by every exporter among the item's sign-in URLs, beside the real password, for the next
password manager (this one included) to offer it there. So every `url` field is a choice, whether the
entry's own website or a link it carries; a link labelled "Website" inside a trusted item is a lure even
when nothing fills on it. Accepting a URL accepts a field and never a host: it stays one of the item's
websites only if its host, derived again from its text, is one of the merged item's scopes (the existing
ones and the hosts accepted by name), and is otherwise added as a plain link. The other hints by which an
imported field speaks for its whole entry (the 1PUX category, the CXF subtitle) are dropped from every
field a merge adds, so the file decides nothing about the existing item beyond the fields themselves. The
exporters' own rule above is the second barrier: an item that came to hold such a field some other way
still exports no URL for a host it is not scoped to.

**Export reports (`ExportReport`).** An export never fails over one item, and never leaves something behind
without a line: the person deletes this app's copy on the strength of the report. Beyond passkeys and moved
fields, each exporter reports a scope limited to its host or with exclusions (no
format can say so, and whatever imports the file will offer the item on subdomains), history a format
cannot hold (all of it in CXF and CSV, everything but earlier passwords in 1PUX), the archived mark (CXF,
CSV), tags (CSV), a website written as an ordinary field because the item is not scoped to its host, and
anything a field records beside its value (which recovery codes are spent). Field
values that sync is keeping for the person to choose between (`Item.conflicts`, `Item.retainedValues`, §7.5)
are *written*, as concealed fields labelled "(unresolved value)" under "Unresolved values" (lines of the
notes in CSV), and reported; unresolved values of anything else (a title, the scopes, a passkey) are
counted and left out, since writing a conflicting scope as if it were the item's would be worse.

**Instructions (`InterchangeGuide`, F8.5).** Step-by-step routes for moving to and from 1Password and Apple
Passwords, as data the UI renders, with the caveats from research: passkeys do not survive CSV, Wi-Fi
passwords are left out of Credential Exchange, and an exported file is plaintext.

**Still to come (integration).** The session step (§14.1) is built. What remains is the apps' part and the
OS's: writing a file with `completeUnlessOpen` (or stronger) protection to a place the person chooses,
showing the standing warning, the screens, and the OS Credential Exchange calls. The duplicate screen must
show each of `DuplicateMatch.newHosts` and ask about it by name before it puts a host in `MergeChoices`, show
each of `MergeAdditions.urlFields` and `signInFields` with its full value before it puts a field there, and
never pre-select either; the export screen must show the `ExportReport` before the person is told the export
is complete.

### 14.1 Through the session, and the encrypted Watchword archive (as built)

`VaultSession+Interchange.swift` is where the module meets the vault's keys and write path. `WatchwordKit`
depends on `WatchwordInterchange`; the module still knows nothing of the session.

**Import is preview, then commit.** `previewImport(_:format:into:options:)` (CSV, 1PUX, CXF; the CSV variant is
read off the header) and `previewArchiveImport(_:passphrase:secretKey:into:options:)` parse the bytes, compare
the drafts with the items of the chosen vault (`DuplicateDetector.matches`) and return an `ImportPreview`: the
`ImportReport`, a summary per entry (title, kind, state, hosts, login names, and the apex hosts added beside a `www`
host, `apexScopesAdded`, from the report's `apexScopeAdded` lines: `ImportOptions.matchApexOfWWWHosts`, on unless the
person turns it off, applies to the other managers' formats; an archive's scopes come back as they were) and the
matches; for an archive also
its identifier and creation time (`archiveID`, `archiveCreatedAt`), set only once it has opened, so they are the
values the manifest authenticated, and the restore screen shows the date: A1 can put an older archive in place of
the newest, and every archive under the same passphrase and Secret Key opens. **Nothing is written, and the
preview holds no secret**: the drafts stay inside the actor (`pendingImport`), and `lock()` drops them, as do
`discardImport()`, the next preview and the commit. Each preview and `discardImport()` advances a generation
(`importGeneration`), so a preview still awaiting the store when the person cancels, or starts another, drops its
drafts and throws `noPendingImport` instead of keeping them. The values a merge would add, with every
value in full for the duplicate screen, come from `importAdditions(preview:importedID:existingID:)` while it is
shown. `commitImport(_:decisions:)` checks every decision before writing anything: an entry that matches an
existing item must have one (`decisionRequired`), and a merge may only go into an item it was matched with
(`unknownMatch`); an entry with no match and no decision is added. Then each entry goes through the vault's own
write path. A new item is stamped by `ItemMerge.stamped` as this device's write, its scopes checked against
`ScopePolicy`, and committed on the condition that no row has its ID (`commitItem`), keeping the history and the
creation and modification times the draft carries (which `save` would replace) and none of the file's sync
metadata (a draft has none: `ImportAssembler` builds a clean item, and `stamped` with no previous version clears
whatever a caller put there). A merge is an edit of the existing item, `DuplicateDetector.merged` computed over the
item as the write reads it, so nothing written since the preview is undone, with only the hosts and fields in
`MergeChoices`. An entry the source had in its trash (when the person asked for those) is saved, then moved to the
trash through `trash(id:)`. One item fails alone (`ImportOutcome.failed`); a `lock()` during a commit stops it
(`importInterrupted(saved:)`) and the preview is gone with the lock.

**`lock()` never waits for interchange work.** Every step whose cost the file or the account's parameters set runs
off the session's actor (`awayFromSession`, each step named by `AwayWork`): a plaintext file's parse into drafts
(bounded by `InterchangeLimits`, but a 100 MB file is still seconds), an archive's parse (up to 256 MiB, with
SHA-256 over it), its key derivation at the iteration count in its cleartext header (up to the 25M ceiling,
seconds on a phone, before anything in the file is authenticated), its decryption and the assembly of its entries,
and an export's account-password derivation and new archive's derivation, both under this account's parameters
with every key resident. On the actor each would hold `lock()`, auto-lock and sync behind it with the vault keys
resident. Each runs on inputs copied for it and touches none of the session's state: the file's bytes, the
password or passphrase, a Secret Key read for the call (zeroised by the caller when the step returns, whatever it
returns), the stored header; what it derives or unwraps is zeroised inside it. A parse draws its item and field IDs
from a `ForkedGenerator` (HMAC-SHA-256 in counter mode, keyed by four words drawn from the session's generator on
the actor), because the session's generator cannot cross threads and a copy of a seeded one would replay the IDs
the session draws next; an archive's salt, keys and nonces still come from the session's own generator, on the
actor, with only the derivation away (`AccountArchive.seal(…wrappingKey:salt:…)`). The lock epoch is checked when
each step returns: a lock meanwhile takes effect at once, and the call throws `locked` with nothing staged. (An
unlock's derivation runs on the actor, but under the account's own parameters and with no keys resident.)

**Plaintext export needs the account password, in the same call.** `exportPlaintext(_:vaults:password:)`
re-derives the Account Unlock Key from the password under the stored header's own KDF parameters and opens the
keyset with it, as `deleteAccount` does; there is no cached "recently verified" state. A wrong password is
`CryptoError.authenticationFailed`. It is refused while locked, a lock while it runs wins (the epoch is checked
after every suspension and once more before the bytes are returned), and the items are those of the chosen vaults
that are not deleted; records that would not open are returned beside the report (`PlaintextExport.unreadable`),
not left out silently. The standing warning is `InterchangeGuide.plaintextExportWarning`
(`VaultSession.plaintextExportWarning`). File protection is the app's: the doc comment says
`FileProtectionType.completeUnlessOpen` or stronger, a place the person chooses, never the App Group container.
The app does it so (`ExportModel`, `ExportView`): the bytes stay in zeroising memory (`SecureBytes`) until the person
saves, are then written by the app itself into a folder of its own in the temporary directory, with
`.completeFileProtectionUnlessOpen` on iOS, and handed to the system's file mover, which moves the file where the
person chooses; the staged copy is removed when the mover is done, on cancel, when the screen closes and at every lock,
and the bytes are zeroised once saved. Not `fileExporter` with `FileWrapper.fileAttributes`, which says nothing about
what the exporter stages. Where the mover copies rather than moves (another file provider), the copy's protection is
the provider's. macOS has no protection classes: the file is as safe as the folder the person picks, which is why the
warning says not to pick a synced one. The screen models also drop the export's bytes, the merge review and typed
passwords on every lock, from `VaultSession.lockEvents()` rather than from views going away (review of the account
screens, findings 5 and 6).

**The encrypted Watchword archive (PRD F8.4; ADR 0008).** A versioned, portable, whole-account backup that only
Watchword reads, made of the vault's own envelope format (`AccountArchive` in `WatchwordCrypto`):

```
magic "WWAR"  formatVersion u8 = 1
archiveID 16  accountID 16  createdAt u64
kdfAlgorithm u8 (1 = PBKDF2-HMAC-SHA256)  iterations u32  salt (u16 length)
wrapKeyID 16  archiveKeyID 16
wrappedKey (u16 length)   the archive key under AWK           kind 9, schema 1, record = archiveKeyID, vault = archiveID
entryCount u32
── header ──
manifest (u16 length)     SHA-256(header) ‖ SHA-256(entries)   kind 9, schema 2, record = archiveID, vault = accountID,
                                                              version = entryCount
entries                   entryCount × (entryID 16, envelope (u32 length))
                                                              kind 9, schema 3, record = entryID, vault = archiveID,
                                                              version = position (from 1)
```

The archive key is fresh for each archive and wrapped under a key derived from a passphrase the person chooses for
the archive (at least ten characters) **and the account's Secret Key**, as 2SKD combines the account password with
it, under its own info strings and salted by the archive ID:

```
salt' = HKDF-SHA256(ikm: salt, salt: archiveID, info: "WW-archive-salt-v1")
Kp    = PBKDF2-HMAC-SHA256(NFKD(passphrase), salt', iterations)
Ks    = HKDF-SHA256(ikm: SK, salt: accountID, info: "WW-archive-2SKD-v1")
AWK   = HKDF-SHA256(ikm: Kp ‖ Ks, salt: archiveID ‖ accountID, info: "WW-archive-key-v1")
```

**The file.** A backup is saved as `Watchword Backup <date>.watchwordbackup`. Both apps declare the type
(`com.ericsuh.watchword.backup`, conforming to `public.data`; `UTExportedTypeDeclarations` in `Apps/project.yml`,
the identifier and extension being `ExportKind`'s constants, which a test holds to the spec), so the system names
the file a "Watchword Backup" and the restore screen's picker offers backups only. The type is exported and never
handled: the apps register no document type (`CFBundleDocumentTypes`), so opening a backup from Files, Finder or a
message does not start Watchword, and the only way a file reaches `AccountArchive.parse` is the person choosing it
on the restore screen (owner decision, 2026-11-17: the convenience was not worth an entry point any app, page or
sender could use). A backup whose extension was changed is not offered until it is renamed.

Why the Secret Key and not the passphrase alone (ADR 0008): the likeliest place for a backup file is the cloud drive
the vault syncs through, adversary A1's. The account's ciphertext there resists offline guessing because of the
Secret Key; an archive protected by the passphrase alone would be the one object beside it that A1 could guess at.
The price is that restoring an archive needs the Emergency Kit, which restoring an account needs anyway. The
iterations are the session's (`KDFStrategy`: calibrated, at least the floor).

Each entry's plaintext is a type byte and its content: `1` a vault (its ID and name, so an import can say which vault
an item came from; the name's UTF-8 cut to 1,024 bytes at a scalar boundary, so it always decodes, and an entry
that does not parse is listed as skipped), `2` an item exactly as `ItemCodec` stores it, history, trash, archived mark and unresolved
values included. `exportArchive(vaults:passphrase:password:)` requires the account password like a plaintext export
(someone holding an unlocked device must not be able to take the vault away under a passphrase of their own).

**Reading one checks everything before decrypting anything.** `AccountArchive.parse` bounds the file (256 MiB),
the entry count (200,000, and against the bytes that could hold it, before anything is allocated), every length,
the creation time, and the KDF parameters on both sides (the floor against a downgrade, the ceiling against an
archive that turns a restore into a hang, `KDFParameters.validate`), and checks every envelope's kind, key and
authenticated data against its place: an entry moved to another position, relabelled with another entry's ID or
taken from another archive, and a header relabelled with another account, all fail here, before any key is
derived. Then `open` derives AWK, opens the archive key (a wrong passphrase, a wrong Secret Key, and a header
altered in any field the key depends on, all fail as one `CryptoError.authenticationFailed`), opens the manifest and
compares its digests with every byte of the header and the entries, and only then decrypts the entries, in order,
handing each plaintext to the caller and zeroising it as soon as it is decoded. Sealing likewise asks for one
entry's plaintext at a time. Every `SecureBytes` is page-rounded (16 KiB on arm64 Darwin), so holding them all
would cost the entry count times a page, about 3 GiB at the format's 200,000-entry limit; held one at a time, a
restore's memory grows with the items it decodes. A truncated, extended, reordered or spliced archive that got that
far fails at the manifest, as the same error.

An archive names its account in the clear. `previewArchiveImport` with no `secretKey` uses this account's Secret Key
and refuses an archive of another account by name (`archiveFromAnotherAccount`), so the person can be asked for that
account's Emergency Kit; given one (a restore into a new account after the old one is gone), it uses it. Either way
the items are hostile input (A7: whoever hands over an archive and its Kit chose every byte) and go through
`ArchivedItems.importEntries`, the archive's road through `ImportAssembler`: fresh item and field IDs from the
injected generator (an earlier version's field keeps the new ID of the current one), the caller's vault, every
scope checked again (`ScopeDerivation.validated`: the normaliser must give back the same host, then the plain-name
rule and `ScopePolicy`; subdomains stay included only where the derived scope includes them, exclusions are kept,
and a refused scope is kept as a website field and reported), one-time passwords through `OTPParameters`,
passkeys through `PasskeyCredential`, the import's budgets (history fields count) and the stored-size bound, and no
sync metadata. Values sync was holding for the person to choose between come back as fields labelled
"(unresolved value)" and are reported (`unresolvedValuesKept`): a field's other text, another title, another set of
scopes' hosts (as `url` fields without `InterchangeMeta.websiteType`, so text and never a scope or an exported
website) and other tags; only flags (archived, trash, exclusion, field order), which settle to the value shown, and
passkeys are counted as omitted (`unresolvedValuesOmitted`). Only the person's own trash is trash on restore
(`Item.isTrashedByPerson`): an item sync left in the trash (kept after a deletion that had not seen it, trashed
without seeing every edit, or over a concurrent restore) comes back live, with `restoredFromSyncTrash`, because
restored as trash `trash(id:)` would make it the person's and the 30-day purge would remove it, and skipped as
`trashedAtSource` the report would call it the person's (PRD F1.5, F7.7). An entry that is neither a vault nor an
item that decodes is listed as skipped. Everything else a Watchword item holds is kept: every field's kind, label and
metadata, the whole history, the times, the archived mark and the exclusion from suggestions. What an archive does
not restore is the vaults themselves: the items of every archived vault go into the one vault the person chooses,
each listing the vault it came from (`ImportEntryReference.container`).

Known-answer vectors for the derivation (one of a passphrase that NFKD changes, a precomposed "é" and the U+FB01
ligature, so a missing or different normalisation fails), and a whole archive written by an independent Python
implementation of this section (fixed keys and nonces), are in `AccountArchiveTests`; the archive is also the seed of the `archive`
fuzz target. The adversarial areas are "encrypted Watchword archive" and "interchange through the session".

## 15. Module and target layout

```
Package.swift (SwiftPM, tools 6.0, Swift 6 language mode)
  Sources/WatchwordModel        pure data types, Codable/CBOR, scopes, fields
  Sources/WatchwordMatching     host normalisation, scope scoring, shadowing
  Sources/WatchwordGenerator    password / passphrase / PIN generation, entropy
  Sources/WatchwordEnvelope     envelope format, AAD context, KDF parameter validation
  Sources/WatchwordCrypto       2SKD, keyset, vault keys, HPKE wrap  (CryptoKit)   [milestone 1, done]
                                encrypted Watchword archive (§14.1)                [milestone 7]
  Sources/SecureMemory          SecureBytes (only unsafe code)                      [milestone 1, done]
  Sources/WatchwordStore        record-store port, in-memory and SQLite stores     [milestone 2, done]
  Sources/WatchwordSync         change log, merge, SyncTransport protocol,
                                SQLite sync state                                  [milestone 3; transports in Platform]
  Sources/WatchwordAutoFill     credential provider request model, TOTP, passkey
                                authenticator, identity planner (§9.2)             [milestone 5; extension adapter open]
  Sources/WatchwordSharing      membership chain, verified contacts, invitations,
                                key grants, rotation plans                         [milestone 4; protocol core
                                                                                    and session wiring done;
                                                                                    transports, UI open]
  Sources/WatchwordHygiene      HIBP clients, scan schedule, strength estimator,
                                reuse, report, HygieneEngine                       [milestone 6; adapters, UI open]
  Sources/WatchwordInterchange  CSV, 1PUX and CXF import/export, ZIP reader,
                                DEFLATE inflater, import mapping, instructions      [milestone 7; session wiring
                                                                                    done (§14.1), apps open]
  Sources/WatchwordKit          VaultSession façade, UnlockPolicy, AutoLockPolicy,
                                ports (KeychainStore, BiometricGate, WallClock)     [milestone 2, done]
  Sources/WatchwordPlatform     Apple adapters: SystemKeychainStore,
                                LocalAuthenticationGate, Emergency Kit PDF          [milestone 2, done]
                                CloudKitTransport, CoordinatedFileSyncTransport,
                                AutoSyncDriver                                      [milestone 3; not run on a Mac]
                                URLSessionHTTPClient, FileDeviceLocalStore          [milestone 6; not run on a Mac]
  Sources/WatchwordPresentation the apps' screen models over VaultSession: vaults,
                                sharing, devices, quarantine, security report,
                                import, export, wording (portable)                  [milestones 3-7; written,
                                                                                    views unbuilt on a Mac]
  Sources/WatchwordTestSupport  seeded/broken generators (milestone 1); fakes for every port and
                                scenario builders as the ports arrive
Apps/ (Xcode project generated with XcodeGen from project.yml)
  Watchword (iOS/iPadOS), Watchword (macOS), AutoFillExtension (iOS), AutoFillExtension (macOS)
Fuzz/ (a package of its own, depending on this one by path; nothing in it reaches an app)
  Sources/WatchwordFuzz         libFuzzer targets for the parsers that read hostile bytes   [milestone 7]
  Corpus/<target>               committed seed inputs
```

Ports (protocols) injected into the core: `KeychainStore`, `BiometricGate`, `RandomSource`,
`Clock`, `HTTPClient`, `SyncTransport`, `CredentialIdentityPublisher`, `FileAccess`. Milestone 2
has `RecordStore`, `KeychainStore`, `BiometricGate` and `WallClock`; randomness is an injected
`RandomNumberGenerator`. The device registry adds `DeviceKeyStore` (this device's signing key:
`KeychainDeviceKeyStore` in software, `FakeDeviceKeyStore` in tests, a Secure Enclave adapter to come). Milestone 3 adds `SyncTransport`, `SyncKeyring`, `RecordMerger` and `SyncStateStore`,
with `InMemorySyncTransport`, `FileSyncTransport` and `InMemorySyncStateStore` in the module and the fakes
(`FakeSyncKeyring`, `FakeItemMerger`, `SyncTestClient`, `SimulatedServer`) in `WatchwordTestSupport`; the
production keyring is `VaultSession` (an `ItemSealer` for the shared `ItemRecordMerger`) and the production state
store `SQLiteSyncStateStore`. Production adapters live in the package (`WatchwordPlatform`,
`SQLiteRecordStore`) rather than `Apps/`, so the strict-memory-safety job, the unsafe tripwire,
lint and `swift test` cover them; `Apps/` holds only UI and OS glue. The screens' logic lives in the package too:
`WatchwordPresentation` holds a main-actor, `@Observable` model per account screen, over `VaultSession` and portable
modules only, so `swift test` runs it on Linux against real sessions; the SwiftUI views in `Apps/Shared` lay a model
out and pass taps on. A model decides nothing about security: every refusal is the session's, and the model words it
(`ErrorWording`, `SyncSummary`). Fakes live in
`WatchwordTestSupport` (`FakeKeychain`, `FakeBiometricGate`, `FakeClock`, `TestVault`). Milestone 5 adds
`CredentialVault`, `CredentialIdentityPublisher` and `AutoFillClock` in `WatchwordAutoFill`, with `FakeCredentialVault`
and `FakeCredentialIdentityPublisher` beside them.

Milestone 6 adds `HTTPClient`, `PwnedRangeCache` (with `InMemoryPwnedRangeCache` in the module) and `SiteDirectory`
(§13); their fakes are `FakeHTTPClient`, which records every request, `RecordingPwnedRangeCache` and
`SimulatedPwnedPasswords`. Hygiene takes the time as a parameter and randomness as a generator, so it needs no clock
port of its own. The session adds `DeviceLocalStore` (§13.8), with `InMemoryDeviceLocalStore` in `WatchwordKit` and
`HygieneSessionFixture` in `WatchwordTestSupport`.

The Apple adapters of those ports are in `WatchwordPlatform`: `URLSessionHTTPClient` (`HTTPClient`),
`FileDeviceLocalStore` (`DeviceLocalStore`), `CoordinatedFileSyncTransport` and `CloudKitTransport` (`SyncTransport`;
the latter over its own `CloudKitDatabase` seam, faked in the tests), and `AutoSyncDriver`. The transport contract is
`SyncTransportContract` in `WatchwordTestSupport`, run against every transport.

Milestone 4 adds `KeyBundleDirectory` and `VerifiedContactStore` (§8.4), each with an in-memory implementation in
`WatchwordSharing`, and in `WatchwordTestSupport` the hostile store and simulated members of the sharing tests
(`HostileSharingStore`, `SimulatedMember`, `SharingHousehold`, `ForgedRecord`). Its integration (§8.10) adds
`SharingStateStore` and `ShareAccessControl` in `WatchwordKit` (with `InMemorySharingStateStore` and
`SQLiteSharingStore`) and `WriteJudge` in `WatchwordSync`; the fixtures are `SharingAccount`, `SharedVaultHousehold`,
`WithholdingTransport` and `RecordingShareAccess`.

## 16. Open questions tracked as ADR candidates

- Whether to offer iCloud Keychain storage of the Secret Key as an opt-in convenience (`adr/0004`).
- Argon2id adoption path (`adr/0003`).
- Per-item keys (wrapped by VK) to make rotation O(members) instead of O(items): **decided in milestone 4, against**
  (`adr/0007-rotation-reencrypts-records.md`, closing review finding D10). Rotation re-encrypts; a per-blob content
  key is the thing to add if attachments arrive.
- The device registry (review finding D9) is built (§7.8): a revoked device can no longer write. What it left
  open is an **account re-key** — a new keyset and Secret Key, every vault key rotated — which is the only thing
  that ends a revoked device's *reading* if it held the keyset, and the remedy for a stolen local header. It
  shares its machinery with vault-key rotation on membership removal (milestone 4, F4.3) and should be decided
  with it. Also open: the Secure Enclave P-256 `DeviceKeyStore` adapter (verification is in place), and
  collecting a deleted vault's objects from the transport.
- OS QuickType behaviour with overlapping domain identities. Planned for milestone 2 but not yet
  verified: it needs a physical device with the AutoFill extension publishing identities, which
  arrives with milestone 5. Carried to milestone 5's on-device QA. Until then the portable core
  assumes the widest matching (the registrable domain) and publishes only whole-site identities
  (§9.1).
