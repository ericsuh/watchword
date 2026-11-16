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
                    5 = snapshot, 6 = vault-metadata, 7 = vault-directory, 8 = device-registry)
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
`VaultMetadata { vaultID, name, createdAt, modifiedAt, version }` (`VaultMetadataCodec`: JSON with sorted keys,
16 KiB at most, a name of at most 256 characters, and the same identity check against the row). A vault's name
is as private as an item's title. Kinds 7 and 8 are not sealed payloads of their own: they name rows of the
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
  reconciling sync, so a state row that does not decode is read as no state). Still to come: `hibp_cache`
  (milestone 6). The schema version is `PRAGMA user_version`; a newer one is refused, not
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
  unlock); key material is never in this file.
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
field group; losers are kept in the item's history (F7.4). §7.5 describes what milestone 3 built. Membership operations are totally
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

### 7.5 As built in milestone 3 (`WatchwordSync`, the portable half)

`WatchwordSync` imports no Apple framework: sealing, opening, signing and verifying reach it through the
`SyncKeyring` port, and field-level merging through the `RecordMerger` port, both implemented with fakes in
`WatchwordTestSupport`, so the whole engine — including the N-device partition simulation and the adversarial
suite "sync log" — runs under `swift test` on Linux. The production keyring, the persistent state store and the
app's conflict UI are described in §7.6, the account's own objects and enrolment in §7.7, the device registry in
§7.8 and automatic syncing in §7.9; the CloudKit and iCloud Drive transports are still to come
(`03-implementation-plan.md`, milestone 3). One engine runs per vault; a vault's log carries its items and its
description (`vaultMetadata`), each kind merged by its own merger (`KindRoutingMerger`).

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
  survive, and two edits of the same line both appear. Histories are unioned, never shortened by a merge. The merge is
  a join — the same versions in any order give the same item — except that field order is last-writer-wins (it
  holds no field's contents) with one corner the deterministic choice settles one exchange later. The merger answers
  keep, adopt, or a new version above both, and the commit names the local version it read
  (`StoreChange.expectations`).
- Moving to the trash is the `trashedAt` group, so trashing and a concurrent edit give a trashed item that contains
  the edit. A permanent deletion is a tombstone carrying an *erasure summary*: the version vector of what its author
  had seen. A version it covers is erased; a version holding an edit its author never saw is kept, in the trash, with
  that edit as its last version and `keptAfterDeletion` set — on the deleting device as on every other. A record can
  be erased more than once, on devices that had each seen something the other had not; a device remembers the *join*
  of every erasure of a record it knows (`RecordMerger.joinErasureSummaries`: for items the pointwise maximum of the
  vectors), and judges a version against that, so which erasure arrives first decides nothing. A device publishes its
  own deletion even when it already knows a later erasure of the same record by another device: that one's author may
  have seen less. The same holds for its own earlier erasure: the person may delete a version that erasure kept, and a
  kept version keeps its own number, so the second deletion's stamp can be the lower. A pending deletion counts as
  published only once this device has published a deletion of the record at or after its stamp *and* the join it holds
  already contains everything this one had seen. An erasure a device already holds is not applied to its local version
  a second time (a later snapshot may carry it again): it erased the version or the version was kept, and applied
  again it would put back in the trash an item the person has since restored. Only a reconciling sync judges again. A
  version kept after an erasure is written above the erasure's own stamp, which the engine passes to the merger (a
  record's versions climb with every merge; its edits, which are all a summary names, do not).
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

**Reconciling** (`sync(reconcile: true)`) forgets everything but pending deletions and replays the log. On a
healthy device it changes nothing; on one whose file was rolled back it restores the newest versions.

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
trusted for the vault, so this is an insider's capability).

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
versions through an `ItemSealer`, calls `ItemMerge.merge` and seals the result through `ItemMerge.written`. The app
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
is ignored: never published, never treated as an erasure. A row A8 plants there erases nothing. This holds per
vault: a pending deletion counts only for the vault it is filed under.

**App.** Settings has Sync Now and the last report in words; a list row with conflicting values shows a badge, and
the item's detail lists each conflicting group with the shown value first and each alternative after it, every one
behind its own Keep button, secrets hidden until shown. Production builds are built without `SyncSettings` until a
transport exists. UI-test launches (`--uitest`) sync over an in-memory transport with `UITestPeer`, a second session
of the same account in the process, so XCUITest drives a concurrent rename through the real keyring
(`SyncConflictTests`).

### 7.7 Vaults, the account's own objects, and enrolment (as built)

**Vaults** (PRD F2.1–F2.3). An account has the Personal vault and any number of others it owns
(`createVault`, `renameVault`, `deleteVault`, `vaults()`, `items(in:)`; sharing is §8). Each vault has its own
256-bit key, wrapped under Ksym as a `vaultKeyWrap` record whose identity — vault and key ID — comes from where it
is stored, and a sealed description (§5). The Personal vault needs no description to exist (its name defaults
to "Personal"), can be renamed, and can be neither deleted nor shared: the session refuses, and a deletion of it
is ignored whoever signed it. Every `VaultSession` invariant holds per vault: contexts from the row, identity
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
   left, however old the parents it names.
2. Between checkpoints: causal order, each revocation as early as that allows (what it had seen, the
   revocation, then what it had not), ties by entry ID.

An entry is applied only if, at its place, its author is a registered device not yet revoked — or the current
enrolment key, for an entry written knowing of it — and its signatures verify. A revoked device's ID and key are
never accepted again; a registered device's key never changes; no key serves two devices. A candidate password
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
- while locked every sync is download-only (F7.5, §7.4), and local changes wait for the unlock.

A clock that moved backwards cannot show that an interval has not passed, so such a wait is treated as over:
syncing early costs a request, waiting for ever would cost the data.

## 8. Sharing protocol

1. Owner O creates vault V, VK, and a membership record `M0 = sign(O, {vaultID, epoch 0, members:
   [O: admin]})`.
2. O invites U: transport share is sent (CloudKit share URL or folder share). O fetches U's
   published X25519/Ed25519 public keys and shows U's fingerprint
   (`SHA-512("WW-fingerprint-v1"||accountID||pkX||pkEd)` truncated to 60 bytes and rendered as a
   60-digit safety number in twelve groups of five, and as a QR; SHA-512 because 60 digits need 60
   bytes of digest). U sees O's fingerprint on acceptance. Both must confirm (F4.2).
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
Characters IDNA keeps distinct (Cyrillic `а`) stay distinct and never match an ASCII scope.

Types carry the guarantee: `ScopeMatcher` and `ItemRanker` accept only a `NormalizedHost`, whose
initializer is internal to the module, so the only way to obtain one is through the normaliser.
`AutoFillGate` is the single function through which a secret may reach the OS, and it re-checks
`isSelectable` even when the person chose the item explicitly.

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
  Sources/WatchwordEnvelope     envelope format, AAD context, KDF parameter validation
  Sources/WatchwordCrypto       2SKD, keyset, vault keys, HPKE wrap  (CryptoKit)   [milestone 1, done]
  Sources/SecureMemory          SecureBytes (only unsafe code)                      [milestone 1, done]
  Sources/WatchwordStore        record-store port, in-memory and SQLite stores     [milestone 2, done]
  Sources/WatchwordSync         change log, merge, SyncTransport protocol,
                                SQLite sync state                                  [milestone 3; transports open]
  Sources/WatchwordSharing      membership, invitations, rotation                  [milestone 4]
  Sources/WatchwordHygiene      HIBP client, strength, reuse                       [milestone 6]
  Sources/WatchwordInterchange  1PUX/CSV/CXF                                       [milestone 7]
  Sources/WatchwordKit          VaultSession façade, UnlockPolicy, AutoLockPolicy,
                                ports (KeychainStore, BiometricGate, WallClock)     [milestone 2, done]
  Sources/WatchwordPlatform     Apple adapters: SystemKeychainStore,
                                LocalAuthenticationGate, Emergency Kit PDF          [milestone 2, done]
  Sources/WatchwordTestSupport  seeded/broken generators (milestone 1); fakes for every port and
                                scenario builders as the ports arrive
Apps/ (Xcode project generated with XcodeGen from project.yml)
  Watchword (iOS/iPadOS), Watchword (macOS), AutoFillExtension (iOS), AutoFillExtension (macOS)
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
lint and `swift test` cover them; `Apps/` holds only UI and OS glue. Fakes live in
`WatchwordTestSupport` (`FakeKeychain`, `FakeBiometricGate`, `FakeClock`, `TestVault`).

## 16. Open questions tracked as ADR candidates

- Whether to offer iCloud Keychain storage of the Secret Key as an opt-in convenience (`adr/0004`).
- Argon2id adoption path (`adr/0003`).
- Per-item keys (wrapped by VK) to make rotation O(members) instead of O(items), including
  re-upload. Promoted from "deferred" to a milestone-4 decision by the review (finding D10):
  rotation runs on every membership change, so its cost is not a tail case.
- The device registry (review finding D9) is built (§7.8): a revoked device can no longer write. What it left
  open is an **account re-key** — a new keyset and Secret Key, every vault key rotated — which is the only thing
  that ends a revoked device's *reading* if it held the keyset, and the remedy for a stolen local header. It
  shares its machinery with vault-key rotation on membership removal (milestone 4, F4.3) and should be decided
  with it. Also open: the Secure Enclave P-256 `DeviceKeyStore` adapter (verification is in place), and
  collecting a deleted vault's objects from the transport.
- OS QuickType behaviour with overlapping domain identities. Planned for milestone 2 but not yet
  verified: it needs a physical device with the AutoFill extension publishing identities, which
  arrives with milestone 5. Carried to milestone 5's on-device QA.
