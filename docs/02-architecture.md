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
- **Vault keys.** One per vault; the Personal vault key is wrapped with Ksym; shared vault keys are
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
                    5 = snapshot)
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
  - `deviceSigningKey` — Secure Enclave P-256 key used to sign this device's change-log segments
    in addition to the account Ed25519 key (lets other devices distinguish which device wrote what).

## 7. Sync

### 7.1 Model: per-device append-only change logs plus snapshots

Each device appends **log segments** (envelopes of kind 4, each containing one or more item
versions or membership operations, signed with the account Ed25519 key and the device key) to its
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
app's conflict UI are described in §7.6; the CloudKit and iCloud Drive transports are still to come
(`03-implementation-plan.md`, milestone 3).

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
  that edit as its last version and `keptAfterDeletion` set — on the deleting device as on every other.
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
sync never stops this. Every device merges *every* listed snapshot, not only the newest, and continues a stream from
the highest coverage any of them has when its next segment is missing. A device deletes its own segment once every
other known stream has acknowledged merging it and some listed snapshot covers it, always keeping its newest; it
deletes one of its own snapshots only when another listed snapshot covers everything it does. A snapshot's contents
are trusted only as far as their signature: existing devices never delete anything because a snapshot omits it.

**Reconciling** (`sync(reconcile: true)`) forgets everything but pending deletions and replays the log. On a
healthy device it changes nothing; on one whose file was rolled back it restores the newest versions.

Known limits, tracked in `06-adversarial-review.md` §H: every device still holds the account signing key, so
the device registry (D9) is still needed before sync ships; a device that stops syncing for good holds garbage
collection back until it is removed; the store can withhold objects (reported, not prevented); an item's history
lives in its record and is never pruned (F1.4), so an item edited often enough to reach the payload limit (SEC9)
refuses further edits until history moves to records of its own; and a snapshot may attribute versions to any device (its author is
trusted for the vault, so this is an insider's capability).

### 7.6 As built in milestone 3 (the vault side, on a Mac)

**Keyring.** `VaultSession` is the production `SyncKeyring` and `ItemSealer`, through `VaultSyncAdapter`, which
holds the session and never a key: every call goes back to the actor, which throws `SyncKeyringError.locked` once
`lock()` has zeroised the keys. Segments and snapshots are sealed with `RecordCipher` under the personal vault's
current key, in the context `SyncObjectLocation.envelopeContext` gives; items with the same code path as a save.
Signatures are the account's Ed25519 key, domain `logSegment`, over `name ‖ 0x00 ‖ envelope`: the envelope already
binds the location, but only once the vault key opens it, so binding the name into the signature also refuses a moved
object at download, while locked. Verification uses the keyset's own public key while unlocked and the Keychain copy
(`accountSigningKey`, §6) while locked; with neither, every object is refused (`trustedKeyUnavailable`, so the report
says why) rather than trusted, and the next unlock restores the copy. The keyring signs only as its own device. Until the device registry (D9)
lands, any device holding the account key may write to the vault.

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
is ignored: never published, never treated as an erasure. A row A8 plants there erases nothing.

**App.** Settings has Sync Now and the last report in words; a list row with conflicting values shows a badge, and
the item's detail lists each conflicting group with the shown value first and each alternative after it, every one
behind its own Keep button, secrets hidden until shown. Production builds are built without `SyncSettings` until a
transport exists. UI-test launches (`--uitest`) sync over an in-memory transport with `UITestPeer`, a second session
of the same account in the process, so XCUITest drives a concurrent rename through the real keyring
(`SyncConflictTests`).

## 8. Sharing protocol

As built in milestone 4's protocol core, `WatchwordSharing`. The module is portable (real cryptography through
`WatchwordCrypto`, the key directory and the contacts store behind ports) and is exercised in-process by simulated
members with real keysets over a hostile store. It is **not yet wired into `VaultSession`, `SyncEngine` or a
transport's own sharing** (CloudKit `CKShare`, a shared folder); §8.8 says what that integration calls.

### 8.1 Model

A shared vault has **members**, each an account with a role:

| Role | May |
| --- | --- |
| owner | everything an administrator may; and alone: grant or revoke the administrator role, remove an administrator, delete the vault. Exactly one, fixed for the life of the vault: never removed, never re-roled. |
| administrator | invite and remove members who are not administrators, change them between read-write and read-only, rotate the vault key |
| read-write | read and write items |
| read-only | read items. They hold the vault key like everyone else: this is a rule the clients keep, **not cryptography** (F4.5, §8.7) |

Membership is a **chain of signed records**, one per change, each naming its epoch (the previous one plus one), the
hash of its predecessor, the operation, the member list and vault key that result, and signed under
`SignatureDomain.membership` by an account that was an administrator in the state before it. Two consequences of the
table carry the rest of the design:

- **The set of accounts that may sign changes only in records the owner signed.** (Everything that adds or removes
  an administrator is the owner's.)
- **The owner can always sign the next record**, so no sequence of records, honest or hostile, leaves a vault that
  nobody can administer. Ownership transfer is not in v1; the last 4,096 epochs of a chain accept only the owner's
  signature, so an administrator cannot use the chain up either.

### 8.2 Formats, and what is in the clear

Every format is binary, little-endian, with one canonical encoding, a four-byte magic and a version byte, and a
bounded parser: a size is checked before anything is copied, a count before anything is allocated, and bytes that
would not re-encode to themselves are refused (SEC9). Sizes: at most 64 members; epochs up to 65,535; a record is at
most 10,040 bytes.

| Object | Magic | Contents | Signed by |
| --- | --- | --- | --- |
| Membership record | `WWMR` | vault ID, epoch, previous hash, signer, operation (`createVault`, `addMember`, `removeMember`, `memberLeft`, `changeRole`, `rotateKey`, `deleteVault`) with operands, vault key ID and the epoch that introduced it, the resulting members (account ID, role, epoch added, X25519 and Ed25519 keys, bundle self-signature) in account order | the signer |
| Key grant | `WWKG` | a `VaultKeyGrant`: vault, key ID, sender, recipient, recipient's X25519 key, HPKE encapsulated key, ciphertext (§4) | the sender (`.vaultKeyGrant`) |
| Leave request | `WWLR` | vault, account, the epoch the member was added | the member |
| Published key bundle | `WWKB` | account ID, X25519 key, Ed25519 key | self-signature (`.publicKeyBundle`) |
| Invitation | `WWIV` | vault ID, owner's account ID | nobody: it only says whose fingerprint to ask about |
| Contact pin (local) | `WWCP` | pinning account, method, time, the contact's bundle | the pinning account |
| Saved ledger (local) | `WWML` | account, vault, digest of the owner's keys, head epoch and hash; then the accepted records, then the records held from losing branches | the account, over the checkpoint |
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
changes it); the signature, under the key the *previous state* lists for the signer; and only then what costs work or
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
again: `writePermission` refuses the member's writes (`removalPending`); `recordsToReseal` is empty, so nothing
written under the newer key is sealed again under one the member holds; `pendingRotation` reports it; and the next
device whose account may sign the removal plans it again, whichever device signed the first. This is a function of
the records held, like the chain itself. A former administrator's removals on a dead branch owe nothing: their signer
has no standing in the accepted state. Nor does a removal that its own branch went on to take back by adding the
member again.

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
key). `RotationPlanner.plan` produces a `RotationPlan`, pure data the integrator executes, in this order:

1. **Revoke transport access** for the departing account. First, because it takes effect at once on the server.
2. **Merge the departing account's outstanding writes**, while this device's ledger still lets it write (§8.7).
3. **Publish the grants**: the new key wrapped to every remaining member, the planner's own account included.
4. **Publish the membership record** that removes the member and names the new key, after one more look at the
   store: a record that can no longer be adopted is not published, the plan is superseded, and it is planned again.
5. **Re-seal** every record `MembershipLedger.recordsToReseal(in:)` lists, as new versions through the ordinary
   save path, repeating until the list is empty.

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

One question, `MembershipLedger.writePermission(for:)` (over `MembershipState.writePermission(for:)`): may this
account write to the vault now? Allowed for the owner, administrators and read-write members of a vault that has not
been deleted, unless their removal is owed (§8.3). The client asks it before its own writes and before merging anyone
else's. (`writePermission(for:atEpoch:)` answers for an earlier epoch of the accepted chain; that is for showing
history, never for deciding whether to merge.)

It is **not cryptographic**: a read-only member holds the vault key, and a former member holds every key of their
time, so either can produce a ciphertext that decrypts. What stops it counting is every remaining member's client
asking, and the transport's own permission where it has one (CloudKit's read-only participant).

**Judged now, merged for good, sealed again.** A write is judged against the membership the device knows *when it
merges it*, not against the time the write claims: a former member can date a write as they please, so only the
newest membership a device knows can refuse them. Two rules keep that from stranding what a member wrote while they
were entitled to (S25):

- What a device has merged stays merged, whatever happens to its author's standing afterwards.
- A record whose stored version was written by an account that may no longer write is **sealed again by a member who
  may**, as a new version under their own name. `recordsToReseal` lists those records beside the ones under an
  earlier key (`SealedRecordReference.author`), and `pendingRotation` counts them. So after a demotion to read-only,
  which rotates nothing, every device that had merged the member's records and may write publishes them again; a
  member invited later, or a device that was offline, refuses the original and reads the copy. After a removal the
  same happens in the rotation's re-seal step, which is why the plan merges the departing account's outstanding
  writes *before* publishing the record that ends them.

What is still lost: a write by a member whose removal or demotion every device learned of before any device that may
write had merged it. That is the price of F4.5 being a rule the clients keep (S12). The reverse also holds: a write
made while read-only counts once its author has been made read-write.

### 8.8 What integration calls, and what is not solved

For each shared vault a session keeps a `MembershipLedger` (saved after every ingest that adopted, outranked or
forgot a record, and kept after the account is removed from the vault), the vault's keys, at most one `RotationPlan`,
and the records it has proposed and not yet seen adopted. `SimulatedMember` in `WatchwordTestSupport` is this loop,
written out against a hostile store. One sync pass, in this order:

1. **Membership.** List `sharing/<vaultID>/membership/`; skip names that are not a membership object's, that carry a
   hash the ledger `holds`, or whose contents were refused as `malformed` or `invalid` before (both are permanent);
   fetch the rest, drop any whose contents are not what the name commits to (`SharingObjectLocation.isName(of:)`),
   and `ingest` what remains. Offer `unconnected` objects again next time. Persist.
2. **Member keys.** `checkMemberKeys` against the verified contacts; report `substituted` members to the person.
3. **Proposals.** For each record this device proposed: `status(of:)`. Adopted: forget it. Awaiting publication:
   publish it again. Superseded: propose the change again on the new head, if it is still wanted and still possible.
   A record of this account's in `IngestReport.superseded` is a proposal again.
4. **Key.** Fetch the grant of the current key if it is not held (`openGrant(of:from:as:)`) and store the key
   wrapped under Ksym.
5. **Items.** Merge other members' writes, judging each author with `writePermission(for:)` (§8.7).
   `SyncKeyring.verify` is where that plugs in, with the author's signing key taken from the ledger's state.
6. **Rotation.** Continue any saved plan (`RotationPlan.parse(_:account:)`, `steps(in:)`); a superseded removal or
   departure is planned again. Plan each of `owedRemovals` this account may sign. As an administrator, plan a
   rotation for each of `pendingLeaveRequests`. Then, as a member who may write, seal again whatever
   `recordsToReseal` lists; a re-seal is the same item state at a higher version (`ItemMerge.written`), not an edit,
   so two devices doing it at once converge.

Accepting an invitation passes the ledger the device already holds for that vault ID, if it ever held one
(`continuing:`), and the owner it knows for it (`knownOwner:`).

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
  member is listed (with their writes refused).
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
  Sources/WatchwordSharing      membership chain, verified contacts, invitations,
                                key grants, rotation plans                         [milestone 4; protocol core,
                                                                                    integration open]
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
`RandomNumberGenerator`. Milestone 3 adds `SyncTransport`, `SyncKeyring`, `RecordMerger` and `SyncStateStore`,
with `InMemorySyncTransport`, `FileSyncTransport` and `InMemorySyncStateStore` in the module and the fakes
(`FakeSyncKeyring`, `FakeItemMerger`, `SyncTestClient`, `SimulatedServer`) in `WatchwordTestSupport`; the
production keyring is `VaultSession` (an `ItemSealer` for the shared `ItemRecordMerger`) and the production state
store `SQLiteSyncStateStore`. Production adapters live in the package (`WatchwordPlatform`,
`SQLiteRecordStore`) rather than `Apps/`, so the strict-memory-safety job, the unsafe tripwire,
lint and `swift test` cover them; `Apps/` holds only UI and OS glue. Fakes live in
`WatchwordTestSupport` (`FakeKeychain`, `FakeBiometricGate`, `FakeClock`, `TestVault`).
Milestone 4 adds `KeyBundleDirectory` and `VerifiedContactStore` (§8.4), each with an in-memory implementation in
`WatchwordSharing`, and in `WatchwordTestSupport` the hostile store and simulated members of the sharing tests
(`HostileSharingStore`, `SimulatedMember`, `SharingHousehold`, `ForgedRecord`).

## 16. Open questions tracked as ADR candidates

- Whether to offer iCloud Keychain storage of the Secret Key as an opt-in convenience (`adr/0004`).
- Argon2id adoption path (`adr/0003`).
- Per-item keys (wrapped by VK) to make rotation O(members) instead of O(items): **decided in milestone 4, against**
  (`adr/0007-rotation-reencrypts-records.md`, closing review finding D10). Rotation re-encrypts; a per-blob content
  key is the thing to add if attachments arrive.
- A device registry signed by existing devices (review finding D9). Today every device holds the
  account Ed25519 key, so a lost device cannot be excluded without rotating the account key.
  Needed before sync ships. `SyncKeyring.verify` is where it plugs in: it already decides, per object, whether
  the author named in the location may write to the vault.
- OS QuickType behaviour with overlapping domain identities. Planned for milestone 2 but not yet
  verified: it needs a physical device with the AutoFill extension publishing identities, which
  arrives with milestone 5. Carried to milestone 5's on-device QA.
