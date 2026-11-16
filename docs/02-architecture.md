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
  reconciling sync, so a state row that does not decode is read as no state). Still to come: the breach-check
  prefix cache and scan ledger, as sealed local records rather than a plaintext `hibp_cache` table (§13.2,
  §13.3; milestone 6). The schema version is `PRAGMA user_version`; a newer one is refused, not
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
hashed, stored or signed for.

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
| Credential list (`prepareCredentialList`) | `credentialList(for:passkey:)` | passwords of the most specific matches, passkeys of the relying party, "other accounts on this site", a suggestion only for a sole match; or `LookAlikeWarning` |
| Password, chosen in the list | `password(for:identifiers:)` | `PasswordCredential` |
| Password, QuickType (`provideCredentialWithoutUserInteraction`) | `passwordWithoutInteraction(for:)` | the credential for an identity the planner would publish now; otherwise `requiresInteraction` or a refusal |
| One-time codes (iOS 18) | `oneTimeCodeList`, `oneTimeCode`, `oneTimeCodeWithoutInteraction` | `OneTimeCode` with the seconds remaining |
| Text to insert, host named | `textInsertionList(for:)`, `textToInsert(for:identifiers:)` | the field's text, one recovery code, or a code field's current code |
| Text to insert, no host (iOS 18's `prepareInterfaceForUserChoosingTextToInsert()`) | `textInsertionListWithoutHost()`, `textToInsertWithoutHost(for:)` | a hand-picked field that is not a secret |
| Passkey assertion | `passkeyAssertion`, `passkeyAssertionWithoutInteraction` | `PasskeyAssertionResult` with `prf` and `largeBlob` output |
| Passkey registration | `passkeyRegistrationOptions`, `registerPasskey` | attestation object, and where the credential was stored |
| Conditional registration (iOS 18) | `registerPasskeyWithoutInteraction` | as above, or `noItemToUpgrade` |
| Save password | `savePasswordPlan`, `savePassword`, `savePasswordWithoutInteraction` | create (alone, or beside the accounts already there), offer an update, or already saved |
| Generate password | `generatePassword(for:)` | a password obeying the site's `passwordrules`, with its entropy |
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
- **Shadowed accounts are shown, not released.** `otherAccounts` lists items that match the host
  less specifically (F6.6). The gate refuses them even when chosen, as it always has; to use one
  on that host the person adds the host to the item, in the app.
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

Still open for milestone 5, all on a Mac: the extension targets' adapter over this model,
`VaultSession`'s conformance to `CredentialVault`, the encrypted index record that lets the
extension list without decrypting every item, and on-device QA (first, what the system hands back
for a QuickType tap and on which hosts it offers an identity, §9.1; then what it passes as `prf`
salts, and how it treats UP = 0 on a conditional registration).

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

The portable core is built (milestone 6); the `URLSession` adapter, the wiring into `VaultSession`, the
background-task glue and the report UI are not (§13.8). The module depends on `WatchwordModel`,
`SecureMemory` and `Crypto` (SHA-1 for the range API, HMAC-SHA-256 for reuse) and on nothing else: it does
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

`ScanLedger` records, per item, the version scanned, when, and the result per password field; per item whose
last check failed, the version, when and how often in a row; and the pass times. It is `Codable` with
explicit, bounded shapes (a ledger with no failures encodes without the key), and it is **derived from
passwords** (a breach count all but names one): the session persists it only sealed, as a local record that
is not synced. It holds no hash, prefix or token.

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
| EFF large wordlist | 7,776 | EFF (CC BY 3.0 US), via a mirror, cross-checked against a second |

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
lower-cased title bytes, then ID; findings by severity, kind, field. A breach result counts only for the
item version it was made for. The report holds titles, so it is as private as the vault; it holds no
password, hash or token.

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

### 13.8 Still to come, and how it plugs in

- **`URLSessionHTTPClient`** in `WatchwordPlatform`: an ephemeral session, no cookies or cache, redirects
  refused, the response cut off at `maximumResponseBytes` of decoded body, a timeout, nothing logged (the
  port's documentation is the contract).
- **Session wiring** in `VaultSession`: derive the reuse key from `Ksym` with its own HKDF label; on unlock,
  unseal the ledger record and call `unlock` with the decrypted items, in a task of its own at no higher
  priority than the one that locks; on save, `update` then `scan`, refetching on `.stale`; seal and store
  `ledger()` after every scan, **failed ones included** (the failure in it is what keeps one refused range
  from being asked for first at every unlock and every launch, §13.3), and hand the stored ledger to the next
  `unlock`; back `PwnedRangeCache` with sealed local records. **On lock the session zeroises
  the keyset first** and does not wait for this actor to do it: it cancels the unlock task if one is running,
  then calls `lock()`, which returns after at most one item's analysis. The reuse key is the engine's own
  copy, so nothing here can keep the vault's keys resident.
- **Background glue**: `BGProcessingTask` (iOS) and `NSBackgroundActivityScheduler` (macOS) only wake the
  loop; whether anything runs is `next(now:)`'s decision, so a wake while locked does nothing.
- **The report UI** and its snapshot tests, and the settings for the site directory and the API key.

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
  Sources/WatchwordAutoFill     credential provider request model, TOTP, passkey
                                authenticator, identity planner (§9.2)             [milestone 5; extension adapter open]
  Sources/WatchwordSharing      membership, invitations, rotation                  [milestone 4]
  Sources/WatchwordHygiene      HIBP clients, scan schedule, strength estimator,
                                reuse, report, HygieneEngine                       [milestone 6; adapter, wiring, UI open]
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
`WatchwordTestSupport` (`FakeKeychain`, `FakeBiometricGate`, `FakeClock`, `TestVault`). Milestone 5 adds
`CredentialVault`, `CredentialIdentityPublisher` and `AutoFillClock` in `WatchwordAutoFill`, with `FakeCredentialVault`
and `FakeCredentialIdentityPublisher` beside them.

Milestone 6 adds `HTTPClient`, `PwnedRangeCache` (with `InMemoryPwnedRangeCache` in the module) and `SiteDirectory`
(§13); their fakes are `FakeHTTPClient`, which records every request, `RecordingPwnedRangeCache` and
`SimulatedPwnedPasswords`. Hygiene takes the time as a parameter and randomness as a generator, so it needs no clock
port of its own.

## 16. Open questions tracked as ADR candidates

- Whether to offer iCloud Keychain storage of the Secret Key as an opt-in convenience (`adr/0004`).
- Argon2id adoption path (`adr/0003`).
- Per-item keys (wrapped by VK) to make rotation O(members) instead of O(items), including
  re-upload. Promoted from "deferred" to a milestone-4 decision by the review (finding D10):
  rotation runs on every membership change, so its cost is not a tail case.
- A device registry signed by existing devices (review finding D9). Today every device holds the
  account Ed25519 key, so a lost device cannot be excluded without rotating the account key.
  Needed before sync ships. `SyncKeyring.verify` is where it plugs in: it already decides, per object, whether
  the author named in the location may write to the vault.
- OS QuickType behaviour with overlapping domain identities. Planned for milestone 2 but not yet
  verified: it needs a physical device with the AutoFill extension publishing identities, which
  arrives with milestone 5. Carried to milestone 5's on-device QA. Until then the portable core
  assumes the widest matching (the registrable domain) and publishes only whole-site identities
  (§9.1).
