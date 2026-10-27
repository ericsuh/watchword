import Foundation
import WatchwordEnvelope
import WatchwordStore

public enum SyncKeyringError: Error, Equatable, Sendable {
    /// The vault is locked: no vault key is resident, so nothing can be sealed or opened (§7.4). Signatures can still
    /// be checked.
    case locked
    /// The envelope names a key this keyring does not hold for the vault.
    case unknownKey(UUID)
    /// The object's author is not a device or member allowed to write to this vault.
    case untrustedAuthor(UUID)
    /// Signature or decryption failed. One error for every cause, as in `CryptoError.authenticationFailed`.
    case authenticationFailed
}

/// The sync layer's only access to keys (docs/02-architecture.md §7.1, §15). Keeping sealing, opening, signing and
/// verifying behind this port is what keeps `WatchwordSync` free of CryptoKit, and so testable on Linux
/// (docs/03-implementation-plan.md, rule 3).
///
/// Production: `VaultSession`'s sync adapter (`WatchwordKit`), with `RecordCipher` under the vault key for sealing and
/// opening and the account's Ed25519 key for signatures — plus, once the device registry (review finding D9) lands,
/// the device's Secure Enclave key. Tests: `WatchwordTestSupport.FakeSyncKeyring`.
public protocol SyncKeyring: Sendable {
    /// Seals `payload` under the vault's current key, as an envelope bound to `location`
    /// (`location.envelopeContext(keyID:)`). Throws `locked` when no key is resident.
    func seal(_ payload: [UInt8], at location: SyncObjectLocation) async throws -> [UInt8]
    /// Opens an envelope whose expected context the engine derived from where it found it. The engine has already run
    /// `Envelope.parse` against that context; an implementation still opens through `RecordCipher.open`, which checks
    /// again. Throws `locked`, `unknownKey` or `authenticationFailed`.
    func open(_ envelope: [UInt8], context: EnvelopeContext) async throws -> [UInt8]
    /// Signs a sealed envelope as this device, for the object at `location`.
    func sign(_ envelope: [UInt8], at location: SyncObjectLocation) async throws -> [UInt8]
    /// Checks that `signature` over `envelope` was made by `location.author` and that the author may write to
    /// `location.vaultID`. Needs public keys only, so it works while locked. Throws `untrustedAuthor` or
    /// `authenticationFailed`.
    func verify(_ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation) async throws
}

/// What to do when a remote version of a record meets the local one.
public enum MergeDecision: Sendable, Hashable {
    /// The local version already contains everything the remote one says.
    case keepLocal
    /// The remote version contains everything the local one says; store it as it is. Only valid when the remote
    /// version is higher (versions only move forward).
    case adoptRemote
    /// Neither contains the other: store this new version, written by this device at a version above both.
    case replace(StoredRecord)
}

/// Field-level merging needs the plaintext, so it needs keys: the merger is the half of merging that lives with them
/// (docs/02-architecture.md §7.5, PRD F7.4, F7.6). The engine calls `merge` only when both versions exist and differ,
/// and `resolveErasure` whenever a version of an erased record is in question; it handles absence and versions itself.
///
/// Implementation: `ItemRecordMerger`, which opens both items, calls `ItemMerge.merge`, and seals the result through
/// an `ItemSealer` — `VaultSession`'s sync adapter in production, `FakeSyncKeyring` in tests.
///
/// A merger that cannot open the remote version (it does not decrypt, or decodes to another item) throws; the engine
/// then rejects the object carrying it, keeps the local version, and the stream waits — nothing is applied in part and
/// the object stays on the transport. One that cannot open the local version must not throw for that reason alone: it
/// adopts the remote version (re-sealing it above the local version if need be), so a damaged row is repaired rather
/// than pinned. When no key is resident it throws `SyncKeyringError.locked`, which defers the merge.
public protocol RecordMerger: Sendable {
    func merge(local: StoredRecord, remote: StoredRecord) async throws -> MergeDecision

    /// What this device has seen of a record it is about to publish the erasure of: carried in the tombstone, so the
    /// erasure removes only that (PRD F7.6). Opaque to the engine; at most `SyncPayload.maximumErasureLength` bytes.
    func erasureSummary(of record: StoredRecord) async throws -> [UInt8]

    /// A version of an erased record — the local one when an erasure arrives, or one arriving after the erasure is
    /// known. If its author had seen everything in it, it is erased; otherwise it holds an edit the erasure's author
    /// never saw, and is kept, in the trash, with that edit as its latest version (PRD F7.6).
    func resolveErasure(_ summary: [UInt8], of record: StoredRecord) async throws -> ErasureDecision
}

/// What to do with a version of a record that has been erased.
public enum ErasureDecision: Sendable, Hashable {
    /// Its author had seen all of it: erase it, or do not store it.
    case erase
    /// It holds something the erasure's author never saw, and is already in the trash: keep it as it is.
    case keep
    /// It holds something the erasure's author never saw: keep this trashed version of it instead, written by this
    /// device at a version above the given one.
    case replace(StoredRecord)
}
