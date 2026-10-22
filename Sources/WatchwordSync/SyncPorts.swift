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
/// Production (milestone 3's Mac half): `RecordCipher` under the vault key for sealing and opening, and the account's
/// Ed25519 key — plus, once the device registry (review finding D9) lands, the device's Secure Enclave key — for
/// signatures. Tests: `WatchwordTestSupport.FakeSyncKeyring`.
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
/// (docs/02-architecture.md §7.1, PRD F7.4). The engine calls it only when both versions exist and differ; it handles
/// absence, deletions and versions itself.
///
/// Production (Mac half): `VaultSession`, which opens both items under the vault key, calls `ItemMerge.merge`, and
/// seals the result. Tests: `WatchwordTestSupport.FakeItemMerger`, the same logic over the fake keyring.
///
/// A merger that cannot open the remote version (it does not decrypt, or decodes to another item) throws; the engine
/// then rejects that entry and keeps the local version. One that cannot open the local version must not throw for
/// that reason alone — it adopts the remote version, so a damaged local row is repaired rather than pinned.
public protocol RecordMerger: Sendable {
    func merge(local: StoredRecord, remote: StoredRecord) async throws -> MergeDecision
}
