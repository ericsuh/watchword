import Foundation
import WatchwordEnvelope

/// An error of the local storage itself (a database that cannot be read or written, a row that cannot be what was
/// written), as opposed to one about what a record says. The sync engine stops a sync on one (`SyncEngine.isFatal`)
/// rather than refusing the object it was working on, which would stop that object's stream for a failure of the
/// disk. `RecordStoreError` is one, and so are the SQLite connection's failures, which the SQLite stores throw as
/// they come (review finding Z39).
public protocol StorageFailure: Error {}

extension RecordStoreError: StorageFailure {}

public enum RecordStoreError: Error, Equatable, Sendable {
    /// `AccountWrite.create` on a store that already holds an account. Creating an account must never overwrite the
    /// wrapped keyset of an existing one: that would destroy the vault.
    case accountAlreadyExists
    /// `AccountWrite.update` on a store with no account, or whose keyset version is not the one the caller read.
    case accountVersionConflict
    /// A write that would lower or repeat a record's version. Versions only move forward (SEC2); the sync layer's
    /// monotonic check (milestone 3) builds on the same rule.
    case versionRegression(recordID: UUID, stored: UInt64, attempted: UInt64)
    /// A conditional deletion found a different version (or no record) from the one the caller read: someone changed
    /// it in between, and deleting it now would silently undo that change.
    case versionConflict(recordID: UUID)
    /// A row whose columns cannot be what this code wrote (wrong UUID length, unknown kind). Reported, never repaired.
    case malformedRow(String)
    /// The database was written by a newer schema; this build refuses to touch it rather than misread it.
    case unsupportedSchemaVersion(Int)
    /// The database holds a table, index, trigger or view this code did not create, or a changed definition of one it
    /// did. Planted triggers can silently undo writes and deletions, so the store refuses to open.
    case unexpectedSchema(String)
    /// The write-ahead log could not be emptied (another process is reading it), so erased data may still be on disk.
    case checkpointIncomplete
}

/// How a commit changes the account header.
public enum AccountWrite: Sendable, Hashable {
    /// First write; fails with `accountAlreadyExists` if there is one.
    case create(AccountRecord)
    /// Replaces the header only if its keyset version is still `expectedKeysetVersion` (a password change racing
    /// another process must not silently lose).
    case update(AccountRecord, expectedKeysetVersion: UInt64)
}

/// How a commit changes the account record's `migration` (review of round 11, L1). The account row is written whole, so
/// a writer that read it before an `await` and writes it back for another reason (a password change) would otherwise
/// write the migration it read: bring back a move that was cleared meanwhile, which then ran again, or clear one recorded
/// meanwhile. By default the stored value is kept, whatever the record passed says; only the two writes that mean to
/// change it say so.
public enum MigrationWrite: Sendable, Hashable {
    /// The migration the store holds stays; for `AccountWrite.create`, where there is none, the record's own is written.
    case keep
    /// Written: the commit that names a new device ID records the move from the old one (Z181).
    case set(DeviceMigration)
    /// Removed: the move is complete, or was not this session's.
    case clear
}

/// What a writer read, and so what the store must still hold for its change to apply.
public enum RecordExpectation: Sendable, Hashable {
    /// No record under the key.
    case absent
    /// A record at exactly this version.
    case version(UInt64)
}

/// One atomic change to the store.
public struct StoreChange: Sendable, Hashable {
    public var account: AccountWrite?
    /// What becomes of the account record's `migration`: kept unless the change says otherwise (`MigrationWrite`).
    /// Anything but `.keep` needs an account in the store or written by this change.
    public var migration: MigrationWrite
    public var upserts: [StoredRecord]
    public var deletions: [RecordKey]
    /// Deletions that apply only if the record is still at the given version.
    public var conditionalDeletions: [RecordKey: UInt64]
    /// Preconditions on records, checked before anything is written; any mismatch fails the whole change with
    /// `versionConflict`. A writer that read a record before an `await` names what it read, so a change that landed in
    /// between (the person saving the same item while sync merges it) is not silently overwritten by a version that
    /// happens to be higher (docs/02-architecture.md §7.1).
    public var expectations: [RecordKey: RecordExpectation]

    public init(
        account: AccountWrite? = nil, migration: MigrationWrite = .keep, upserts: [StoredRecord] = [],
        deletions: [RecordKey] = [], conditionalDeletions: [RecordKey: UInt64] = [:],
        expectations: [RecordKey: RecordExpectation] = [:]
    ) {
        self.account = account
        self.migration = migration
        self.upserts = upserts
        self.deletions = deletions
        self.conditionalDeletions = conditionalDeletions
        self.expectations = expectations
    }

    /// Every key this change deletes.
    var allDeletions: [RecordKey] {
        deletions + conditionalDeletions.keys
    }
}

/// The local ciphertext store port (docs/02-architecture.md §6, §15). It sees envelopes and storage locations only;
/// nothing it holds is readable without the keys, which never pass through it.
///
/// Implementations: `InMemoryRecordStore` (tests, previews, UI-test launches) and `SQLiteRecordStore` (the App Group
/// database). Both run the same contract suite.
public protocol RecordStore: Sendable {
    func loadAccount() async throws -> AccountRecord?
    func record(_ key: RecordKey) async throws -> StoredRecord?
    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord]
    /// Applies `change` atomically: all of it or none of it.
    func commit(_ change: StoreChange) async throws
    /// Removes every account and record (PRD F10.3).
    func eraseAll() async throws
}

extension StoreChange {
    /// Checks shared by every implementation, run against the current state before anything is written.
    func validate(
        currentAccount: AccountRecord?,
        existingVersion: (RecordKey) throws -> UInt64?
    ) throws {
        switch account {
        case .create:
            if currentAccount != nil { throw RecordStoreError.accountAlreadyExists }
        case .update(_, let expected):
            guard let currentAccount, currentAccount.keysetVersion == expected else {
                throw RecordStoreError.accountVersionConflict
            }
        case nil:
            if migration != .keep, currentAccount == nil { throw RecordStoreError.accountVersionConflict }
        }
        for (key, expected) in conditionalDeletions where try existingVersion(key) != expected {
            throw RecordStoreError.versionConflict(recordID: key.recordID)
        }
        for (key, expectation) in expectations {
            let found = try existingVersion(key)
            switch expectation {
            case .absent where found != nil, .version where found == nil:
                throw RecordStoreError.versionConflict(recordID: key.recordID)
            case .version(let expected) where found != expected:
                throw RecordStoreError.versionConflict(recordID: key.recordID)
            default:
                break
            }
        }
        for record in upserts {
            if let stored = try existingVersion(record.key), record.version <= stored {
                throw RecordStoreError.versionRegression(
                    recordID: record.recordID, stored: stored, attempted: record.version)
            }
        }
    }

    /// The account record to store once `validate` has passed, `currentAccount` being what the store holds: the one
    /// this change writes, or the current one where only its migration changes, with the migration `migration` says;
    /// `nil` where the account row is left as it is.
    func accountToStore(currentAccount: AccountRecord?) -> AccountRecord? {
        var record: AccountRecord
        switch account {
        case .create(let written): record = written
        case .update(let written, _):
            record = written
            record.migration = currentAccount?.migration
        case nil:
            guard migration != .keep, let currentAccount else { return nil }
            record = currentAccount
        }
        switch migration {
        case .keep: break
        case .set(let written): record.migration = written
        case .clear: record.migration = nil
        }
        return record
    }

}
