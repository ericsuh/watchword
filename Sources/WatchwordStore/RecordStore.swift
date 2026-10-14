import Foundation
import WatchwordEnvelope

public enum RecordStoreError: Error, Equatable, Sendable {
    /// `AccountWrite.create` on a store that already holds an account. Creating an account must never overwrite the
    /// wrapped keyset of an existing one: that would destroy the vault.
    case accountAlreadyExists
    /// `AccountWrite.update` on a store with no account, or whose keyset version is not the one the caller read.
    case accountVersionConflict
    /// A write that would lower or repeat a record's version. Versions only move forward (SEC2); the sync layer's
    /// monotonic check (milestone 3) builds on the same rule.
    case versionRegression(recordID: UUID, stored: UInt64, attempted: UInt64)
    /// A row whose columns cannot be what this code wrote (wrong UUID length, unknown kind). Reported, never repaired.
    case malformedRow(String)
    /// The database was written by a newer schema; this build refuses to touch it rather than misread it.
    case unsupportedSchemaVersion(Int)
}

/// How a commit changes the account header.
public enum AccountWrite: Sendable, Hashable {
    /// First write; fails with `accountAlreadyExists` if there is one.
    case create(AccountRecord)
    /// Replaces the header only if its keyset version is still `expectedKeysetVersion` (a password change racing
    /// another process must not silently lose).
    case update(AccountRecord, expectedKeysetVersion: UInt64)
}

/// One atomic change to the store.
public struct StoreChange: Sendable, Hashable {
    public var account: AccountWrite?
    public var upserts: [StoredRecord]
    public var deletions: [RecordKey]

    public init(account: AccountWrite? = nil, upserts: [StoredRecord] = [], deletions: [RecordKey] = []) {
        self.account = account
        self.upserts = upserts
        self.deletions = deletions
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
            break
        }
        for record in upserts {
            if let stored = try existingVersion(record.key), record.version <= stored {
                throw RecordStoreError.versionRegression(
                    recordID: record.recordID, stored: stored, attempted: record.version)
            }
        }
    }

    var newAccount: AccountRecord? {
        switch account {
        case .create(let record), .update(let record, _): return record
        case nil: return nil
        }
    }
}
