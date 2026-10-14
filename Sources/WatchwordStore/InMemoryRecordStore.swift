import Foundation
import WatchwordEnvelope

/// A `RecordStore` that keeps everything in memory. Used by tests, SwiftUI previews and UI-test launches; it holds the
/// same ciphertext the SQLite store would, so nothing about it is less safe, only less durable.
public actor InMemoryRecordStore: RecordStore {
    private var account: AccountRecord?
    private var rows: [RecordKey: StoredRecord] = [:]

    public init() {}

    public func loadAccount() -> AccountRecord? {
        account
    }

    public func record(_ key: RecordKey) -> StoredRecord? {
        rows[key]
    }

    public func records(in vaultID: UUID, kind: EnvelopeKind) -> [StoredRecord] {
        rows.values.filter { $0.vaultID == vaultID && $0.kind == kind }.sorted {
            $0.recordID.uuidString < $1.recordID.uuidString
        }
    }

    public func commit(_ change: StoreChange) throws {
        try change.validate(currentAccount: account) { rows[$0]?.version }
        if let newAccount = change.newAccount {
            account = newAccount
        }
        for key in change.allDeletions {
            rows[key] = nil
        }
        for record in change.upserts {
            rows[record.key] = record
        }
    }

    public func eraseAll() {
        account = nil
        rows = [:]
    }

    // MARK: - Test seams

    /// Overwrites a row without any checks: what an attacker with write access to the database file can do.
    public func tamper(_ record: StoredRecord) {
        rows[record.key] = record
    }

    /// Overwrites the account header without any checks.
    public func tamper(account: AccountRecord) {
        self.account = account
    }

    public var allRecords: [StoredRecord] {
        Array(rows.values)
    }
}
