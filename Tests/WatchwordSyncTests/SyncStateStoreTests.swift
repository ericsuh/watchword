import Foundation
import Testing
import WatchwordEnvelope
import WatchwordStore

@testable import WatchwordSync

#if canImport(SQLite3)
    import SecureMemory
#endif

enum StateStoreKind: String, CaseIterable, CustomTestStringConvertible, Sendable {
    case inMemory
    case sqlite

    var testDescription: String { rawValue }

    static var available: [StateStoreKind] {
        #if canImport(SQLite3)
            return allCases
        #else
            return [.inMemory]
        #endif
    }

    func make() throws -> any SyncStateStore {
        switch self {
        case .inMemory: return InMemorySyncStateStore()
        case .sqlite:
            #if canImport(SQLite3)
                return try SQLiteSyncStateStore(url: StateStoreFixtures.temporaryURL())
            #else
                throw CocoaError(.featureUnsupported)
            #endif
        }
    }
}

enum StateStoreFixtures {
    static func temporaryURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("watchword-sync-state-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("sync.sqlite")
    }

    static func record(_ n: UInt8, version: UInt64 = 3) -> StoredRecord {
        StoredRecord(
            recordID: UUID(uuid: (n, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, n)), kind: .item,
            vaultID: SyncFixtures.vault, keyID: UUID(uuid: (0xEE, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1)),
            version: version, deviceID: SyncFixtures.deviceA, envelope: Array(repeating: n, count: 40))
    }

    /// A state with something in every field.
    static func state() -> SyncState {
        var state = SyncState(vaultID: SyncFixtures.vault)
        state.nextSequence = 9
        state.lastPublishedSequence = 8
        state.merged = [SyncFixtures.deviceA: 8, SyncFixtures.deviceB: 3]
        let key = record(1).key
        state.known = [
            key: RecordStamp(version: 4, device: SyncFixtures.deviceB),
            record(2).key: RecordStamp(version: 7, device: SyncFixtures.deviceA, deleted: true),
        ]
        state.erasures = [
            record(2).key: Erasure(
                stamp: RecordStamp(version: 7, device: SyncFixtures.deviceA, deleted: true), summary: [1, 2, 3])
        ]
        state.published = [key: RecordStamp(version: 3, device: SyncFixtures.deviceA)]
        state.acknowledgements = [SyncFixtures.deviceB: [SyncFixtures.deviceA: 6, SyncFixtures.deviceB: 3]]
        state.publishedAcknowledgement = [SyncFixtures.deviceB: 3]
        let snapshot = SyncObjectLocation.snapshot(
            vaultID: SyncFixtures.vault, author: SyncFixtures.deviceB, lamport: 12)
        state.snapshots = [snapshot: [SyncFixtures.deviceA: 5, SyncFixtures.deviceB: 2]]
        state.snapshotCoverage = [SyncFixtures.deviceA: 5, SyncFixtures.deviceB: 2]
        return state
    }
}

/// One contract, every `SyncStateStore` (docs/02-architecture.md §6): the in-memory one the simulations use, and the
/// SQLite one the app uses.
@Suite("Sync state store contract")
struct SyncStateStoreContractTests {
    @Test("state round-trips with every field, per vault", arguments: StateStoreKind.available)
    func stateRoundTrip(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        #expect(try await store.loadState(vaultID: SyncFixtures.vault) == nil)
        let state = StateStoreFixtures.state()
        try await store.saveState(state)
        #expect(try await store.loadState(vaultID: SyncFixtures.vault) == state)
        #expect(try await store.loadState(vaultID: SyncFixtures.otherVault) == nil)
        var next = state
        next.nextSequence = 10
        try await store.saveState(next)
        #expect(try await store.loadState(vaultID: SyncFixtures.vault) == next)
    }

    @Test("staged objects are kept by location and unstaged by location", arguments: StateStoreKind.available)
    func staging(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        let first = StagedObject(
            location: .segment(vaultID: SyncFixtures.vault, author: SyncFixtures.deviceB, sequence: 1),
            object: SignedObject(signature: [9, 9], envelope: [1, 2, 3]))
        let second = StagedObject(
            location: .snapshot(vaultID: SyncFixtures.vault, author: SyncFixtures.deviceB, lamport: 4),
            object: SignedObject(signature: [8], envelope: [4, 5]))
        try await store.stage(first)
        try await store.stage(second)
        try await store.stage(first)
        #expect(Set(try await store.staged(vaultID: SyncFixtures.vault)) == [first, second])
        #expect(try await store.staged(vaultID: SyncFixtures.otherVault).isEmpty)
        try await store.unstage([first.location])
        #expect(try await store.staged(vaultID: SyncFixtures.vault) == [second])
    }

    @Test(
        "a pending deletion is replaced only by a newer one, and removed only if unchanged",
        arguments: StateStoreKind.available)
    func pendingDeletions(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        let row = StateStoreFixtures.record(1)
        let older = PendingDeletion(
            stamp: RecordStamp(version: 4, device: SyncFixtures.deviceA, deleted: true), record: row)
        let newer = PendingDeletion(
            stamp: RecordStamp(version: 6, device: SyncFixtures.deviceA, deleted: true), record: row)
        try await store.addPendingDeletion(newer)
        try await store.addPendingDeletion(older)
        #expect(try await store.pendingDeletions(vaultID: SyncFixtures.vault) == [row.key: newer])
        try await store.removePendingDeletions([row.key: older.stamp], vaultID: SyncFixtures.vault)
        #expect(try await store.pendingDeletions(vaultID: SyncFixtures.vault) == [row.key: newer])
        try await store.removePendingDeletions([row.key: newer.stamp], vaultID: SyncFixtures.vault)
        #expect(try await store.pendingDeletions(vaultID: SyncFixtures.vault).isEmpty)
    }

    @Test("the quarantine keeps each entry once until it is discarded (F7.7)", arguments: StateStoreKind.available)
    func quarantine(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        let live = SyncFixtures.entry(1, version: 1 << 50)
        let tombstone = SyncEntry.tombstone(
            StateStoreFixtures.record(2).key, stamp: RecordStamp(version: 1 << 51, device: SyncFixtures.deviceB),
            erasure: [7, 7])
        try await store.quarantine(live, vaultID: SyncFixtures.vault)
        try await store.quarantine(tombstone, vaultID: SyncFixtures.vault)
        try await store.quarantine(live, vaultID: SyncFixtures.vault)
        #expect(try await store.quarantined(vaultID: SyncFixtures.vault) == [live, tombstone])
        try await store.discardQuarantined([tombstone], vaultID: SyncFixtures.vault)
        #expect(try await store.quarantined(vaultID: SyncFixtures.vault) == [live])
    }

    @Test("eraseAll removes everything", arguments: StateStoreKind.available)
    func erase(_ kind: StateStoreKind) async throws {
        let store = try kind.make()
        try await store.saveState(StateStoreFixtures.state())
        try await store.addPendingDeletion(
            PendingDeletion(
                stamp: RecordStamp(version: 4, device: SyncFixtures.deviceA, deleted: true),
                record: StateStoreFixtures.record(1)))
        try await store.quarantine(SyncFixtures.entry(1), vaultID: SyncFixtures.vault)
        try await store.eraseAll()
        #expect(try await store.loadState(vaultID: SyncFixtures.vault) == nil)
        #expect(try await store.pendingDeletions(vaultID: SyncFixtures.vault).isEmpty)
        #expect(try await store.quarantined(vaultID: SyncFixtures.vault).isEmpty)
    }
}

#if canImport(SQLite3)
    @Suite("SQLite sync state store")
    struct SQLiteSyncStateStoreTests {
        @Test("everything survives closing and reopening the database")
        func persistence() async throws {
            let url = StateStoreFixtures.temporaryURL()
            let deletion = PendingDeletion(
                stamp: RecordStamp(version: 4, device: SyncFixtures.deviceA, deleted: true),
                record: StateStoreFixtures.record(1))
            do {
                let store = try SQLiteSyncStateStore(url: url)
                try store.saveState(StateStoreFixtures.state())
                try store.addPendingDeletion(deletion)
                try store.quarantine(SyncFixtures.entry(3), vaultID: SyncFixtures.vault)
            }
            let reopened = try SQLiteSyncStateStore(url: url)
            #expect(try reopened.loadState(vaultID: SyncFixtures.vault) == StateStoreFixtures.state())
            #expect(try reopened.pendingDeletions(vaultID: SyncFixtures.vault) == [deletion.record.key: deletion])
            #expect(try reopened.quarantined(vaultID: SyncFixtures.vault) == [SyncFixtures.entry(3)])
        }

        @Test("a state row that does not decode is no state, so the next sync replays the log")
        func damagedStateIsAbsent() throws {
            let url = StateStoreFixtures.temporaryURL()
            let store = try SQLiteSyncStateStore(url: url)
            try store.saveState(StateStoreFixtures.state())
            let raw = try SQLiteConnection(path: SQLiteRecordStore.resolvingSymlinks(url.path))
            try raw.query("UPDATE sync_state SET state = ?", [.blob(Array("{not json".utf8))])
            #expect(try store.loadState(vaultID: SyncFixtures.vault) == nil)
        }

        @Test("a planted trigger makes the database refuse to open (review finding S1)")
        func plantedTrigger() throws {
            let url = StateStoreFixtures.temporaryURL()
            _ = try SQLiteSyncStateStore(url: url)
            let raw = try SQLiteConnection(path: SQLiteRecordStore.resolvingSymlinks(url.path))
            try raw.execute(
                "CREATE TRIGGER keep BEFORE DELETE ON pending_deletions BEGIN SELECT RAISE(IGNORE); END")
            raw.close()
            #expect(throws: RecordStoreError.unexpectedSchema("keep")) { _ = try SQLiteSyncStateStore(url: url) }
        }

        @Test("a database from a newer schema is refused, not misread")
        func newerSchema() throws {
            let url = StateStoreFixtures.temporaryURL()
            _ = try SQLiteSyncStateStore(url: url)
            try SQLiteConnection(path: SQLiteRecordStore.resolvingSymlinks(url.path)).execute("PRAGMA user_version = 2")
            #expect(throws: RecordStoreError.unsupportedSchemaVersion(2)) { _ = try SQLiteSyncStateStore(url: url) }
        }
    }
#endif
