import Foundation
import Testing
import WatchwordEnvelope

@testable import WatchwordStore

/// One contract, two implementations: everything the vault relies on from a store holds for the in-memory store and for
/// the SQLite database alike (docs/02-architecture.md §6).
enum StoreKind: String, CaseIterable, CustomTestStringConvertible, Sendable {
    case inMemory
    case sqlite

    var testDescription: String { rawValue }

    func make() throws -> any RecordStore {
        switch self {
        case .inMemory:
            return InMemoryRecordStore()
        case .sqlite:
            #if canImport(SQLite3)
                return try SQLiteRecordStore(url: StoreFixtures.temporaryDatabaseURL())
            #else
                return InMemoryRecordStore()
            #endif
        }
    }
}

enum StoreFixtures {
    static let vaultA = UUID(uuidString: "0A0A0A0A-0000-4000-8000-00000000000A")!
    static let vaultB = UUID(uuidString: "0B0B0B0B-0000-4000-8000-00000000000B")!
    static let device = UUID(uuidString: "D0D0D0D0-0000-4000-8000-0000000000D0")!

    static func temporaryDatabaseURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("watchword-store-tests-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("Watchword.sqlite")
    }

    #if canImport(SQLite3)
        /// A fresh path with no symlink in it, for opening a raw `SQLiteConnection` (which uses `SQLITE_OPEN_NOFOLLOW`).
        static func physicalTemporaryPath() throws -> String {
            let url = temporaryDatabaseURL()
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            return try SQLiteRecordStore.resolvingSymlinks(url.path)
        }
    #endif

    static func account(keysetVersion: UInt64 = 0, confirmed: Date? = nil) -> AccountRecord {
        AccountRecord(
            accountID: UUID(uuidString: "ACC00000-0000-4000-8000-000000000001")!,
            deviceID: device,
            personalVaultID: vaultA,
            personalVaultKeyID: UUID(uuidString: "4E400000-0000-4000-8000-000000000001")!,
            kdf: .baseline,
            salt: Array(repeating: 0x5A, count: 32),
            unlockKeyID: UUID(uuidString: "A0C00000-0000-4000-8000-000000000001")!,
            wrappedKeyset: Array(0..<120),
            keysetVersion: keysetVersion,
            credentialGeneration: 3,
            createdAt: Date(timeIntervalSince1970: 1_800_000_000.5),
            emergencyKitConfirmedAt: confirmed
        )
    }

    static func record(
        _ id: UUID = UUID(), vault: UUID = vaultA, kind: EnvelopeKind = .item, version: UInt64 = 1,
        envelope: [UInt8] = [1, 2, 3]
    ) -> StoredRecord {
        StoredRecord(
            recordID: id, kind: kind, vaultID: vault, keyID: UUID(), version: version, deviceID: device,
            envelope: envelope)
    }
}

@Suite("Record store contract")
struct RecordStoreContractTests {
    @Test("a new store has no account and no records", arguments: StoreKind.allCases)
    func empty(_ kind: StoreKind) async throws {
        let store = try kind.make()
        #expect(try await store.loadAccount() == nil)
        #expect(try await store.records(in: StoreFixtures.vaultA, kind: .item).isEmpty)
    }

    @Test("the account header round-trips exactly", arguments: StoreKind.allCases)
    func accountRoundTrip(_ kind: StoreKind) async throws {
        let store = try kind.make()
        let account = StoreFixtures.account(confirmed: Date(timeIntervalSince1970: 1_800_000_100))
        try await store.commit(StoreChange(account: .create(account)))
        #expect(try await store.loadAccount() == account)
    }

    @Test("creating an account never overwrites an existing one", arguments: StoreKind.allCases)
    func createIsExclusive(_ kind: StoreKind) async throws {
        let store = try kind.make()
        try await store.commit(StoreChange(account: .create(StoreFixtures.account())))
        var other = StoreFixtures.account()
        other.wrappedKeyset = [9, 9, 9]
        await #expect(throws: RecordStoreError.accountAlreadyExists) {
            try await store.commit(StoreChange(account: .create(other)))
        }
        #expect(try await store.loadAccount() == StoreFixtures.account())
    }

    @Test("an account update must name the keyset version it read", arguments: StoreKind.allCases)
    func updateIsConditional(_ kind: StoreKind) async throws {
        let store = try kind.make()
        try await store.commit(StoreChange(account: .create(StoreFixtures.account())))
        let next = StoreFixtures.account(keysetVersion: 1)
        await #expect(throws: RecordStoreError.accountVersionConflict) {
            try await store.commit(StoreChange(account: .update(next, expectedKeysetVersion: 7)))
        }
        try await store.commit(StoreChange(account: .update(next, expectedKeysetVersion: 0)))
        #expect(try await store.loadAccount()?.keysetVersion == 1)
    }

    @Test("updating a missing account is a conflict", arguments: StoreKind.allCases)
    func updateWithoutAccount(_ kind: StoreKind) async throws {
        let store = try kind.make()
        await #expect(throws: RecordStoreError.accountVersionConflict) {
            try await store.commit(StoreChange(account: .update(StoreFixtures.account(), expectedKeysetVersion: 0)))
        }
    }

    @Test("records round-trip and are listed by vault and kind only", arguments: StoreKind.allCases)
    func recordsByVaultAndKind(_ kind: StoreKind) async throws {
        let store = try kind.make()
        let item = StoreFixtures.record(envelope: Array(repeating: 0xEE, count: 70_000))
        let otherVault = StoreFixtures.record(vault: StoreFixtures.vaultB)
        let wrap = StoreFixtures.record(kind: .vaultKeyWrap)
        let empty = StoreFixtures.record(envelope: [])
        try await store.commit(StoreChange(upserts: [item, otherVault, wrap, empty]))
        #expect(try await store.record(item.key) == item)
        #expect(try await store.record(empty.key) == empty)
        let items = try await store.records(in: StoreFixtures.vaultA, kind: .item)
        #expect(Set(items) == [item, empty])
        #expect(try await store.records(in: StoreFixtures.vaultA, kind: .vaultKeyWrap) == [wrap])
        #expect(try await store.records(in: StoreFixtures.vaultB, kind: .item) == [otherVault])
    }

    @Test("the same record ID under two kinds is two records", arguments: StoreKind.allCases)
    func kindIsPartOfIdentity(_ kind: StoreKind) async throws {
        let store = try kind.make()
        let id = UUID()
        let item = StoreFixtures.record(id, kind: .item, envelope: [1])
        let wrap = StoreFixtures.record(id, kind: .vaultKeyWrap, envelope: [2])
        try await store.commit(StoreChange(upserts: [item, wrap]))
        #expect(try await store.record(item.key) == item)
        #expect(try await store.record(wrap.key) == wrap)
    }

    @Test("versions only move forward", arguments: StoreKind.allCases)
    func versionsAreMonotonic(_ kind: StoreKind) async throws {
        let store = try kind.make()
        let id = UUID()
        try await store.commit(StoreChange(upserts: [StoreFixtures.record(id, version: 5)]))
        for stale: UInt64 in [5, 4, 0] {
            await #expect(throws: RecordStoreError.versionRegression(recordID: id, stored: 5, attempted: stale)) {
                try await store.commit(StoreChange(upserts: [StoreFixtures.record(id, version: stale)]))
            }
        }
        try await store.commit(StoreChange(upserts: [StoreFixtures.record(id, version: 6)]))
        #expect(try await store.record(RecordKey(recordID: id, kind: .item))?.version == 6)
    }

    @Test("large versions survive the Int64 column", arguments: StoreKind.allCases)
    func largeVersions(_ kind: StoreKind) async throws {
        let store = try kind.make()
        let record = StoreFixtures.record(version: UInt64.max - 1)
        try await store.commit(StoreChange(upserts: [record]))
        #expect(try await store.record(record.key)?.version == UInt64.max - 1)
    }

    @Test("a failing commit writes nothing", arguments: StoreKind.allCases)
    func commitIsAtomic(_ kind: StoreKind) async throws {
        let store = try kind.make()
        let existing = StoreFixtures.record(version: 5)
        try await store.commit(StoreChange(upserts: [existing]))
        let fresh = StoreFixtures.record()
        await #expect(throws: RecordStoreError.self) {
            try await store.commit(
                StoreChange(
                    account: .create(StoreFixtures.account()),
                    upserts: [fresh, StoreFixtures.record(existing.recordID, version: 1)],
                    deletions: [existing.key]))
        }
        #expect(try await store.loadAccount() == nil)
        #expect(try await store.record(fresh.key) == nil)
        #expect(try await store.record(existing.key) == existing)
    }

    @Test("deletions remove only the named record", arguments: StoreKind.allCases)
    func deletion(_ kind: StoreKind) async throws {
        let store = try kind.make()
        let keep = StoreFixtures.record()
        let drop = StoreFixtures.record()
        try await store.commit(StoreChange(upserts: [keep, drop]))
        try await store.commit(StoreChange(deletions: [drop.key]))
        #expect(try await store.record(drop.key) == nil)
        #expect(try await store.record(keep.key) == keep)
    }

    /// The sync engine reads a record, awaits the merger, then writes; the session may have saved the same record in
    /// between. Expectations make that write fail instead of overwriting the newer save (docs/02-architecture.md §7.1).
    @Test("expectations make a change conditional on what the writer read", arguments: StoreKind.allCases)
    func expectations(_ kind: StoreKind) async throws {
        let store = try kind.make()
        let id = UUID()
        let key = RecordKey(recordID: id, kind: .item)
        try await store.commit(
            StoreChange(upserts: [StoreFixtures.record(id, version: 1)], expectations: [key: .absent]))
        await #expect(throws: RecordStoreError.versionConflict(recordID: id)) {
            try await store.commit(
                StoreChange(upserts: [StoreFixtures.record(id, version: 9)], expectations: [key: .absent]))
        }
        await #expect(throws: RecordStoreError.versionConflict(recordID: id)) {
            try await store.commit(
                StoreChange(upserts: [StoreFixtures.record(id, version: 9)], expectations: [key: .version(2)]))
        }
        let other = UUID()
        await #expect(throws: RecordStoreError.versionConflict(recordID: other)) {
            try await store.commit(
                StoreChange(expectations: [RecordKey(recordID: other, kind: .item): .version(1)]))
        }
        #expect(try await store.record(key)?.version == 1)
        try await store.commit(
            StoreChange(upserts: [StoreFixtures.record(id, version: 2)], expectations: [key: .version(1)]))
        #expect(try await store.record(key)?.version == 2)
    }

    @Test("eraseAll removes the account and every record", arguments: StoreKind.allCases)
    func eraseAll(_ kind: StoreKind) async throws {
        let store = try kind.make()
        try await store.commit(
            StoreChange(account: .create(StoreFixtures.account()), upserts: [StoreFixtures.record()]))
        try await store.eraseAll()
        #expect(try await store.loadAccount() == nil)
        #expect(try await store.records(in: StoreFixtures.vaultA, kind: .item).isEmpty)
    }
}
