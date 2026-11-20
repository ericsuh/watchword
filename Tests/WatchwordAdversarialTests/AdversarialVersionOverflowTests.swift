import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

/// Version columns the file controls (review finding Z23). A row's version is stored as the bit pattern of a
/// `UInt64`, so the local database can hold `UInt64.max`, and rows that no authenticated data binds (the account
/// header's row, a vault's directory row, any row whose envelope was damaged) can be put there by A8, who edits the
/// file while the app is locked. Each place that writes "one above the row it read" must answer with a typed error or
/// leave the row alone; a trap is a crash at every sync or at every attempt to change the password.
extension AdversarialAccountTests {
    static func memoryStore(_ vault: TestVault) throws -> InMemoryRecordStore {
        try #require(vault.store as? InMemoryRecordStore)
    }

    /// Threat: A8 sets the published account header's row to the last version there is. Changing the password
    /// writes the new header one above it.
    @Test("an account header row at the last version refuses a password change with a typed error")
    func headerRowAtTheLastVersion() async throws {
        let vault = TestVault.syncing(over: InMemorySyncTransport())
        let kit = try await vault.createAccount()
        try await vault.session.sync()
        let store = try Self.memoryStore(vault)
        var header = try #require(await store.record(VaultSession.headerKey(kit.accountID)))
        header.version = .max
        await store.tamper(header)
        await #expect(throws: VaultError.versionOverflow) {
            try await vault.session.changePassword(current: TestVault.password, new: Self.newPassword)
        }
        // Nothing changed: the old password still opens the vault.
        await vault.session.lock()
        try await vault.session.unlock(password: TestVault.password)
    }

    /// Threat: A8 sets a vault's directory row to the last version. Deleting the vault writes its signed deletion one
    /// above that row.
    @Test("a vault directory row at the last version refuses the vault's deletion with a typed error")
    func directoryRowAtTheLastVersion() async throws {
        let vault = TestVault.syncing(over: InMemorySyncTransport())
        let kit = try await vault.createAccount()
        let work = try await vault.session.createVault(name: "Work")
        let store = try Self.memoryStore(vault)
        var row = try #require(await store.record(RecordKey(recordID: work.id, kind: .vaultDirectory)))
        row.version = .max
        await store.tamper(row)
        await #expect(throws: VaultError.versionOverflow) {
            try await vault.session.deleteVault(id: work.id, confirmingItemCount: 0)
        }
        #expect(try await vault.session.vaults().map(\.name).contains("Work"))
        _ = kit
    }

    /// Threat: the same row, on a device that then fetches another device's signed deletion of the vault, which it
    /// stores one above the row. The row cannot be replaced; it is left as it is and the rest of the sync goes on.
    @Test("a vault deletion fetched over a directory row at the last version does not trap the sync")
    func fetchedDeletionOverTheLastVersion() async throws {
        let transport = InMemorySyncTransport()
        let a = TestVault.syncing(over: transport)
        try await a.createAccount()
        let b = try await a.enrolledDevice(deviceID: Self.deviceB, over: transport)
        try await b.session.unlock(password: TestVault.password)
        let work = try await b.session.createVault(name: "Work")
        try await b.session.sync()
        try await a.session.sync()
        #expect(try await a.session.vaults().map(\.name).contains("Work"))
        try await b.session.deleteVault(id: work.id, confirmingItemCount: 0)
        try await b.session.sync()

        let store = try Self.memoryStore(a)
        var row = try #require(await store.record(RecordKey(recordID: work.id, kind: .vaultDirectory)))
        row.version = .max
        await store.tamper(row)
        let report = try await a.session.syncAll()
        #expect(!report.transportUnavailable)
        #expect(await store.record(row.key) == row)
    }
}

extension AdversarialVaultSyncTests {
    /// Threat: A8 replaces a vault's description row with garbage at the last version and deletes the vault's sync
    /// state, so that the next sync replays the log. The description's merger finds a local row that does not open
    /// and stores the remote one "above" it (Z23). It must refuse with a typed error: the object is reported, and
    /// the sync, and every sync after it, completes.
    @Test("a description row at the last version does not trap the merge")
    func metadataRowAtTheLastVersion() async throws {
        let f = try await Self.fixture()
        let work = try await f.b.session.createVault(name: "Work")
        try await f.b.session.sync()
        try await f.a.session.sync()
        let store = try #require(f.a.store as? InMemoryRecordStore)
        var row = try #require(await store.record(RecordKey(recordID: work.id, kind: .vaultMetadata)))
        row.version = .max
        row.envelope = [1, 2, 3]
        await store.tamper(row)
        try await #require(f.a.sync?.state).eraseAll()

        for _ in 0..<2 {
            let report = try await f.a.session.syncAll()
            #expect(report.vaults[work.id]?.rejected.map(\.reason) == [.mergeFailed(work.id)])
            #expect(report.vaults[f.vaultID]?.rejected.isEmpty == true, "the other vault syncs as before")
        }
        #expect(await store.record(row.key) == row)
    }
}
