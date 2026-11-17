import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// A record store that, once armed, locks the session the moment a commit holding deletions has landed: an
/// auto-lock, or the app going to the background, in the middle of a deletion.
actor LockingStore: RecordStore {
    let base = InMemoryRecordStore()
    private var session: VaultSession?
    private var armed = false
    private(set) var locks = 0

    func arm(_ session: VaultSession) {
        self.session = session
        armed = true
    }

    func loadAccount() async throws -> AccountRecord? { await base.loadAccount() }
    func record(_ key: RecordKey) async throws -> StoredRecord? { await base.record(key) }
    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        await base.records(in: vaultID, kind: kind)
    }

    func commit(_ change: StoreChange) async throws {
        try await base.commit(change)
        if armed, !change.conditionalDeletions.isEmpty || !change.deletions.isEmpty, let session {
            armed = false
            locks += 1
            await session.lock()
        }
    }

    func eraseAll() async throws { await base.eraseAll() }
}

/// Review finding Z28: a deletion's tombstones are signed before the deletion is committed, so a lock that lands
/// after the commit cannot leave rows deleted here with nothing to tell the other devices.
@Suite("Vault session: a lock during a deletion")
struct DeletionLockRaceTests {
    @Test("a vault deleted as the session locks is deleted on every device, items and all")
    func lockAfterTheCommit() async throws {
        let transport = InMemorySyncTransport()
        let store = LockingStore()
        let a = TestVault(
            store: store, sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport))
        try await a.createAccount()
        let b = try await a.enrolledDevice(deviceID: SyncPair.deviceB, over: transport)
        try await b.session.unlock(password: TestVault.password)
        let work = try await a.session.createVault(name: "Work")
        var ids: [UUID] = []
        for index in 0..<12 {
            ids.append(
                try await a.session.save(Item(vaultID: work.id, title: "Item \(index)", scopes: [], fields: [])).id)
        }
        try await a.session.sync()
        try await b.session.sync()
        #expect(try await b.session.items(in: work.id).items.count == 12)

        await store.arm(a.session)
        // The call may report the lock; what matters is what it left behind.
        try? await a.session.deleteVault(id: work.id, confirmingItemCount: 12)
        #expect(await store.locks == 1)
        #expect(try await a.session.state() == .locked)
        #expect(await store.base.records(in: work.id, kind: .item).isEmpty, "the deletion was committed")

        try await a.session.unlock(password: TestVault.password)
        let signed = try #require(await a.session.syncState)
        let pending = try await signed.pendingDeletions(vaultID: work.id)
        #expect(Set(pending.keys.map(\.recordID)).isSuperset(of: ids), "every deleted item has its signed tombstone")
        try await a.session.sync()
        try await b.session.sync()
        #expect(try await b.session.vaults(includingDeleted: true).first { $0.id == work.id }?.isDeleted == true)
        #expect(try await b.session.items(in: work.id).items.isEmpty, "items the person deleted stayed on B")
    }

    @Test("a lock before the commit deletes nothing and records nothing")
    func lockBeforeTheCommit() async throws {
        let pair = try await SyncPair.make()
        let item = try await pair.a.session.save(Item(vaultID: pair.vaultID, title: "Kept", scopes: [], fields: []))
        try await pair.a.session.trash(id: item.id)
        let account = try #require(await pair.a.session.account)
        let writer = await pair.a.session.writer(for: account)
        let row = try #require(try await pair.a.store.record(RecordKey(recordID: item.id, kind: .item)))
        await pair.a.session.lock()
        await #expect(throws: SyncKeyringError.locked) {
            try await writer.commit(StoreChange(conditionalDeletions: [row.key: row.version]))
        }
        #expect(try await pair.a.store.record(row.key) == row, "no deletion without its tombstone")
        let base = try #require(pair.a.sync?.state)
        #expect(try await base.pendingDeletions(vaultID: pair.vaultID).isEmpty)
    }
}
