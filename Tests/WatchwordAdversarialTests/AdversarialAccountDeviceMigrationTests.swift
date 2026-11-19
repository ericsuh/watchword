import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of round 10 (docs/06-adversarial-review.md Z181, Z184): moving a restored installation's sync state from
// its old device ID to its new one. In the suite "account enrolment and device registry".
extension AdversarialAccountTests {
    /// A's store and sync state, a deletion made and never published, restored onto other hardware (no device key)
    /// over `state`: the restored device, not yet unlocked, and the deleted item's ID.
    static func restoredWithUnpublishedDeletion(_ fixture: Fixture, state: InterceptingStateStore) async throws
        -> (restored: TestVault, other: TestVault, doomed: UUID)
    {
        let other = try await fixture.enrolled(Self.deviceC)
        let doomed = try await fixture.a.session.save(
            Item(vaultID: fixture.personal, title: "Deleted on A, never synced", scopes: [], fields: []))
        try await fixture.a.session.sync()
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed.id)) != nil)
        try await fixture.a.session.trash(id: doomed.id)
        try await fixture.a.session.deletePermanently(id: doomed.id)

        let original = try #require(fixture.a.store as? InMemoryRecordStore)
        let store = InMemoryRecordStore()
        try await store.commit(
            StoreChange(
                account: .create(try #require(await original.loadAccount())), upserts: await original.allRecords))
        let raw = try #require(fixture.a.sync?.state)
        if let saved = try await raw.loadState(vaultID: fixture.personal) { await state.saveState(saved) }
        for deletion in try await raw.pendingDeletions(vaultID: fixture.personal).values {
            try await state.addPendingDeletion(deletion)
        }
        let restored = TestVault(
            store: store, sync: SyncSettings(state: state, transport: fixture.transport), seed: 181,
            deviceName: "Restored phone", deviceKeys: FakeDeviceKeyStore(seed: 181))
        return (restored, other, doomed.id)
    }

    /// Threat: none needed but a sync state file that fails one write (a full or damaged database) while a store
    /// restored onto other hardware registers its new device ID; the review of round 10 (Z181, F7.7). The old ID's
    /// pending deletions were recorded again as the new ID's after the commit that named it, under `try?`: one failed
    /// write left them stamped by the old ID, which this installation never publishes again, so the deletion the person
    /// made before the backup never reached the account's other devices. The move is recorded with the new account
    /// record and made again at each unlock until it is complete, and the deletion goes out.
    @Test("a restore's move of its old device ID's deletions that fails once is made again, and the deletion goes out")
    func interruptedDeviceMigration() async throws {
        let fixture = try await Self.fixture(seed: 18_100)
        let state = InterceptingStateStore()
        let (restored, other, doomed) = try await Self.restoredWithUnpublishedDeletion(fixture, state: state)
        await state.failNextPendingDeletionWrite()
        try await restored.session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        let account = try #require(await restored.store.loadAccount())
        let oldID = try #require(await fixture.a.store.loadAccount()).deviceID
        #expect(account.deviceID != oldID)
        #expect(account.migration != nil, "the interrupted move was not recorded")

        await restored.session.lock()
        try await restored.session.unlock(password: TestVault.password)
        #expect(try await restored.store.loadAccount()?.migration == nil, "the next unlock did not finish the move")
        try await restored.session.sync()
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed)) == nil, "the deletion never went out")
    }

    /// Threat: none needed; the review of round 10 (Z181). While the move is incomplete the restored device
    /// publishes nothing, since completing it starts each vault's state over, and a sync tries the move again: here
    /// the write fails at the unlock and again at the first sync, and the second sync finishes it.
    @Test("a device whose move is incomplete publishes nothing until a sync completes it")
    func incompleteMigrationPublishesNothing() async throws {
        let fixture = try await Self.fixture(seed: 18_110)
        let state = InterceptingStateStore()
        let (restored, other, doomed) = try await Self.restoredWithUnpublishedDeletion(fixture, state: state)
        await state.failNextPendingDeletionWrite()
        try await restored.session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        let fresh = try await restored.session.save(
            Item(vaultID: fixture.personal, title: "Written while the move waits", scopes: [], fields: []))
        await state.failNextPendingDeletionWrite()
        let blocked = try await restored.session.syncAll()
        #expect(blocked.deviceMigrationIncomplete)
        #expect(blocked.combined.segmentsWritten == 0)
        try await other.session.sync()
        #expect((try? await other.session.item(id: fresh.id)) == nil, "published while the move was incomplete")

        let done = try await restored.session.syncAll()
        #expect(!done.deviceMigrationIncomplete)
        try await restored.session.sync()
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed)) == nil, "the deletion never went out")
        #expect((try? await other.session.item(id: fresh.id)) != nil, "the edit never went out")
    }

    /// Threat: someone with the device's files (A8) who plants a move record in the database, naming another device
    /// of the account whose genuine pending deletions they copied into this device's state file. A move this session
    /// did not sign moves nothing, and is cleared (Z181).
    @Test("a move record the session did not sign moves nothing")
    func plantedMigrationMovesNothing() async throws {
        let fixture = try await Self.fixture(seed: 18_120)
        let state = InterceptingStateStore()
        let (restored, other, _) = try await Self.restoredWithUnpublishedDeletion(fixture, state: state)
        try await restored.session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        try await restored.session.sync()
        try await other.session.sync()
        await restored.session.lock()

        // The other device's genuine deletion, made and not yet published, copied out of its state file.
        let victim = try await other.session.save(
            Item(vaultID: fixture.personal, title: "Deleted on C", scopes: [], fields: []))
        try await other.session.trash(id: victim.id)
        try await other.session.deletePermanently(id: victim.id)
        let otherState = try #require(other.sync?.state)
        let pendingOnC = try await otherState.pendingDeletions(vaultID: fixture.personal)
        let copied = try #require(pendingOnC[RecordKey(recordID: victim.id, kind: .item)])
        await state.base.addPendingDeletion(copied)
        // The file edited between launches: a move naming the other device's ID.
        let store = try #require(restored.store as? InMemoryRecordStore)
        var account = try #require(await store.loadAccount())
        let otherID = Self.deviceC
        account.migration = DeviceMigration(previousDeviceID: otherID, authenticator: Array(repeating: 7, count: 64))
        try await store.commit(StoreChange(account: .update(account, expectedKeysetVersion: account.keysetVersion)))

        let relaunched = restored.relaunched(seed: 18_121)
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(try await store.loadAccount()?.migration == nil, "the planted move was kept")
        let pending = try await state.base.pendingDeletions(vaultID: fixture.personal)
        #expect(pending[copied.record.key]?.stamp.device == otherID, "another device's deletion was taken as its own")
    }

    /// Threat: none needed; the review of round 10 (Z184). The empty state a move saves for each vault was written to
    /// the raw store, unsigned, so it read back as no state (Z20): a second restore before the next sync then carried
    /// items over and no vault's description (`unpublishedRows`). It is signed now.
    @Test("the empty state a restore saves for each vault verifies and reads back as that state")
    func migratedStateIsSigned() async throws {
        let fixture = try await Self.fixture(seed: 18_130)
        let state = InterceptingStateStore()
        let (restored, _, _) = try await Self.restoredWithUnpublishedDeletion(fixture, state: state)
        try await restored.session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        let syncState = try #require(await restored.session.syncState)
        var loaded = try #require(try await syncState.loadState(vaultID: fixture.personal))
        loaded.authenticator = []
        // Empty, but for the installation's fact that it had synced before (V49), and that this state has not handed
        // on since the move (V52).
        var expected = SyncState(vaultID: fixture.personal)
        expected.syncedBefore = true
        expected.startedOverByMove = true
        #expect(loaded == expected)
    }
}
