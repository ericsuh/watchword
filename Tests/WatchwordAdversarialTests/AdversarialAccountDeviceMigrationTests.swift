import Foundation
import Testing
import WatchwordEnvelope
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
    static func restoredWithUnpublishedDeletion(
        _ fixture: Fixture, state: InterceptingStateStore, into store: any RecordStore = InMemoryRecordStore(),
        deviceKeys: FakeDeviceKeyStore = FakeDeviceKeyStore(seed: 181)
    ) async throws -> (restored: TestVault, other: TestVault, doomed: UUID) {
        let other = try await fixture.enrolled(Self.deviceC)
        let doomed = try await fixture.a.session.save(
            Item(vaultID: fixture.personal, title: "Deleted on A, never synced", scopes: [], fields: []))
        try await fixture.a.session.sync()
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed.id)) != nil)
        try await fixture.a.session.trash(id: doomed.id)
        try await fixture.a.session.deletePermanently(id: doomed.id)

        let original = try #require(fixture.a.store as? InMemoryRecordStore)
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
            deviceName: "Restored phone", deviceKeys: deviceKeys)
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
        let planted = DeviceMigration(previousDeviceID: otherID, authenticator: Array(repeating: 7, count: 64))
        account.migration = planted
        try await store.commit(
            StoreChange(
                account: .update(account, expectedKeysetVersion: account.keysetVersion), migration: .set(planted)))

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

    /// Threat: none needed but a sync state file that fails one write at a restore's unlock, and an app relaunched
    /// before the next; the review of round 11 (Z190). The unlock made the move again before it read which vaults are
    /// shared, and until it has read them every vault but the Personal one is held closed: the deletion of an item of a
    /// private vault found no key, and (now that such a deletion is parked rather than stopping the move, M1) would
    /// wait parked for the next sync. The markers are read first, and the deletion is carried as the new ID's.
    @Test("the move an unlock makes again reads which vaults are shared first, and carries a private vault's deletion")
    func unlockRetryReadsMarkersFirst() async throws {
        let fixture = try await Self.fixture(seed: 18_600)
        let other = try await fixture.enrolled(Self.deviceC)
        let vaultID = try await fixture.a.session.createVault(name: "Other").id
        let doomed = try await fixture.a.session.save(
            Item(vaultID: vaultID, title: "Deleted on A, never synced", scopes: [], fields: []))
        try await fixture.a.session.trash(id: doomed.id)
        try await fixture.a.session.sync()
        try await other.session.sync()
        try await fixture.a.session.deletePermanently(id: doomed.id)

        let original = try #require(fixture.a.store as? InMemoryRecordStore)
        let store = InMemoryRecordStore()
        try await store.commit(
            StoreChange(
                account: .create(try #require(await original.loadAccount())), upserts: await original.allRecords))
        let raw = try #require(fixture.a.sync?.state)
        let state = InterceptingStateStore()
        for vault in [fixture.personal, vaultID] {
            if let saved = try await raw.loadState(vaultID: vault) { await state.saveState(saved) }
            for deletion in try await raw.pendingDeletions(vaultID: vault).values {
                try await state.addPendingDeletion(deletion)
            }
        }
        let restored = TestVault(
            store: store, sync: SyncSettings(state: state, transport: fixture.transport), seed: 18_601,
            deviceName: "Restored phone", deviceKeys: FakeDeviceKeyStore(seed: 18_601))
        await state.failNextPendingDeletionWrite()
        try await restored.session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        #expect(try await store.loadAccount()?.migration != nil, "the interrupted move was not recorded")

        await restored.session.lock()
        let relaunched = restored.relaunched(seed: 18_602)
        try await relaunched.session.unlock(password: TestVault.password)
        let account = try #require(try await store.loadAccount())
        #expect(account.migration == nil, "the unlock did not finish the move")
        let pending = try await state.base.pendingDeletions(vaultID: vaultID)
        let carried = try #require(pending[RecordKey(recordID: doomed.id, kind: .item)])
        #expect(carried.stamp.device == account.deviceID, "parked for want of the markers, not carried")
        try await relaunched.session.sync()
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed.id)) == nil, "the deletion never went out")
    }

    /// Threat: none needed but a database that refuses one write (full, or busy past its timeout) while a restore
    /// registers its new device ID; the review of round 11 (Z189, Z182's residual). The new device's key is made before
    /// the label is sealed for its ID and the registry entry signed with it, and a failure after it and before the
    /// commit left the key in the Keychain under an ID nothing registered, one per failed attempt. It is deleted again.
    @Test("a restore's registration that fails before its commit leaves no device key behind")
    func failedRegistrationLeavesNoKey() async throws {
        let fixture = try await Self.fixture(seed: 18_700)
        let state = InterceptingStateStore()
        let store = HookedRecordStore()
        let keys = FakeDeviceKeyStore(seed: 18_701)
        let (restored, other, doomed) = try await Self.restoredWithUnpublishedDeletion(
            fixture, state: state, into: store, deviceKeys: keys)
        let oldID = try #require(try await store.loadAccount()?.deviceID)
        await store.failNextAccountCommit()
        try await restored.session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        #expect(try await store.loadAccount()?.deviceID == oldID, "registered although the commit failed")
        #expect(await keys.created == 1)
        #expect(await keys.isEmpty(), "the failed registration left its key behind")

        await restored.session.lock()
        try await restored.session.unlock(password: TestVault.password)
        let account = try #require(try await store.loadAccount())
        #expect(account.deviceID != oldID, "the next unlock did not register")
        #expect(await keys.created == 2)
        #expect(try await keys.publicKey(accountID: account.accountID, deviceID: account.deviceID) != nil)
        try await restored.session.sync()
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed)) == nil, "the deletion never went out")
    }

    /// Threat: none needed but a lock and an unlock while a restore's registration waits on its commit, which then
    /// fails; the review of round 12 (L1, Z189's residual). The unlock's reconciliation saw the old ID still in the
    /// account record and registered a second new device, its key replacing the first's in the Keychain; the first's
    /// failure then deleted whatever key the account held, the second's, and the account named a device whose key was
    /// gone (`deviceKeyUnreadable` until the next unlock registered a third, and left that one keyless in the registry).
    /// One registration runs at a time now, and a failed one deletes only the key it made.
    @Test("a restore's registration interrupted by an unlock leaves no registered device without its key")
    func registrationDuringRegistration() async throws {
        let fixture = try await Self.fixture(seed: 18_900)
        let state = InterceptingStateStore()
        let store = HookedRecordStore()
        let keys = FakeDeviceKeyStore(seed: 18_901)
        let (restored, other, doomed) = try await Self.restoredWithUnpublishedDeletion(
            fixture, state: state, into: store, deviceKeys: keys)
        let oldID = try #require(try await store.loadAccount()?.deviceID)
        let session = restored.session
        await store.onNextAccountCommit {
            await session.lock()
            try? await session.unlock(password: TestVault.password)
        }
        try? await session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        let account = try #require(try await store.loadAccount())
        let held = try await keys.publicKey(accountID: account.accountID, deviceID: account.deviceID)
        let keylessRegistration = account.deviceID != oldID && held == nil
        #expect(!keylessRegistration, "the account names a device whose key a failed registration deleted")
        #expect(await keys.created == 1, "a second registration ran while the first waited")

        await session.lock()
        try await session.unlock(password: TestVault.password)
        let registered = try #require(try await store.loadAccount())
        #expect(registered.deviceID != oldID)
        #expect(try await keys.publicKey(accountID: registered.accountID, deviceID: registered.deviceID) != nil)
        try await session.sync()
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed)) == nil, "the deletion never went out")
    }

    /// Threat: none needed but a lock and an unlock while a restore's unlock, having read the account record, waits on
    /// the Keychain for its device key; the review of round 13 (L-b). The second unlock registered the new device and
    /// finished before the first went on, which then registered again from the record it had read: still the old ID,
    /// no move recorded, no key. Its new key replaced the first's in the Keychain's one slot, and its commit, which
    /// named only the keyset version, replaced the registered device: the registry listed a device whose key was
    /// gone. A registration reads the account again under its flag now, and its commit names the device ID it
    /// replaces.
    @Test("a restore's registration that read the account before another finished does not register over it")
    func registrationFromAStaleAccount() async throws {
        let fixture = try await Self.fixture(seed: 19_300)
        let state = InterceptingStateStore()
        let keys = FakeDeviceKeyStore(seed: 19_301)
        let (restored, other, doomed) = try await Self.restoredWithUnpublishedDeletion(
            fixture, state: state, deviceKeys: keys)
        let oldID = try #require(try await restored.store.loadAccount()?.deviceID)
        let session = restored.session
        let secretKey = fixture.kit.secretKey
        await keys.onNextLookup(of: oldID) {
            await session.lock()
            try? await session.unlock(password: TestVault.password, secretKey: secretKey)
        }
        try? await session.unlock(password: TestVault.password, secretKey: secretKey)
        let account = try #require(try await restored.store.loadAccount())
        #expect(account.deviceID != oldID)
        #expect(await keys.created == 1, "a registration from a stale account made a second key")
        #expect(try await keys.publicKey(accountID: account.accountID, deviceID: account.deviceID) != nil)
        try await session.sync()
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed)) == nil, "the deletion never went out")
    }

    /// Threat: none needed; the review of round 13 (L-b). A restore whose registration does not happen at its unlock
    /// (one already under way, which then failed) waited for the next unlock: the sync never registered it, and the
    /// device published nothing. A sync now registers it, as an unlock would.
    @Test("a restore's registration that did not happen at its unlock happens at the next sync")
    func registrationAtTheNextSync() async throws {
        let fixture = try await Self.fixture(seed: 19_310)
        let state = InterceptingStateStore()
        let store = HookedRecordStore()
        let keys = FakeDeviceKeyStore(seed: 19_311)
        let (restored, other, doomed) = try await Self.restoredWithUnpublishedDeletion(
            fixture, state: state, into: store, deviceKeys: keys)
        let oldID = try #require(try await store.loadAccount()?.deviceID)
        await store.failNextAccountCommit()
        try? await restored.session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        #expect(try await store.loadAccount()?.deviceID == oldID, "the registration was not refused")

        try await restored.session.sync()
        let account = try #require(try await store.loadAccount())
        #expect(account.deviceID != oldID, "the sync did not register the restored device")
        #expect(try await keys.publicKey(accountID: account.accountID, deviceID: account.deviceID) != nil)
        try await restored.session.sync()
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed)) == nil, "the deletion never went out")
    }

    /// Threat: none needed; the review of round 11 (Z186). A password change reads the account record, derives and signs
    /// across several awaits, and commits the record it read. A move completed during those awaits cleared the record's
    /// migration, and the commit wrote it back: the move ran again after the device had published under its new ID
    /// (each vault's state started over, the log replayed, rows published again). The store now keeps the migration a
    /// commit does not name, and the session caches what the store kept.
    @Test("a password change across a completed move does not bring the move back")
    func passwordChangeKeepsACompletedMove() async throws {
        let fixture = try await Self.fixture(seed: 18_500)
        let state = InterceptingStateStore()
        let store = HookedRecordStore()
        let (restored, _, _) = try await Self.restoredWithUnpublishedDeletion(fixture, state: state, into: store)
        await state.failNextPendingDeletionWrite()
        try await restored.session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        #expect(try await store.loadAccount()?.migration != nil, "the interrupted move was not recorded")

        let session = restored.session
        await store.onNextHeaderListing {
            guard let account = try? await session.loadAccount() else { return }
            try? await session.completeDeviceMigration(account: account)
        }
        try await session.changePassword(current: TestVault.password, new: "a new password for the restored phone")
        #expect(await store.hookRan)
        #expect(try await store.loadAccount()?.migration == nil, "the password change wrote the cleared move back")
        #expect(await session.account?.migration == nil, "the session cached the cleared move")
        let report = try await session.syncAll()
        #expect(!report.deviceMigrationIncomplete)
    }

    /// Threat: none needed; the review of round 19 (Z237). A restore's move is made by the unlock, by each sync and by
    /// `configureSharing`, each from an account it read before an await. One made while another was under way, or
    /// after another had cleared the record, from an account read before that, started each vault's state over after
    /// the engine had published there (what the state recorded of this device's publishing lost, and the old ID's
    /// deletions carried again). Here a sync runs while the unlock's move waits on its first save: the sync's move
    /// returns, the record stays and the sync publishes nothing; and a move made afterwards from the account read
    /// while the record stood changes nothing.
    @Test("a restore's move is made once at a time, and never again from an account read before it finished")
    func moveIsMadeOnceAtATime() async throws {
        let fixture = try await Self.fixture(seed: 18_120)
        let state = InterceptingStateStore()
        let (restored, other, doomed) = try await Self.restoredWithUnpublishedDeletion(fixture, state: state)
        let observed = MoveObservation()
        let session = restored.session
        let store = restored.store
        await state.intercept { _ in
            guard await observed.claim(), let stale = try? await store.loadAccount(), stale.migration != nil else {
                return
            }
            await observed.record(stale: stale, during: try? await session.syncAll())
        }
        try await restored.session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        await state.intercept(afterSave: nil)
        let stale = try #require(await observed.stale, "no state was saved while the move was pending")
        let during = try #require(await observed.during, "the sync during the move did not run")
        #expect(during.deviceMigrationIncomplete, "a second move ran while the first was under way")
        #expect(during.combined.segmentsWritten == 0, "the sync published while a move was under way")
        #expect(try await restored.store.loadAccount()?.migration == nil, "the unlock's move did not finish")

        try await restored.session.sync()
        let published = try #require(await state.loadState(vaultID: fixture.personal))
        #expect(published.lastPublishedSequence > 0, "nothing was published: nothing is tested")
        try await restored.session.completeDeviceMigration(account: stale)
        #expect(await state.loadState(vaultID: fixture.personal) == published, "a stale move started the state over")
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed)) == nil, "the deletion never went out")
    }

    /// Threat: none needed; the review of round 20 (Z241, Z242). Since Z237 a caller of the move turned away while
    /// another was under way returned and was forgotten. Here the session is locked and unlocked again while the
    /// unlock's move waits on its first save: the new unlock's move is turned away, and the move under way then stops
    /// at the lock (`requireKeys(since:)`), so nobody made it until the next sync or unlock, and this device sent
    /// nothing meanwhile. The same holds for `configureSharing` while a move begun without sharing waits for it. The
    /// move under way is now made once more, under the new keys, for the caller it turned away.
    @Test("a restore's move turned away while another is under way is made when that one ends")
    func turnedAwayMoveIsMadeAfterwards() async throws {
        let fixture = try await Self.fixture(seed: 18_130)
        let state = InterceptingStateStore()
        let (restored, other, doomed) = try await Self.restoredWithUnpublishedDeletion(fixture, state: state)
        let observed = MoveObservation()
        let session = restored.session
        let store = restored.store
        await state.intercept { _ in
            guard await observed.claim(), let stale = try? await store.loadAccount(), stale.migration != nil else {
                return
            }
            await session.lock()
            try? await session.unlock(password: TestVault.password)
            await observed.record(stale: stale, during: nil)
        }
        try? await restored.session.unlock(password: TestVault.password, secretKey: fixture.kit.secretKey)
        await state.intercept(afterSave: nil)
        #expect(await observed.stale != nil, "no state was saved while the move was pending: nothing is tested")
        #expect(try await restored.session.state() == .unlocked, "the second unlock did not unlock")
        #expect(try await restored.store.loadAccount()?.migration == nil, "the turned-away move was not made")

        let report = try await restored.session.syncAll()
        #expect(!report.deviceMigrationIncomplete)
        try await other.session.sync()
        #expect((try? await other.session.item(id: doomed)) == nil, "the deletion never went out")
    }
}

/// A record store that runs a step once, the next time the account's headers are listed (where a password change
/// is between reading the account record and committing it), and that can fail the next commit of the account record.
actor HookedRecordStore: RecordStore {
    let base = InMemoryRecordStore()
    private var hook: (@Sendable () async -> Void)?
    private(set) var hookRan = false

    private var accountCommitFails = false
    private var accountCommitHook: (@Sendable () async -> Void)?

    func onNextHeaderListing(_ hook: @escaping @Sendable () async -> Void) { self.hook = hook }
    /// Runs `hook` inside the next commit that writes the account record, before it is written, and then fails that
    /// commit: what a registration's commit meets when the session is locked and unlocked again while it waits.
    func onNextAccountCommit(_ hook: @escaping @Sendable () async -> Void) { accountCommitHook = hook }
    /// The next commit that writes the account record fails, as a database that cannot be written would.
    func failNextAccountCommit() { accountCommitFails = true }

    func loadAccount() async throws -> AccountRecord? { await base.loadAccount() }
    func record(_ key: RecordKey) async throws -> StoredRecord? { await base.record(key) }
    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        if kind == .accountHeader, let hook {
            self.hook = nil
            await hook()
            hookRan = true
        }
        return await base.records(in: vaultID, kind: kind)
    }
    func commit(_ change: StoreChange) async throws {
        if let hook = accountCommitHook, change.account != nil {
            accountCommitHook = nil
            await hook()
            throw RecordStoreError.checkpointIncomplete
        }
        if accountCommitFails, change.account != nil {
            accountCommitFails = false
            throw RecordStoreError.checkpointIncomplete
        }
        try await base.commit(change)
    }
    func eraseAll() async throws { await base.eraseAll() }
}

/// What `moveIsMadeOnceAtATime` saw from inside the unlock's move: the account then, and the report of the sync it ran.
actor MoveObservation {
    private var claimed = false
    private(set) var stale: AccountRecord?
    private(set) var during: AccountSyncReport?

    func claim() -> Bool {
        defer { claimed = true }
        return !claimed
    }

    func record(stale: AccountRecord, during: AccountSyncReport?) {
        self.stale = stale
        self.during = during
    }
}
