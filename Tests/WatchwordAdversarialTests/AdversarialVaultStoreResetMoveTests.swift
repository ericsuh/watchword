import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

// A store reset meeting a device move (docs/02-architecture.md §7.10; owner decision, 2026-11-17: re-upload, "but
// ask the user first"): an installation restored onto other hardware starts each vault's sync state over for its new
// device ID (Z181), and must still know that it had synced, and that an upload it began was not finished
// (docs/06-adversarial-review.md V49, V51).
extension AdversarialVaultSyncTests {
    /// The device's store and sync state on other hardware: the same files, without the device key, so the next unlock
    /// registers a new device ID and moves the old ID's sync state to it.
    static func restoreOntoOtherHardware(_ device: TestVault) async throws {
        let accountID = try #require(await device.store.loadAccount()).accountID
        await device.session.lock()
        await device.forgetDeviceKey(accountID: accountID)
        try await device.session.unlock(password: TestVault.password)
    }

    static func login(_ title: String, in vaultID: UUID) -> Item {
        Item(vaultID: vaultID, title: title, scopes: [], fields: [Field(kind: .password, label: "P", value: "s")])
    }

    /// Threat: none needed but the person's own act. They deleted Watchword's data from iCloud on purpose (the store
    /// lists nothing, and an unmarked CloudKit zone is simply created), and then restored a backup of this device onto
    /// new hardware: the `SyncStoreMarker` is not in the backup, and the move started every vault's state over, so
    /// before V49 `hasSyncedBefore` read the installation as new and its first sync filled the store again, the
    /// account's objects and every carried row, without asking. It asks now, publishes nothing however often it syncs,
    /// and on the person's yes hands on everything it holds, the other device's work included.
    @Test("a restore onto other hardware into a store the person emptied asks before it uploads anything")
    func restoredIntoEmptiedStoreAsks() async throws {
        let store = ResettableSyncTransport()
        let a = TestVault.syncing(over: store)
        try await a.createAccount()
        let b = try await a.enrolledDevice(deviceID: Self.deviceB, over: store)
        try await b.session.unlock(password: TestVault.password)
        let vaultID = try #require(await a.session.personalVaultID)
        _ = try await a.session.save(Self.login("Bank", in: vaultID))
        _ = try await b.session.save(Self.login("Post", in: vaultID))
        for _ in 0..<3 {
            for device in [a, b] { try await device.session.sync() }
        }

        await store.base.removeEverything()
        await store.forgetCreates()
        let oldID = try #require(await b.store.loadAccount()).deviceID
        try await Self.restoreOntoOtherHardware(b)
        let moved = try #require(await b.store.loadAccount())
        #expect(moved.deviceID != oldID && moved.migration == nil)

        for round in 0..<3 {
            let report = try await b.session.syncAll(reconcile: round == 2)
            #expect(report.storeNeedsReupload)
            #expect(report.transportFailure == .storeReset)
        }
        let created = await store.created
        #expect(created.isEmpty, "\(created)")
        #expect(await store.startsAgain == 0)

        // A, which held "Bank" alone, is gone for good; the person says yes on the restored device.
        let answered = try await b.session.reuploadAfterStoreReset(confirming: try await b.session.reuploadPlan())
        #expect(!answered.storeNeedsReupload)
        #expect(answered.vaults[vaultID]?.snapshotsWritten == 1)
        let c = try await b.enrolledDevice(deviceID: Self.deviceC, over: store)
        try await c.session.unlock(password: TestVault.password)
        try await c.session.sync()
        #expect(Set(try await c.session.items().items.map(\.title)) == ["Bank", "Post"])
    }

    /// Threat: none; the property the fix must not break. An installation that never synced (sync set up, the store
    /// never reached) is restored onto other hardware: its store is new, not emptied, and its first sync publishes
    /// without asking, as any new account's does.
    @Test("a never-synced installation restored onto other hardware publishes without asking")
    func neverSyncedRestorePublishes() async throws {
        let store = ResettableSyncTransport()
        let a = TestVault.syncing(over: store)
        try await a.createAccount()
        let vaultID = try #require(await a.session.personalVaultID)
        _ = try await a.session.save(Self.login("Bank", in: vaultID))
        try #require(await store.created.isEmpty, "the installation synced before the restore")

        try await Self.restoreOntoOtherHardware(a)
        let report = try await a.session.syncAll()
        #expect(!report.storeNeedsReupload)
        #expect(report.transportFailure == nil)
        #expect(await !store.created.isEmpty)
        let c = try await a.enrolledDevice(deviceID: Self.deviceC, over: store)
        try await c.session.unlock(password: TestVault.password)
        try await c.session.sync()
        #expect(try await c.session.items().items.map(\.title) == ["Bank"])
    }

    /// Threat: none (SR21 meeting a device move). The person said yes after a reset, and the upload stopped part-way:
    /// the store was started again and the account's objects went in, then the connection went before the vault's
    /// snapshot, so only the engine's own sign (`storeResetSuspected`) still asks. A backup taken then is restored
    /// onto new hardware; before V49 the move dropped that sign with the rest of the state, and the restored device
    /// was never asked again while the vault was in no store. It still asks, until it has handed on.
    @Test("an upload stopped part-way before a backup still asks after the restore's device move")
    func interruptedUploadAsksAfterMove() async throws {
        let store = ResettableSyncTransport()
        let a = TestVault.syncing(over: store)
        try await a.createAccount()
        let b = try await a.enrolledDevice(deviceID: Self.deviceB, over: store)
        try await b.session.unlock(password: TestVault.password)
        let vaultID = try #require(await a.session.personalVaultID)
        _ = try await a.session.save(Self.login("Bank", in: vaultID))
        for _ in 0..<3 {
            for device in [a, b] { try await device.session.sync() }
        }

        await store.reset()
        await store.refuseCreates(under: SyncObjectLocation.vaultPrefix(vaultID))
        let stopped = try await b.session.reuploadAfterStoreReset(confirming: try await b.session.reuploadPlan())
        #expect(stopped.vaults[vaultID]?.snapshotsWritten == 0)
        await store.refuseCreates(under: nil)

        try await Self.restoreOntoOtherHardware(b)
        #expect(try await b.store.loadAccount()?.migration == nil)
        #expect(try await b.session.syncAll().storeNeedsReupload, "the move dropped the unfinished upload's question")
        #expect(try await b.session.syncAll().storeNeedsReupload)

        let finished = try await b.session.reuploadAfterStoreReset(confirming: try await b.session.reuploadPlan())
        #expect(finished.vaults[vaultID]?.snapshotsWritten == 1)
        #expect(!finished.storeNeedsReupload)
        #expect(try await b.session.syncAll().storeNeedsReupload == false)
        let c = try await b.enrolledDevice(deviceID: Self.deviceC, over: store)
        try await c.session.unlock(password: TestVault.password)
        try await c.session.sync()
        #expect(try await c.session.items().items.map(\.title) == ["Bank"])
    }

    /// The vault's sync state as the session signed it.
    static func signedState(_ device: TestVault, vaultID: UUID) async throws -> SyncState {
        let syncState = try #require(await device.session.syncState)
        return try #require(try await syncState.loadState(vaultID: vaultID))
    }

    /// Threat: none; liveness (the review of V49 to V51, V52). A restored installation that handed everything on
    /// after its move kept asking for the rest of its life: the engine read "started over and not handed on since" as
    /// "no hand-on held now", and the hand-on is collected once another device's snapshot supersedes it. Every later
    /// suspected reset then needed the person's yes on this device, even after another device had uploaded
    /// everything again. The question the move raised ends with the move's own hand-on (`startedOverByMove`), and a
    /// later reset ends here as anywhere: once the store stands for everything this device holds.
    @Test("a moved installation's later reset ends without asking once another device uploads everything again")
    func movedThenHandedOnAsksOnlyOnce() async throws {
        let store = ResettableSyncTransport()
        let a = TestVault.syncing(over: store)
        try await a.createAccount()
        let b = try await a.enrolledDevice(deviceID: Self.deviceB, over: store)
        try await b.session.unlock(password: TestVault.password)
        let vaultID = try #require(await a.session.personalVaultID)
        _ = try await a.session.save(Self.login("Bank", in: vaultID))
        _ = try await b.session.save(Self.login("Post", in: vaultID))
        for _ in 0..<3 {
            for device in [a, b] { try await device.session.sync() }
        }

        // The store emptied, B restored onto other hardware: B asks, and on the yes hands on.
        await store.base.removeEverything()
        try await Self.restoreOntoOtherHardware(b)
        #expect(try await b.session.syncAll().storeNeedsReupload)
        let handed = try await b.session.reuploadAfterStoreReset(confirming: try await b.session.reuploadPlan())
        #expect(handed.vaults[vaultID]?.snapshotsWritten == 1)
        #expect(try await Self.signedState(b, vaultID: vaultID).startedOverByMove == false)
        // A, whose own objects are gone too, is asked and answers; then both sync until B's hand-on is superseded by
        // a snapshot of A's and collected.
        #expect(try await a.session.syncAll().storeNeedsReupload)
        _ = try await a.session.reuploadAfterStoreReset(confirming: try await a.session.reuploadPlan())
        for _ in 0..<4 {
            for device in [a, b] { _ = try await device.session.syncAll() }
        }
        #expect(try await Self.signedState(b, vaultID: vaultID).handedOn == nil, "B's hand-on was not collected")
        #expect(try await b.session.syncAll().storeNeedsReupload == false)

        // A later reset. A says yes and uploads everything again, B's work included.
        await store.reset()
        #expect(try await b.session.syncAll().storeNeedsReupload)
        #expect(try await a.session.syncAll().storeNeedsReupload)
        let again = try await a.session.reuploadAfterStoreReset(confirming: try await a.session.reuploadPlan())
        #expect(again.vaults[vaultID]?.snapshotsWritten == 1)

        // B is not asked again: the store stands for everything it holds.
        let after = try await b.session.syncAll()
        #expect(!after.storeNeedsReupload)
        #expect(try await Self.signedState(b, vaultID: vaultID).storeResetSuspected == false)
        _ = try await b.session.save(Self.login("Later", in: vaultID))
        #expect(try await b.session.syncAll().storeNeedsReupload == false)
        let c = try await a.enrolledDevice(deviceID: Self.deviceC, over: store)
        try await c.session.unlock(password: TestVault.password)
        try await c.session.sync()
        #expect(Set(try await c.session.items().items.map(\.title)) == ["Bank", "Post", "Later"])
    }

    /// Threat: none needed but a sync state file that fails one write while a restore moves the old device ID's state
    /// (Z181). While the move is incomplete the sync publishes nothing; an upload after a reset begun then would start
    /// the store again and leave it empty, and the move, made afterwards, would start the states over beneath it. The
    /// call refuses (V51), starts nothing, and works once a sync has completed the move.
    @Test("the upload after a reset is refused while a device move is incomplete")
    func reuploadRefusedDuringMove() async throws {
        let store = ResettableSyncTransport()
        let state = InterceptingStateStore()
        let a = TestVault(sync: SyncSettings(state: state, transport: store), seed: 5_100)
        try await a.createAccount()
        let vaultID = try #require(await a.session.personalVaultID)
        _ = try await a.session.save(Self.login("Kept", in: vaultID))
        let doomed = try await a.session.save(Self.login("Deleted, never published", in: vaultID))
        try await a.session.sync()
        try await a.session.trash(id: doomed.id)
        try await a.session.deletePermanently(id: doomed.id)
        await store.reset()

        await state.failNextPendingDeletionWrite()
        try await Self.restoreOntoOtherHardware(a)
        #expect(try await a.store.loadAccount()?.migration != nil, "the move was not left incomplete")
        let plan = try await a.session.reuploadPlan()
        await #expect(throws: VaultError.deviceMigrationIncomplete) {
            try await a.session.reuploadAfterStoreReset(confirming: plan)
        }
        #expect(await store.startsAgain == 0)

        _ = try await a.session.syncAll()
        #expect(try await a.store.loadAccount()?.migration == nil)
        let answered = try await a.session.reuploadAfterStoreReset(confirming: try await a.session.reuploadPlan())
        #expect(!answered.storeNeedsReupload)
        #expect(await store.startsAgain == 1)
    }

    /// Threat: none needed but a Keychain that is closed for a moment while the vault is open (the device locked, a
    /// sync in the background), met by the person's answer to a reset (merge of round 24, V70). The sync an upload runs
    /// writes nothing without this device's own key, read now (`mayWrite`, Z253), so the upload started the store again
    /// and left it empty, as V51 says of a move. The call refuses, starts nothing, and works once the key reads again;
    /// the sync before it says the key is why (`ownDeviceKeyWait`, Z264) beside the question.
    @Test("the upload after a reset is refused while this device's own key cannot be read")
    func reuploadRefusedWhileTheKeyIsUnreadable() async throws {
        let store = ResettableSyncTransport()
        let keys = UnreadableDeviceKeyStore(base: FakeDeviceKeyStore(seed: 5_200))
        let a = TestVault(
            sync: SyncSettings(state: InMemorySyncStateStore(), transport: store), seed: 5_200, deviceKeys: keys)
        try await a.createAccount()
        let vaultID = try #require(await a.session.personalVaultID)
        _ = try await a.session.save(Self.login("Kept", in: vaultID))
        try await a.session.sync()
        await store.reset()

        await keys.setUnreadable(true)
        let report = try await a.session.syncAll()
        #expect(report.storeNeedsReupload, "the reset was not noticed: nothing is tested")
        #expect(report.ownDeviceKeyWait == .unreadable)
        let plan = try await a.session.reuploadPlan()
        await #expect(throws: VaultError.deviceKeyUnreadable) {
            try await a.session.reuploadAfterStoreReset(confirming: plan)
        }
        #expect(await store.startsAgain == 0, "the store was started again for an upload that could write nothing")

        await keys.setUnreadable(false)
        let answered = try await a.session.reuploadAfterStoreReset(confirming: try await a.session.reuploadPlan())
        #expect(!answered.storeNeedsReupload)
        #expect(answered.ownDeviceKeyWait == nil)
        #expect(await store.startsAgain == 1)
    }

    /// Threat: none needed; the same as above while a registration of this installation is under way, its key held
    /// (a same-ID registration begun by an unlock, Z253): the upload's sync would only download, said as
    /// `ownDeviceKeyWait == .registering` (Z272), so the call refuses as for a device not registered and starts nothing
    /// (V70; pinned since the review of PR #22's eighth merge, finding 3, where only reading had covered it).
    @Test("the upload after a reset is refused while this device's registration is under way")
    func reuploadRefusedWhileRegistering() async throws {
        let store = ResettableSyncTransport()
        let a = TestVault(sync: SyncSettings(state: InMemorySyncStateStore(), transport: store), seed: 5_250)
        try await a.createAccount()
        let vaultID = try #require(await a.session.personalVaultID)
        _ = try await a.session.save(Self.login("Kept", in: vaultID))
        try await a.session.sync()
        await store.reset()
        #expect(try await a.session.syncAll().storeNeedsReupload, "the reset was not noticed: nothing is tested")

        await a.session.setRegistrationInFlightForTest(true)
        let plan = try await a.session.reuploadPlan()
        await #expect(throws: VaultError.deviceNotRegistered) {
            try await a.session.reuploadAfterStoreReset(confirming: plan)
        }
        #expect(await store.startsAgain == 0, "the store was started again for an upload that could write nothing")

        await a.session.setRegistrationInFlightForTest(false)
        let answered = try await a.session.reuploadAfterStoreReset(confirming: try await a.session.reuploadPlan())
        #expect(!answered.storeNeedsReupload)
        #expect(await store.startsAgain == 1)
    }

    /// Threat: none needed; the same as above for a store whose Keychain holds no key for the device ID the account
    /// names (restored onto other hardware, before its registration as a new device): the upload's sync would only
    /// download (Z253), so the call refuses as for a device not registered, and starts nothing (V70).
    @Test("the upload after a reset is refused while this device has no key of its own here")
    func reuploadRefusedWithoutAKey() async throws {
        let store = ResettableSyncTransport()
        let a = TestVault(sync: SyncSettings(state: InMemorySyncStateStore(), transport: store), seed: 5_300)
        try await a.createAccount()
        let vaultID = try #require(await a.session.personalVaultID)
        _ = try await a.session.save(Self.login("Kept", in: vaultID))
        try await a.session.sync()
        await store.reset()

        let plan = try await a.session.reuploadPlan()
        await a.forgetDeviceKey(accountID: try #require(await a.store.loadAccount()).accountID)
        await #expect(throws: VaultError.deviceNotRegistered) {
            try await a.session.reuploadAfterStoreReset(confirming: plan)
        }
        #expect(await store.startsAgain == 0, "the store was started again for an upload that could write nothing")
    }
}
