import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// How the sync store lost what it held.
enum ResetKind: String, CaseIterable, Sendable, CustomTestStringConvertible {
    /// The transport says so (a CloudKit zone this device had seen is gone): every operation is `storeReset`.
    case said
    /// Nothing says so (a folder emptied; a CloudKit marker lost as well): the store just lists nothing.
    case emptied

    var testDescription: String { rawValue }
}

/// Devices of one account, each a real `VaultSession`, over a store that can be reset and that records every
/// create (docs/02-architecture.md §7.10).
struct ResetFleet {
    let store: ResettableSyncTransport
    var devices: [TestVault]
    let personal: UUID

    static func deviceID(_ index: Int) -> UUID {
        UUID(uuid: (0xD0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, UInt8(0xA0 + index)))
    }

    static func make(_ count: Int = 2) async throws -> ResetFleet {
        let store = ResettableSyncTransport()
        let first = TestVault.syncing(over: store, name: "Device 0")
        try await first.createAccount()
        var fleet = ResetFleet(
            store: store, devices: [first], personal: try #require(await first.session.personalVaultID))
        for index in 1..<max(count, 1) { try await fleet.enrol(index) }
        return fleet
    }

    /// Enrols one more device from the store alone, unlocked, its registration published and accepted.
    @discardableResult
    mutating func enrol(_ index: Int) async throws -> TestVault {
        let device = try await devices[0].enrolledDevice(
            deviceID: Self.deviceID(index), over: store, name: "Device \(index)")
        try await device.session.unlock(password: TestVault.password)
        try await device.session.sync()
        try await devices[0].session.sync()
        devices.append(device)
        return device
    }

    @discardableResult
    func save(_ title: String, on index: Int, in vault: UUID? = nil) async throws -> Item {
        try await devices[index].session.save(
            Item(
                vaultID: vault ?? personal, title: title, scopes: [],
                fields: [Field(kind: .password, label: "Password", value: "secret of \(title)")]))
    }

    /// Syncs every device until a whole round changes nothing.
    func settle(rounds: Int = 8) async throws {
        for _ in 0..<rounds {
            var changed = false
            for device in devices {
                let report = try await device.session.sync()
                if report.applied > 0 || report.pushedEntries > 0 || report.snapshotsWritten > 0 { changed = true }
            }
            if !changed { return }
        }
    }

    func reset(_ kind: ResetKind) async {
        switch kind {
        case .said: await store.reset()
        case .emptied: await store.base.removeEverything()
        }
        await store.forgetCreates()
    }

    func titles(_ index: Int) async throws -> Set<String> {
        Set(try await devices[index].session.items().items.map(\.title))
    }

    /// The person's yes on one device: the plan they would be shown, confirmed.
    @discardableResult
    func upload(from index: Int) async throws -> AccountSyncReport {
        let session = devices[index].session
        return try await session.reuploadAfterStoreReset(confirming: try await session.reuploadPlan())
    }
}

@Suite("Store reset: the session")
struct VaultStoreResetTests {
    @Test(
        "after a reset no sync uploads anything, the report asks, and nothing local changes",
        arguments: ResetKind.allCases)
    func nothingUnasked(_ kind: ResetKind) async throws {
        let fleet = try await ResetFleet.make()
        try await fleet.save("Bank", on: 0)
        try await fleet.save("Post", on: 1)
        try await fleet.settle()
        await fleet.reset(kind)

        for round in 0..<3 {
            for device in fleet.devices {
                let report = try await device.session.syncAll(reconcile: round == 1)
                #expect(report.storeNeedsReupload && report.transportFailure == .storeReset)
                #expect(report.combined.pushedEntries == 0 && report.combined.snapshotsWritten == 0)
            }
        }
        // Locked, too.
        await fleet.devices[1].session.lock()
        #expect(try await fleet.devices[1].session.syncAll().storeNeedsReupload)
        try await fleet.devices[1].session.unlock(password: TestVault.password)

        #expect(await fleet.store.created.isEmpty)
        #expect(await fleet.store.objects().isEmpty)
        #expect(await fleet.store.startsAgain == 0)
        for index in 0..<2 { #expect(try await fleet.titles(index) == ["Bank", "Post"]) }
    }

    @Test("a new edit made after a reset is not uploaded either, and is not lost", arguments: ResetKind.allCases)
    func newEditsWait(_ kind: ResetKind) async throws {
        let fleet = try await ResetFleet.make()
        try await fleet.save("Bank", on: 0)
        try await fleet.settle()
        await fleet.reset(kind)
        try await fleet.save("Written after", on: 0)
        #expect(try await fleet.devices[0].session.syncAll().storeNeedsReupload)
        #expect(await fleet.store.created.isEmpty)
        try await fleet.upload(from: 0)
        try await fleet.settle()
        #expect(try await fleet.titles(1) == ["Bank", "Written after"])
    }

    @Test("a store that never held the account is not a reset: the first sync publishes")
    func neverSetUp() async throws {
        let store = ResettableSyncTransport()
        let device = TestVault.syncing(over: store)
        try await device.createAccount()
        let report = try await device.session.syncAll()
        #expect(!report.storeNeedsReupload && report.transportFailure == nil)
        #expect(await !store.created.isEmpty)
    }

    @Test(
        "after the call a brand-new device enrols from the store alone and reads everything",
        arguments: ResetKind.allCases)
    func newDeviceReadsEverything(_ kind: ResetKind) async throws {
        var fleet = try await ResetFleet.make()
        let (a, b) = (fleet.devices[0].session, fleet.devices[1].session)
        let work = try await a.createVault(name: "Work")
        let gone = try await b.createVault(name: "Gone")
        try await fleet.settle()
        try await fleet.save("Bank", on: 0)
        try await fleet.save("Payroll", on: 1, in: work.id)
        try await fleet.save("In a deleted vault", on: 1, in: gone.id)
        try await fleet.settle()
        try await b.deleteVault(id: gone.id, confirmingItemCount: 1)
        let trashed = try await fleet.save("Trashed", on: 1)
        try await b.trash(id: trashed.id)
        try await fleet.settle()
        await fleet.reset(kind)

        let plan = try await a.reuploadPlan()
        let thisDevice = try await a.devices().first { $0.isThisDevice }?.id
        #expect(plan.deviceID == thisDevice && plan.sharedVaults.isEmpty)
        #expect(Set(plan.vaults.filter { !$0.isDeleted }.map(\.id)) == [fleet.personal, work.id])
        #expect(plan.vaults.contains { $0.id == work.id && $0.name == "Work" && $0.itemCount == 1 })
        #expect(plan.vaults.filter(\.isDeleted).map(\.id) == [gone.id])
        #expect(plan.itemCount == 3)
        let report = try await a.reuploadAfterStoreReset(confirming: plan)
        #expect(!report.storeNeedsReupload && report.transportFailure == nil && report.reuploadRefusals.isEmpty)
        #expect(await fleet.store.startsAgain == 1)

        // From the store alone: nothing but what one device uploaded again.
        let c = try await fleet.enrol(2)
        let joined = try await c.session.syncAll()
        #expect(joined.combined.rejected.isEmpty && joined.combined.waiting.isEmpty && !joined.storeNeedsReupload)
        #expect(Set(try await c.session.vaults().map(\.id)) == [fleet.personal, work.id])
        #expect(try await c.session.vaults().contains { $0.id == work.id && $0.name == "Work" })
        #expect(try await c.session.vaults(includingDeleted: true).contains { $0.id == gone.id && $0.isDeleted })
        #expect(try await fleet.titles(2) == ["Bank", "Payroll", "Trashed"])
        #expect(try await c.session.items(in: work.id).items.map(\.title) == ["Payroll"])
        #expect(try await c.session.items().items.first { $0.title == "Trashed" }?.isTrashed == true)

        // The device that was in step is asked nothing, and its next edit reaches the others.
        let returning = try await b.syncAll()
        #expect(!returning.storeNeedsReupload && returning.combined.snapshotsWritten == 0)
        try await fleet.save("After", on: 1)
        try await fleet.settle()
        for index in 0..<3 { #expect(try await fleet.titles(index) == ["Bank", "Payroll", "Trashed", "After"]) }
    }

    @Test("the call refuses a plan that no longer describes the device, and uploads nothing")
    func staleConfirmation() async throws {
        let fleet = try await ResetFleet.make(1)
        try await fleet.save("Bank", on: 0)
        try await fleet.settle()
        await fleet.reset(.said)
        let session = fleet.devices[0].session
        let plan = try await session.reuploadPlan()
        try await fleet.save("Saved since the question", on: 0)
        await #expect(throws: VaultError.reuploadNotConfirmed) {
            try await session.reuploadAfterStoreReset(confirming: plan)
        }
        var other = plan
        other.deviceID = UUID()
        await #expect(throws: VaultError.reuploadNotConfirmed) {
            try await session.reuploadAfterStoreReset(confirming: other)
        }
        #expect(await fleet.store.startsAgain == 0)
        #expect(await fleet.store.created.isEmpty)
    }

    @Test("the call needs the vault unlocked and a device that may write")
    func whoMayUpload() async throws {
        let fleet = try await ResetFleet.make(2)
        try await fleet.save("Bank", on: 0)
        try await fleet.settle()
        let (a, b) = (fleet.devices[0].session, fleet.devices[1].session)
        let plan = try await b.reuploadPlan()
        try await a.revokeDevice(ResetFleet.deviceID(1), password: .keepPassword(current: TestVault.password))
        try await fleet.settle()
        await fleet.reset(.said)

        await #expect(throws: VaultError.deviceRevoked) { try await b.reuploadAfterStoreReset(confirming: plan) }
        await b.lock()
        await #expect(throws: VaultError.locked) { try await b.reuploadAfterStoreReset(confirming: plan) }
        await #expect(throws: VaultError.locked) { try await b.reuploadPlan() }
        #expect(await fleet.store.startsAgain == 0)
        #expect(await fleet.store.created.isEmpty)

        let unconfigured = TestVault()
        try await unconfigured.createAccount()
        await #expect(throws: VaultError.syncNotConfigured) { try await unconfigured.session.reuploadPlan() }
    }

    @Test(
        "two devices upload in either order and converge, concurrent edits of one item included",
        arguments: zip([ResetKind.said, .said, .emptied, .emptied], [false, true, false, true]))
    func eitherOrder(_ kind: ResetKind, _ reversed: Bool) async throws {
        var fleet = try await ResetFleet.make()
        let shared = try await fleet.save("Shared", on: 0)
        try await fleet.settle()
        // Concurrent edits of one item and an item each. Device 0 publishes its own; device 1 then merges them
        // and publishes what device 0 never merges; device 1 also holds an edit it has not published at all.
        var first = try #require(try await fleet.devices[0].session.items().items.first { $0.id == shared.id })
        first.title = "Titled on device 0"
        try await fleet.devices[0].session.save(first)
        try await fleet.save("Only on 0", on: 0)
        var second = try #require(try await fleet.devices[1].session.items().items.first { $0.id == shared.id })
        second.fields[0].value = "changed on device 1"
        try await fleet.devices[1].session.save(second)
        try await fleet.devices[0].session.sync()
        try await fleet.devices[1].session.sync()
        try await fleet.save("Only on 1", on: 1)
        await fleet.reset(kind)

        for index in reversed ? [1, 0] : [0, 1] {
            let report = try await fleet.upload(from: index)
            #expect(report.transportFailure == nil)
        }
        try await fleet.settle()
        try await fleet.enrol(2)
        try await fleet.settle()
        for index in 0..<3 {
            #expect(try await fleet.titles(index) == ["Titled on device 0", "Only on 0", "Only on 1"])
            let item = try #require(try await fleet.devices[index].session.items().items.first { $0.id == shared.id })
            #expect(item.fields[0].value == "changed on device 1")
            let report = try await fleet.devices[index].session.syncAll()
            #expect(report.combined.waiting.isEmpty && !report.storeNeedsReupload)
        }
    }

    @Test(
        "a device that was offline during the reset and holds more is asked, then merges cleanly",
        arguments: ResetKind.allCases)
    func offlineDeviceReturns(_ kind: ResetKind) async throws {
        let fleet = try await ResetFleet.make(3)
        try await fleet.save("Bank", on: 0)
        try await fleet.settle()
        // Device 2 publishes an edit nobody merges, and goes offline; the store is reset and device 0 starts again.
        try await fleet.save("Only device 2 has this", on: 2)
        try await fleet.devices[2].session.sync()
        await fleet.reset(kind)
        try await fleet.upload(from: 0)
        try await fleet.devices[1].session.sync()

        let returning = try await fleet.devices[2].session.syncAll()
        #expect(returning.storeNeedsReupload && returning.transportFailure == nil)
        #expect(returning.combined.snapshotsWritten == 0)
        #expect(try await fleet.titles(2) == ["Bank", "Only device 2 has this"], "it loses nothing while it waits")
        #expect(try await fleet.titles(1) == ["Bank"])
        let answered = try await fleet.upload(from: 2)
        #expect(!answered.storeNeedsReupload)
        try await fleet.settle()
        for index in 0..<3 { #expect(try await fleet.titles(index) == ["Bank", "Only device 2 has this"]) }
    }

    @Test("a deletion made before the reset is not undone by a device that had not heard of it")
    func deletionSurvives() async throws {
        let fleet = try await ResetFleet.make(3)
        let doomed = try await fleet.save("Doomed", on: 0)
        try await fleet.save("Kept", on: 0)
        try await fleet.settle()
        // Device 1 deletes; device 0 merges the deletion; device 2 never hears of it before the reset.
        try await fleet.devices[1].session.trash(id: doomed.id)
        try await fleet.devices[1].session.deletePermanently(id: doomed.id)
        try await fleet.devices[1].session.sync()
        try await fleet.devices[0].session.sync()
        await fleet.reset(.emptied)
        try await fleet.upload(from: 0)
        try await fleet.settle()
        for index in 0..<3 { #expect(try await fleet.titles(index) == ["Kept"]) }
    }

    @Test("a shared vault is refused by name, stays readable, and does not keep the question open")
    func sharedVaultRefused() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite])
        let member = members[0]
        try await owner.session.save(
            Item(vaultID: vaultID, title: "Shared login", scopes: [], fields: []))
        let personal = try #require(await owner.session.personalVaultID)
        try await owner.session.save(Item(vaultID: personal, title: "Own login", scopes: [], fields: []))
        for _ in 0..<3 {
            try await owner.session.sync()
            try await member.session.sync()
        }
        #expect(try await member.session.items(in: vaultID).items.map(\.title) == ["Shared login"])
        await household.transport.removeEverything()

        let stopped = try await owner.session.syncAll()
        #expect(stopped.storeNeedsReupload && stopped.transportFailure == .storeReset)
        #expect(await household.transport.allObjects.isEmpty)

        let plan = try await owner.session.reuploadPlan()
        #expect(plan.sharedVaults.map(\.id) == [vaultID] && !plan.vaults.contains { $0.id == vaultID })
        let report = try await owner.session.reuploadAfterStoreReset(confirming: plan)
        #expect(report.reuploadRefusals == [vaultID: .sharedVault])
        #expect(!report.storeNeedsReupload, "a vault that cannot be uploaded is not asked about again")
        let uploaded = await household.transport.allObjects.keys
        #expect(!uploaded.contains { $0.hasPrefix(SyncObjectLocation.vaultPrefix(vaultID)) })
        #expect(uploaded.contains { $0.hasPrefix(SyncObjectLocation.vaultPrefix(personal)) })
        // Nothing of it was dropped, here or on the member's device.
        #expect(try await owner.session.items(in: vaultID).items.map(\.title) == ["Shared login"])
        let later = try await owner.session.syncAll()
        #expect(later.reuploadRefusals == [vaultID: .sharedVault] && !later.storeNeedsReupload)
        _ = try await member.session.syncAll()
        #expect(try await member.session.items(in: vaultID).items.map(\.title) == ["Shared login"])
    }
}
