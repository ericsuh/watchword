import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

/// The sync store after a reset, against real sessions and real keys (docs/02-architecture.md §7.10; owner
/// decision, 2026-11-17: re-upload, "but ask the user first"). **A1** holds the store: it can reset it, say it was
/// reset when it was not, delete any object, and put old objects back. **A8** can delete this device's memory of
/// having seen the store. And the person on another device may have deleted the data on purpose. In every case:
/// nothing is uploaded again without `reuploadAfterStoreReset`, which only a screen calls on the person's answer;
/// that call gives the store nothing it did not have, rolls no device back, and drops or overwrites nothing local.
extension AdversarialVaultSyncTests {
    struct ResetFixture {
        let store: ResettableSyncTransport
        let a: TestVault
        let b: TestVault
        let vaultID: UUID

        var devices: [TestVault] { [a, b] }

        func save(_ title: String, value: String = "secret", on device: TestVault) async throws -> Item {
            try await device.session.save(
                Item(
                    vaultID: vaultID, title: title, scopes: [],
                    fields: [Field(kind: .password, label: "Password", value: value)]))
        }

        func settle() async throws {
            for _ in 0..<4 {
                for device in devices { try await device.session.sync() }
            }
        }

        func titles(_ device: TestVault) async throws -> Set<String> {
            Set(try await device.session.items().items.map(\.title))
        }

        func state(_ device: TestVault) async throws -> SyncState {
            try #require(try await device.sync?.state.loadState(vaultID: vaultID))
        }

        func upload(from device: TestVault) async throws -> AccountSyncReport {
            try await device.session.reuploadAfterStoreReset(confirming: try await device.session.reuploadPlan())
        }
    }

    /// Two devices of one account, each with an item of its own, in sync.
    static func resetFixture() async throws -> ResetFixture {
        let store = ResettableSyncTransport()
        let a = TestVault.syncing(over: store)
        try await a.createAccount()
        let b = try await a.enrolledDevice(deviceID: deviceB, over: store)
        try await b.session.unlock(password: TestVault.password)
        let f = ResetFixture(store: store, a: a, b: b, vaultID: try #require(await a.session.personalVaultID))
        _ = try await f.save("Bank", on: a)
        _ = try await f.save("Post", on: b)
        try await f.settle()
        return f
    }

    /// Threat: the person deleted Watchword's data from the sync store on another device, on purpose; or A1 emptied
    /// it; and A8 (or a reinstall) has removed this device's memory that the store ever existed, so that the store
    /// reads as new. Automatic syncing calls `syncAll` and nothing else. However often it runs, unlocked or locked,
    /// replaying or not, nothing is created on the store, not even the account's own objects, and the store is never
    /// started again.
    @Test(
        "no sync puts anything back in a store that was reset or emptied, the account's objects included",
        arguments: [true, false])
    func nothingIsPutBackUnasked(_ transportSaysSo: Bool) async throws {
        let f = try await Self.resetFixture()
        if transportSaysSo { await f.store.reset() } else { await f.store.base.removeEverything() }
        await f.store.forgetCreates()
        for round in 0..<3 {
            for device in f.devices {
                let report = try await device.session.syncAll(reconcile: round == 2)
                #expect(report.storeNeedsReupload)
            }
        }
        await f.b.session.lock()
        _ = try await f.b.session.syncAll()
        try await f.b.session.unlock(password: TestVault.password)
        _ = try await f.b.session.syncAll()
        #expect(await f.store.created.isEmpty)
        #expect(await f.store.objects().isEmpty)
        #expect(await f.store.startsAgain == 0)
        for device in f.devices { #expect(try await f.titles(device) == ["Bank", "Post"]) }
    }

    /// Threat: A1 says the store was reset while it still holds everything, to get the person to say yes and see
    /// what the device then gives it. The yes gives it nothing: no vault object is created, because nothing the
    /// device holds is missing from the store, and the device's sync state is exactly what it was.
    @Test("a reset that was only claimed gets nothing from the person's yes")
    func claimedReset() async throws {
        let f = try await Self.resetFixture()
        let before = try await f.state(f.a)
        let held = await f.store.objects()
        await f.store.pretendReset()
        #expect(try await f.a.session.syncAll().storeNeedsReupload)
        await f.store.forgetCreates()
        let report = try await f.upload(from: f.a)
        #expect(!report.storeNeedsReupload && report.combined.snapshotsWritten == 0)
        #expect(await f.store.created.isEmpty)
        #expect(await f.store.objects() == held)
        let after = try await f.state(f.a)
        #expect(after.published == before.published && after.merged == before.merged)
        #expect(after.nextSequence == before.nextSequence && after.handedOn == nil)
    }

    /// Threat: A1 resets the store again after every upload, hoping that some round makes a device reuse an object
    /// name (a second object under a name is a fork), go back to an older version of an item, or lose one. Over
    /// several rounds with an edit in each, no name is ever created twice, each item's version only rises, and both
    /// devices end with every item at its newest value.
    @Test("resets repeated after every upload reuse no name and take no item back")
    func repeatedResets() async throws {
        let f = try await Self.resetFixture()
        var created: [String] = []
        var item = try await f.save("Edited every round", value: "round 0", on: f.a)
        try await f.settle()
        var version = item.version
        for round in 1...3 {
            await f.store.forgetCreates()
            item.fields[0].value = "round \(round)"
            item = try await f.a.session.save(item)
            #expect(item.version > version)
            version = item.version
            if round.isMultiple(of: 2) { await f.store.reset() } else { await f.store.base.removeEverything() }
            _ = try await f.upload(from: f.a)
            _ = try await f.b.session.syncAll()
            created += await f.store.created.filter { $0.hasPrefix(SyncObjectLocation.vaultPrefix(f.vaultID)) }
            let onB = try await f.b.session.item(id: item.id)
            #expect(onB.fields[0].value == "round \(round)" && onB.version >= version)
        }
        // The account's own objects are named by their contents or their device, and are the same objects each
        // time; a vault's log is where a name written twice would be a fork.
        #expect(Set(created).count == created.count && created.count >= 6)
        for device in f.devices {
            #expect(try await f.titles(device) == ["Bank", "Post", "Edited every round"])
        }
    }

    /// Threat: A1 empties the store and puts back the objects it held at an earlier time, so that the store shows
    /// an older vault. No device takes an older value: the devices keep their newer versions, the one that holds
    /// what the old copy lacks reports it, and after the person's yes a brand-new device reads the newest values.
    @Test("an old copy of the store put back after a reset takes no device and no new device back")
    func oldCopyPutBack() async throws {
        let f = try await Self.resetFixture()
        var item = try await f.save("Bank card", value: "old PIN", on: f.a)
        try await f.settle()
        let old = await f.store.objects()
        item.fields[0].value = "new PIN"
        item = try await f.a.session.save(item)
        try await f.settle()
        await f.store.base.removeEverything()
        for (name, bytes) in old { await f.store.base.tamper(name, contents: bytes) }

        for device in f.devices {
            let report = try await device.session.syncAll()
            #expect(report.combined.applied == 0)
            #expect(try await device.session.item(id: item.id).fields[0].value == "new PIN")
        }
        #expect(try await f.a.session.syncAll().storeNeedsReupload)
        _ = try await f.upload(from: f.a)
        let c = try await f.a.enrolledDevice(deviceID: Self.deviceC, over: f.store)
        try await c.session.unlock(password: TestVault.password)
        try await c.session.sync()
        #expect(try await c.session.item(id: item.id).fields[0].value == "new PIN")
    }

    /// Threat: the store is reset while one device holds versions kept aside for the person (the quarantine) and a
    /// deletion it has not published. An upload that swept the quarantine into its snapshot would launder versions
    /// that were refused; one that dropped the pending deletion would bring the item back everywhere. Neither
    /// happens: the kept version is still kept and reaches no other device, and the deletion still erases.
    @Test("held-aside versions are neither uploaded nor dropped, and an unpublished deletion still erases")
    func quarantineAndPendingDeletion() async throws {
        let f = try await Self.resetFixture()
        let doomed = try await f.save("Doomed", on: f.a)
        try await f.settle()
        let row = try #require(try await f.a.store.record(RecordKey(recordID: doomed.id, kind: .item)))
        var implausible = SyncEntry(row)
        implausible.version = 1 << 50
        try await f.a.sync?.state.quarantine(implausible, vaultID: f.vaultID)
        try await f.a.session.trash(id: doomed.id)
        try await f.a.session.deletePermanently(id: doomed.id)
        await f.store.reset()

        _ = try await f.upload(from: f.a)
        #expect(try await f.a.session.quarantinedVersions() == [implausible])
        _ = try await f.b.session.syncAll()
        #expect(try await f.titles(f.b) == ["Bank", "Post"])
        #expect(try await f.b.session.quarantinedVersions().isEmpty)
    }

    /// Threat: after a reset a member of a shared vault (or A1 prompting one) uploads the vault again from that
    /// member's device. The other members' work would arrive with no segment for any device to judge a write cut by
    /// (§8.10), and a write made outside a cut would count again. The session refuses the shared vault by name and
    /// uploads nothing under it; it stays readable where it is, and the member's own vaults are uploaded as usual.
    @Test("after a reset a shared vault is never uploaded again from one member's device")
    func sharedVaultIsNotUploaded() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite])
        let member = members[0]
        _ = try await member.session.save(Item(vaultID: vaultID, title: "The member's work", scopes: [], fields: []))
        for _ in 0..<3 {
            try await member.session.sync()
            try await owner.session.sync()
        }
        #expect(try await owner.session.items(in: vaultID).items.map(\.title) == ["The member's work"])
        await household.transport.removeEverything()

        for account in [owner, member] {
            #expect(try await account.session.syncAll().storeNeedsReupload)
            let plan = try await account.session.reuploadPlan()
            #expect(plan.sharedVaults.map(\.id) == [vaultID])
            let report = try await account.session.reuploadAfterStoreReset(confirming: plan)
            #expect(report.reuploadRefusals == [vaultID: .sharedVault])
            #expect(report.vaults[vaultID]?.snapshotsWritten == 0)
        }
        let names = await household.transport.allObjects.keys
        #expect(!names.contains { $0.hasPrefix(SyncObjectLocation.vaultPrefix(vaultID)) })
        for account in [owner, member] {
            #expect(try await account.session.items(in: vaultID).items.map(\.title) == ["The member's work"])
        }
    }
}
