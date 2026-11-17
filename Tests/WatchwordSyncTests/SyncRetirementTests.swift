import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// What the engine does once the keyring says a device is revoked (docs/02-architecture.md §7.8; review findings D9,
/// Y5, Y6). The registry itself is the crypto core's; here `FakeAccountKeys.retire` stands in for it, so these tests
/// are about the engine: it stops reading the device's stream, stops waiting for it, and hands on what it had merged.
@Suite("Sync engine: revoked devices")
struct SyncRetirementTests {
    static func configuration(snapshotThreshold: Int = 64) -> SyncConfiguration {
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = snapshotThreshold
        return configuration
    }

    @Test("nothing a revoked device wrote is read after the revocation, and its stream is not waited for")
    func objectsIgnored() async throws {
        let home = await Household.make(3)
        let (a, b, lost) = (home.devices[0], home.devices[1], home.devices[2])
        try await a.save(Household.login(title: "A's"))
        try await home.settle()

        try await lost.save(Household.login(title: "Written after it was lost", password: "planted-by-thief"))
        try await lost.sync()
        await home.keys.retire(device: await lost.deviceID)
        let report = try await a.sync()
        #expect(report.retiredObjects >= 1)
        #expect(report.rejected.isEmpty && report.waiting.isEmpty, "not rejected again at every sync: not read")
        #expect(report.applied == 0)
        try await b.sync()
        #expect(try await a.items().values.map(\.title) == ["A's"])
        #expect(try await b.items().values.map(\.title) == ["A's"])
    }

    @Test("an object staged before its author was revoked is dropped unmerged")
    func stagedBeforeRevocation() async throws {
        let home = await Household.make(2)
        let (a, lost) = (home.devices[0], home.devices[1])
        try await lost.save(Household.login(title: "Staged"))
        try await lost.sync()
        await a.keyring.lock()
        #expect(try await a.sync().fetched == 1)
        #expect(await a.syncState.staged(vaultID: Household.vault).count == 1)
        await home.keys.retire(device: await lost.deviceID)
        await a.keyring.unlock()
        let report = try await a.sync()
        #expect(report.applied == 0 && report.rejected.isEmpty)
        #expect(await a.syncState.staged(vaultID: Household.vault).isEmpty)
        #expect(try await a.items().isEmpty)
    }

    /// Review finding Y6: a device that stopped syncing for good held back garbage collection of every other stream,
    /// because its acknowledgement never came.
    @Test("a revoked device no longer holds back garbage collection (Y6)")
    func collectionResumes() async throws {
        let transport = InMemorySyncTransport()
        let home = await Household.make(
            3, transport: transport, configuration: Self.configuration(snapshotThreshold: 4))
        let (a, b, lost) = (home.devices[0], home.devices[1], home.devices[2])
        try await lost.save(Household.login(title: "From the lost device"))
        try await home.settle()
        // The lost device never syncs again. The others keep working; the segments it never acknowledged pile up.
        for round in 0..<12 {
            try await a.save(Household.login(title: "A \(round)"))
            try await b.save(Household.login(title: "B \(round)"))
            for device in [a, b, a] { try await device.sync() }
        }
        let prefix = SyncObjectLocation.vaultPrefix(Household.vault) + "log/"
        func segments() async -> Int {
            await transport.list(prefix: prefix).count
        }
        let before = await segments()
        #expect(before >= 24, "held back while the silent device is still a device of the account: \(before)")

        await home.keys.retire(device: await lost.deviceID)
        var collected = 0
        for _ in 0..<4 {
            collected += try await a.sync().collected + (try await b.sync().collected)
        }
        let after = await segments()
        #expect(collected >= 20 && after <= before - 20, "collected once the device is revoked: \(after)")
        // And nothing was lost to collection: a device joining now sees everything, the lost device's item included.
        let joinerID = UUID()
        await home.keys.trust(device: joinerID)
        let joiner = SyncTestClient(
            deviceID: joinerID, vaultID: Household.vault, keys: home.keys, transport: transport,
            configuration: Self.configuration(snapshotThreshold: 4))
        try await joiner.sync()
        try await joiner.sync()
        #expect(
            try await joiner.items().mapValues(MergeFixtures.current)
                == a.items().mapValues(MergeFixtures.current))
        #expect(try await joiner.items().values.contains { $0.title == "From the lost device" })
    }

    @Test("a revoked device is not waited for to write the next snapshot")
    func snapshotElectionSkipsRevoked() async throws {
        // The lowest device ID is the one elected; here it is the lost one.
        let home = await Household.make(3, configuration: Self.configuration(snapshotThreshold: 4))
        // `Household.deviceIDs` are in ascending order, so the first device is the lowest.
        let (lost, a, b) = (home.devices[0], home.devices[1], home.devices[2])
        try await lost.save(Household.login(title: "Lost"))
        try await lost.sync()
        var snapshots = 0
        for round in 0..<3 {
            try await a.save(Household.login(title: "A \(round)"))
            try await b.save(Household.login(title: "B \(round)"))
            snapshots += try await a.sync().snapshotsWritten + (try await b.sync().snapshotsWritten)
        }
        #expect(snapshots == 0, "the others wait for the elected device")
        await home.keys.retire(device: await lost.deviceID)
        snapshots += try await a.sync().snapshotsWritten + (try await b.sync().snapshotsWritten)
        #expect(snapshots >= 1)
    }

    /// The edit was made on the lost device before it was lost, and only one other device had merged it when the
    /// device was revoked. Everyone refuses the lost device's stream from then on, so the device that has the edit
    /// must hand it on, or it would exist there alone and the devices would never agree (PRD F7.7).
    @Test("what one device had merged from a revoked device reaches the others in a snapshot of its own")
    func mergedContentIsHandedOn() async throws {
        let home = await Household.make(3)
        let (a, b, lost) = (home.devices[0], home.devices[1], home.devices[2])
        let item = try await a.save(Household.login(title: "Shared"))
        try await home.settle()

        try await lost.edit(item.id) { $0.notes = "typed on the phone, on the bus" }
        try await lost.save(Household.login(title: "Created on the phone"))
        try await lost.sync()
        try await b.sync()  // B has it; A does not.
        await home.keys.retire(device: await lost.deviceID)

        let handedOn = try await b.sync()
        #expect(handedOn.snapshotsWritten == 1, "B owes what it merged from the revoked device")
        #expect(try await b.sync().snapshotsWritten == 0, "once")
        let received = try await a.sync()
        #expect(received.applied >= 2 && received.rejected.isEmpty)
        #expect(try await a.item(item.id).notes == "typed on the phone, on the bus")
        try await home.devices[0].sync()
        let honest = Household(keys: home.keys, devices: [a, b])
        try await honest.settle()
        try await honest.expectConverged()
        #expect(try await a.items().values.contains { $0.title == "Created on the phone" })
    }

    @Test("a device that merged nothing from the revoked device beyond trusted snapshots writes no extra snapshot")
    func noSnapshotWhenNothingIsOwed() async throws {
        let home = await Household.make(3)
        let (a, b, lost) = (home.devices[0], home.devices[1], home.devices[2])
        try await a.save(Household.login(title: "A's"))
        try await home.settle()
        await home.keys.retire(device: await lost.deviceID)
        // The lost device wrote nothing anyone merged.
        #expect(try await a.sync().snapshotsWritten == 0)
        #expect(try await b.sync().snapshotsWritten == 0)
    }

    @Test("a revoked device's own engine publishes nothing")
    func revokedDeviceStops() async throws {
        let home = await Household.make(2)
        let (a, lost) = (home.devices[0], home.devices[1])
        try await home.settle()
        await home.keys.retire(device: await lost.deviceID)
        try await lost.save(Household.login(title: "After revocation"))
        let report = try await lost.sync()
        #expect(report.deviceRevoked && report.segmentsWritten == 0)
        #expect(try await a.sync().applied == 0)
    }

    @Test("a merger for one kind never sees another kind's records")
    func routing() async throws {
        let router = KindRoutingMerger([:])
        let row = StoredRecord(
            recordID: UUID(), kind: .item, vaultID: Household.vault, keyID: UUID(), version: 1, deviceID: UUID(),
            envelope: [1])
        await #expect(throws: KindRoutingMerger.NoMerger(kind: .item)) {
            _ = try await router.merge(local: row, remote: row)
        }
        var other = row
        other.kind = .vaultMetadata
        let home = await Household.make(1)
        let items = KindRoutingMerger([.item: FakeItemMerger(keyring: await home.devices[0].keyring)])
        await #expect(throws: KindRoutingMerger.NoMerger(kind: .vaultMetadata)) {
            _ = try await items.merge(local: row, remote: other)
        }
    }
}

/// A record can be erased more than once, by devices that had each seen something the other had not. Found by the
/// vault simulation (review findings W13, W9): which erasure a device learns of first must decide nothing.
@Suite("Sync engine: several erasures of one record")
struct SyncErasureJoinTests {
    /// The item is in the trash everywhere but on C, which never heard of the trashing; C renames it after a lot of
    /// other work — so its versions are high — and deletes it for good. C's erasure had not seen the trashing, so the
    /// others keep the trashed item as it is. Then the person on B, who sees all of it, deletes it for good. B's
    /// deletion has an earlier stamp than C's, and used to be dropped as "already published": B erased the item,
    /// nobody else ever did.
    @Test("a deletion is published even when another device's later-stamped erasure of the record is known")
    func deletionAfterAnotherDevicesErasure() async throws {
        let home = await Household.make(3)
        let (a, b, c) = (home.devices[0], home.devices[1], home.devices[2])
        let item = try await a.save(Household.login(title: "Printer"))
        try await home.settle()
        try await a.edit(item.id) { $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_100) }
        try await a.sync()
        try await b.sync()

        for index in 0..<4 { try await c.save(Household.login(title: "C \(index)")) }
        try await c.edit(item.id) { $0.title = "Renamed on C" }
        try await c.delete(item.id)
        try await c.sync()
        try await b.sync()
        #expect(try await b.items()[item.id]?.isTrashed == true, "kept: C's erasure had not seen the trashing")

        try await b.delete(item.id)
        try await home.settle()
        for device in home.devices {
            #expect(try await device.items()[item.id] == nil, "B had seen all of it, and deleted it")
        }
        try await home.expectConverged()
    }

    /// A deletes the item after editing it several times (its deletion's stamp is high); B, concurrently, had put it
    /// in the trash (a version with a low number). A's deletion had not seen B's trashing, so the trashed version
    /// is kept everywhere, at its own low version — below A's earlier deletion. The person on A, who now sees it,
    /// deletes it again. That second deletion's stamp is lower than A's first, and used to be dropped as "already
    /// published by this device": the item was gone on A and kept on every other device.
    @Test("a second deletion by the same device, of a version kept after its first, is published")
    func secondDeletionBySameDevice() async throws {
        let home = await Household.make(3)
        let (a, b) = (home.devices[0], home.devices[1])
        let item = try await a.save(Household.login(title: "Printer"))
        try await home.settle()
        for index in 0..<5 { try await a.edit(item.id) { $0.notes = "note \(index)" } }
        try await b.edit(item.id) { $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_100) }
        try await a.delete(item.id)
        try await a.sync()
        try await b.sync()
        try await a.sync()
        let kept = try #require(try await a.items()[item.id], "kept: A's deletion had not seen B's trashing")
        #expect(kept.isTrashed)

        try await a.delete(item.id)
        try await home.settle()
        for device in home.devices {
            #expect(try await device.items()[item.id] == nil, "A had seen all of it, and deleted it")
        }
        try await home.expectConverged()
    }

    /// An erasure that had not seen an edit leaves the item in the trash, kept. The person restores it. The same
    /// erasure then arrives again, in a snapshot written by a device that never held the kept item. It has had its
    /// say: the restored item stays restored.
    @Test("an erasure already applied does not put a restored item back in the trash")
    func restoredItemStaysRestored() async throws {
        let transport = InMemorySyncTransport()
        let home = await Household.make(3, transport: transport)
        let (a, b, c) = (home.devices[0], home.devices[1], home.devices[2])
        let item = try await a.save(Household.login(title: "Printer"))
        try await home.settle()
        try await b.edit(item.id) { $0.notes = "typed on B" }
        try await a.delete(item.id)
        try await a.sync()
        try await b.sync()
        let kept = try #require(try await b.items()[item.id])
        #expect(kept.isTrashed && kept.keptAfterDeletion && kept.notes == "typed on B")
        try await b.edit(item.id) {
            $0.trashedAt = nil
            $0.keptAfterDeletion = false
        }

        // The erasure once more, as a snapshot from C would carry it.
        let key = RecordKey(recordID: item.id, kind: .item)
        let erasure = try #require(await b.state()?.erasures[key])
        let location = SyncObjectLocation.snapshot(vaultID: Household.vault, author: await c.deviceID, lamport: 500)
        let payload = SyncPayload(
            kind: .snapshot, vaultID: Household.vault, author: location.author, number: location.number, vector: [:],
            entries: [.tombstone(key, stamp: erasure.stamp, erasure: erasure.summary)])
        let envelope = try await c.keyring.seal(payload.encoded(), at: location)
        let signature = try await c.keyring.sign(envelope, at: location)
        try await transport.create(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())

        let report = try await b.sync()
        #expect(report.rejected.isEmpty && report.staleSnapshots == 1)
        let after = try #require(try await b.items()[item.id])
        #expect(!after.isTrashed && after.notes == "typed on B")
        try await home.settle()
        try await home.expectConverged()
    }
}
