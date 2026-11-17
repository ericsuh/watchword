import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// A store that lost everything it held (docs/02-architecture.md §7.10; owner decision, 2026-11-17: re-upload, "but
/// ask the user first"): what the engine notices, what it refuses to do unasked, and what `sync(handingOn: true)`,
/// the person's answer, uploads. The engine here runs over fakes; `VaultStoreResetTests` runs real sessions.
@Suite("Store reset: the engine")
struct SyncStoreResetTests {
    /// Three devices whose vault holds one item written by each of the first two, all in sync.
    static func settled(_ count: Int = 2, transport: InMemorySyncTransport = InMemorySyncTransport()) async throws
        -> (home: Household, transport: InMemorySyncTransport, ids: [UUID])
    {
        let home = await Household.make(count, transport: transport)
        var ids: [UUID] = []
        for (index, device) in home.devices.prefix(2).enumerated() {
            ids.append(try await device.save(Household.login(title: "Item \(index)")).id)
        }
        try await home.settle()
        return (home, transport, ids)
    }

    static func newcomer(_ home: Household, on transport: any SyncTransport, id: UUID = UUID()) async
        -> SyncTestClient
    {
        await home.keys.trust(device: id)
        return SyncTestClient(deviceID: id, vaultID: Household.vault, keys: home.keys, transport: transport)
    }

    static func titles(_ device: SyncTestClient) async throws -> Set<String> {
        Set(try await device.items().values.map(\.title))
    }

    @Test("after a reset no sync uploads again what the store held, however often it runs, replays included")
    func nothingUnasked() async throws {
        let (home, transport, _) = try await Self.settled()
        await transport.removeEverything()
        for round in 0..<4 {
            for device in home.devices {
                let report = try await device.sync(reconcile: round == 2)
                #expect(report.storeLacksObjects && report.snapshotsWritten == 0 && report.segmentsWritten == 0)
                #expect(report.replayPostponed == (round == 2))
            }
        }
        #expect(await transport.allObjects.isEmpty)
        for device in home.devices {
            #expect(try await Self.titles(device) == ["Item 0", "Item 1"])
            #expect(await device.state()?.storeResetSuspected == true)
        }
    }

    @Test("a store that never held anything is not a reset: a first sync publishes as ever")
    func neverSetUp() async throws {
        let home = await Household.make(1)
        try await home.devices[0].save(Household.login())
        let report = try await home.devices[0].sync()
        #expect(!report.storeLacksObjects && report.segmentsWritten == 1)
    }

    @Test("on the person's answer one device hands on everything, and a new device reads all of it")
    func handOn() async throws {
        let (home, transport, _) = try await Self.settled()
        let (a, b) = (home.devices[0], home.devices[1])
        await transport.removeEverything()
        let before = await a.state()
        let report = try await a.engine.sync(handingOn: true)
        #expect(report.snapshotsWritten == 1 && report.segmentsWritten == 0 && !report.storeLacksObjects)
        #expect(report.reuploadRefused == nil)
        let names = await transport.allObjects.keys
        #expect(names.count == 1 && names.allSatisfy { SyncObjectLocation(name: $0)?.kind == .snapshot })

        // Sequence numbers go on; nothing this device knew is forgotten.
        let after = try #require(await a.state())
        #expect(after.nextSequence == before?.nextSequence && after.published == before?.published)
        #expect(after.merged == before?.merged && after.known == before?.known)

        let c = await Self.newcomer(home, on: transport)
        let joined = try await c.sync()
        #expect(joined.rejected.isEmpty && joined.waiting.isEmpty && !joined.storeLacksObjects)
        #expect(try await Self.titles(c) == ["Item 0", "Item 1"])

        // B was in step with A: the snapshot stands for all B holds, so it is asked nothing and goes on.
        let returning = try await b.sync()
        #expect(!returning.storeLacksObjects && returning.snapshotsWritten == 0 && returning.segmentsWritten == 0)
        try await b.save(Household.login(title: "After the reset"))
        #expect(try await b.sync().segmentsWritten == 1)
        try await Household(keys: home.keys, devices: [a, b, c]).settle()
        for device in [a, b, c] {
            #expect(try await Self.titles(device) == ["Item 0", "Item 1", "After the reset"])
        }
    }

    @Test("asked twice, a device hands on once")
    func handOnOnce() async throws {
        let (home, transport, _) = try await Self.settled()
        await transport.removeEverything()
        #expect(try await home.devices[0].engine.sync(handingOn: true).snapshotsWritten == 1)
        #expect(try await home.devices[0].engine.sync(handingOn: true).snapshotsWritten == 0)
        let snapshots = await transport.allObjects.keys.filter { SyncObjectLocation(name: $0)?.kind == .snapshot }
        #expect(snapshots.count == 1)
    }

    @Test("a device that was offline and holds more is asked, and until it answers its new edits wait behind a gap")
    func offlineDeviceWithMore() async throws {
        let (home, transport, _) = try await Self.settled()
        let (a, b) = (home.devices[0], home.devices[1])
        // B publishes an edit A never merges; then the store is reset and A starts it again.
        try await b.save(Household.login(title: "Only B has this"))
        try await b.sync()
        await transport.removeEverything()
        try await a.engine.sync(handingOn: true)

        try await b.save(Household.login(title: "Written after"))
        let asked = try await b.sync()
        #expect(asked.storeLacksObjects && asked.snapshotsWritten == 0 && asked.segmentsWritten == 1)
        let c = await Self.newcomer(home, on: transport)
        let waiting = try await c.sync()
        #expect(waiting.waiting[SyncFixtures.deviceB] != nil)
        #expect(try await Self.titles(c) == ["Item 0", "Item 1"])

        let answered = try await b.engine.sync(handingOn: true)
        #expect(answered.snapshotsWritten == 1 && !answered.storeLacksObjects)
        try await Household(keys: home.keys, devices: [a, b, c]).settle()
        for device in [a, b, c] {
            #expect(try await Self.titles(device) == ["Item 0", "Item 1", "Only B has this", "Written after"])
            #expect(try await device.sync().waiting.isEmpty)
        }
    }

    @Test("two devices handing on converge in either order", arguments: [false, true])
    func eitherOrder(_ reversed: Bool) async throws {
        let (home, transport, ids) = try await Self.settled()
        let (a, b) = (home.devices[0], home.devices[1])
        // Each holds something the other lacks, and both edit the same item.
        try await a.edit(ids[0]) { $0.title = "A's title" }
        try await a.sync()
        try await b.edit(ids[0]) { $0.fields[1].value = "B's password" }
        try await b.save(Household.login(title: "B alone"))
        try await b.sync()
        await transport.removeEverything()
        let order = reversed ? [b, a] : [a, b]
        // The second writes a snapshot only if it holds something the first's does not stand for: B had merged
        // everything of A's, A nothing of B's latest.
        #expect(try await order[0].engine.sync(handingOn: true).snapshotsWritten == 1)
        #expect(try await order[1].engine.sync(handingOn: true).snapshotsWritten == (reversed ? 0 : 1))
        let c = await Self.newcomer(home, on: transport)
        let everyone = Household(keys: home.keys, devices: [a, b, c])
        try await everyone.settle()
        try await everyone.expectConverged()
        let item = try await c.item(ids[0])
        #expect(item.title == "A's title" && item.fields[1].value == "B's password")
        #expect(try await Self.titles(c).contains("B alone"))
        for device in [a, b, c] { #expect(try await device.sync().waiting.isEmpty) }
    }

    @Test("two devices that upload at once, neither seeing the other's snapshot, converge")
    func concurrentUploads() async throws {
        let server = SimulatedServer(seed: 42, maximumVisibilityDelay: 0, duplicateListings: false)
        let keys = FakeAccountKeys(seed: 99)
        await keys.addVaultKey(vaultID: Household.vault)
        var devices: [SyncTestClient] = []
        for id in Household.deviceIDs {
            await keys.trust(device: id)
            devices.append(
                SyncTestClient(
                    deviceID: id, vaultID: Household.vault, keys: keys, transport: await server.transport(for: id)))
        }
        let home = Household(keys: keys, devices: devices)
        let (a, b, c) = (devices[0], devices[1], devices[2])
        let shared = try await a.save(Household.login(title: "Shared"))
        try await home.settle()
        try await a.edit(shared.id) { $0.title = "A's title" }
        try await a.save(Household.login(title: "A alone"))
        try await a.sync()
        try await b.edit(shared.id) { $0.fields[1].value = "B's password" }
        try await b.save(Household.login(title: "B alone"))
        try await b.sync()

        await server.removeEverything()
        // From here a new object is seen by other devices only after the partition heals.
        await server.setVisibilityDelay(1_000)
        #expect(try await a.engine.sync(handingOn: true).snapshotsWritten == 1)
        #expect(
            try await server.transport(for: SyncFixtures.deviceB).list(prefix: "vault/").isEmpty,
            "B must not see it yet")
        #expect(try await b.engine.sync(handingOn: true).snapshotsWritten == 1)
        await server.heal()
        try await home.settle()
        try await home.expectConverged()
        #expect(
            try await Self.titles(c) == ["A's title", "A alone", "B alone"])
        #expect(try await c.item(shared.id).fields[1].value == "B's password")
        for device in devices { #expect(try await device.sync().waiting.isEmpty) }
    }

    @Test("a device whose own stream another device's upload stands for is still asked about a third stream")
    func thirdStreamHidden() async throws {
        let (home, transport, _) = try await Self.settled(3)
        let (a, b, c) = (home.devices[0], home.devices[1], home.devices[2])
        // C writes; only B merges it. Then C is gone for good and the store is reset.
        try await c.save(Household.login(title: "From C, seen by B alone"))
        try await c.sync()
        try await b.sync()
        await transport.removeEverything()
        try await a.engine.sync(handingOn: true)

        let asked = try await b.sync()
        #expect(asked.storeLacksObjects, "A's snapshot covers B's own stream, and B still holds more of C's")
        #expect(asked.snapshotsWritten == 0)
        try await b.engine.sync(handingOn: true)
        let d = await Self.newcomer(home, on: transport)
        try await d.sync()
        #expect(try await Self.titles(d).contains("From C, seen by B alone"))
    }

    @Test("a second reset after an upload is noticed by the missing snapshot, and nothing is uploaded unasked")
    func secondReset() async throws {
        let (home, transport, _) = try await Self.settled()
        let (a, b) = (home.devices[0], home.devices[1])
        await transport.removeEverything()
        try await a.engine.sync(handingOn: true)
        #expect(try await a.sync().storeLacksObjects == false)
        let first = Set(await transport.allObjects.keys)
        // B merges A's snapshot and writes something only B holds; A merges it; then the store is reset again.
        try await b.save(Household.login(title: "Between the resets"))
        try await home.settle()
        await transport.removeEverything()
        let report = try await a.sync()
        #expect(report.storeLacksObjects && report.snapshotsWritten == 0)
        #expect(await transport.allObjects.isEmpty)
        #expect(try await a.engine.sync(handingOn: true).snapshotsWritten == 1)
        // The second snapshot has a name of its own: B, which merged the first, reads it like any new object.
        let second = Set(await transport.allObjects.keys)
        #expect(first.isDisjoint(with: second))
        let c = await Self.newcomer(home, on: transport)
        try await c.sync()
        #expect(try await Self.titles(c) == ["Item 0", "Item 1", "Between the resets"])
    }

    @Test("an upload after a second reset is never named as the first was, even with nothing written in between")
    func snapshotNamesAreNotReused() async throws {
        let (home, transport, _) = try await Self.settled()
        let (a, b) = (home.devices[0], home.devices[1])
        var names: [String] = []
        for _ in 0..<3 {
            await transport.removeEverything()
            #expect(try await a.engine.sync(handingOn: true).snapshotsWritten == 1)
            names += await transport.allObjects.keys.filter { SyncObjectLocation(name: $0)?.kind == .snapshot }
            #expect(try await b.sync().rejected.isEmpty)
        }
        #expect(Set(names).count == 3)
    }

    @Test("a deletion not yet published goes out as a tombstone after the upload, and erases elsewhere")
    func pendingDeletion() async throws {
        let (home, transport, ids) = try await Self.settled()
        let (a, b) = (home.devices[0], home.devices[1])
        try await a.delete(ids[1])
        await transport.removeEverything()
        let report = try await a.engine.sync(handingOn: true)
        #expect(report.snapshotsWritten == 1 && report.segmentsWritten == 1)
        try await b.sync()
        #expect(try await Self.titles(b) == ["Item 0"])
        let c = await Self.newcomer(home, on: transport)
        try await c.sync()
        #expect(try await Self.titles(c) == ["Item 0"])
    }

    @Test("an erasure this device had merged travels in the upload, so an older copy does not come back")
    func mergedErasure() async throws {
        let (home, transport, ids) = try await Self.settled(3)
        let (a, b, c) = (home.devices[0], home.devices[1], home.devices[2])
        // C is offline while B deletes an item and A merges the deletion.
        try await b.delete(ids[0])
        try await b.sync()
        try await a.sync()
        await transport.removeEverything()
        try await a.engine.sync(handingOn: true)
        try await c.sync()
        #expect(try await Self.titles(c) == ["Item 1"])
    }

    @Test("versions held aside stay where they are: neither uploaded nor dropped")
    func quarantineStays() async throws {
        let (home, transport, _) = try await Self.settled()
        let a = home.devices[0]
        let held = SyncFixtures.entry(9, version: 1 << 40, device: SyncFixtures.deviceB)
        await a.syncState.quarantine(held, vaultID: Household.vault)
        await transport.removeEverything()
        try await a.engine.sync(handingOn: true)
        #expect(await a.syncState.quarantined(vaultID: Household.vault) == [held])
        let c = await Self.newcomer(home, on: transport)
        try await c.sync()
        #expect(try await c.items()[held.recordID] == nil)
        #expect(await c.syncState.quarantined(vaultID: Household.vault).isEmpty)
    }

    @Test("a device holding entries it cannot read keeps them, and its upload covers its own stream alone")
    func stashIsKept() async throws {
        let home = await VersionedHousehold.make()
        let item = try await home.later.save(Household.login())
        try await home.scan(item, "result")
        try await home.later.sync()
        try await home.earlier.save(Household.login(title: "Earlier's"))
        try await home.earlier.sync()
        try await home.later.sync()
        let stash = await home.earlier.stash()
        #expect(stash.count == 1)

        await home.transport.removeEverything()
        let report = try await home.earlier.engine.sync(handingOn: true)
        #expect(report.snapshotsWritten == 1 && report.snapshotWithheldBy == [home.laterID])
        #expect(await home.earlier.stash() == stash)

        // A reader passes the gap in the uploader's stream and waits at the other, whose device holds what the
        // uploader could not carry.
        let reader = await home.newcomer()
        try await reader.sync()
        #expect(try await Self.titles(reader) == ["Bank", "Earlier's"])
        #expect(try await VersionedHousehold.rows(reader, .scanStatus).isEmpty)
        let merged = try #require(await reader.state()?.merged)
        #expect(merged[home.earlierID] == 1 && merged[home.laterID] == nil)
        let asked = try await home.later.sync()
        #expect(asked.storeLacksObjects)
        try await home.later.engine.sync(handingOn: true)
        try await reader.sync()
        #expect(try await VersionedHousehold.rows(reader, .scanStatus).count == 1)
        // The uploader is not asked again for what it cannot carry.
        #expect(try await home.earlier.sync().storeLacksObjects == false)
    }

    @Test("a vault that keeps its whole log refuses, uploads nothing and drops nothing")
    func wholeLogVaultRefuses() async throws {
        let transport = InMemorySyncTransport()
        var configuration = SyncTestClient.configuration
        configuration.maintainsLog = false
        let home = await Household.make(2, transport: transport, configuration: configuration)
        try await home.devices[0].save(Household.login())
        try await home.settle()
        await transport.removeEverything()
        let unasked = try await home.devices[0].sync()
        #expect(unasked.storeLacksObjects && unasked.reuploadRefused == .sharedVault)
        let asked = try await home.devices[0].engine.sync(handingOn: true)
        #expect(asked.reuploadRefused == .sharedVault && asked.snapshotsWritten == 0 && asked.segmentsWritten == 0)
        #expect(await transport.allObjects.isEmpty)
        #expect(try await Self.titles(home.devices[0]) == ["Bank"])
    }

    @Test("an honest store never raises the question: snapshots, collection and a restored state included")
    func honestStore() async throws {
        let transport = InMemorySyncTransport()
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 4
        let home = await Household.make(3, transport: transport, configuration: configuration)
        var early: SyncState?
        var collected = 0
        for round in 0..<16 {
            try await home.devices[round % 3].save(Household.login(title: "Item \(round)"))
            for device in home.devices {
                let report = try await device.sync()
                #expect(!report.storeLacksObjects && report.reuploadRefused == nil)
                collected += report.collected
            }
            if round == 5 { early = await home.devices[0].state() }
        }
        #expect(collected > 0)
        // A's state file restored from a backup: it remembers segments its later self collected. Not a reset.
        await home.devices[0].syncState.tamper(try #require(early))
        for _ in 0..<3 {
            for device in home.devices {
                let report = try await device.sync()
                #expect(!report.storeLacksObjects)
            }
        }
        #expect(await home.devices[0].state()?.storeResetSuspected == false)
        try await home.expectConverged()
    }

    @Test("a replay asked for while the store cannot be listed is postponed, and the state kept")
    func replayPostponedOffline() async throws {
        let (home, _, _) = try await Self.settled()
        let a = home.devices[0]
        let before = await a.state()
        let report = try await a.engine.sync(reconcile: true, transportStopped: .unavailable)
        #expect(report.replayPostponed && report.transportUnavailable)
        #expect(await a.state() == before)
        let replayed = try await a.sync(reconcile: true)
        #expect(!replayed.replayPostponed && replayed.segmentsWritten == 0)
    }

    @Test("after an upload a replay rebuilds from the snapshot and publishes nothing again")
    func replayAfterUpload() async throws {
        let (home, transport, _) = try await Self.settled()
        let (a, b) = (home.devices[0], home.devices[1])
        await transport.removeEverything()
        try await a.engine.sync(handingOn: true)
        try await home.settle()
        let objects = await transport.allObjects.count
        for device in [a, b] {
            let report = try await device.sync(reconcile: true)
            #expect(!report.replayPostponed && report.segmentsWritten == 0 && report.snapshotsWritten == 0)
            #expect(!report.storeLacksObjects)
        }
        #expect(await transport.allObjects.count == objects)
        try await home.expectConverged()
    }

    @Test("what the engine remembers about a reset survives the state's encoding")
    func encoding() throws {
        var state = SyncState(vaultID: SyncFixtures.vault)
        state.collectedThrough = 7
        state.storeResetSuspected = true
        state.highestOwnSnapshot = 9
        state.handedOn = HandedOn(
            snapshot: .snapshot(vaultID: SyncFixtures.vault, author: SyncFixtures.deviceA, lamport: 9),
            holding: [SyncFixtures.deviceA: 7, SyncFixtures.deviceB: 3])
        let data = try JSONEncoder().encode(EncodedState(state))
        #expect(try JSONDecoder().decode(EncodedState.self, from: data).state == state)
        // A row from before any of it was kept: the fields are absent.
        let bare = SyncState(vaultID: SyncFixtures.vault)
        let json = String(decoding: try JSONEncoder().encode(EncodedState(bare)), as: UTF8.self)
        var old = json
        for field in ["\"storeResetSuspected\":false", "\"highestOwnSnapshot\":0"] {
            old = old.replacingOccurrences(of: field + ",", with: "").replacingOccurrences(of: "," + field, with: "")
        }
        #expect(!old.contains("storeResetSuspected") && !old.contains("highestOwnSnapshot"))
        #expect(old != json && !old.contains("collectedThrough") && !old.contains("handedOn"))
        #expect(try JSONDecoder().decode(EncodedState.self, from: Data(old.utf8)).state == bare)
    }
}
