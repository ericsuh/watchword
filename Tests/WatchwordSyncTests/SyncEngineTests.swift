import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// Simulated devices of one account, sharing a transport (docs/04-test-plan.md §2).
struct Household {
    let keys: FakeAccountKeys
    let devices: [SyncTestClient]

    static let vault = SyncFixtures.vault
    static let deviceIDs = [SyncFixtures.deviceA, SyncFixtures.deviceB, SyncFixtures.deviceC]

    static func make(
        _ count: Int = 2, transport: any SyncTransport = InMemorySyncTransport(),
        configuration: SyncConfiguration = SyncTestClient.configuration
    ) async -> Household {
        let keys = FakeAccountKeys(seed: 99)
        await keys.addVaultKey(vaultID: vault)
        var devices: [SyncTestClient] = []
        for index in 0..<count {
            let id = index < deviceIDs.count ? deviceIDs[index] : UUID()
            await keys.trust(device: id)
            devices.append(
                SyncTestClient(
                    deviceID: id, vaultID: vault, keys: keys, transport: transport, configuration: configuration))
        }
        return Household(keys: keys, devices: devices)
    }

    static func login(_ id: UUID = UUID(), title: String = "Bank", password: String = "hunter22") -> Item {
        Item(
            id: id, vaultID: vault, title: title, scopes: [ServiceScope(host: "firstbank.co.uk")],
            fields: [
                Field(id: MergeFixtures.fieldID(1), kind: .username, label: "Username", value: "pat"),
                Field(id: MergeFixtures.fieldID(2), kind: .password, label: "Password", value: password),
            ])
    }

    /// Syncs every device, round after round, until a full round changes nothing anywhere.
    @discardableResult
    func settle(maximumRounds: Int = 12) async throws -> Int {
        for round in 1...maximumRounds {
            var changed = false
            for device in devices {
                let report = try await device.sync()
                if report.applied > 0 || report.segmentsWritten > 0 || report.snapshotsWritten > 0 { changed = true }
            }
            if !changed { return round }
        }
        Issue.record("did not settle in \(maximumRounds) rounds")
        return maximumRounds
    }

    /// Asserts every device holds the same current state of every item.
    func expectConverged(sourceLocation: SourceLocation = #_sourceLocation) async throws {
        let reference = try await devices[0].items().mapValues(MergeFixtures.current)
        for device in devices.dropFirst() {
            #expect(
                try await device.items().mapValues(MergeFixtures.current) == reference, sourceLocation: sourceLocation)
        }
    }
}

@Suite("Sync engine")
struct SyncEngineTests {
    @Test("an item saved on one device reaches another")
    func basic() async throws {
        let home = await Household.make()
        let (a, b) = (home.devices[0], home.devices[1])
        let saved = try await a.save(Household.login())
        let pushed = try await a.sync()
        #expect(pushed.segmentsWritten == 1 && pushed.pushedEntries == 1)
        let pulled = try await b.sync()
        #expect(pulled.applied == 1 && pulled.rejected.isEmpty)
        #expect(try await b.item(saved.id) == saved)
        #expect(try await b.sync().applied == 0, "a second sync changes nothing")
    }

    /// Found by the long simulation: when the merge kept a local version (it already contained a higher remote one —
    /// here a no-op save on a device with a slower clock), the local version was never published, because the outbox
    /// compared rows with the highest stamp seen rather than with what this device had published.
    @Test("a local version kept over a higher remote version is still published")
    func keptLocalVersionIsPublished() async throws {
        let home = await Household.make(3)
        let (a, b, c) = (home.devices[0], home.devices[1], home.devices[2])
        let item = try await b.save(Household.login())
        try await b.sync()
        try await a.sync()
        // B's versions climb through C's items without B's clock moving; A's clock moves without its versions passing B's.
        for index in 0..<10 { try await c.save(Household.login(title: "C \(index)")) }
        try await c.sync()
        try await b.sync()
        for index in 0..<4 { try await a.save(Household.login(title: "A \(index)")) }
        try await a.edit(item.id) { $0.notes = "only on A" }
        try await b.edit(item.id) { _ in }  // A no-op save: a higher version that changes nothing.
        try await b.sync()
        let report = try await a.sync()
        #expect(report.pushedEntries == 5)
        try await home.settle()
        #expect(try await b.item(item.id).notes == "only on A")
        try await home.expectConverged()
    }

    /// Found by the long simulation: a device that deleted an item, and before publishing the deletion merged an
    /// older version of it (here by replaying the log), put the item back on itself only — everyone else applied the
    /// tombstone. Unpublished deletions count as tombstones.
    @Test("an unpublished local deletion is not undone by an older version merged before it is published")
    func pendingDeletionBeatsOlderVersions() async throws {
        let home = await Household.make()
        let (a, b) = (home.devices[0], home.devices[1])
        let item = try await b.save(Household.login())
        try await home.settle()
        try await a.delete(item.id)
        try await a.sync(reconcile: true)
        try await home.settle()
        #expect(try await a.items().isEmpty)
        #expect(try await b.items().isEmpty)
    }

    @Test("while locked a device downloads and checks; it merges on unlock with no network (§7.4)")
    func lockedDownload() async throws {
        let server = SimulatedServer(seed: 3, maximumVisibilityDelay: 0, duplicateListings: false)
        let keys = FakeAccountKeys(seed: 5)
        await keys.addVaultKey(vaultID: Household.vault)
        let ids = Household.deviceIDs
        for id in ids { await keys.trust(device: id) }
        let a = SyncTestClient(
            deviceID: ids[0], vaultID: Household.vault, keys: keys, transport: await server.transport(for: ids[0]))
        let b = SyncTestClient(
            deviceID: ids[1], vaultID: Household.vault, keys: keys, transport: await server.transport(for: ids[1]))
        let item = try await a.save(Household.login())
        try await a.sync()

        await b.keyring.lock()
        let locked = try await b.sync()
        #expect(locked.deferredUntilUnlock)
        #expect(locked.fetched == 1)
        #expect(try await b.items().isEmpty)

        await server.setOffline(ids[1], true)
        await b.keyring.unlock()
        let offline = try await b.sync()
        #expect(offline.transportUnavailable)
        #expect(offline.applied == 1)
        #expect(try await b.item(item.id) == item)
    }

    @Test("snapshots let old segments be collected and a new device join from them")
    func snapshotsAndCollection() async throws {
        let transport = InMemorySyncTransport()
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 4
        let home = await Household.make(2, transport: transport, configuration: configuration)
        let (a, b) = (home.devices[0], home.devices[1])
        var ids: [UUID] = []
        var collected = 0
        var snapshots = 0
        for index in 0..<12 {
            ids.append(try await a.save(Household.login(title: "Item \(index)")).id)
            for device in [a, b] {
                let report = try await device.sync()
                collected += report.collected
                snapshots += report.snapshotsWritten
            }
        }
        for _ in 0..<3 {
            for device in [a, b] { collected += try await device.sync().collected }
        }
        #expect(snapshots > 0)
        #expect(collected > 0)
        let segmentsOfA = await transport.list(prefix: "vault/").filter {
            $0.contains("/log/\(SyncFixtures.deviceA.uuidString)/")
        }
        #expect(segmentsOfA.count < 12, "A's covered segments were deleted")

        await home.keys.trust(device: SyncFixtures.deviceC)
        let c = SyncTestClient(
            deviceID: SyncFixtures.deviceC, vaultID: Household.vault, keys: home.keys, transport: transport,
            configuration: configuration)
        let joined = try await c.sync()
        #expect(joined.rejected.isEmpty && joined.waiting.isEmpty)
        #expect(Set(try await c.items().keys) == Set(ids))
    }

    @Test("reconciling a healthy device changes nothing")
    func reconcileIsIdempotent() async throws {
        let home = await Household.make()
        let (a, b) = (home.devices[0], home.devices[1])
        let item = try await a.save(Household.login())
        try await b.save(Household.login(title: "Other"))
        try await home.settle()
        try await a.edit(item.id) { $0.title = "Renamed" }
        try await home.settle()
        let before = try await b.items()
        let report = try await b.sync(reconcile: true)
        #expect(report.applied == 0)
        #expect(report.segmentsWritten == 0)
        #expect(try await b.items() == before)
    }

    @Test("a device whose next sequence number is taken never overwrites it, and recovers")
    func ownStreamConflict() async throws {
        // Eventually consistent: neither installation sees the other's segment when it next publishes.
        let server = SimulatedServer(seed: 8, maximumVisibilityDelay: 100, duplicateListings: false)
        let keys = FakeAccountKeys(seed: 6)
        await keys.addVaultKey(vaultID: Household.vault)
        await keys.trust(device: SyncFixtures.deviceA)
        let a = SyncTestClient(
            deviceID: SyncFixtures.deviceA, vaultID: Household.vault, keys: keys,
            transport: await server.transport(for: SyncFixtures.deviceA))
        // A second installation with the same device ID: a restored backup.
        let clone = SyncTestClient(
            deviceID: SyncFixtures.deviceA, vaultID: Household.vault, keys: keys,
            transport: await server.transport(for: UUID()))
        let first = try await a.save(Household.login(title: "From A"))
        let second = try await clone.save(Household.login(title: "From the clone"))
        try await a.sync()
        let conflicted = try await clone.sync()
        #expect(conflicted.ownStreamConflict == 1)
        #expect(conflicted.segmentsWritten == 0)
        let stored = await server.allObjects
        #expect(stored.count == 1, "A's segment was not overwritten")

        await server.heal()
        let recovered = try await clone.sync()
        #expect(recovered.ownStreamConflict == 1, "merging the foreign segment in its own stream is reported")
        #expect(recovered.segmentsWritten == 1)
        await server.heal()
        try await a.sync()
        #expect(Set(try await a.items().keys) == [first.id, second.id])
        #expect(Set(try await clone.items().keys) == [first.id, second.id])
    }
}
