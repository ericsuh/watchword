import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

// Regression tests for the independent review of milestone 3 (docs/06-adversarial-review.md §H, Y8–Y12). Each was a
// reproduction of a failure before its fix.

/// A store that, once armed, runs a session deletion of `key` the moment the engine reads it.
actor HookStore: RecordStore {
    let base: InMemoryRecordStore
    var session: DeletionRecordingStore?
    var armedKey: RecordKey?

    init(base: InMemoryRecordStore) { self.base = base }
    func setSession(_ s: DeletionRecordingStore) { session = s }
    func arm(_ key: RecordKey) { armedKey = key }

    func loadAccount() async throws -> AccountRecord? { await base.loadAccount() }
    func record(_ key: RecordKey) async throws -> StoredRecord? {
        if key == armedKey, let session {
            armedKey = nil
            if let row = await base.record(key) {
                try await session.commit(StoreChange(conditionalDeletions: [key: row.version]))
            }
        }
        return await base.record(key)
    }
    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        await base.records(in: vaultID, kind: kind)
    }
    func commit(_ change: StoreChange) async throws { try await base.commit(change) }
    func eraseAll() async throws { await base.eraseAll() }
}

/// A transport view that hides some names from fetch (deleted between list and fetch).
actor HidingTransport: SyncTransport {
    let base: InMemorySyncTransport
    var hidden: Set<String> = []
    init(base: InMemorySyncTransport) { self.base = base }
    func hide(_ names: Set<String>) { hidden = names }
    func list(prefix: String) async throws -> [String] { await base.list(prefix: prefix) }
    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        if hidden.contains(name) { return nil }
        return try await base.fetch(name, maximumLength: maximumLength)
    }
    func create(_ name: String, contents: [UInt8]) async throws { try await base.create(name, contents: contents) }
    func delete(_ name: String) async throws { await base.delete(name) }
}

actor PartitionView: SyncTransport {
    let base: InMemorySyncTransport
    var baseline: Set<String> = []
    var mine: Set<String> = []
    var partitioned = false
    var alwaysHidden: Set<String> = []
    init(base: InMemorySyncTransport) { self.base = base }
    func partition() async {
        baseline = Set(await base.list(prefix: ""))
        partitioned = true
    }
    func heal() { partitioned = false }
    func hideForever(_ names: Set<String>) { alwaysHidden = names }
    func visible(_ name: String) -> Bool {
        if alwaysHidden.contains(name) { return false }
        return !partitioned || baseline.contains(name) || mine.contains(name)
    }
    func list(prefix: String) async throws -> [String] { await base.list(prefix: prefix).filter(visible) }
    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        guard visible(name) else { return nil }
        return try await base.fetch(name, maximumLength: maximumLength)
    }
    func create(_ name: String, contents: [UInt8]) async throws {
        try await base.create(name, contents: contents)
        mine.insert(name)
    }
    func delete(_ name: String) async throws { await base.delete(name) }
}

@Suite("Sync review regressions")
struct SyncReviewRegressionTests {
    static let vault = SyncFixtures.vault
    static let a = SyncFixtures.deviceA
    static let b = SyncFixtures.deviceB
    static let c = SyncFixtures.deviceC

    /// Device B built by hand so its engine reads through `HookStore`, which deletes a record (as the person would)
    /// at the moment the engine reads it.
    static func racingDevice(keys: FakeAccountKeys, transport: any SyncTransport) async
        -> (SyncEngine, InMemoryRecordStore, HookStore)
    {
        let base = InMemoryRecordStore()
        let state = InMemorySyncStateStore()
        let hook = HookStore(base: base)
        await hook.setSession(DeletionRecordingStore(base: base, syncState: state, deviceID: b))
        let keyring = FakeSyncKeyring(deviceID: b, keys: keys)
        let engine = SyncEngine(
            vaultID: vault, deviceID: b, store: hook, syncState: state, transport: transport, keyring: keyring,
            merger: FakeItemMerger(keyring: keyring), configuration: SyncTestClient.configuration)
        return (engine, base, hook)
    }

    @Test(
        "Y10: a deletion made while sync merges the same record leaves every device agreeing", arguments: [false, true])
    func deletionDuringMerge(_ reconciling: Bool) async throws {
        let keys = FakeAccountKeys(seed: 5)
        await keys.addVaultKey(vaultID: Self.vault)
        await keys.trust(device: Self.a)
        await keys.trust(device: Self.b)
        let transport = InMemorySyncTransport()
        let deviceA = SyncTestClient(deviceID: Self.a, vaultID: Self.vault, keys: keys, transport: transport)
        let (engineB, baseB, hook) = await Self.racingDevice(keys: keys, transport: transport)
        let item = try await deviceA.save(Household.login())
        try await deviceA.sync()
        _ = try await engineB.sync()
        if !reconciling {
            try await deviceA.edit(item.id) { $0.notes = "edited on A" }
            try await deviceA.sync()
        }
        await hook.arm(RecordKey(recordID: item.id, kind: .item))
        _ = try await engineB.sync(reconcile: reconciling)
        for _ in 0..<3 {
            try await deviceA.sync()
            _ = try await engineB.sync()
        }
        let key = RecordKey(recordID: item.id, kind: .item)
        let onA = try await deviceA.items()[item.id]
        let rowB = await baseB.record(key)
        #expect((onA == nil) == (rowB == nil), "both devices erased it, or both kept it")
    }

    @Test("Y9: a device that merged a snapshot and then lost a covered segment does not wait forever")
    func gapCoveredBySnapshot() async throws {
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 4
        let keys = FakeAccountKeys(seed: 6)
        await keys.addVaultKey(vaultID: Self.vault)
        for device in [Self.a, Self.b, Self.c] { await keys.trust(device: device) }
        let transport = InMemorySyncTransport()
        let hiding = HidingTransport(base: transport)
        let deviceA = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: keys, transport: transport, configuration: configuration)
        let deviceB = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: keys, transport: transport, configuration: configuration)
        let deviceC = SyncTestClient(
            deviceID: Self.c, vaultID: Self.vault, keys: keys, transport: hiding, configuration: configuration)
        try await deviceB.save(Household.login(title: "B's item"))
        try await deviceB.sync()
        var ids: [UUID] = []
        for index in 0..<3 {
            ids.append(try await deviceA.save(Household.login(title: "A \(index)")).id)
            try await deviceA.sync()
        }
        await hiding.hide([SyncObjectLocation.segment(vaultID: Self.vault, author: Self.a, sequence: 2).name])
        try await deviceC.sync()
        await hiding.hide([])
        for _ in 0..<2 {
            try await deviceB.sync()
            try await deviceA.sync()
        }
        try await deviceA.edit(ids[0]) { $0.title = "Edited later" }
        try await deviceA.sync()
        var last = SyncReport()
        for _ in 0..<3 { last = try await deviceC.sync() }
        #expect(last.waiting.isEmpty)
        #expect(try await deviceC.item(ids[0]).title == "Edited later")
    }

    @Test("Y8: a device whose sync state is rolled back never reuses a sequence number, and its edits arrive")
    func rolledBackState() async throws {
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 4
        let home = await Household.make(2, configuration: configuration)
        let (a, b) = (home.devices[0], home.devices[1])
        let first = try await a.save(Household.login(title: "First"))
        try await a.sync()
        try await b.sync()
        let early = try #require(await a.state())
        var collected = 0
        for index in 0..<8 {
            try await a.save(Household.login(title: "Item \(index)"))
            collected += try await a.sync().collected
            try await b.sync()
        }
        for _ in 0..<4 {
            collected += try await a.sync().collected
            try await b.sync()
        }
        #expect(collected > 0, "the scenario needs collected segments")
        await a.syncState.tamper(early)  // A restored backup, or A8, rolls back the sync state only.
        try await a.edit(first.id) { $0.title = "Edited after restore" }
        let report = try await a.sync()
        #expect(report.segmentsWritten == 1)
        try await home.settle()
        #expect(try await b.item(first.id).title == "Edited after restore")
        for index in 0..<5 {
            try await a.edit(first.id) { $0.notes = "tail \(index)" }
            #expect(try await a.sync().ownStreamConflict == nil)
        }
        try await b.sync()
        #expect(try await b.item(first.id).notes == "tail 4")
    }

    @Test("Y12: a junk object under the vault's prefix does not stop snapshots or garbage collection")
    func junkDoesNotBlockSnapshots() async throws {
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 4
        let transport = InMemorySyncTransport()
        let home = await Household.make(2, transport: transport, configuration: configuration)
        let (a, b) = (home.devices[0], home.devices[1])
        let junk = SyncObjectLocation.segment(vaultID: Household.vault, author: UUID(), sequence: 1).name
        await transport.tamper(junk, contents: [1, 2, 3])
        var snapshots = 0
        var collected = 0
        for index in 0..<20 {
            try await a.save(Household.login(title: "Item \(index)"))
            for device in [a, b] {
                let report = try await device.sync()
                snapshots += report.snapshotsWritten
                collected += report.collected
            }
        }
        #expect(snapshots > 0)
        #expect(collected > 0)
    }

    @Test("Y9: snapshots that cover different streams do not strand a device joining later")
    func incomparableSnapshots() async throws {
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 4
        let keys = FakeAccountKeys(seed: 11)
        await keys.addVaultKey(vaultID: Household.vault)
        let (idA, idB, idC) = (Self.a, Self.b, Self.c)
        for device in [idA, idB, idC] { await keys.trust(device: device) }
        let base = InMemorySyncTransport()
        let viewA = PartitionView(base: base)
        let viewB = PartitionView(base: base)
        let a = SyncTestClient(
            deviceID: idA, vaultID: Household.vault, keys: keys, transport: viewA, configuration: configuration)
        let b = SyncTestClient(
            deviceID: idB, vaultID: Household.vault, keys: keys, transport: viewB, configuration: configuration)
        let x = try await b.save(Household.login(title: "X"))
        try await b.sync()
        var aItems = [try await a.save(Household.login(title: "A0")).id]
        try await a.sync()
        try await b.sync()
        try await a.sync()

        await viewA.partition()
        await viewB.partition()
        for index in 1...3 {
            aItems.append(try await a.save(Household.login(title: "A\(index)")).id)
            try await a.sync()
        }
        for index in 1...40 {
            try await b.edit(x.id) { $0.notes = "b \(index)" }
            if try await b.sync().snapshotsWritten > 0 { break }
        }
        let snapshotsByB = Set(
            await base.list(prefix: "").filter { $0.contains("/snapshot/") && $0.hasSuffix(idB.uuidString) })
        await viewA.heal()
        await viewB.heal()
        await viewA.hideForever(snapshotsByB)
        for round in 0..<3 {
            if round > 0 { try await b.edit(x.id) { $0.notes = "after heal \(round)" } }
            try await b.sync()
            try await a.sync()
        }
        await viewA.hideForever([])
        for _ in 0..<3 {
            try await a.sync()
            try await b.sync()
        }
        let c = SyncTestClient(
            deviceID: idC, vaultID: Household.vault, keys: keys, transport: base, configuration: configuration)
        let joined = try await c.sync()
        #expect(joined.waiting.isEmpty)
        #expect(Set(aItems).isSubset(of: Set(try await c.items().keys)))
    }
}
