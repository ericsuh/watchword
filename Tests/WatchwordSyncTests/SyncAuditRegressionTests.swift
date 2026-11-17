import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

// Regression tests for the end-to-end audit of 2026-11-17 (docs/06-adversarial-review.md §Z, Z20 to Z39): the
// behaviour each fix had to keep, and the cases that are not an adversary's.

@Suite("Sync engine, audit regressions")
struct SyncAuditRegressionTests {
    /// A vault's log before it is shared is an ordinary one: snapshots are written and segments collected. Once it is
    /// shared its engine runs with a judge and keeps the log whole, but the prefix collected earlier is gone for
    /// good, and only those snapshots say so. A device that reads the log from the start afterwards (a new member, or
    /// any device at a replay, which a shared vault makes at every change of head) must still get across the gap:
    /// refusing every snapshot in a vault with a judge would stop each such stream at its first number (Z21).
    @Test("a judged vault still crosses the gap collection left before it was shared, at a replay too")
    func snapshotsBridgeWhatWasCollectedBeforeSharing() async throws {
        let transport = InMemorySyncTransport()
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 4
        let home = await Household.make(2, transport: transport, configuration: configuration)
        let (a, b) = (home.devices[0], home.devices[1])
        for index in 0..<12 {
            try await a.save(Household.login(title: "Item \(index)"))
            for device in [a, b] { try await device.sync() }
        }
        for _ in 0..<3 {
            for device in [a, b] { try await device.sync() }
        }
        let first = SyncObjectLocation.segment(vaultID: Household.vault, author: SyncFixtures.deviceA, sequence: 1)
        #expect(await transport.allObjects[first.name] == nil, "A's first segment was collected")

        // The vault is shared from here on: a judge, no snapshots, no collection.
        await home.keys.trust(device: SyncFixtures.deviceC)
        let keyring = FakeSyncKeyring(deviceID: SyncFixtures.deviceC, keys: home.keys)
        var shared = configuration
        shared.maintainsLog = false
        let store = InMemoryRecordStore()
        let engine = SyncEngine(
            vaultID: Household.vault, deviceID: SyncFixtures.deviceC, store: store,
            syncState: InMemorySyncStateStore(), transport: transport, keyring: keyring,
            merger: FakeItemMerger(keyring: keyring), configuration: shared, judge: ScriptedJudge())
        let joined = try await engine.sync()
        #expect(joined.waiting.isEmpty && joined.rejected.isEmpty)

        let later = try await a.save(Household.login(title: "After sharing"))
        try await a.sync()
        let caughtUp = try await engine.sync()
        #expect(caughtUp.waiting.isEmpty)
        #expect(await store.record(RecordKey(recordID: later.id, kind: .item)) != nil)
        let replayed = try await engine.sync(reconcile: true)
        #expect(replayed.waiting.isEmpty && replayed.rejected.isEmpty)
        #expect(await store.record(RecordKey(recordID: later.id, kind: .item)) != nil)
    }

    /// A snapshot's tombstone in a vault with a judge is asked about like a segment's (Z21): refused, it is held
    /// aside and erases nothing; admitted, it applies.
    @Test("a judge is asked about a snapshot's tombstones")
    func snapshotTombstonesAreJudged() async throws {
        let transport = InMemorySyncTransport()
        let home = await Household.make(2, transport: transport)
        let (a, b) = (home.devices[0], home.devices[1])
        let item = try await a.save(Household.login())
        try await a.sync()
        let key = RecordKey(recordID: item.id, kind: .item)
        let summary = try ItemErasure(
            seen: VersionVector([SyncFixtures.deviceA: 50, SyncFixtures.deviceB: 50]), row: 50,
            device: SyncFixtures.deviceB, date: nil
        ).summary()
        let snapshot = SyncPayload(
            kind: .snapshot, vaultID: Household.vault, author: SyncFixtures.deviceB, number: 51, vector: [:],
            entries: [
                .tombstone(
                    key, stamp: RecordStamp(version: 51, device: SyncFixtures.deviceB, deleted: true),
                    erasure: summary)
            ])
        let envelope = try await b.keyring.seal(snapshot.encoded(), at: snapshot.location)
        let signature = try await b.keyring.sign(envelope, at: snapshot.location)
        await transport.tamper(
            snapshot.location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())

        for refuses in [true, false] {
            await home.keys.trust(device: SyncFixtures.deviceC)
            let keyring = FakeSyncKeyring(deviceID: SyncFixtures.deviceC, keys: home.keys)
            var shared = SyncTestClient.configuration
            shared.maintainsLog = false
            let judge = ScriptedJudge()
            if refuses { await judge.refuseErasures() }
            let store = InMemoryRecordStore()
            let state = InMemorySyncStateStore()
            let engine = SyncEngine(
                vaultID: Household.vault, deviceID: SyncFixtures.deviceC, store: store, syncState: state,
                transport: transport, keyring: keyring, merger: FakeItemMerger(keyring: keyring),
                configuration: shared, judge: judge)
            let report = try await engine.sync()
            #expect((await store.record(key) != nil) == refuses)
            #expect(report.heldAside == (refuses ? [key] : []))
            #expect((await state.loadState(vaultID: Household.vault)?.erasures[key] == nil) == refuses)
        }
    }
}
