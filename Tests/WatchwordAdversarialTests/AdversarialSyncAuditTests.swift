import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// The sync engine and its local state, as the end-to-end audit of 2026-11-17 attacked them
/// (docs/06-adversarial-review.md §Z, Z20 to Z39), over the fakes. The same adversaries as the rest of the suite.
extension AdversarialSyncTests {
    // MARK: - This device's own stream

    /// Threat: an insider (a device of the account, or in a shared vault whoever may sign a snapshot) signs a snapshot
    /// whose coverage vector names the *reader's own* device at 2^48. A reader believes coverage for a stream whose
    /// next segment it does not hold, its own included, and takes its next sequence number from it: 2^48 + 1, a name
    /// every reader ignores as out of range. Its later edits are "published" there, marked as sent, and never seen;
    /// a replay keeps the number (review finding Z21). Coverage of a device's own stream counts no further than that
    /// stream can have got.
    @Test("a snapshot claiming this device's own stream does not move its next sequence number")
    func coverageOfOwnStream() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("Bank", password: "x"))
        try await f.writer.sync()
        await f.keys.trust(device: Self.b)
        let insider = FakeSyncKeyring(deviceID: Self.b, keys: f.keys)
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: Self.b, number: 1, vector: [Self.a: 1 << 48],
                entries: []),
            signedBy: insider)

        let merged = try await f.writer.sync()
        #expect(merged.rejected.isEmpty)
        let later = try await f.writer.save(Self.login("Later", password: "y"))
        let published = try await f.writer.sync()
        #expect(published.segmentsWritten == 1 && !published.ownStreamExhausted)
        #expect(await f.writer.state()?.nextSequence == 3)
        #expect(await f.transport.allObjects[f.segmentName(2)] != nil)
        let reader = await f.reader(UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!)
        try await reader.sync()
        #expect(try await reader.items()[later.id] != nil, "the later edit never arrived")
        // A replay does not bring the number back either.
        try await f.writer.sync(reconcile: true)
        #expect(await f.writer.state()?.nextSequence == 3)
    }

    /// Threat: the same end reached another way (a state row from before this was fixed, or damage): this device's
    /// next sequence number is already beyond what any reader lists. Publishing there would mark every row as sent
    /// while no device ever reads it. Nothing is written, nothing is marked, and the report says so.
    @Test("a next sequence number no reader would list is never published at")
    func exhaustedStream() async throws {
        let f = try await Self.fixture()
        let item = try await f.writer.save(Self.login("Bank", password: "x"))
        var state = SyncState(vaultID: Self.vault)
        state.nextSequence = (1 << 48) + 1
        await f.writer.syncState.tamper(state)

        let report = try await f.writer.sync()
        #expect(report.ownStreamExhausted)
        #expect(report.segmentsWritten == 0 && report.pushedEntries == 0)
        #expect(await f.transport.allObjects.isEmpty)
        #expect(await f.writer.state()?.published[RecordKey(recordID: item.id, kind: .item)] == nil)
    }

    // MARK: - One key space for every vault

    /// Threat: A4, a writer in one shared vault who knows (or can compute, for a moved item) a record ID that will
    /// arrive in another of the victim's vaults, publishes a record under that ID in the vault where they may write.
    /// The local store keys records by (record ID, kind) across all vaults, so whichever vault gets an ID into a
    /// device's store first decides which vault's honest record collides. The collision used to reject the whole
    /// segment, and a stream is merged strictly in sequence: the honest author's stream then stopped at that segment
    /// at every sync, and nothing they wrote afterwards arrived (Z22). It costs the colliding entry alone: kept aside
    /// for the person, with the rest of the segment and the stream merged.
    @Test("a record ID held by another vault costs one entry, not its author's stream")
    func collisionCostsOneEntry() async throws {
        let f = try await Self.fixture()
        let first = try await f.writer.save(Self.login("First", password: "1"))
        try await f.writer.sync()
        let colliding = try await f.writer.save(Self.login("Colliding", password: "2"))
        let beside = try await f.writer.save(Self.login("Beside it", password: "3"))
        try await f.writer.sync()
        let later = try await f.writer.save(Self.login("Later", password: "4"))
        try await f.writer.sync()

        let reader = await f.reader()
        // The plant: the same ID, stored under another vault before this vault's record arrives.
        let planted = StoredRecord(
            recordID: colliding.id, kind: .item, vaultID: Self.otherVault, keyID: UUID(), version: 1,
            deviceID: Self.b, envelope: [9, 9, 9])
        await reader.store.tamper(planted)
        let report = try await reader.sync()
        #expect(report.waiting.isEmpty && report.rejected.isEmpty)
        #expect(report.collided == [planted.key])
        #expect(Set(try await reader.items().keys) == [first.id, beside.id, later.id])
        #expect(await reader.store.record(planted.key) == planted, "the other vault's row is untouched")
        #expect(await reader.syncState.quarantined(vaultID: Self.vault).map(\.recordID) == [colliding.id])
        #expect(await reader.state()?.merged[Self.a] == 3)
        // Kept once, however often it is offered again.
        try await reader.sync(reconcile: true)
        #expect(await reader.syncState.quarantined(vaultID: Self.vault).count == 1)
    }

    /// Threat: the same plant against a device that bootstraps the vault from a snapshot. The snapshot used to be
    /// refused whole at the colliding entry, at every sync: the entries sorted after it never arrived, and the streams
    /// it covered stayed where they were.
    @Test("a snapshot is not refused whole for one colliding record")
    func collisionInSnapshot() async throws {
        let f = try await Self.fixture()
        var ids: [UUID] = []
        for index in 0..<6 { ids.append(try await f.writer.save(Self.login("Item \(index)", password: "p")).id) }
        let rows = await f.writer.store.records(in: Self.vault, kind: .item)
        let snapshot = SyncPayload(
            kind: .snapshot, vaultID: Self.vault, author: Self.a, number: 6, vector: [:],
            entries: rows.map(SyncEntry.init).sorted(by: SyncPayload.entryOrder))
        try await f.plant(snapshot, signedBy: f.writer.keyring)
        let victim = try #require(snapshot.entries.first)

        let reader = await f.reader()
        let planted = StoredRecord(
            recordID: victim.recordID, kind: .item, vaultID: Self.otherVault, keyID: UUID(), version: 1,
            deviceID: Self.b, envelope: [9, 9, 9])
        await reader.store.tamper(planted)
        let report = try await reader.sync()
        #expect(report.rejected.isEmpty)
        #expect(report.collided == [planted.key])
        #expect(Set(try await reader.items().keys) == Set(ids).subtracting([victim.recordID]))
        #expect(await reader.state()?.snapshots[snapshot.location] != nil)
    }
}
