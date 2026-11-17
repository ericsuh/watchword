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
}
