import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// The sync engine's audit fixes (Z20 to Z29) as the independent review of them attacked them
/// (docs/06-adversarial-review.md §Z, Z30 to Z39), over the fakes.
extension AdversarialSyncTests {
    // MARK: - This device's own stream (Z31)

    /// Threat: anyone who can create a file under the vault's prefix without a key (A1, or a read-only or former
    /// member of a shared folder): one name in the victim's own stream, far past its head, that cannot be fetched (a
    /// file named as a placeholder not yet downloaded, one with no read permission, or one in conflict). An own-stream
    /// object that could not be told from the device's own held its publishing back in that vault, at every sync,
    /// for as long as the name was there, and its deletions in every other vault with it. A device whose newest
    /// published segment is listed knows that no number past it was collected, so publishing cannot reuse one: the
    /// name is refused at its own number, if the stream ever gets there, and holds nothing back.
    @Test("a name far ahead in a device's own stream that cannot be fetched does not mute it")
    func unfetchableNameFarAheadInOwnStream() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("Bank", password: "x"))
        try await f.writer.sync()
        let phantom = f.segmentName(1 << 40)
        await f.transport.tamper(phantom, contents: [1, 2, 3])
        let (store, syncState) = (await f.writer.store, await f.writer.syncState)
        let writer = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys,
            transport: UnreadableObjectTransport(base: f.transport, unreadable: phantom), store: store,
            syncState: syncState)

        let later = try await writer.save(Self.login("Later", password: "y"))
        for _ in 0..<2 {
            let report = try await writer.sync()
            #expect(report.ownStreamUnverified == nil, "a name nobody can read mutes the device")
        }
        #expect(await f.transport.allObjects[f.segmentName(2)] != nil)
        let reader = await f.reader()
        try await reader.sync()
        #expect(try await reader.items()[later.id] != nil, "the later edit never arrived")
    }

    /// Threat: none needed but the device's own state put back (a restored backup, or A8 restoring an earlier row
    /// this device signed, which verifies), with its newest segment not usable in this sync: A1 serves other bytes
    /// for it, or withholds it, or a listing is stale. The device's segments up to its head were collected, as a
    /// trusted device's snapshot that covers its whole stream allowed. It took its next number from its old state,
    /// created a segment there (the number was free, having been collected), and marked its rows as sent; every
    /// reader had merged past that number and never fetched it. The listed name used to stop that; Z24 removed it,
    /// and Z21 clipped the snapshot's coverage. A snapshot of a device still trusted that claims more of this
    /// device's stream than it can account for holds its publishing back, without moving its numbering.
    @Test("a device whose state is behind its collected stream does not publish over a collected number")
    func olderStateUnderACoveringSnapshot() async throws {
        let f = try await Self.fixture()
        var older: SyncState?
        for index in 1...9 {
            try await f.writer.save(Self.login("Item \(index)", password: "p\(index)"))
            try await f.writer.sync()
            if index == 3 { older = await f.writer.state() }
        }
        #expect(await f.writer.state()?.lastPublishedSequence == 9)
        await f.keys.trust(device: Self.b)
        let other = FakeSyncKeyring(deviceID: Self.b, keys: f.keys)
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: Self.b, number: 20, vector: [Self.a: 9],
                entries: []),
            signedBy: other)
        let head = try #require(await f.transport.allObjects[f.segmentName(9)])
        for sequence in 1...8 { await f.transport.tamper(f.segmentName(UInt64(sequence)), contents: nil) }
        await f.transport.tamper(f.segmentName(9), contents: [1, 2, 3])
        await f.writer.syncState.tamper(try #require(older))

        let after = try await f.writer.save(Self.login("After the restore", password: "q"))
        let held = try await f.writer.sync()
        #expect(held.ownStreamUnverified == 4, "nothing says why the device publishes nothing")
        #expect(held.segmentsWritten == 0)
        #expect(await f.transport.allObjects[f.segmentName(4)] == nil, "a collected number was used again")

        // Its own head readable again: the device numbers from it and publishes above it.
        await f.transport.tamper(f.segmentName(9), contents: head)
        let resumed = try await f.writer.sync()
        #expect(resumed.ownStreamUnverified == nil)
        #expect(await f.transport.allObjects[f.segmentName(10)] != nil)
        let reader = await f.reader(UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!)
        try await reader.sync()
        #expect(try await reader.items()[after.id] != nil, "the edit made after the restore never arrived")
    }
}
