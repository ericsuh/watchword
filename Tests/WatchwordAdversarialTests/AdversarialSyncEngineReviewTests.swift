import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// The engine's third-round fixes (Z135 to Z143) as their independent review attacked them
/// (docs/06-adversarial-review.md §Z, rows from Z144), over the fakes.
extension AdversarialSyncTests {
    // MARK: - Publishing held back for this device's own stream (Z145)

    /// Threat: an insider device of the account (C) together with anyone who can create a file in the folder (A1, a
    /// read-only or former member of a shared folder, or C itself). C snapshots the vault claiming that device A's
    /// stream got to 5, though A has never published there, and an unreadable file is created under A's segment 5.
    /// Z139 let the claim hold A back only while some object of A's stream at or past its next number was listed, and
    /// the planted name was one: A published nothing there, held its deletions back in every vault, and nothing removed
    /// the file. A name shown not to be A's own is no evidence of anything, and a device that never published is not
    /// held by a claim.
    @Test("a junk name where a snapshot's claim points does not hold back a device that never published")
    func junkNameWhereAClaimPoints() async throws {
        let f = try await Self.fixture()
        let insiderID = UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!
        await f.keys.trust(device: insiderID)
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: insiderID, number: 50, vector: [Self.a: 5], entries: []),
            signedBy: FakeSyncKeyring(deviceID: insiderID, keys: f.keys))
        await f.transport.tamper(f.segmentName(5), contents: Array(repeating: 0x41, count: 64))

        let mine = try await f.writer.save(Self.login("Mine", password: "m"))
        for _ in 0..<2 {
            let report = try await f.writer.sync()
            #expect(report.ownStreamUnverified == nil, "a junk name and a claim mute the device")
        }
        #expect(await f.transport.allObjects[f.segmentName(1)] != nil, "the device published nothing")
        await f.keys.retire(device: insiderID)
        let reader = await f.reader()
        try await reader.sync()
        #expect(try await reader.items()[mine.id] != nil)
    }

    /// Threat: none needed but this device's own state put back (a restored backup, or A8 restoring an earlier row it
    /// signed, which verifies), with its genuine head missing from this sync's listing: a stale listing, or a store
    /// (A1) or someone with the files (A8) holding it back. Its segments below the head were collected, as a trusted
    /// device's snapshot covering the whole stream allowed. Z139 lifted the hold whenever nothing of the stream at or
    /// past the next number was listed, so the device published at a number it had used and collected, marked its rows
    /// as sent, and every device that had merged past it never fetched it. A device that has published here holds
    /// back while a trusted device says it merged the stream further than this state accounts for, until its own head
    /// is listed again.
    @Test("a restored state whose head is missing from the listing does not publish over a collected number")
    func restoredStateWithItsHeadMissing() async throws {
        let f = try await Self.fixture()
        var older: SyncState?
        for index in 1...9 {
            try await f.writer.save(Self.login("Item \(index)", password: "p\(index)"))
            try await f.writer.sync()
            if index == 3 { older = await f.writer.state() }
        }
        await f.keys.trust(device: Self.b)
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: Self.b, number: 20, vector: [Self.a: 9], entries: []),
            signedBy: FakeSyncKeyring(deviceID: Self.b, keys: f.keys))
        let head = try #require(await f.transport.allObjects[f.segmentName(9)])
        for sequence in 1...9 { await f.transport.tamper(f.segmentName(UInt64(sequence)), contents: nil) }
        await f.writer.syncState.tamper(try #require(older))

        let after = try await f.writer.save(Self.login("After the restore", password: "q"))
        let held = try await f.writer.sync()
        #expect(held.ownStreamUnverified == 4, "the device published with its head missing")
        #expect(await f.transport.allObjects[f.segmentName(4)] == nil, "a collected number was used again")

        // Its head listed again: the device numbers from it and publishes above it, where readers look.
        await f.transport.tamper(f.segmentName(9), contents: head)
        let resumed = try await f.writer.sync()
        #expect(resumed.ownStreamUnverified == nil)
        #expect(await f.transport.allObjects[f.segmentName(10)] != nil)
        let reader = await f.reader(UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!)
        try await reader.sync()
        #expect(try await reader.items()[after.id] != nil, "the edit made after the restore never arrived")
    }

    /// Threat: none; the hold of Z145 must not be one the person cannot leave. A store emptied of the vault's objects
    /// (the person cleared the folder), with this device's current state: nothing says its stream went further than
    /// it published, so it publishes on.
    @Test("a device whose store was emptied publishes on from its state")
    func emptiedStoreDoesNotHold() async throws {
        let f = try await Self.fixture()
        for index in 1...3 {
            try await f.writer.save(Self.login("Item \(index)", password: "p\(index)"))
            try await f.writer.sync()
        }
        for name in await f.transport.allObjects.keys { await f.transport.tamper(name, contents: nil) }
        try await f.writer.save(Self.login("After", password: "a"))
        let report = try await f.writer.sync()
        #expect(report.ownStreamUnverified == nil)
        #expect(await f.transport.allObjects[f.segmentName(4)] != nil)
    }
}
