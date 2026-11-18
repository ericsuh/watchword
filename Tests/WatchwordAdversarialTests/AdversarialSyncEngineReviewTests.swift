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

    // MARK: - A version the store refused for a crowded digest (Z147)

    /// Threat: a device of the account crafting entries that share a held-aside entry's unkeyed lookup digest, or
    /// someone with the files (A8) writing quarantine rows that do. The store keeps nothing more under a crowded
    /// digest, and Z141 remembered the version as dropped; the caps still had room, so every sync replayed the whole
    /// log, dropped it again, and withheld this device's snapshots, for as long as the crowding stood. The log is
    /// offered again only once something has left the quarantine, so the crowding costs one replay, not one a sync;
    /// the snapshots stay withheld (nothing covers a version kept nowhere) until the person discards entries.
    @Test("a version refused for a crowded digest is not offered again at every sync")
    func crowdedDigestDoesNotReplayEverySync() async throws {
        let f = try await Self.fixture()
        let configuration = Self.jumpConfiguration()
        let author = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration, store: await f.writer.store)
        try await author.save(Self.login("Mine", password: "m"))
        let kept = try await Self.plantVersion(900, title: "Kept aside", on: author)
        try await author.sync()
        let refused = try await Self.plantVersion(950, title: "Crowded out", on: author)
        try await author.sync()
        let state = InterceptingStateStore()
        await state.refuse([RecordKey(recordID: refused, kind: .item)])
        let (engine, _, _) = await Self.joiner(f, state: state, configuration: configuration)
        let first = try await engine.sync()
        #expect(first.quarantineFull == 1, "the refused version was not counted: the test proves nothing")

        for _ in 0..<2 {
            let again = try await engine.sync()
            #expect(again.fetched == 0 && again.quarantineFull == 0, "the whole log was replayed for nothing")
            #expect(again.snapshotWithheldForQuarantine || again.snapshotsWritten == 0)
        }
        #expect(await state.loadState(vaultID: Self.vault)?.quarantineDropped == [Self.a])

        // The person discards the kept entry and the crowding is gone: the log is offered again, and the version kept.
        let held = await state.quarantined(vaultID: Self.vault)
        await state.discardQuarantined(held.filter { $0.recordID == kept }, vaultID: Self.vault)
        await state.refuse([])
        let replayed = try await engine.sync()
        #expect(replayed.fetched > 0, "the log was never offered again")
        #expect(await state.quarantined(vaultID: Self.vault).contains { $0.recordID == refused })
        #expect(await state.loadState(vaultID: Self.vault)?.quarantineDropped.isEmpty == true)
    }

    // MARK: - Collection above what was collected (Z149)

    /// Threat: anyone who can create a file under the vault's prefix (A1, a read-only or former member of a shared
    /// folder), holding no key. Collection takes a contiguous run of listed numbers from the lowest (Z135); a name
    /// planted in the range this device had already collected was that lowest, so each pass deleted it alone and
    /// stopped at the gap above it, and planted again each sync it stalled collection for good, the log growing. The
    /// run starts above what this device has collected.
    @Test("a name planted below what a device collected does not stop it collecting")
    func plantedNameBelowTheCollectedRun() async throws {
        let f = try await Self.fixture()
        let reader = try await Self.collectableStream(f, segments: 4)
        try await f.writer.sync()
        #expect(await f.writer.state()?.collectedThrough == 3, "nothing was collected: the test proves nothing")
        for index in 5...8 {
            try await f.writer.save(Self.login("Later \(index)", password: "p"))
            try await f.writer.sync()
        }
        try await reader.sync()
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: Self.b, number: 40, vector: [Self.a: 8], entries: []),
            signedBy: reader.keyring)
        try await reader.sync()
        for _ in 0..<2 {
            await f.transport.tamper(f.segmentName(2), contents: [1, 2, 3])
            try await f.writer.sync()
        }
        for sequence in UInt64(4)...7 {
            #expect(
                await f.transport.allObjects[f.segmentName(sequence)] == nil, "segment \(sequence) was not collected")
        }
        #expect(await f.transport.allObjects[f.segmentName(8)] != nil, "the head was collected")
    }
}

// The review of the engine's fourth round (rows Z144 to Z149), over the fakes (docs/06-adversarial-review.md §Z, rows
// from Z150).
extension AdversarialSyncTests {
    /// Threat: a member of a shared vault who may write (A4), whose segment acknowledges this device's stream as far
    /// as 10, and anyone who can delete in the folder (A1, or a member with delete access to the shared folder) removing
    /// this device's head. A vault that keeps its whole log collects nothing, so no number of this stream was ever
    /// freed: publishing at the next one cannot land where no reader looks, and creating at a used one is refused. Z145's
    /// hold for a trusted device's claim guarded nothing there, and a replay re-made the claim each time: the device
    /// published nothing in that vault and held its deletions back in every vault, for good.
    @Test("an acknowledgement does not hold back a device of a vault that keeps its whole log")
    func acknowledgementInAWholeLog() async throws {
        let f = try await Self.fixture()
        var configuration = SyncTestClient.configuration
        configuration.maintainsLog = false
        let writer = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport, configuration: configuration)
        for index in 1...3 {
            try await writer.save(Self.login("Item \(index)", password: "p\(index)"))
            try await writer.sync()
        }
        await f.keys.trust(device: Self.b)
        try await f.plant(
            SyncPayload(
                kind: .segment, vaultID: Self.vault, author: Self.b, number: 1, vector: [Self.a: 10], entries: []),
            signedBy: FakeSyncKeyring(deviceID: Self.b, keys: f.keys))
        await f.transport.tamper(f.segmentName(3), contents: nil)

        try await writer.save(Self.login("After the head went", password: "q"))
        for _ in 0..<2 {
            let report = try await writer.sync()
            #expect(report.ownStreamUnverified == nil, "the device is held for a claim that guards nothing")
        }
        // At the number after its head, which was never collected: nothing it used is written over.
        #expect(await f.transport.allObjects[f.segmentName(4)] != nil, "the device published nothing")
    }
}
