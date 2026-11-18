import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// A transport whose listings leave out the names the test chooses, as an eventually consistent provider's listing
/// can, or as a store (A1) that withholds them; fetches, creations and deletions pass through.
actor HidingTransport: SyncTransport {
    let base: InMemorySyncTransport
    var hidden: Set<String> = []
    var unreadable: Set<String> = []

    init(base: InMemorySyncTransport) {
        self.base = base
    }

    func hide(_ names: Set<String>) { hidden = names }
    func makeUnreadable(_ names: Set<String>) { unreadable = names }

    func list(prefix: String) async throws -> [String] {
        await base.list(prefix: prefix).filter { !hidden.contains($0) }
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        if unreadable.contains(name) { throw SyncTransportError.objectUnreadable(name) }
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws { try await base.create(name, contents: contents) }

    func delete(_ name: String) async throws { await base.delete(name) }
}

/// The engine's second-round fixes (Z30 to Z39) as their independent review attacked them (docs/06-adversarial-review.md
/// §Z, rows from Z126), over the fakes.
extension AdversarialSyncTests {
    /// Device A publishes `segments` segments; device B merges them, merges a snapshot of its own covering A's stream
    /// to its head, and acknowledges it, so that A may collect everything below its head.
    static func collectableStream(_ f: Fixture, segments: UInt64 = 3) async throws -> SyncTestClient {
        for index in 1...segments {
            try await f.writer.save(Self.login("Item \(index)", password: "p\(index)"))
            try await f.writer.sync()
        }
        let reader = await f.reader()
        try await reader.sync()
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: Self.b, number: 20, vector: [Self.a: segments],
                entries: []),
            signedBy: reader.keyring)
        let acknowledged = try await reader.sync()
        #expect(acknowledged.segmentsWritten == 1, "the reader did not acknowledge: the test proves nothing")
        return reader
    }

    // MARK: - Collection keeps this device's own head (Z126)

    /// Threat: anyone who can create a file under the vault's prefix (A1, or a read-only or former member of a shared
    /// folder), holding no key. One name in the victim's own stream far past its head, which cannot be fetched (a
    /// placeholder not yet downloaded, a file with no read permission). Z31 anchors the victim on its listed head, so
    /// the name held nothing back; but collection kept "the newest" by listed names, so at the next quiet collection
    /// the planted name was the newest and the victim deleted its genuine head. From then on it had no anchor, the
    /// planted name held its publishing back in that vault for good, and with it its deletions in every vault. The
    /// newest kept is this device's own genuine head, never a name.
    @Test("a name planted far ahead in a device's own stream is not kept in place of its head when it collects")
    func plantedNameIsNotTheNewestToKeep() async throws {
        let f = try await Self.fixture()
        let reader = try await Self.collectableStream(f)
        let phantom = f.segmentName(1 << 40)
        await f.transport.tamper(phantom, contents: [1, 2, 3])
        let (store, syncState) = (await f.writer.store, await f.writer.syncState)
        let transport = HidingTransport(base: f.transport)
        await transport.makeUnreadable([phantom])
        let writer = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: transport, store: store,
            syncState: syncState)

        let collecting = try await writer.sync()
        #expect(collecting.collected >= 2, "nothing was collected: the test proves nothing")
        #expect(await f.transport.allObjects[f.segmentName(3)] != nil, "the device's own head was collected")

        let later = try await writer.save(Self.login("Later", password: "y"))
        for _ in 0..<2 {
            let report = try await writer.sync()
            #expect(report.ownStreamUnverified == nil, "a planted name mutes the device once its head is gone")
        }
        try await reader.sync()
        #expect(try await reader.items()[later.id] != nil, "the later edit never arrived")
    }

    /// Threat: none needed but a listing that leaves out one of this device's segments while it collects (an
    /// eventually consistent provider, or A1 withholding it). Collection took the listed numbers it could, so it
    /// deleted the ones above the missing one: a lower segment then stayed listed with higher ones gone, which is
    /// exactly what the anchor (Z31) says cannot happen, and a state put back to that lower number would publish over
    /// a collected one. Only a contiguous run of listed numbers is collected, stopping at the first one missing.
    @Test("collection stops at a segment missing from the listing")
    func collectionStopsAtAGap() async throws {
        let f = try await Self.fixture()
        _ = try await Self.collectableStream(f, segments: 5)
        let (store, syncState) = (await f.writer.store, await f.writer.syncState)
        let transport = HidingTransport(base: f.transport)
        await transport.hide([f.segmentName(2)])
        let writer = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: transport, store: store,
            syncState: syncState)
        let report = try await writer.sync()
        #expect(report.collected == 1)
        #expect(await f.transport.allObjects[f.segmentName(2)] != nil)
        #expect(
            await f.transport.allObjects[f.segmentName(3)] != nil,
            "a segment above one still listed was collected")
    }

    // MARK: - What this device published (Z129)

    /// Threat: whoever can put a validly signed object in a device's own stream (a device of the account in any vault;
    /// in a shared vault, Z46 holds another account's aside), before that device has a row of the record. Record IDs
    /// can be predicted: a move's copy takes an ID derived from the original's ID, the destination, the device and
    /// the version, all known to the source vault's readers. The plant is a tombstone naming this device for that ID,
    /// with a stamp far above the vault's clock. With no row held, a deletion found in the log under this device's
    /// name counted as published, so its stamp went into `SyncState.published` and `known`: the copy, written below
    /// it, was never published, and the deletion gate saw it as known, so the original's deletion went out. A
    /// deletion counts as published only if it is this device's pending one or the one it published at that stamp.
    @Test("a planted deletion for a record this device does not hold yet does not mark its first version as sent")
    func plantedDeletionBeforeTheRecordExists() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("First", password: "1"))
        try await f.writer.sync()
        let id = UUID()
        let key = RecordKey(recordID: id, kind: .item)
        let sequence = try #require(await f.writer.state()?.nextSequence)
        let planted = SyncEntry.tombstone(
            key, stamp: RecordStamp(version: 1000, device: Self.a, deleted: true), erasure: [])
        try await f.plant(
            SyncPayload(
                kind: .segment, vaultID: Self.vault, author: Self.a, number: sequence, vector: [:],
                entries: [planted]),
            signedBy: f.writer.keyring)
        try await f.writer.sync()
        #expect(await f.writer.state()?.published[key] == nil, "a deletion this device never made is marked as sent")

        try await f.writer.save(Self.login("The copy", password: "2", id: id))
        let report = try await f.writer.sync()
        #expect(report.pushedEntries == 1, "the new record was passed over as sent")
        let reader = await f.reader()
        try await reader.sync()
        #expect(try await reader.items()[id] != nil, "the record never reached another device")
    }

    // MARK: - A snapshot's claim about this device's stream (Z130)

    /// Threat: an insider device of the account (C), alone. C snapshots the vault claiming that device A's stream has
    /// got to 5, though A has never published in the vault. Z32 holds a device without an anchor back while a trusted
    /// snapshot claims more of its stream than its state accounts for, which is what an older state would see after its
    /// segments were collected; here it held A back for good, since A had no anchor to get and an honest device that
    /// merged C's snapshot carries the claim on in snapshots of its own, which revoking C does not end. Its deletions
    /// in every vault were held back with it. A genuine claim implies a listed object of A's at or past the claimed
    /// number, since a device's head is never collected (Z126): with none listed, the claim holds nothing back.
    @Test("a snapshot's claim about a stream that lists nothing does not hold that device back")
    func claimAboutAStreamWithNothingListed() async throws {
        let f = try await Self.fixture()
        let other = await f.reader()
        try await other.save(Self.login("Theirs", password: "t"))
        try await other.sync()
        let insiderID = UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!
        await f.keys.trust(device: insiderID)
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: insiderID, number: 50, vector: [Self.a: 5, Self.b: 1],
                entries: []),
            signedBy: FakeSyncKeyring(deviceID: insiderID, keys: f.keys))
        try await other.sync()

        let mine = try await f.writer.save(Self.login("Mine", password: "m"))
        for _ in 0..<2 {
            let report = try await f.writer.sync()
            #expect(report.ownStreamUnverified == nil, "a claim about a stream that lists nothing mutes the device")
        }
        #expect(await f.transport.allObjects[f.segmentName(1)] != nil, "the device published nothing")
        // A device that has merged the claim passes over what it covers (Z21 accepts that of whoever signs a
        // snapshot); once the insider is revoked, one that never merged it is shown the device's work.
        await f.keys.retire(device: insiderID)
        let later = await f.reader(UUID(uuidString: "D0000000-0000-4000-8000-0000000000D0")!)
        try await later.sync()
        #expect(try await later.items()[mine.id] != nil, "the device's work never arrived")
    }

    // MARK: - The version-jump ceiling in the retry (Z131)

    /// Threat: an insider device of the account (any trusted device in a vault with no judge). Its segment carries
    /// versions one ceiling apart, each over a row the reader holds and each with an envelope that does not open, and
    /// a real version one ceiling above the last: all refused as out of reach when first met, and tried again once
    /// the pass has merged the rest. The ceiling was raised before each merge was tried, so every failing entry
    /// lifted it by one more step, and the real version merged past U5. The ceiling moves only for what merges.
    @Test("versions that fail to merge in the retry do not lift the version-jump ceiling")
    func failedRetriesDoNotLiftTheCeiling() async throws {
        let f = try await Self.fixture()
        let configuration = Self.jumpConfiguration()
        let store = await f.writer.store
        let a = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration, store: store)
        await f.keys.trust(device: Self.b)
        let b = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration)
        try await a.save(Self.login("First", password: "1"))
        try await a.sync()
        let readerID = UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!
        await f.keys.trust(device: readerID)
        let reader = SyncTestClient(
            deviceID: readerID, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration)
        try await reader.sync()
        try await b.sync()
        var theirs: [Item] = []
        for index in 0..<29 { theirs.append(try await b.save(Self.login("B \(index)", password: "b"))) }
        try await b.sync()
        try await a.sync()
        // 30 is the highest version once B's segment is merged; the ceiling is 16 above whatever has merged.
        var rows: [StoredRecord] = []
        for (index, version) in [UInt64(46), 62].enumerated() {
            var edited = try await a.item(theirs[index].id)
            edited.notes = "does not open"
            var row = try await a.keyring.sealItem(
                ItemMerge.written(edited, as: Revision(version: version, device: Self.a)))
            row.envelope[row.envelope.count - 1] ^= 0x01
            rows.append(row)
        }
        var far = Self.login("Three steps up", password: "f")
        far.version = 78
        far = ItemMerge.stamped(far, previous: nil, revision: Revision(version: 78, device: Self.a))
        rows.append(try await a.keyring.sealItem(far))
        let sequence = try #require(await a.state()?.nextSequence)
        try await f.plant(Self.payload(rows, sequence: sequence), signedBy: a.keyring)
        try await b.save(Self.login("After", password: "c"))
        try await b.sync()

        let report = try await reader.sync()
        #expect(report.quarantined.contains(RecordKey(recordID: far.id, kind: .item)))
        #expect(try await reader.items()[far.id] == nil, "a version three ceilings up was merged")
    }
}
