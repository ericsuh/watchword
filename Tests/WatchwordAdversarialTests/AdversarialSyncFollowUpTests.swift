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

    /// Every name deleted through this view, in order.
    var deleted: [String] = []
    /// A name whose deletion fails, as an unreachable store's would.
    var failingDelete: String?

    func hide(_ names: Set<String>) { hidden = names }
    func makeUnreadable(_ names: Set<String>) { unreadable = names }
    func failDeleting(_ name: String) { failingDelete = name }

    func list(prefix: String) async throws -> [String] {
        await base.list(prefix: prefix).filter { !hidden.contains($0) }
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        if unreadable.contains(name) { throw SyncTransportError.objectUnreadable(name) }
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws { try await base.create(name, contents: contents) }

    func delete(_ name: String) async throws {
        if name == failingDelete { throw SyncTransportError.unavailable }
        deleted.append(name)
        await base.delete(name)
    }
}

/// The engine's second-round fixes (Z30 to Z39) as their independent review attacked them (docs/06-adversarial-review.md
/// §Z, rows from Z135), over the fakes.
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

    // MARK: - Collection keeps this device's own head (Z135)

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

    // MARK: - What this device published (Z138)

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

    // MARK: - A snapshot's claim about this device's stream (Z139)

    /// Threat: an insider device of the account (C), alone. C snapshots the vault claiming that device A's stream has
    /// got to 5, though A has never published in the vault. Z32 holds a device without an anchor back while a trusted
    /// snapshot claims more of its stream than its state accounts for, which is what an older state would see after its
    /// segments were collected; here it held A back for good, since A had no anchor to get and an honest device that
    /// merged C's snapshot carries the claim on in snapshots of its own, which revoking C does not end. Its deletions
    /// in every vault were held back with it. A genuine claim implies a listed object of A's at or past the claimed
    /// number, since a device's head is never collected (Z135): with none listed, the claim holds nothing back.
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

    // MARK: - The version-jump ceiling in the retry (Z140)

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

    // MARK: - A version the quarantine's store would not keep (Z141)

    /// Threat: a member who sees a held-aside entry's ciphertext (the log is the vault's), or any writer whose versions
    /// this device keeps aside. FNV-1a, the quarantine's lookup digest in SQLite, is not keyed, so sixteen entries
    /// crafted to share one entry's digest, kept first, crowd that digest, and the store keeps nothing more under it
    /// (Z39). It said so by answering "already held", so the engine neither counted the version as not kept nor
    /// remembered whose it was: the version was unkept, uncounted and unrecorded, and nothing held back the snapshot
    /// that covers its segment. A version the store does not keep, and does not hold, is a drop like one past a cap.
    @Test("a version the quarantine's store refuses to keep is counted and remembered as not kept")
    func refusedByTheStoreIsADrop() async throws {
        let f = try await Self.fixture()
        let configuration = Self.jumpConfiguration()
        let author = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration, store: await f.writer.store)
        try await author.save(Self.login("Mine", password: "m"))
        let far = try await Self.plantVersion(900, title: "Far ahead", on: author)
        try await author.sync()
        let state = InterceptingStateStore()
        await state.refuse([RecordKey(recordID: far, kind: .item)])
        let (engine, _, _) = await Self.joiner(f, state: state, configuration: configuration)
        let report = try await engine.sync()
        #expect(report.quarantined == [RecordKey(recordID: far, kind: .item)])
        #expect(report.quarantineFull == 1, "a version kept nowhere was not counted")
        #expect(
            await state.loadState(vaultID: Self.vault)?.quarantineDropped == [Self.a],
            "whose version was not kept was not remembered")
    }

    // MARK: - Local storage failing while downloading (Z142)

    /// Threat: none; a database that fails as an object is staged (a full disk, a damaged file). Z39 made a failure of
    /// local storage stop a sync, but the download still caught it as a refusal of the object: reported as a rejected
    /// object and a waiting stream, as if the object were at fault, and the sync went on to publish. It stops the
    /// sync, as it does while merging.
    @Test("a state store that fails while staging stops the sync instead of refusing the object")
    func stagingFailureStopsTheSync() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("Bank", password: "x"))
        try await f.writer.sync()
        let state = InterceptingStateStore()
        await state.fail(staging: DiskFailure())
        let (engine, _, _) = await Self.joiner(f, state: state, configuration: SyncTestClient.configuration)
        await #expect(throws: DiskFailure.self) { try await engine.sync() }
        await #expect(throws: DiskFailure.self) { try await engine.download() }
    }

    // MARK: - Claims of rows Z31 to Z39 that no test held (the review's list)

    /// Z31's order: a device collects its own segments lowest first, and a delete that fails part-way stops there, so
    /// no gap opens below a segment still listed. Threat: none but a store that fails between two deletions.
    @Test("collection deletes lowest first and stops at a delete that fails")
    func collectionOrderAndAFailedDelete() async throws {
        let f = try await Self.fixture()
        _ = try await Self.collectableStream(f, segments: 5)
        let (store, syncState) = (await f.writer.store, await f.writer.syncState)
        let transport = HidingTransport(base: f.transport)
        await transport.failDeleting(f.segmentName(3))
        let writer = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: transport, store: store,
            syncState: syncState)
        let report = try await writer.sync()
        #expect(report.transportUnavailable)
        #expect(await transport.deleted == [f.segmentName(1), f.segmentName(2)])
        for sequence in UInt64(3)...5 { #expect(await f.transport.allObjects[f.segmentName(sequence)] != nil) }
        // The store reachable again: the rest goes, lowest first, and the head stays.
        await transport.failDeleting("")
        try await writer.sync()
        #expect(await transport.deleted == (1...4).map { f.segmentName(UInt64($0)) })
        #expect(await f.transport.allObjects[f.segmentName(5)] != nil)
    }

    /// Z32's end: the hold for a trusted snapshot's claim ends with its signer. Threat: an insider device of the
    /// account whose claim holds a device with an older state back, and which the person then revokes.
    @Test("a hold for a snapshot's claim ends when its signer is revoked")
    func claimEndsWithItsSigner() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("First", password: "1"))
        try await f.writer.sync()
        let insiderID = UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!
        await f.keys.trust(device: insiderID)
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: insiderID, number: 50, vector: [Self.a: 9],
                entries: []),
            signedBy: FakeSyncKeyring(deviceID: insiderID, keys: f.keys))
        // Its own segment 1 is not usable in this sync and an unusable name sits where the claim points, so the
        // device has no anchor and the claim holds it.
        await f.transport.tamper(f.segmentName(1), contents: [1, 2, 3])
        await f.transport.tamper(f.segmentName(9), contents: [1, 2, 3])
        await f.writer.syncState.tamper(SyncState(vaultID: Self.vault))
        try await f.writer.save(Self.login("Second", password: "2"))
        let held = try await f.writer.sync()
        #expect(held.ownStreamUnverified != nil, "nothing held the device: the test proves nothing")
        await f.keys.retire(device: insiderID)
        let released = try await f.writer.sync()
        #expect(released.ownStreamUnverified == nil, "the claim of a revoked device still holds the device")
    }

    /// Z38: a device whose version found no room, revoked since, holds this device's snapshots back no longer: what a
    /// revoked device wrote is not waited for. Threat: none; a revocation after the quarantine filled.
    @Test("a dropped version of a device revoked since holds no snapshot back")
    func droppedVersionOfARevokedDevice() async throws {
        let f = try await Self.fixture()
        var configuration = Self.jumpConfiguration()
        configuration.snapshotThreshold = 4
        configuration.maximumQuarantinedEntriesPerAuthor = 1
        let store = await f.writer.store
        let elected = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration, store: store)
        await f.keys.trust(device: Self.b)
        let author = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration)
        try await elected.save(Self.login("Mine", password: "m"))
        try await elected.sync()
        try await author.sync()
        _ = try await Self.plantVersion(900, title: "Far ahead", on: author)
        _ = try await Self.plantVersion(901, title: "Farther ahead", on: author)
        try await author.sync()
        #expect(try await elected.sync().quarantineFull == 1)
        await elected.syncState.discardQuarantined(
            await elected.syncState.quarantined(vaultID: Self.vault), vaultID: Self.vault)
        await f.keys.retire(device: Self.b)
        var written = 0
        for index in 0..<8 {
            try await elected.save(Self.login("More \(index)", password: "m"))
            written += try await elected.sync().snapshotsWritten
        }
        #expect(written > 0, "a revoked device's dropped version still holds snapshots back")
    }

    /// Z39: a staged row past the bounds a reader lists (the staging area is a local file, A8) is dropped before
    /// anything reads its number. Threat: A8, who plants a staged object at `UInt64.max` in this device's own stream
    /// carrying this device's genuine signatures (an earlier object of its own, renamed).
    @Test("a staged object past the listed bounds is dropped and moves nothing")
    func stagedPastTheBounds() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("First", password: "1"))
        try await f.writer.sync()
        let location = SyncObjectLocation.segment(vaultID: Self.vault, author: Self.a, sequence: .max)
        let payload = SyncPayload(
            kind: .segment, vaultID: Self.vault, author: Self.a, number: .max, vector: [:], entries: [])
        let keyring = await f.writer.keyring
        let envelope = try await keyring.seal(payload.encoded(), at: location)
        let signature = try await keyring.sign(envelope, at: location)
        await f.writer.syncState.stage(
            StagedObject(location: location, object: SignedObject(signature: signature, envelope: envelope)))
        let later = try await f.writer.save(Self.login("Later", password: "2"))
        let report = try await f.writer.sync()
        #expect(report.segmentsWritten == 1 && !report.ownStreamExhausted)
        #expect(await f.writer.state()?.nextSequence == 3)
        #expect(await f.writer.syncState.staged(vaultID: Self.vault).isEmpty)
        let reader = await f.reader()
        try await reader.sync()
        #expect(try await reader.items()[later.id] != nil)
    }

    /// Z33 through a snapshot: a version refused as a jump while a snapshot is merged is tried again once the rest of
    /// the pass is in. Threat: none; the record-ID order a snapshot's entries come in, on a device with a history.
    @Test("a version a snapshot carries ahead of the ones below it is merged once they are")
    func jumpInsideASnapshot() async throws {
        let f = try await Self.fixture()
        let configuration = Self.jumpConfiguration()
        let store = await f.writer.store
        let a = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration, store: store)
        try await a.save(Self.login("First", password: "1"))
        try await a.sync()
        await f.keys.trust(device: Self.b)
        let reader = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration)
        try await reader.sync()
        // Thirty more versions in A's store, published only in a snapshot; the lowest record ID carries the highest.
        var ids: [UUID] = []
        for index in 0..<29 {
            let id = UUID(uuidString: String(format: "F%07X-0000-4000-8000-000000000000", index + 1))!
            ids.append(try await a.save(Self.login("Later \(index)", password: "l", id: id)).id)
        }
        let first = UUID(uuidString: "00000000-0000-4000-8000-000000000001")!
        ids.append(try await a.save(Self.login("Highest", password: "h", id: first)).id)
        let rows = await store.records(in: Self.vault, kind: .item)
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: Self.a, number: 31, vector: [Self.a: 1],
                entries: rows.map(SyncEntry.init).sorted(by: SyncPayload.entryOrder)),
            signedBy: a.keyring)
        let report = try await reader.sync()
        #expect(report.quarantined.isEmpty)
        #expect(Set(ids).isSubset(of: Set(try await reader.items().keys)))
        #expect(await reader.syncState.quarantined(vaultID: Self.vault).isEmpty)
    }
}
