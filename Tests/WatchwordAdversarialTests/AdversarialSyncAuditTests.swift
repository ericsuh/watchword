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

    /// Threat: A1, or anyone who can create a file under the vault's prefix without holding a key (a read-only or
    /// former member of a shared folder): one object, any bytes, named as a segment of the *victim's own* stream at
    /// 2^48, the highest number a reader lists. The victim took its next sequence number from the listing's names, so
    /// its next segment went to 2^48 + 1, which every reader ignores; its rows were marked as sent; and the number was
    /// saved, so the device stayed mute in that vault after the object was gone (Z24). A name moves nothing: the
    /// object is refused, as before, and the stream goes on from where it was.
    @Test("an unsigned object named far ahead in a device's own stream does not move its numbering")
    func junkFarAheadInOwnStream() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("Bank", password: "x"))
        try await f.writer.sync()
        let junk = f.segmentName(1 << 48)
        await f.transport.tamper(junk, contents: [1, 2, 3])

        let later = try await f.writer.save(Self.login("Later", password: "y"))
        let report = try await f.writer.sync()
        #expect(report.rejected.map(\.name) == [junk], "refused, and said so")
        #expect(report.segmentsWritten == 1 && !report.ownStreamExhausted)
        #expect(await f.writer.state()?.nextSequence == 3)
        let reader = await f.reader()
        let read = try await reader.sync()
        #expect(read.waiting[Self.a] == nil || read.waiting[Self.a] == 1 << 48)
        #expect(try await reader.items()[later.id] != nil, "the later edit never arrived")
    }

    /// Threat: the same adversary plants the object a little past the victim's head instead. Taken as the stream's
    /// highest number it left a hole below it that no device can fill: every reader waited at the hole for good,
    /// while the victim marked each later row as sent. The victim goes on publishing below it; when it reaches the
    /// number itself its create is refused (objects are never overwritten), which it reports at every sync without
    /// marking anything as sent, and it goes on once the object is gone.
    @Test("an unsigned object just ahead in a device's own stream leaves no hole and loses no edit")
    func junkJustAheadInOwnStream() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("One", password: "1"))
        try await f.writer.sync()
        let junk = f.segmentName(3)
        await f.transport.tamper(junk, contents: Array(repeating: 0x41, count: 300))

        let second = try await f.writer.save(Self.login("Two", password: "2"))
        let published = try await f.writer.sync()
        #expect(published.segmentsWritten == 1)
        #expect(await f.transport.allObjects[f.segmentName(2)] != nil, "published at its next number, below the junk")
        let reader = await f.reader()
        try await reader.sync()
        #expect(try await reader.items()[second.id] != nil)

        // At the squatted number the stream cannot go on, and says so; nothing is marked as sent.
        let third = try await f.writer.save(Self.login("Three", password: "3"))
        for _ in 0..<2 {
            let blocked = try await f.writer.sync()
            #expect(blocked.ownStreamConflict == 3 && blocked.segmentsWritten == 0)
            #expect(blocked.rejected.map(\.name) == [junk])
        }
        #expect(await f.writer.state()?.published[RecordKey(recordID: third.id, kind: .item)] == nil)
        // The object removed (by the provider, or the person): the stream goes on, and the edit arrives.
        await f.transport.tamper(junk, contents: nil)
        #expect(try await f.writer.sync().segmentsWritten == 1)
        try await reader.sync()
        #expect(try await reader.items()[third.id] != nil)
    }

    /// Threat: none; the case the listing was read for (Y8). A device whose state was rolled back (a restored
    /// backup) finds its newest segment listed but cannot read it yet (a file not downloaded). It must neither take
    /// the bare name as its own nor publish below it, where the numbers were collected and no reader looks: it
    /// publishes nothing until it can tell, and then continues above its own segment.
    @Test("an own segment that cannot be read yet holds publishing back, not the numbering")
    func unreadableOwnSegment() async throws {
        let f = try await Self.fixture()
        for index in 0..<3 {
            try await f.writer.save(Self.login("Item \(index)", password: "p"))
            try await f.writer.sync()
        }
        // Segments 1 and 2 collected; the state lost; segment 3 listed and unreadable.
        await f.transport.tamper(f.segmentName(1), contents: nil)
        await f.transport.tamper(f.segmentName(2), contents: nil)
        let newest = f.segmentName(3)
        let store = await f.writer.store
        let restored = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys,
            transport: UnreadableObjectTransport(base: f.transport, unreadable: newest), store: store)
        try await restored.save(Self.login("After the restore", password: "q"))
        let held = try await restored.sync()
        #expect(held.ownStreamUnverified == 3)
        #expect(held.segmentsWritten == 0 && held.pushedEntries == 0)
        #expect(await f.transport.allObjects[f.segmentName(1)] == nil, "a collected number was not used again")

        let readable = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport, store: store,
            syncState: await restored.syncState)
        let resumed = try await readable.sync()
        #expect(resumed.ownStreamUnverified == nil)
        #expect(await readable.state()?.nextSequence == 5)
        #expect(await f.transport.allObjects[f.segmentName(4)] != nil)
    }

    // MARK: - The version-jump ceiling

    static func jumpConfiguration() -> SyncConfiguration {
        var configuration = SyncTestClient.configuration
        configuration.maximumVersionJump = 16
        return configuration
    }

    /// Threat: a device of the account (or simply years of use: versions are a vault-wide clock that every save, merge
    /// and weekly check advances). One version is written exactly at the ceiling above the vault's highest, and the
    /// row that held that highest is saved again, so no stored row lies below the jump any more. Every current device
    /// accepted each step. A device that joins later starts from a snapshot with nothing to measure against, and
    /// quarantined every row above the gap, for good: no sync or replay merged them, and its own low versions were
    /// accepted by everyone, so the split was one-way and unannounced (Z25). A device that holds nothing of a vault
    /// takes the snapshots it starts from as its baseline.
    @Test("a device that joins from a snapshot is not cut off by a jump every earlier device accepted")
    func lateJoinerAcrossAJump() async throws {
        let f = try await Self.fixture()
        let configuration = Self.jumpConfiguration()
        let store = await f.writer.store
        let writer = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration, store: store)
        var ids: [UUID] = []
        for index in 0..<3 { ids.append(try await writer.save(Self.login("Old \(index)", password: "o")).id) }
        // The jump: exactly at the ceiling above version 3, and then the row that held 3 written again.
        var jump = Self.login("Jump", password: "j")
        jump.version = 19
        jump = ItemMerge.stamped(jump, previous: nil, revision: Revision(version: 19, device: Self.a))
        try await store.commit(StoreChange(upserts: [try await writer.keyring.sealItem(jump)]))
        ids.append(jump.id)
        try await writer.edit(ids[2]) { $0.notes = "written again above the jump" }
        for index in 0..<3 { ids.append(try await writer.save(Self.login("New \(index)", password: "n")).id) }
        // What a later device finds: a snapshot of all of it, and the segments collected.
        let rows = await store.records(in: Self.vault, kind: .item)
        #expect(rows.map(\.version).sorted() == [1, 2, 19, 20, 21, 22, 23])
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: Self.a, number: 23, vector: [:],
                entries: rows.map(SyncEntry.init).sorted(by: SyncPayload.entryOrder)),
            signedBy: writer.keyring)

        await f.keys.trust(device: Self.b)
        let joiner = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration)
        let report = try await joiner.sync()
        #expect(report.quarantined.isEmpty)
        #expect(Set(try await joiner.items().keys) == Set(ids))
        #expect(await joiner.syncState.quarantined(vaultID: Self.vault).isEmpty)
    }

    /// Threat: none needed; the order in which a log is read. A device replaying a whole log merges one stream after
    /// another, and a segment's entries in record-ID order, so it meets a version before the ones written between it
    /// and the last it knows: measured where it stood, an honest version looked like a jump, was quarantined, and
    /// nothing ever merged it. Whatever a pass refuses as out of reach is tried again, lowest first, once the rest
    /// of the pass has been merged, and only what is still out of reach stays in the quarantine.
    @Test("a version met before the ones below it is merged once they have been")
    func jumpThatIsOnlyAnOrderOfReading() async throws {
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
        var ids: [UUID] = [try await a.save(Self.login("First", password: "1")).id]
        try await a.sync()
        try await b.sync()
        for index in 0..<29 { ids.append(try await b.save(Self.login("B \(index)", password: "b")).id) }
        try await b.sync()
        try await a.sync()
        ids.append(try await a.save(Self.login("Last", password: "31")).id)
        try await a.sync()

        let reader = SyncTestClient(
            deviceID: UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!, vaultID: Self.vault, keys: f.keys,
            transport: f.transport, configuration: configuration)
        await f.keys.trust(device: reader.deviceID)
        let report = try await reader.sync()
        #expect(report.quarantined.isEmpty)
        #expect(Set(try await reader.items().keys) == Set(ids))
        #expect(await reader.syncState.quarantined(vaultID: Self.vault).isEmpty)

        // What is out of reach of everything else still is: kept, not merged.
        var far = Self.login("Far", password: "f")
        far.version = 500
        far = ItemMerge.stamped(far, previous: nil, revision: Revision(version: 500, device: Self.a))
        try await store.commit(StoreChange(upserts: [try await a.keyring.sealItem(far)]))
        try await a.sync()
        let later = try await reader.sync()
        #expect(later.quarantined == [RecordKey(recordID: far.id, kind: .item)])
        #expect(try await reader.items()[far.id] == nil)
    }

    // MARK: - The quarantine

    /// An item at a version of the caller's choosing, sealed as `client`'s own and put in its store unpublished.
    static func plantVersion(_ version: UInt64, title: String, on client: SyncTestClient) async throws -> UUID {
        var item = Self.login(title, password: "v")
        item.version = version
        let device = await client.deviceID
        item = ItemMerge.stamped(item, previous: nil, revision: Revision(version: version, device: device))
        try await client.store.commit(StoreChange(upserts: [try await client.keyring.sealItem(item)]))
        return item.id
    }

    /// Threat: a writer whose versions a reader keeps aside rather than merges (A4 through implausible versions; A5,
    /// a former member whose segments beyond their cut are accepted only to be held aside) publishes them without
    /// end. The quarantine had no cap, kept each for good, and looked for a duplicate by reading every kept entry,
    /// envelopes included, once per entry offered: disk filled without bound and each sync, and each replay of a
    /// shared vault's log, reread it all (Z27). It is held to a cap for the vault and for what any one device wrote,
    /// an entry already kept is found by a lookup, and what is not kept is counted.
    @Test("the quarantine is capped per vault and per writing device, and keeps each entry once")
    func quarantineIsCapped() async throws {
        let f = try await Self.fixture()
        var configuration = Self.jumpConfiguration()
        configuration.maximumQuarantinedEntriesPerAuthor = 5
        configuration.maximumQuarantinedEntries = 8
        let store = await f.writer.store
        let a = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration, store: store)
        await f.keys.trust(device: Self.former)
        let other = SyncTestClient(
            deviceID: Self.former, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration)
        for index in 0..<12 {
            _ = try await Self.plantVersion(1000 + UInt64(index), title: "A \(index)", on: a)
            _ = try await Self.plantVersion(5000 + UInt64(index), title: "F \(index)", on: other)
        }
        try await a.sync()
        await f.keys.trust(device: Self.b)
        let reader = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration)
        let first = try await reader.sync()
        #expect(first.quarantined.count == 12 && first.quarantineFull == 7)
        #expect(await reader.syncState.quarantined(vaultID: Self.vault).count == 5, "one device's share")

        try await other.sync()
        let second = try await reader.sync()
        #expect(second.quarantineFull == 9)
        let kept = await reader.syncState.quarantined(vaultID: Self.vault)
        #expect(kept.count == 8, "the vault's cap")
        #expect(kept.filter { $0.device == Self.former }.count == 3, "one device cannot take the whole of it")

        // A replay offers every one of them again: nothing is kept twice, and nothing more is kept.
        let replayed = try await reader.sync(reconcile: true)
        #expect(await reader.syncState.quarantined(vaultID: Self.vault) == kept)
        #expect(replayed.quarantineFull == 16, "the sixteen not kept, counted again")
        #expect(try await reader.items().isEmpty)
    }

    /// Threat: none needed (two honest devices whose concurrent edits do not fit in one record, Y37), or an insider's
    /// implausible version. The device that kept a version aside counted its segment as merged all the same, and
    /// went on to write ordinary snapshots whose coverage included that segment while their entries did not include
    /// the version. Once the author collected the segment, a device joining later was never shown it (Z26). A device
    /// whose quarantine holds a trusted device's version writes no ordinary snapshot, as one holding entries it
    /// cannot read does not (ADR 0009); it writes again once the person has dealt with what was kept.
    @Test("a device that kept a version aside writes no snapshot covering it")
    func quarantineWithholdsSnapshot() async throws {
        let f = try await Self.fixture()
        var configuration = Self.jumpConfiguration()
        configuration.snapshotThreshold = 4
        let store = await f.writer.store
        // The lowest device ID, so the one elected to write the snapshot.
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
        let far = try await Self.plantVersion(900, title: "Far ahead", on: author)
        try await author.sync()
        var withheld = false
        var written = 0
        for index in 0..<6 {
            try await elected.save(Self.login("More \(index)", password: "m"))
            let report = try await elected.sync()
            withheld = withheld || report.snapshotWithheldForQuarantine
            written += report.snapshotsWritten
            try await author.sync()
        }
        #expect(await elected.syncState.quarantined(vaultID: Self.vault).map(\.recordID) == [far])
        #expect(withheld && written == 0, "a snapshot covered a segment whose version was only kept aside")
        #expect(await f.transport.allObjects.keys.allSatisfy { !$0.contains("/snapshot/\(Self.a.uuidString)") })

        // The person discards what was kept: snapshots resume.
        await elected.syncState.discardQuarantined(
            await elected.syncState.quarantined(vaultID: Self.vault), vaultID: Self.vault)
        try await elected.save(Self.login("After", password: "m"))
        let after = try await elected.sync()
        #expect(after.snapshotsWritten == 1 && !after.snapshotWithheld)
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
