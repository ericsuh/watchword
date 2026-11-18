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

/// A state store over the in-memory one that lets a test lock the device's keyring the moment a state is saved, or
/// make the quarantine's sizes read as a tampered file would make them.
actor InterceptingStateStore: SyncStateStore {
    let base = InMemorySyncStateStore()
    /// Called after each state is saved.
    var afterSave: (@Sendable (SyncState) async -> Void)?
    /// What the quarantine is said to hold, in place of what it holds.
    var usage: QuarantineUsage?

    func intercept(afterSave: (@Sendable (SyncState) async -> Void)?) { self.afterSave = afterSave }
    func report(usage: QuarantineUsage?) { self.usage = usage }

    func loadState(vaultID: UUID) async -> SyncState? { await base.loadState(vaultID: vaultID) }
    func saveState(_ state: SyncState) async {
        await base.saveState(state)
        await afterSave?(state)
    }
    func stage(_ object: StagedObject) async { await base.stage(object) }
    func staged(vaultID: UUID) async -> [StagedObject] { await base.staged(vaultID: vaultID) }
    func unstage(_ locations: [SyncObjectLocation]) async { await base.unstage(locations) }
    func addPendingDeletion(_ deletion: PendingDeletion) async { await base.addPendingDeletion(deletion) }
    func pendingDeletions(vaultID: UUID) async -> [RecordKey: PendingDeletion] {
        await base.pendingDeletions(vaultID: vaultID)
    }
    func removePendingDeletions(_ deletions: [RecordKey: RecordStamp], vaultID: UUID) async {
        await base.removePendingDeletions(deletions, vaultID: vaultID)
    }
    func quarantine(_ entry: SyncEntry, vaultID: UUID) async -> Bool {
        await base.quarantine(entry, vaultID: vaultID)
    }
    func quarantined(vaultID: UUID) async -> [SyncEntry] { await base.quarantined(vaultID: vaultID) }
    func discardQuarantined(_ entries: [SyncEntry], vaultID: UUID) async {
        await base.discardQuarantined(entries, vaultID: vaultID)
    }
    func holdsQuarantined(_ entry: SyncEntry, vaultID: UUID) async -> Bool {
        await base.holdsQuarantined(entry, vaultID: vaultID)
    }
    func quarantineUsage(vaultID: UUID) async -> QuarantineUsage {
        if let usage { return usage }
        return await base.quarantineUsage(vaultID: vaultID)
    }
    func stash(vaultID: UUID) async -> [UInt8]? { await base.stash(vaultID: vaultID) }
    func saveStash(_ bytes: [UInt8], vaultID: UUID) async { await base.saveStash(bytes, vaultID: vaultID) }
    func eraseAll() async { await base.eraseAll() }
}

extension AdversarialSyncTests {
    // MARK: - What this device published (Z35)

    /// Threat: whoever can put a validly signed object in the victim's own stream (in a shared vault a member listing
    /// the victim's device ID, S33; in any vault a device of the account). Z29 counted a *version* found in the log
    /// under this device's name as published only if it is the row held, but a *deletion* was counted whatever it
    /// was. The item has met a real deletion already, and this device kept it, trashed, for an edit the deletion had
    /// not seen. The plant is a tombstone naming this device with the same summary and a far higher stamp: it changes
    /// nothing in the store (the deletion has had its say), and its stamp was recorded as published, so the outbox
    /// passed over every later edit of the item until the vault's clock caught up with it. A deletion found in the
    /// log counts as published only if no row of the record is held, or it is this device's own.
    @Test("a planted deletion in a device's own name does not mark its later edits as sent")
    func plantedOwnDeletionDoesNotSuppressPublishing() async throws {
        let f = try await Self.fixture()
        let item = try await f.writer.save(Self.login("Bank", password: "old"))
        try await f.writer.sync()
        let other = await f.reader()
        try await other.sync()
        try await other.delete(item.id)
        try await other.sync()
        // An edit the deletion had not seen: the item is kept here, trashed.
        try await f.writer.edit(item.id) { $0.notes = "unseen by the deletion" }
        try await f.writer.sync()
        let key = RecordKey(recordID: item.id, kind: .item)
        let erasure = try #require(await f.writer.state()?.erasures[key])

        let sequence = try #require(await f.writer.state()?.nextSequence)
        let planted = SyncEntry.tombstone(
            key, stamp: RecordStamp(version: 1000, device: Self.a, deleted: true), erasure: erasure.summary)
        try await f.plant(
            SyncPayload(
                kind: .segment, vaultID: Self.vault, author: Self.a, number: sequence, vector: [:],
                entries: [planted]),
            signedBy: f.writer.keyring)
        try await f.writer.sync()
        try await f.writer.edit(item.id) { $0.fields[1].value = "new, made after the plant" }
        let report = try await f.writer.sync()
        #expect(report.pushedEntries == 1, "the edit was passed over as sent")
        try await other.sync()
        #expect(try await other.item(item.id).field(.password)?.value == "new, made after the plant")
    }

    // MARK: - Retrying what was out of reach (Z33, Z36)

    /// A device joining the vault through `syncState`, with a keyring the test can lock.
    static func joiner(
        _ f: Fixture, state: InterceptingStateStore, configuration: SyncConfiguration
    ) async -> (engine: SyncEngine, keyring: FakeSyncKeyring, store: InMemoryRecordStore) {
        let device = UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!
        await f.keys.trust(device: device)
        let keyring = FakeSyncKeyring(deviceID: device, keys: f.keys)
        let store = InMemoryRecordStore()
        let engine = SyncEngine(
            vaultID: vault, deviceID: device, store: store, syncState: state, transport: f.transport,
            keyring: keyring, merger: FakeItemMerger(keyring: keyring), configuration: configuration)
        return (engine, keyring, store)
    }

    /// Threat: none needed; the order of a replay, and a lock. A device that joins, or replays a log, meets an honest
    /// version before the ones written between it and what it holds: refused as a jump for now, kept aside, and
    /// listed in memory to be tried again once the rest of the pass is merged (Z25). Auto-lock lands while the later
    /// streams merge, after the segment that carried it was counted as merged. The list was gone with the engine, and
    /// nothing merges from the quarantine: the version was never merged on this device, and with it in the
    /// quarantine this device wrote no ordinary snapshot again (Z26). The state saved meanwhile says a retry is owed,
    /// and the next sync replays the log.
    @Test("a lock before the retry of an out-of-reach version does not leave it out for good")
    func lockBeforeTheRetry() async throws {
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
        try await b.sync()
        for index in 0..<29 { try await b.save(Self.login("B \(index)", password: "b")) }
        try await b.sync()
        try await a.sync()
        let last = try await a.save(Self.login("Last", password: "31"))
        try await a.sync()
        let head = try #require(await a.state()?.lastPublishedSequence)

        let state = InterceptingStateStore()
        let (engine, keyring, joined) = await Self.joiner(f, state: state, configuration: configuration)
        // Locked the moment the joiner has counted the whole of A's stream as merged, before B's.
        await state.intercept { saved in
            if (saved.merged[Self.a] ?? 0) >= head, (saved.merged[Self.b] ?? 0) == 0 { await keyring.lock() }
        }
        let interrupted = try await engine.sync()
        #expect(interrupted.deferredUntilUnlock)
        await state.intercept(afterSave: nil)
        await keyring.unlock()

        _ = try await engine.sync()
        #expect(await joined.record(RecordKey(recordID: last.id, kind: .item)) != nil, "the version was left out")
        #expect(await state.quarantined(vaultID: Self.vault).isEmpty)
    }

    /// Threat: an insider device of the account (any device in a vault with no judge). Its entry is met at a jump,
    /// over a row this device holds, with an envelope that does not open; once the rest of the pass has merged it is
    /// tried again, and its merge fails. Inside the loops that costs the object; in the retry it escaped the merge as
    /// an untyped error, so the sync failed as a whole, every vault after this one went unsynced, and nothing was
    /// published or saved. A retried entry that does not merge stays in the quarantine, and the rest goes on.
    @Test("a retried version whose merge fails stays aside and stops nothing")
    func retriedEntryThatDoesNotMerge() async throws {
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
        let first = try await a.save(Self.login("First", password: "1"))
        try await a.sync()
        let readerID = UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!
        await f.keys.trust(device: readerID)
        let reader = SyncTestClient(
            deviceID: readerID, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration)
        try await reader.sync()
        try await b.sync()
        for index in 0..<29 { try await b.save(Self.login("B \(index)", password: "b")) }
        try await b.sync()
        // A's next segment carries the item at a version above everything B wrote, with ciphertext that does not open.
        var edited = try await a.item(first.id)
        edited.notes = "beyond"
        var row = try await a.keyring.sealItem(
            ItemMerge.written(edited, as: Revision(version: 31, device: Self.a)))
        row.envelope[row.envelope.count - 1] ^= 0x01
        let sequence = try #require(await a.state()?.nextSequence)
        try await f.plant(Self.payload([row], sequence: sequence), signedBy: a.keyring)
        let later = try await b.save(Self.login("After", password: "c"))
        try await b.sync()

        let report = try await reader.sync()
        #expect(report.quarantined == [RecordKey(recordID: first.id, kind: .item)])
        #expect(try await reader.items()[later.id] != nil)
        #expect(try await reader.item(first.id).notes.isEmpty)
    }

    // MARK: - The quarantine's caps (Z38, Z39)

    /// Threat: a writer whose versions this device keeps aside (an insider's implausible versions; a former member's,
    /// held aside) sends more than one device's share. Past the share a version is not kept here (Z27), and its
    /// segment counts as merged. Once the person had emptied the list, nothing held back this device's snapshots,
    /// which cover that segment without the version; and nothing offered the version again. The drop is remembered
    /// in the signed state: no ordinary snapshot while it stands, and once there is room the log is replayed.
    @Test("a version the full quarantine could not keep holds snapshots back and is offered again when there is room")
    func droppedVersionIsRemembered() async throws {
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
        let first = try await elected.sync()
        #expect(first.quarantineFull == 1)
        let kept = await elected.syncState.quarantined(vaultID: Self.vault)
        #expect(kept.count == 1)

        // The person discards what was kept. The version that found no room is offered again (a replay offers the
        // whole log, so what was discarded comes first again, and it still finds no room), and no ordinary snapshot
        // is written while it stands.
        await elected.syncState.discardQuarantined(kept, vaultID: Self.vault)
        var written = 0
        var offered = 0
        for index in 0..<6 {
            try await elected.save(Self.login("More \(index)", password: "m"))
            let report = try await elected.sync()
            written += report.snapshotsWritten
            offered += report.quarantineFull
            try await author.sync()
        }
        #expect(offered > 0, "the version that was not kept was never offered again")
        #expect(written == 0, "a snapshot covered a segment whose version this device does not hold")
    }

    /// Threat: A8, with the local database: the quarantine's stored sizes are what the file says, and a size near
    /// `Int.max` (the SQLite store clamps a column to that) made the cap check overflow and trap, at every sync of
    /// the vault. The sums saturate, and a share that full reads as full.
    @Test("quarantine sizes near the integer limit read as full, never trap")
    func quarantineSizesNearTheLimit() async throws {
        let f = try await Self.fixture()
        let configuration = Self.jumpConfiguration()
        let author = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: configuration, store: await f.writer.store)
        try await author.save(Self.login("Mine", password: "m"))
        try await author.sync()
        _ = try await Self.plantVersion(900, title: "Far ahead", on: author)
        try await author.sync()
        let state = InterceptingStateStore()
        await state.report(
            usage: QuarantineUsage(devices: [
                Self.former: .init(entries: 1, bytes: .max / 2), Self.b: .init(entries: 1, bytes: .max / 2 + 2),
            ]))
        let (engine, _, _) = await Self.joiner(f, state: state, configuration: configuration)
        let report = try await engine.sync()
        #expect(report.quarantineFull == 1)
        #expect(
            QuarantineUsage(devices: [Self.a: .init(entries: .max, bytes: .max), Self.b: .init(bytes: 1)]).bytes
                == .max)
    }
}
