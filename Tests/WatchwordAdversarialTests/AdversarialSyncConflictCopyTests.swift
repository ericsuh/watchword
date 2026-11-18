import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// Conflict copies (docs/02-architecture.md §7.5): a provider can hold several copies under one object name — iCloud
/// Drive keeps a conflict version or a renamed second create — and **A1** can manufacture either at will. The
/// transport hands every copy over and decides nothing; these tests are about what the engine then does. The fakes'
/// keyed checksum stands for the signatures, as in the rest of this suite.
extension AdversarialSyncTests {
    /// A judge that admits everything: enough to make an engine run as a shared vault's does (one digest per
    /// position, no snapshots, no collection).
    actor AdmittingJudge: WriteJudge {
        var recorded: [SyncObjectLocation: Int] = [:]

        func record(segment location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8], entries: [SyncEntry]) {
            recorded[location, default: 0] += 1
        }

        func admitsSegment(_ location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8]) -> SegmentAdmission {
            .apply
        }

        func admits(_ record: StoredRecord) -> Bool { true }

        func passesOverSegment(sealedUnder keyID: UUID, vaultID: UUID) -> Bool { false }
    }

    /// Every field value an item holds: shown, kept as a conflict, or retained.
    static func heldValues(_ item: Item) -> Set<String> {
        var present = Set(item.fields.map(\.value))
        for conflict in Array(item.conflicts.values.joined()) + item.retainedValues {
            if case .field(let field?) = conflict.value { present.insert(field.value) }
        }
        return present
    }

    /// Threat: A1 plants copies beside a genuine segment, hoping one is taken for it or that their presence stops
    /// the object being read (it did: the transport used to refuse any object with a conflict, and the stream waited
    /// for good). The copies: noise, a truncation of the genuine object, the genuine object with its signature
    /// replaced, a genuine segment of another position, and a segment a device no longer trusted signed. Each
    /// costs one check and is dropped; the genuine object is applied, nothing is rejected, and nothing but it is
    /// staged while locked.
    @Test("junk planted beside a genuine object is refused copy by copy, and the object is applied")
    func plantedJunkCopies() async throws {
        let f = try await Self.fixture()
        let saved = try await f.writer.save(Self.login("Bank", password: "copy-secret"))
        try await f.writer.sync()
        try await f.writer.save(Self.login("Second", password: "second-secret"))
        try await f.writer.sync()
        let name = f.segmentName(1)
        let genuine = try #require(await f.transport.allObjects[name])
        let object = try SignedObject.parse(genuine)
        // A segment a device since revoked really signed, for its own stream.
        await f.keys.trust(device: Self.former)
        let formerKeyring = FakeSyncKeyring(deviceID: Self.former, keys: f.keys)
        let location = SyncObjectLocation.segment(vaultID: Self.vault, author: Self.a, sequence: 1)
        let formerLocation = SyncObjectLocation.segment(vaultID: Self.vault, author: Self.former, sequence: 1)
        let formerEnvelope = try await formerKeyring.seal(
            Self.payload([], author: Self.former).encoded(), at: formerLocation)
        let formerSignature = try await formerKeyring.sign(formerEnvelope, at: formerLocation)
        await f.keys.revoke(device: Self.former)
        let junk: [[UInt8]] = [
            Array(repeating: 0x5A, count: 64),
            Array(genuine.dropLast(9)),
            SignedObject(signature: Array(repeating: 7, count: object.signature.count), envelope: object.envelope)
                .serialized(),
            try #require(await f.transport.allObjects[f.segmentName(2)]),
            SignedObject(signature: formerSignature, envelope: formerEnvelope).serialized(),
        ]
        for copy in junk { await f.transport.plantCopy(name, contents: copy) }

        let locked = await f.reader()
        await locked.keyring.lock()
        let download = try await locked.sync()
        #expect(download.deferredUntilUnlock && download.rejected.isEmpty, "\(download)")
        #expect(download.copiesRefused == junk.count)
        let staged = await locked.syncState.staged(vaultID: Self.vault).first { $0.location == location }
        #expect(staged?.object == object && staged?.alternates.isEmpty == true, "only the genuine copy is staged")
        await locked.keyring.unlock()
        let report = try await locked.sync()
        #expect(report.applied == 2 && report.rejected.isEmpty && report.waiting.isEmpty)
        #expect(try await locked.item(saved.id) == saved)
        #expect(try await locked.sync().copiesExamined == 0, "and the junk is not read again")
    }

    /// Threat: A1 makes its junk the provider's *current* version of the object and leaves the genuine one as the
    /// conflict copy (or the renamed file), so that a client reading "the object" gets junk and waits for ever while
    /// the genuine bytes sit beside it. The engine reads every copy and uses the one that verifies.
    @Test("a genuine object hidden behind a junk current version is found and applied")
    func genuineBehindJunk() async throws {
        let f = try await Self.fixture()
        let saved = try await f.writer.save(Self.login("Bank", password: "hidden-secret"))
        try await f.writer.sync()
        let name = f.segmentName(1)
        let genuine = try #require(await f.transport.allObjects[name])
        await f.transport.tamper(name, contents: Array(genuine.reversed()))
        await f.transport.plantCopy(name, contents: [0])
        await f.transport.plantCopy(name, contents: genuine)
        let reader = await f.reader()
        let report = try await reader.sync()
        #expect(report.applied == 1 && report.rejected.isEmpty && report.waiting.isEmpty)
        #expect(report.copiesRefused == 2)
        #expect(try await reader.item(saved.id) == saved)
    }

    /// Threat: not an attacker but a restored backup (A8's position, or the person's own): a device rolled back to
    /// an earlier state writes again under a sequence number its earlier self used, and the provider keeps both. A
    /// client that picked one copy would silently lose the other's edits. Both verify, both are merged: the items
    /// only one copy carried are all there, an item both wrote at one revision holds both values, a device that had
    /// already merged the position learns the second copy late, the forked device hands both on in a snapshot, and
    /// every device ends up with the same items.
    @Test("two copies that both verify are merged, lose nothing, and reach devices already past the position")
    func twoVerifyingForks() async throws {
        let f = try await Self.fixture()
        let shared = UUID()
        try await f.writer.save(Self.login("Shared", password: "before-the-backup", id: shared))
        let first = try await f.writer.save(Self.login("Only in the first", password: "first-secret"))
        try await f.writer.sync()
        let early = await f.reader()
        try await early.sync()
        #expect(try await early.items().count == 2)

        // The restored installation: the same device and keys, an empty store, a provider that had not caught up.
        let elsewhere = InMemorySyncTransport()
        let restored = SyncTestClient(deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: elsewhere)
        try await restored.save(Self.login("Shared", password: "after-the-restore", id: shared))
        let second = try await restored.save(Self.login("Only in the second", password: "second-secret"))
        try await restored.sync()
        let name = f.segmentName(1)
        await f.transport.plantCopy(name, contents: try #require(await elsewhere.allObjects[name]))

        let late = try await early.sync()
        #expect(late.forkedObjects == [name] && late.rejected.isEmpty)
        let fresh = await f.reader(UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!)
        let report = try await fresh.sync()
        #expect(report.forkedObjects == [name] && report.rejected.isEmpty && report.waiting.isEmpty)
        let handedOn = try await f.writer.sync()
        #expect(handedOn.forkedObjects == [name] && handedOn.snapshotsWritten == 1)
        for device in [early, fresh, f.writer] {
            try await device.sync()
            let items = try await device.items()
            #expect(items[first.id] != nil && items[second.id] != nil)
            #expect(
                Self.heldValues(try #require(items[shared])).isSuperset(of: ["before-the-backup", "after-the-restore"]))
        }
        let reference = try await f.writer.items()
        for device in [early, fresh] {
            let items = try await device.items()
            #expect(Set(items.keys) == Set(reference.keys))
            for (id, item) in items {
                #expect(ItemMerge.sameState(item, try #require(reference[id])), "\(item.title) differs")
            }
        }
    }

    /// Threat: no adversary (review finding R11), the normal state of a fresh iCloud conflict on iOS: a restored
    /// device writes again under a sequence number it had published, and the provider keeps the second copy as a
    /// conflict version whose contents are not on this device yet. The transport lists it and cannot hand it over.
    /// A reader that took the name as examined would never read the copy once it arrived, and the author, which never
    /// saw two copies either, would collect the name once a snapshot covered it and every device had acknowledged it,
    /// deleting the unread copy with it: the restored device's edits would then exist nowhere else. A name with a
    /// copy not read is looked at again at every sync and never collected by its author meanwhile; once the copy
    /// can be read it is merged everywhere and the author hands both on.
    @Test("a copy that cannot be read yet is read once it can be, and its name is not collected before")
    func unreadableCopyReadLater() async throws {
        let f = try await Self.fixture()
        var eager = SyncTestClient.configuration
        eager.snapshotThreshold = 1
        let writer = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport, configuration: eager)
        let first = try await writer.save(Self.login("First", password: "first-secret"))
        try await writer.sync()
        try await writer.save(Self.login("Second", password: "second-secret"))
        try await writer.sync()
        // The restored installation writes its own position 1, which the provider keeps beside the first.
        let elsewhere = InMemorySyncTransport()
        let restored = SyncTestClient(deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: elsewhere)
        let forked = try await restored.save(Self.login("Only in the fork", password: "fork-secret"))
        try await restored.sync()
        let name = f.segmentName(1)
        await f.transport.plantUnreadableCopy(name, contents: try #require(await elsewhere.allObjects[name]))

        let reader = await f.reader()
        let read = try await reader.sync()
        #expect(read.applied == 2 && read.forkedObjects.isEmpty && read.copiesNotExamined == 1)
        // The writer snapshots its stream; the reader acknowledges it; the writer would now collect position 1.
        try await writer.sync()
        try await reader.sync()
        let collecting = try await writer.sync()
        #expect(await f.transport.allObjects[name] != nil, "a name with a copy never read is not collected")
        #expect(collecting.copiesNotExamined >= 1)
        #expect(try await reader.sync().copiesNotExamined == 1, "and is looked at again")

        await f.transport.makeCopiesReadable(name)
        let late = try await reader.sync()
        #expect(late.forkedObjects == [name] && late.rejected.isEmpty)
        #expect(try await reader.item(forked.id).title == "Only in the fork")
        #expect(try await reader.item(first.id).title == "First")
        let handedOn = try await writer.sync()
        #expect(handedOn.forkedObjects == [name])
        #expect(try await writer.item(forked.id).title == "Only in the fork")
    }

    /// Threat: A1 (review finding R17), or no adversary at all in a long-lived vault: copies that are listed and can
    /// never be read (conflict versions whose contents never reach this device, which A1 can arrange by withholding
    /// them) under many names this device has already merged. Nothing about such a name is remembered as examined
    /// (R11, rightly: it may be readable later), so each one cost part of the late half of the per-sync bound at
    /// every sync, in name order; enough of them sorting first kept a late fork of the writer's own stream from ever
    /// being read. A name whose copies were unread goes after the rest, so a fork under a name with no unread copy is
    /// read within two syncs here, and the unreadable copies are still looked at again. (How long a fork under one of
    /// those names waits is R19's test, `unreadNamesTakeTurns`.)
    @Test("copies that are never readable cannot keep a late fork from being read")
    func unreadableCopiesStarveNothing() async throws {
        let f = try await Self.fixture()
        for index in 1...12 {
            try await f.writer.save(Self.login("Item \(index)", password: "item-\(index)"))
            try await f.writer.sync()
        }
        var configuration = SyncTestClient.configuration
        configuration.maximumCopiesPerSync = 8
        await f.keys.trust(device: Self.b)
        let reader = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport, configuration: configuration)
        #expect(try await reader.sync().applied == 12)

        for sequence in 1...11 {
            await f.transport.plantUnreadableCopy(f.segmentName(UInt64(sequence)), contents: [UInt8(sequence)])
        }
        // The restored installation writes positions 1 to 12 of its own; the provider keeps its 12th beside the first.
        let elsewhere = InMemorySyncTransport()
        let restored = SyncTestClient(deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: elsewhere)
        for index in 1...11 {
            try await restored.save(Self.login("Fork \(index)", password: "fork-\(index)"))
            try await restored.sync()
        }
        let forked = try await restored.save(Self.login("Only in the fork", password: "fork-secret"))
        try await restored.sync()
        let name = f.segmentName(12)
        await f.transport.plantCopy(name, contents: try #require(await elsewhere.allObjects[name]))

        var forkRead = false
        for _ in 0..<2 where !forkRead {
            forkRead = try await reader.sync().forkedObjects == [name]
        }
        #expect(forkRead, "the late fork is read by the second sync at the latest")
        #expect(try await reader.item(forked.id).title == "Only in the fork")
        // The unreadable copies are still looked at, after the rest, and once readable are examined like any other.
        #expect(try await reader.sync().copiesNotExamined >= 1)
        for sequence in 1...11 { await f.transport.makeCopiesReadable(f.segmentName(UInt64(sequence))) }
        var settled = false
        for _ in 0..<4 where !settled {
            let report = try await reader.sync()
            settled = report.copiesExamined == 0 && report.copiesNotExamined == 0
        }
        #expect(settled, "once readable, every copy is examined, and then not read again")
    }

    /// Threat: A1 (review finding R19), withholding the contents of copies under more names than the late half of the
    /// per-sync bound covers, and a fork of the writer's own stream under one of those names: unread when first
    /// seen, readable later. The names behind the rest were examined in name order, so the same ones took the bound at
    /// every sync and those sorting last were never examined again, the fork with them. And a name whose count A1
    /// changed at every sync was never put behind the rest. Now the names behind the rest take turns, least recently
    /// examined first, whatever count is listed: the fork is read within as many syncs as the names need turns, and a
    /// changing count brings nothing forward.
    @Test("names with unread copies take turns, and a changing count brings none forward")
    func unreadNamesTakeTurns() async throws {
        let f = try await Self.fixture()
        for index in 1...12 {
            try await f.writer.save(Self.login("Item \(index)", password: "item-\(index)"))
            try await f.writer.sync()
        }
        var configuration = SyncTestClient.configuration
        configuration.maximumCopiesPerSync = 4
        await f.keys.trust(device: Self.b)
        let reader = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport, configuration: configuration)
        #expect(try await reader.sync().applied == 12)

        // Eleven names with an unread copy each, and a fork of the writer's own stream under the twelfth, unread when
        // it arrives: twelve names behind the rest, at the same count from sync to sync. The bound covers four per sync.
        for sequence in 1...11 {
            await f.transport.plantUnreadableCopy(f.segmentName(UInt64(sequence)), contents: [UInt8(sequence)])
        }
        let elsewhere = InMemorySyncTransport()
        let restored = SyncTestClient(deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: elsewhere)
        for index in 1...11 {
            try await restored.save(Self.login("Fork \(index)", password: "fork-\(index)"))
            try await restored.sync()
        }
        let forked = try await restored.save(Self.login("Only in the fork", password: "fork-secret"))
        try await restored.sync()
        let name = f.segmentName(12)
        await f.transport.plantUnreadableCopy(name, contents: try #require(await elsewhere.allObjects[name]))
        for _ in 0..<4 { try await reader.sync() }

        // iCloud delivers the fork's contents; the count listed is unchanged.
        await f.transport.makeCopiesReadable(name)
        var forkRead = false
        for _ in 0..<4 where !forkRead {
            forkRead = try await reader.sync().forkedObjects == [name]
        }
        #expect(forkRead, "the fork is read within the turns twelve names need at four a sync")
        #expect(try await reader.item(forked.id).title == "Only in the fork")

        // A1 changes the count of every name with an unread copy. A late fork under a name with none is still read
        // first: no name comes forward on a changed count.
        try await f.writer.save(Self.login("Thirteenth", password: "thirteen"))
        try await f.writer.sync()
        try await reader.sync()
        let second = try await restored.save(Self.login("A later fork", password: "later-secret"))
        try await restored.sync()
        let later = f.segmentName(13)
        for sequence in 1...11 {
            await f.transport.plantUnreadableCopy(f.segmentName(UInt64(sequence)), contents: [UInt8(sequence), 1])
        }
        await f.transport.plantCopy(later, contents: try #require(await elsewhere.allObjects[later]))
        #expect(try await reader.sync().forkedObjects == [later], "the late fork goes first")
        #expect(try await reader.item(second.id).title == "A later fork")
    }

    /// Threat: A1 (review finding R13) plants junk under names no device will ever merge, snapshot names of a real
    /// device with junk as the current file and a full set of junk copies beside it. A name a device waits on is
    /// examined again at every sync, and nothing is remembered about junk that never verifies, so before this the
    /// whole per-sync bound went on them, ahead of every name the device had already merged: a fork of its stream
    /// that arrived late was never read, and a forked author never learnt of its own fork. Half of the bound is kept
    /// for copies found late, so the late fork is read in the first sync after it appears.
    @Test("junk under names a device waits on cannot keep a late copy from being read")
    func junkUnderWantedNamesStarvesNothing() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("First", password: "first-secret"))
        try await f.writer.sync()
        var configuration = SyncTestClient.configuration
        configuration.maximumCopiesPerSync = 64
        await f.keys.trust(device: Self.b)
        let reader = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport, configuration: configuration)
        try await reader.sync()

        for lamport in 900..<904 {
            let name = SyncObjectLocation.snapshot(vaultID: Self.vault, author: Self.a, lamport: UInt64(lamport)).name
            await f.transport.tamper(name, contents: [UInt8(lamport & 0xFF)])
            for index in 0..<16 { await f.transport.plantCopy(name, contents: [UInt8(lamport & 0xFF), UInt8(index)]) }
        }
        let elsewhere = InMemorySyncTransport()
        let restored = SyncTestClient(deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: elsewhere)
        let forked = try await restored.save(Self.login("Only in the fork", password: "fork-secret"))
        try await restored.sync()
        let name = f.segmentName(1)
        await f.transport.plantCopy(name, contents: try #require(await elsewhere.allObjects[name]))

        let report = try await reader.sync()
        #expect(report.forkedObjects == [name], "\(report.copiesExamined) examined")
        #expect(try await reader.item(forked.id).title == "Only in the fork")
        #expect(report.copiesExamined < configuration.maximumCopiesPerSync + 2 * configuration.maximumCopiesPerObject)
    }

    /// Threat: A1 floods the store with copies — hundreds under one name, and some under every name of a long
    /// stream — to make each sync read and check without end, or to keep a device from ever getting through a
    /// stream or publishing. Each sync reads a bounded number of copies; the stream is merged from its current files
    /// regardless; the device's own edit is published in the same sync; and once everything has been looked at
    /// nothing is read again.
    @Test("a flood of copies costs a bounded number of checks per sync and stalls nothing")
    func copyFlood() async throws {
        let f = try await Self.fixture()
        for index in 0..<40 {
            try await f.writer.save(Self.login("Item \(index)", password: "flood-\(index)"))
            try await f.writer.sync()
        }
        for sequence in 1...40 {
            for index in 0..<(sequence == 1 ? 400 : 20) {
                await f.transport.plantCopy(
                    f.segmentName(UInt64(sequence)),
                    contents: [UInt8(sequence), UInt8(index & 0xFF), UInt8(index >> 8)])
            }
        }
        var configuration = SyncTestClient.configuration
        configuration.maximumCopiesPerSync = 64
        await f.keys.trust(device: Self.b)
        let reader = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport, configuration: configuration)
        let mine = try await reader.save(Self.login("Mine", password: "published-anyway"))
        let report = try await reader.sync()
        #expect(report.applied == 40 && report.waiting.isEmpty && report.rejected.isEmpty, "\(report.waiting)")
        #expect(report.segmentsWritten == 1, "published in the same sync")
        let bound = configuration.maximumCopiesPerSync + configuration.maximumCopiesPerObject
        #expect(report.copiesExamined < bound)
        var syncs = 0
        while syncs < 40 {
            syncs += 1
            let next = try await reader.sync()
            #expect(next.copiesExamined < bound && next.rejected.isEmpty)
            if next.copiesExamined == 0 { break }
        }
        #expect(syncs < 40, "the flood is worked through, not read for ever")
        #expect(try await reader.items().count == 41)
        try await f.writer.sync()
        #expect(try await f.writer.item(mine.id) == mine)
    }

    /// Threat: a member of a shared vault whose device signs two different segments under one sequence number (A4,
    /// or their restored backup), with the provider keeping both. A write cut is a chain of segment digests, one per
    /// position: shown one copy, the administrator's cut holds one chain; shown the other, everyone else judges
    /// against another. The engine cannot show merging them sound, so it refuses: a device that has not merged the
    /// position waits at it and applies nothing of either copy, a device that had merged one reports the other and
    /// does not apply it, and the judge is never given a second digest for the position. One genuine copy among
    /// junk is still used.
    @Test("a shared vault refuses two verifying copies of one position, and still reads one genuine copy among junk")
    func sharedVaultFork() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("First", password: "first-copy"))
        try await f.writer.sync()
        let elsewhere = InMemorySyncTransport()
        let restored = SyncTestClient(deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: elsewhere)
        try await restored.save(Self.login("Second", password: "second-copy"))
        try await restored.sync()
        let name = f.segmentName(1)
        let location = SyncObjectLocation.segment(vaultID: Self.vault, author: Self.a, sequence: 1)
        var configuration = SyncTestClient.configuration
        configuration.maintainsLog = false
        await f.keys.trust(device: Self.b)
        func member() -> (SyncEngine, InMemoryRecordStore, AdmittingJudge) {
            let store = InMemoryRecordStore()
            let judge = AdmittingJudge()
            let keyring = FakeSyncKeyring(deviceID: Self.b, keys: f.keys)
            let engine = SyncEngine(
                vaultID: Self.vault, deviceID: Self.b, store: store, syncState: InMemorySyncStateStore(),
                transport: f.transport, keyring: keyring, merger: FakeItemMerger(keyring: keyring),
                configuration: configuration, judge: judge)
            return (engine, store, judge)
        }

        await f.transport.plantCopy(name, contents: [0xBA, 0xD0])
        let (early, earlyStore, earlyJudge) = member()
        let amongJunk = try await early.sync()
        #expect(amongJunk.applied == 1 && amongJunk.rejected.isEmpty)

        await f.transport.plantCopy(name, contents: try #require(await elsewhere.allObjects[name]))
        let late = try await early.sync()
        #expect(late.applied == 0)
        #expect(late.rejected.map(\.reason) == [.transport(.conflictingVersions(name))])
        #expect(await earlyStore.records(in: Self.vault, kind: .item).count == 1)
        #expect(await earlyJudge.recorded[location] == 1, "one digest for the position, never two")

        let (fresh, freshStore, freshJudge) = member()
        for _ in 0..<2 {
            let report = try await fresh.sync()
            #expect(report.applied == 0 && report.waiting == [Self.a: 1])
            #expect(report.rejected.map(\.reason) == [.transport(.conflictingVersions(name))])
            #expect(!report.transportUnavailable)
        }
        #expect(await freshStore.records(in: Self.vault, kind: .item).isEmpty)
        #expect(await freshJudge.recorded.isEmpty)
    }

    /// Threat: A8, with the local file, edits the staging area so that a position holds a copy the download never
    /// verified beside the genuine one, or raises the count of copies "examined" to keep a real second copy from
    /// being looked at. Staged copies are verified again one by one before anything is applied, and a copy that
    /// fails refuses the position whole; the count only ever decides whether to look again.
    @Test("a copy added to the staging area in the local file is verified again and refuses the position whole")
    func stagedCopyPlanted() async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("Bank", password: "staged-secret"))
        try await f.writer.sync()
        let reader = await f.reader()
        await reader.keyring.lock()
        try await reader.sync()
        let staged = try #require(await reader.syncState.staged(vaultID: Self.vault).first)
        var forged = staged.object
        forged.signature[0] ^= 1
        await reader.syncState.stage(
            StagedObject(location: staged.location, object: staged.object, alternates: [forged], copies: 2))
        await reader.keyring.unlock()
        let report = try await reader.sync()
        #expect(report.applied == 0 && report.forkedObjects.isEmpty, "nothing of the position is applied in part")
        #expect(report.rejected.map(\.name) == [staged.location.name])
        #expect(report.waiting == [Self.a: 1])
        // The planted row is gone with the refusal; the genuine object is fetched again and applied.
        let next = try await reader.sync()
        #expect(next.applied == 1 && next.rejected.isEmpty && next.forkedObjects.isEmpty)
    }
}
