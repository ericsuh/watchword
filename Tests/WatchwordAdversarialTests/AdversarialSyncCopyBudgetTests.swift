import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

// The review of V56 and V57 (docs/06-adversarial-review.md V58, V59): a vault with a judge and the sync's bound of
// conflict copies (`maximumCopiesPerSync`, R13), and what a staged snapshot's coverage does to a restore's reach. In
// the suite "sync log".
extension AdversarialSyncTests {
    /// A judged engine of device B over `f`'s store, with `configuration` (the shared vault's: the log kept whole),
    /// and its state and record store.
    func judgedReader(_ f: Fixture, configuration: SyncConfiguration? = nil) async -> (
        engine: SyncEngine, store: InMemoryRecordStore, syncState: InMemorySyncStateStore
    ) {
        var shared = configuration ?? SyncTestClient.configuration
        shared.maintainsLog = false
        await f.keys.trust(device: Self.b)
        let store = InMemoryRecordStore()
        let syncState = InMemorySyncStateStore()
        let keyring = FakeSyncKeyring(deviceID: Self.b, keys: f.keys)
        let engine = SyncEngine(
            vaultID: Self.vault, deviceID: Self.b, store: store, syncState: syncState, transport: f.transport,
            keyring: keyring, merger: FakeItemMerger(keyring: keyring), configuration: shared,
            judge: AdmittingJudge())
        return (engine, store, syncState)
    }

    /// Threat: A1 lists junk names with many copies each (here twenty snapshot names of sixteen copies, which come
    /// first among the names a sync wants) ahead of a forked name, the earlier device ID's genuine signatures on two
    /// segments under one number (V59, found in the review of V56). The junk spent the sync's bound of copies, and the
    /// forked name was then fetched as whichever copy the provider calls current, staged with no copies and merged in a
    /// vault with a judge, which must refuse it (`conflictingVersions`): members could merge different objects at one
    /// position, which a write cut's chain assumes never happens (§7.5). A name a stream waits on is examined before
    /// names it does not wait on now, and is refused. Fails with the fix reverted (the record was applied).
    @Test("junk with copies ahead of a forked name does not get one copy of it merged in a judged vault")
    func junkCopiesAheadOfAForkDoNotGetItMerged() async throws {
        let f = try await Self.fixture()
        let (name, key) = try await forkedFirstPosition(f)
        for index in 0..<20 {
            let junk = SyncObjectLocation.snapshot(vaultID: Self.vault, author: UUID(), lamport: UInt64(index + 1))
            try await f.transport.create(junk.name, contents: [1, 2, 3])
            for copy in 0..<15 { await f.transport.plantCopy(junk.name, contents: [UInt8(copy), 9, 9]) }
        }
        let reader = await judgedReader(f)
        let report = try await reader.engine.sync()
        #expect(report.copiesExamined < 20 * 16, "the junk did not spend the bound: nothing is tested")
        #expect(report.rejected.contains { $0.name == name && $0.reason == .transport(.conflictingVersions(name)) })
        #expect(try await reader.store.record(key) == nil, "a judged vault merged one copy of a forked name")
    }

    /// Threat: as for `junkCopiesAheadOfAForkDoNotGetItMerged`, with the sync's bound of copies spent before the
    /// forked name however the names are ordered (here a bound of none; in use, other streams' forks or A1's junk at
    /// their next positions). In a vault with a judge a name listed with copies is never fetched alone: it is left
    /// unstaged and reported (`copiesLeftUnfetched`), its stream waits there, nothing of it is merged, and what bounds
    /// a restore counts nothing at or past it when it adds the names left unfetched (`copyWaits`) to the stops, as
    /// the hold does; the stops themselves are only names refused (V62: the carry waits for such a name instead). A
    /// later sync with the budget examines it whole and refuses it. Fails with the fix reverted (the current copy was
    /// staged and merged).
    @Test("in a judged vault a name with copies is never fetched alone when the sync's bound of copies is spent")
    func spentBudgetLeavesAForkUnfetched() async throws {
        let f = try await Self.fixture()
        let (name, key) = try await forkedFirstPosition(f)
        var spent = SyncTestClient.configuration
        spent.maximumCopiesPerSync = 0
        let reader = await judgedReader(f, configuration: spent)
        let report = try await reader.engine.sync()
        #expect(report.copiesLeftUnfetched == [name])
        #expect(report.waiting[Self.a] == 1)
        #expect(try await reader.syncState.staged(vaultID: Self.vault).allSatisfy { $0.location.name != name })
        #expect(try await reader.store.record(key) == nil, "a judged vault merged one copy of a forked name")
        #expect(report.copyStops.isEmpty, "a name merely left unfetched was taken for a refused one")
        let waits = report.copyWaits
        #expect(waits.map(\.name) == [name])
        let reach = try await reader.engine.mergeReach(of: [Self.a], stoppedAt: report.copyStops.union(waits))
        #expect(reach[Self.a] == 0, "the reach ran past a name left for its copies")
        let counted = try await reader.engine.stagedEntries(
            of: [key], authoredBy: [Self.a], stoppedAt: report.copyStops.union(waits))
        #expect(counted.isEmpty, "a version past a name left for its copies counted as carried")

        var shared = SyncTestClient.configuration
        shared.maintainsLog = false
        let keyring = FakeSyncKeyring(deviceID: Self.b, keys: f.keys)
        let withBudget = SyncEngine(
            vaultID: Self.vault, deviceID: Self.b, store: reader.store, syncState: reader.syncState,
            transport: f.transport, keyring: keyring, merger: FakeItemMerger(keyring: keyring), configuration: shared,
            judge: AdmittingJudge())
        let later = try await withBudget.sync()
        #expect(later.rejected.map(\.reason) == [.transport(.conflictingVersions(name))])
        #expect(try await reader.store.record(key) == nil)
    }

    /// Threat: as for `refusedForkCountsNothingAfterIt` (a forked name refused at the download, A1 keeping both
    /// genuine copies), with a snapshot of the stream's author staged that covers the forked position, as an owner's
    /// snapshot from before sharing covers what collection left (Z144). The merge passes a refused position a
    /// snapshot covers, so a restore's carry may count what follows it (V58): with the reach stopped there, it renamed
    /// that published work as the new device ID's and members held it twice. The reach and the staged entries pass the
    /// name, and the merge applies what follows it.
    @Test("a staged snapshot that covers a refused forked name lets the reach pass it, as the merge does")
    func stagedSnapshotCoverPassesARefusedName() async throws {
        let f = try await Self.fixture()
        let (name, key) = try await forkedFirstPosition(f)
        let keyring = FakeSyncKeyring(deviceID: Self.a, keys: f.keys)
        let snapshot = SyncPayload(
            kind: .snapshot, vaultID: Self.vault, author: Self.a, number: 3, vector: [Self.a: 1], entries: [])
        try await f.plant(snapshot, signedBy: keyring)
        let reader = await judgedReader(f)
        let pulled = try await reader.engine.download()
        #expect(pulled.copyStops.map(\.name) == [name], "the fork was not refused: nothing is tested")
        let reach = try await reader.engine.mergeReach(of: [Self.a], stoppedAt: pulled.copyStops)
        #expect(reach[Self.a] == .max, "the reach stopped at a name a staged snapshot covers")
        let counted = try await reader.engine.stagedEntries(
            of: [key], authoredBy: [Self.a], stoppedAt: pulled.copyStops)
        #expect(counted.map(\.key) == [key], "what follows a covered name did not count as carried")
        _ = try await reader.engine.sync()
        #expect(try await reader.store.record(key) != nil, "the merge did not pass the covered name")
    }

    /// Threat: an honest fork of a member's stream (a restore that wrote again under numbers it had published, or old
    /// hardware still running under the ID, Z198) on iCloud Drive, where a device sees the second copy listed before
    /// its contents have downloaded (or A1's `.N 2.wwe.icloud`, R21, beside a forked name). With one copy verifying and
    /// the other unread, a vault with a judge staged the name as its one readable copy and merged it, while a member
    /// that read both copies refuses it for good (`conflictingVersions`): V59's harm (members merging different objects
    /// at one position) by another door than a spent bound (a merge review of the hygiene branch, finding 2; V61). A
    /// name not read whole is refused for now (`objectUnreadable`, reported), its stream waits there, and the sync that
    /// reads it whole refuses the fork. Fails at 121589c (the first reader merged the record).
    @Test("a judged vault does not merge a forked name whose other copy is listed and not readable yet")
    func unreadCopyOfAForkIsNotMerged() async throws {
        let f = try await Self.fixture()
        let saved = try await f.writer.save(Self.login("First", password: "first-copy"))
        try await f.writer.sync()
        let elsewhere = InMemorySyncTransport()
        let restored = SyncTestClient(deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: elsewhere)
        try await restored.save(Self.login("Second", password: "second-copy"))
        try await restored.sync()
        let name = f.segmentName(1)
        await f.transport.plantUnreadableCopy(name, contents: try #require(await elsewhere.allObjects[name]))
        let key = RecordKey(recordID: saved.id, kind: .item)

        let early = await judgedReader(f)
        let first = try await early.engine.sync()
        #expect(try await early.store.record(key) == nil, "a judged vault merged one copy of a forked name")
        #expect(first.rejected.map(\.reason) == [.transport(.objectUnreadable(name))])
        #expect(first.waiting[Self.a] == 1, "the stream did not wait at the name")
        #expect(first.copyStops.isEmpty && first.copyWaits.isEmpty)
        #expect(try await early.syncState.staged(vaultID: Self.vault).allSatisfy { $0.location.name != name })

        await f.transport.makeCopiesReadable(name)
        let second = try await early.engine.sync()
        #expect(second.rejected.map(\.reason) == [.transport(.conflictingVersions(name))])
        #expect(try await early.store.record(key) == nil)
        let late = await judgedReader(f)
        let elsewhereReport = try await late.engine.sync()
        #expect(elsewhereReport.rejected.map(\.reason) == [.transport(.conflictingVersions(name))])
        #expect(try await late.store.record(key) == nil)
    }

    /// Threat: A1 adds one junk copy (any bytes) beside a genuine, unforked segment of a stream, and spends the sync's
    /// bound of copies first (here a bound of none; in use, junk names with sixteen copies at the next positions of
    /// authors of its own, ahead by name: `junkAheadByNameSpendsTheBoundInOneOrder`). V59 leaves the genuine name
    /// unfetched, and V58 took every name left unfetched for a stop: a restore's carry then renamed everything the
    /// earlier ID published at or past it as the new ID's, and every member held the replaced title beside its
    /// replacement (round 13's M2; a merge review of the hygiene branch, finding 3; V62). A name left unfetched is no
    /// stop (`copyStops`) but a reason for the carry to wait (`copyWaits`); with the bound, the junk is refused and the
    /// genuine copy staged, and the reach runs on. Fails at 121589c (the name was a stop, and the reach stopped there).
    @Test("a junk copy beside a genuine name, with the bound of copies spent, makes no stop of it")
    func junkCopyBesideAGenuineNameMakesNoStop() async throws {
        let f = try await Self.fixture()
        let saved = try await f.writer.save(Self.login("First", password: "first-copy"))
        try await f.writer.sync()
        _ = try await f.writer.edit(saved.id) { $0.title = "First, edited" }
        try await f.writer.sync()
        let name = f.segmentName(1)
        await f.transport.plantCopy(name, contents: [9, 9, 9])
        let key = RecordKey(recordID: saved.id, kind: .item)

        var spent = SyncTestClient.configuration
        spent.maximumCopiesPerSync = 0
        let starved = await judgedReader(f, configuration: spent)
        let pulled = try await starved.engine.download()
        #expect(pulled.copyStops.isEmpty, "a junk copy beside a genuine name stopped the reach")
        #expect(pulled.copyWaits.map(\.name) == [name], "the name was not left for the carry to wait on")
        let reach = try await starved.engine.mergeReach(of: [Self.a], stoppedAt: pulled.copyStops)
        #expect(reach[Self.a] == .max)

        let fed = await judgedReader(f)
        let report = try await fed.engine.download()
        #expect(report.copyStops.isEmpty && report.copyWaits.isEmpty)
        #expect(report.copiesRefused == 1)
        let counted = try await fed.engine.stagedEntries(of: [key], authoredBy: [Self.a], stoppedAt: report.copyStops)
        #expect(counted.count == 2, "the genuine name's work did not count as carried")
        #expect(counted.allSatisfy { $0.key == key })
    }

    /// Threat: A1 lists junk names with sixteen copies each at the next position of sixteen authors of its own, to
    /// spend the half of the sync's bound kept for names a stream waits on before a genuine name with copies is
    /// reached (V59's residual). Which names came first was the order of a set and a dictionary, different in every
    /// process (a merge review of the hygiene branch, finding 5; V64): one device examined the genuine name and another
    /// left it, and V59's row said "ahead of it by name". Names with copies are now taken by name: junk ahead of the
    /// genuine name by name leaves it unfetched in every process, junk behind it does not. Fails at 121589c unless the
    /// hash order puts the genuine name last of seventeen in the first case and not in the second (about 16 in 289).
    @Test("names with copies a stream waits on are examined in name order")
    func junkAheadByNameSpendsTheBoundInOneOrder() async throws {
        for ahead in [true, false] {
            let f = try await Self.fixture()
            _ = try await f.writer.save(Self.login("First", password: "first-copy"))
            try await f.writer.sync()
            let name = f.segmentName(1)
            await f.transport.plantCopy(name, contents: [9, 9, 9])
            for index in 0..<16 {
                let prefix = ahead ? "00000000" : "FFFFFFFF"
                let author = try #require(UUID(uuidString: prefix + String(format: "-0000-4000-8000-%012d", index)))
                let junk = f.segmentName(1, author: author)
                try await f.transport.create(junk, contents: [1, 2, 3])
                for copy in 0..<15 { await f.transport.plantCopy(junk, contents: [UInt8(copy), 9, 9]) }
            }
            let reader = await judgedReader(f)
            let report = try await reader.engine.download()
            let left = report.copiesLeftUnfetched.contains(name)
            #expect(left == ahead, "junk \(ahead ? "ahead of" : "behind") the name by name: left unfetched \(left)")
        }
    }
}
