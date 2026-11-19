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
    /// unstaged and reported (`copiesLeftUnfetched`), its stream waits there, nothing of it is merged, and a restore's
    /// carry counts nothing at or past it (`copyStops`); a later sync with the budget examines it whole and refuses
    /// it. Fails with the fix reverted (the current copy was staged and merged).
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
        let reach = try await reader.engine.mergeReach(of: [Self.a], stoppedAt: report.copyStops)
        #expect(reach[Self.a] == 0, "the reach ran past a name left for its copies")
        let counted = try await reader.engine.stagedEntries(
            of: [key], authoredBy: [Self.a], stoppedAt: report.copyStops)
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
}
