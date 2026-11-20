import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// A store that lost what it held (docs/02-architecture.md §7.10). **A1** holds the store and can empty it, delete
/// any one object, or put an old copy of everything back, at will and as often as it likes; **A8** can edit the
/// device's sync state file. Neither may make the engine upload again what a reset removed (that is the person's
/// decision alone), drop or overwrite anything local, or reuse a name. The fakes' keyed checksum stands for the
/// signatures, as in the rest of this suite; `AdversarialVaultSyncTests` repeats the essentials with real keys.
extension AdversarialSyncTests {
    static func titles(_ client: SyncTestClient) async throws -> Set<String> {
        Set(try await client.items().values.map(\.title))
    }

    /// Threat: A1 empties the store, hoping the devices fill it again by themselves (the person on another device
    /// may have deleted the data on purpose), and A8 helps by marking the state file as needing a replay: a replay
    /// used to forget what the device had published, and the outbox then published every row it ever wrote. No sync,
    /// replay or not, uploads anything; the device's rows and state are as they were.
    @Test("an emptied store is filled by no sync, and a replay planted in the state file republishes nothing")
    func emptiedStoreAndPlantedReplay() async throws {
        let f = try await Self.fixture()
        let reader = await f.reader()
        try await f.writer.save(Self.login("Bank", password: "reset-secret"))
        try await f.writer.sync()
        try await reader.save(Self.login("Post", password: "other-secret"))
        try await reader.sync()
        try await f.writer.sync()
        let before = try #require(await f.writer.state())
        await f.transport.removeEverything()

        var planted = before
        planted.stashUnsaved = true
        await f.writer.syncState.tamper(planted)
        for reconcile in [false, true, false] {
            let report = try await f.writer.sync(reconcile: reconcile)
            #expect(report.replayPostponed && report.storeLacksObjects)
            #expect(report.segmentsWritten == 0 && report.snapshotsWritten == 0 && report.collected == 0)
        }
        #expect(await f.transport.allObjects.isEmpty)
        let after = try #require(await f.writer.state())
        #expect(after.published == before.published && after.merged == before.merged)
        #expect(after.nextSequence == before.nextSequence && after.erasures == before.erasures)
        #expect(try await Self.titles(f.writer) == ["Bank", "Post"])
    }

    /// Threat: A1 deletes single objects of a device, its newest segment or its snapshot, to make the engine's own
    /// sign of a reset appear and see what the device then does unasked. It writes no snapshot and collects nothing;
    /// it still publishes a new edit under the next number, never under the deleted one's; and it holds everything
    /// it held.
    @Test("deleting a device's own objects makes it ask, not upload; a new edit takes the next number")
    func deletedOwnObjects() async throws {
        let f = try await Self.fixture()
        let reader = await f.reader()
        try await f.writer.save(Self.login("Bank", password: "first"))
        try await f.writer.sync()
        try await reader.sync()
        try await f.writer.save(Self.login("Post", password: "second"))
        try await f.writer.sync()
        await f.transport.tamper(f.segmentName(2), contents: nil)

        let asked = try await f.writer.sync()
        #expect(asked.storeLacksObjects && asked.snapshotsWritten == 0 && asked.segmentsWritten == 0)
        try await f.writer.save(Self.login("Third", password: "third"))
        let published = try await f.writer.sync()
        #expect(published.segmentsWritten == 1 && published.snapshotsWritten == 0)
        #expect(await f.transport.allObjects[f.segmentName(2)] == nil, "the deleted number is not written again")
        #expect(await f.transport.allObjects[f.segmentName(3)] != nil)
        #expect(try await Self.titles(f.writer) == ["Bank", "Post", "Third"])
        // The reader waits at the gap; it applies nothing past it and loses nothing.
        let waiting = try await reader.sync()
        #expect(waiting.waiting[Self.a] == 2)
        #expect(try await Self.titles(reader) == ["Bank"])
    }

    /// Threat: A1 fakes a reset and, once the person has said yes, fakes another, again and again, hoping a device
    /// eventually reuses a sequence number or a snapshot name (two different objects under one name is a fork) or
    /// forgets something. Every object ever created has a name of its own, sequence numbers only rise, and after
    /// each round the device holds what it held.
    @Test("resets repeated after every upload never make a device reuse a name or forget a record")
    func repeatedResets() async throws {
        let f = try await Self.fixture()
        var everCreated: [String] = []
        var lastSequence: UInt64 = 0
        for round in 0..<4 {
            try await f.writer.save(Self.login("Item \(round)", password: "secret \(round)"))
            let report = try await f.writer.engine.sync(handingOn: round > 0)
            #expect(report.segmentsWritten == 1)
            everCreated += await f.transport.allObjects.keys
            let state = try #require(await f.writer.state())
            #expect(state.lastPublishedSequence > lastSequence)
            lastSequence = state.lastPublishedSequence
            await f.transport.removeEverything()
        }
        #expect(Set(everCreated).count == everCreated.count)
        #expect(try await f.writer.items().count == 4)
        #expect(try await f.writer.engine.sync(handingOn: true).snapshotsWritten == 1)
        let reader = await f.reader()
        try await reader.sync()
        #expect(try await reader.items().count == 4)
    }

    /// Threat: A1 empties the store and puts an old copy of it back (everything as it was before the devices' latest
    /// edits), so that a device takes the store's older state for the truth. Nothing local goes back: the newer
    /// versions stay, the device sees that its newer objects are gone and asks, and once the person says yes a new
    /// device gets the newer versions, never the old.
    @Test("a store rolled back to an older copy rolls no device back")
    func rolledBackStore() async throws {
        let f = try await Self.fixture()
        let item = try await f.writer.save(Self.login("Bank", password: "old password"))
        try await f.writer.sync()
        let old = await f.transport.allObjects
        try await f.writer.edit(item.id) { $0.fields[1].value = "new password" }
        try await f.writer.sync()
        await f.transport.removeEverything()
        for (name, bytes) in old { await f.transport.tamper(name, contents: bytes) }

        let report = try await f.writer.sync()
        #expect(report.storeLacksObjects && report.applied == 0)
        #expect(try await f.writer.item(item.id).fields[1].value == "new password")
        try await f.writer.engine.sync(handingOn: true)
        let reader = await f.reader()
        try await reader.sync()
        #expect(try await reader.item(item.id).fields[1].value == "new password")
    }

    /// Threat: a member of a shared vault, or A1 prompting one, answers a reset by uploading the vault from that
    /// member's device. A snapshot would hand every member's work on with no segment for a write cut to be judged
    /// against (§8.10), laundering a write made outside a cut. An engine that keeps its whole log (a shared
    /// vault's, here with a judge) writes no snapshot however it is asked, says why, and keeps every row.
    @Test("an engine that keeps its whole log refuses to hand on, with a judge and however often it is asked")
    func wholeLogVaultNeverHandsOn() async throws {
        let f = try await Self.fixture()
        var configuration = SyncTestClient.configuration
        configuration.maintainsLog = false
        let store = InMemoryRecordStore()
        let state = InMemorySyncStateStore()
        let client = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport, configuration: configuration,
            store: store, syncState: state)
        let keyring = FakeSyncKeyring(deviceID: Self.a, keys: f.keys)
        let judged = SyncEngine(
            vaultID: Self.vault, deviceID: Self.a, store: store, syncState: state, transport: f.transport,
            keyring: keyring, merger: FakeItemMerger(keyring: keyring), configuration: configuration,
            judge: AdmittingJudge())
        try await client.save(Self.login("Shared", password: "shared-secret"))
        #expect(try await judged.sync().segmentsWritten == 1)
        await f.transport.removeEverything()
        for handingOn in [false, true, true] {
            let report = try await judged.sync(reconcile: handingOn, handingOn: handingOn)
            #expect(report.reuploadRefused == .sharedVault && report.replayPostponed == handingOn)
            #expect(report.snapshotsWritten == 0 && report.segmentsWritten == 0)
        }
        #expect(await f.transport.allObjects.isEmpty)
        #expect(try await Self.titles(client) == ["Shared"])
    }
}
