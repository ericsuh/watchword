import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// Two versions of the app on one account (ADR 0009): a later one that carries scan results (`scanStatus`, ignorable)
/// and vault descriptions (`vaultMetadata`, critical), and an earlier one that carries items only. The earlier one
/// is modelled by restricting the kinds its engine carries; "upgrading" it is a new engine over the same store and
/// state.
struct VersionedHousehold {
    static let schema: UInt64 = 1
    static let laterKinds: [EnvelopeKind: UInt64] = [.scanStatus: schema, .vaultMetadata: schema]

    let keys: FakeAccountKeys
    let transport: InMemorySyncTransport
    let laterID: UUID
    let earlierID: UUID
    let later: SyncTestClient
    let earlier: SyncTestClient
    let earlierStore: InMemoryRecordStore
    let earlierState: InMemorySyncStateStore

    static func laterConfiguration(_ tune: (inout SyncConfiguration) -> Void = { _ in }) -> SyncConfiguration {
        var configuration = SyncTestClient.configuration
        for (kind, schema) in laterKinds { configuration.schemaVersions[kind] = schema }
        tune(&configuration)
        return configuration
    }

    static func earlierConfiguration(_ tune: (inout SyncConfiguration) -> Void = { _ in }) -> SyncConfiguration {
        var configuration = SyncTestClient.configuration
        tune(&configuration)
        return configuration
    }

    /// `laterID` and `earlierID` decide which of the two is elected to write snapshots (the lower ID).
    static func make(
        laterID: UUID = SyncFixtures.deviceA, earlierID: UUID = SyncFixtures.deviceB,
        tune: @escaping (inout SyncConfiguration) -> Void = { _ in }
    ) async -> VersionedHousehold {
        let keys = FakeAccountKeys(seed: 2009)
        await keys.addVaultKey(vaultID: SyncFixtures.vault)
        await keys.trust(device: laterID)
        await keys.trust(device: earlierID)
        let transport = InMemorySyncTransport()
        let earlierStore = InMemoryRecordStore()
        let earlierState = InMemorySyncStateStore()
        return VersionedHousehold(
            keys: keys, transport: transport, laterID: laterID, earlierID: earlierID,
            later: SyncTestClient(
                deviceID: laterID, vaultID: SyncFixtures.vault, keys: keys, transport: transport,
                configuration: laterConfiguration(tune), opaqueKinds: laterKinds),
            earlier: SyncTestClient(
                deviceID: earlierID, vaultID: SyncFixtures.vault, keys: keys, transport: transport,
                configuration: earlierConfiguration(tune), store: earlierStore, syncState: earlierState),
            earlierStore: earlierStore, earlierState: earlierState)
    }

    /// The earlier device after an update to the later version: same device, store and state.
    func upgraded(_ tune: @escaping (inout SyncConfiguration) -> Void = { _ in }) async -> SyncTestClient {
        SyncTestClient(
            deviceID: earlierID, vaultID: SyncFixtures.vault, keys: keys, transport: transport,
            configuration: Self.laterConfiguration(tune), store: earlierStore, syncState: earlierState,
            opaqueKinds: Self.laterKinds)
    }

    /// A device of the later version that has never synced.
    func newcomer(_ id: UUID = SyncFixtures.deviceC) async -> SyncTestClient {
        await keys.trust(device: id)
        return SyncTestClient(
            deviceID: id, vaultID: SyncFixtures.vault, keys: keys, transport: transport,
            configuration: Self.laterConfiguration(), opaqueKinds: Self.laterKinds)
    }

    @discardableResult
    func scan(_ item: Item, _ text: String, on client: SyncTestClient? = nil) async throws -> StoredRecord {
        try await (client ?? later).saveRecord(
            Array(text.utf8), recordID: item.id, kind: .scanStatus, schemaVersion: Self.schema)
    }

    static func rows(_ client: SyncTestClient, _ kind: EnvelopeKind) async throws -> [UUID: StoredRecord] {
        Dictionary(
            uniqueKeysWithValues: await client.store.records(in: SyncFixtures.vault, kind: kind).map {
                ($0.recordID, $0)
            })
    }
}

@Suite("Record kinds a device does not know")
struct SyncUnknownKindTests {
    @Test("an earlier version merges items past results it cannot read, and processes them once it can")
    func ignorableKindIsKeptAndProcessedAfterUpgrade() async throws {
        let home = await VersionedHousehold.make()
        let bank = try await home.later.save(Household.login(title: "Bank"))
        try await home.scan(bank, "breached once")
        let shop = try await home.later.save(Household.login(title: "Shop"))
        try await home.later.sync()
        try await home.later.edit(shop.id) { $0.notes = "after the scan" }
        let latest = try await home.scan(bank, "breached twice")
        try await home.later.sync()

        let report = try await home.earlier.sync()
        #expect(report.rejected.isEmpty && report.waiting.isEmpty && !report.requiresNewerVersion)
        #expect(report.unknownEntriesKept == 2 && report.unknownEntriesDropped == 0)
        #expect(try await home.earlier.items() == home.later.items(), "every item merged, the later edit included")
        #expect(
            try await VersionedHousehold.rows(home.earlier, .scanStatus).isEmpty, "nothing it cannot read is stored")
        let state = try #require(await home.earlier.state())
        #expect(state.merged[home.laterID] == 2, "the stream went on past both segments")
        let kept = await home.earlier.stash()
        #expect(kept.count == 1, "the second result replaced the first: its author's later version")
        #expect(kept.entries.first?.entry.envelope == latest.envelope, "kept byte for byte")
        #expect(kept.entries.first?.author == home.laterID)

        let upgraded = await home.upgraded()
        let after = try await upgraded.sync()
        #expect(after.fetched == 0, "nothing downloaded again")
        #expect(after.unknownEntriesProcessed == 1 && after.quarantined.isEmpty)
        #expect(try await VersionedHousehold.rows(upgraded, .scanStatus)[bank.id] == latest)
        #expect(await upgraded.stash().isEmpty)
    }

    @Test("results kept aside are processed after an upgrade even when they arrived in a snapshot")
    func ignorableKindFromSnapshot() async throws {
        let home = await VersionedHousehold.make { $0.snapshotThreshold = 4 }
        var latest: [UUID: StoredRecord] = [:]
        for round in 0..<6 {
            let item = try await home.later.save(Household.login(title: "Item \(round)"))
            latest[item.id] = try await home.scan(item, "result \(round)")
            try await home.later.sync()
        }
        #expect(
            await home.transport.list(prefix: SyncObjectLocation.vaultPrefix(SyncFixtures.vault))
                .contains { SyncObjectLocation(name: $0)?.kind == .snapshot })
        // An earlier device that joins now bootstraps from the snapshot as well as the segments.
        let report = try await home.earlier.sync()
        #expect(report.rejected.isEmpty && !report.requiresNewerVersion)
        #expect(try await home.earlier.items().count == 6)
        let upgraded = await home.upgraded { $0.snapshotThreshold = 4 }
        try await upgraded.sync()
        #expect(try await VersionedHousehold.rows(upgraded, .scanStatus) == latest)
    }

    /// The device holding results it cannot read is the elected snapshot writer (lowest ID). Were it to write one, the
    /// snapshot would cover the later device's segments without their results, the later device would collect them,
    /// and a later-version device joining afterwards would never see those results. It withholds instead, the other
    /// steps in at four times the threshold, and collection goes on.
    @Test("an earlier version writes no snapshot while it holds entries it cannot read, so collection loses nothing")
    func noSnapshotFromAStash() async throws {
        let home = await VersionedHousehold.make(laterID: SyncFixtures.deviceB, earlierID: SyncFixtures.deviceA) {
            $0.snapshotThreshold = 4
        }
        var latest: [UUID: StoredRecord] = [:]
        var withheld = false
        var collected = 0
        for round in 0..<24 {
            let item = try await home.later.save(Household.login(title: "Item \(round)"))
            latest[item.id] = try await home.scan(item, "result \(round)")
            collected += try await home.later.sync().collected
            let report = try await home.earlier.sync()
            #expect(report.snapshotsWritten == 0)
            withheld = withheld || report.snapshotWithheld
        }
        #expect(withheld, "the elected device was due to write one")
        #expect(collected > 0, "the later device stepped in, and segments were collected")
        let names = await home.transport.list(prefix: SyncObjectLocation.vaultPrefix(SyncFixtures.vault))
        #expect(
            !names.contains {
                SyncObjectLocation(name: $0).map { $0.kind == .snapshot && $0.author == home.earlierID } ?? false
            })

        let newcomer = await home.newcomer()
        try await newcomer.sync()
        #expect(try await newcomer.items() == home.later.items())
        #expect(try await VersionedHousehold.rows(newcomer, .scanStatus) == latest, "no result lost to collection")

        // Upgraded, it reads what it held, and is a snapshot writer like any other again.
        let upgraded = await home.upgraded { $0.snapshotThreshold = 4 }
        try await upgraded.sync()
        #expect(try await VersionedHousehold.rows(upgraded, .scanStatus) == latest)
        #expect(await upgraded.stash().isEmpty)
    }

    @Test("a critical kind an earlier version does not know stops the stream there, skips nothing, and says so")
    func criticalKindStopsTheStream() async throws {
        let home = await VersionedHousehold.make()
        let first = try await home.later.save(Household.login(title: "First"))
        try await home.later.sync()
        let second = try await home.later.save(Household.login(title: "Second"))
        let description = try await home.later.saveRecord(
            Array("Household".utf8), recordID: SyncFixtures.vault, kind: .vaultMetadata,
            schemaVersion: VersionedHousehold.schema)
        try await home.later.sync()
        let third = try await home.later.save(Household.login(title: "Third"))
        try await home.later.sync()
        let segment2 = SyncObjectLocation.segment(
            vaultID: SyncFixtures.vault, author: home.laterID, sequence: 2)

        let report = try await home.earlier.sync()
        #expect(report.requiresNewerVersion)
        #expect(
            report.rejected == [
                SyncRejection(
                    name: segment2.name, reason: .format(.unsupportedRecordKind(EnvelopeKind.vaultMetadata.rawValue)))
            ])
        #expect(report.waiting[home.laterID] == 2)
        #expect(Set(try await home.earlier.items().keys) == [first.id], "not the item beside it, nor the one after")
        #expect(await home.earlier.state()?.merged[home.laterID] == 1)
        let again = try await home.earlier.sync()
        #expect(again.requiresNewerVersion && again.fetched == 0, "kept staged, not downloaded again")

        let upgraded = await home.upgraded()
        let after = try await upgraded.sync()
        #expect(!after.requiresNewerVersion && after.rejected.isEmpty && after.fetched == 0)
        #expect(Set(try await upgraded.items().keys) == [first.id, second.id, third.id])
        #expect(try await VersionedHousehold.rows(upgraded, .vaultMetadata)[SyncFixtures.vault] == description)
    }

    @Test("a snapshot with a critical kind an earlier version does not know is refused whole and kept staged")
    func criticalKindInASnapshot() async throws {
        let home = await VersionedHousehold.make { $0.snapshotThreshold = 4 }
        try await home.later.saveRecord(
            Array("Household".utf8), recordID: SyncFixtures.vault, kind: .vaultMetadata,
            schemaVersion: VersionedHousehold.schema)
        for round in 0..<6 {
            try await home.later.save(Household.login(title: "Item \(round)"))
            try await home.later.sync()
        }
        let report = try await home.earlier.sync()
        #expect(report.requiresNewerVersion)
        #expect(report.rejected.contains { SyncObjectLocation(name: $0.name)?.kind == .snapshot })
        #expect(try await home.earlier.items().isEmpty, "the stream stops at its first segment, which carries it")
        // The later device goes on writing snapshots and collecting the ones they supersede; what the earlier one
        // keeps staged never outgrows what is listed.
        for round in 6..<30 {
            try await home.later.save(Household.login(title: "Item \(round)"))
            try await home.later.sync()
            try await home.earlier.sync()
        }
        let listed = await home.transport.list(prefix: SyncObjectLocation.vaultPrefix(SyncFixtures.vault))
            .compactMap(SyncObjectLocation.init(name:)).filter { $0.kind == .snapshot }
        let staged = await home.earlierState.staged(vaultID: SyncFixtures.vault).filter {
            $0.location.kind == .snapshot
        }
        #expect(!staged.isEmpty && Set(staged.map(\.location)).isSubset(of: Set(listed)))
        let upgraded = await home.upgraded { $0.snapshotThreshold = 4 }
        let after = try await upgraded.sync()
        #expect(after.rejected.isEmpty)
        #expect(try await upgraded.items().count == 30)
    }

    @Test("past the stash's cap entries are dropped, the stream still merges, and the upgrade replays the log")
    func overflowReplaysOnUpgrade() async throws {
        let home = await VersionedHousehold.make { $0.maximumStashedEntries = 2 }
        var latest: [UUID: StoredRecord] = [:]
        for index in 0..<5 {
            let item = try await home.later.save(Household.login(title: "Item \(index)"))
            latest[item.id] = try await home.scan(item, "result \(index)")
        }
        try await home.later.sync()
        let last = try await home.later.save(Household.login(title: "After"))
        try await home.later.sync()

        let report = try await home.earlier.sync()
        #expect(report.unknownEntriesKept == 2 && report.unknownEntriesDropped == 3)
        #expect(report.rejected.isEmpty && report.waiting.isEmpty)
        let merged = try await home.earlier.items()
        #expect(merged.count == 6 && merged[last.id] != nil)
        #expect(await home.earlier.stash().crowdedOut == [EnvelopeKind.scanStatus.rawValue], "the vault's cap")

        let upgraded = await home.upgraded { $0.maximumStashedEntries = 2 }
        let after = try await upgraded.sync()
        #expect(after.fetched > 0, "the log replayed")
        #expect(try await VersionedHousehold.rows(upgraded, .scanStatus) == latest)
        #expect(await upgraded.stash().isEmpty)
        #expect(await upgraded.state()?.stashUnsaved == false)
    }
}

@Suite("Unknown record kinds in the payload")
struct SyncPayloadUnknownKindTests {
    static func unknown(_ n: UInt8, rawKind: UInt8, deleted: Bool = false) -> UnknownSyncEntry {
        var entry = UnknownSyncEntry(SyncFixtures.entry(n, deleted: deleted))
        entry.rawKind = rawKind
        return entry
    }

    @Test("entries of ignorable kinds a reader does not carry are kept byte for byte", arguments: [10, 11, 77, 127])
    func ignorable(_ rawKind: UInt8) throws {
        var payload = SyncFixtures.payload()
        payload.unknownEntries = [Self.unknown(1, rawKind: rawKind), Self.unknown(4, rawKind: rawKind, deleted: true)]
        let bytes = payload.encoded()
        let parsed = try SyncPayload.parse(bytes, allowedKinds: [.item])
        #expect(parsed.entries == payload.entries.sorted(by: SyncPayload.entryOrder))
        #expect(Set(parsed.unknownEntries) == Set(payload.unknownEntries))
        #expect(parsed.encoded() == bytes)
    }

    @Test("an entry of a critical kind a reader does not carry refuses the payload", arguments: [6, 9, 128, 200, 255])
    func critical(_ rawKind: UInt8) {
        var payload = SyncFixtures.payload()
        payload.unknownEntries = [Self.unknown(5, rawKind: rawKind)]
        #expect(throws: SyncFormatError.unsupportedRecordKind(rawKind)) {
            try SyncPayload.parse(payload.encoded(), allowedKinds: [.item])
        }
    }

    @Test("a known and an unknown entry for the same record and kind are not canonical")
    func duplicateAcrossLists() {
        var payload = SyncFixtures.payload(entries: [SyncFixtures.entry(1)])
        payload.unknownEntries = [Self.unknown(1, rawKind: EnvelopeKind.item.rawValue)]
        #expect(throws: SyncFormatError.notCanonical) {
            try SyncPayload.parse(payload.encoded(), allowedKinds: [.item])
        }
    }
}

extension VersionedHousehold {
    /// Seals and signs `payload` as `client` would, and puts it on the transport under its own name.
    func plant(_ payload: SyncPayload, as client: SyncTestClient) async throws {
        let keyring = await client.keyring
        let envelope = try await keyring.seal(payload.encoded(), at: payload.location)
        let signature = try await keyring.sign(envelope, at: payload.location)
        await transport.tamper(
            payload.location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
    }
}

extension SyncUnknownKindTests {
    @Test("a revoked device's own results kept aside survive a replay, and are processed after the upgrade")
    func revokedAuthorsOwnEntriesSurviveReconcile() async throws {
        let home = await VersionedHousehold.make()
        let item = try await home.later.save(Household.login(title: "Bank"))
        let result = try await home.scan(item, "found once")
        try await home.later.sync()
        try await home.earlier.sync()
        #expect(await home.earlier.stash().count == 1)
        await home.keys.retire(device: home.laterID)
        // The replay reads nothing of the revoked device's, so what it kept of that device's own is kept across it.
        try await home.earlier.sync(reconcile: true)
        let kept = await home.earlier.stash()
        #expect(kept.count == 1 && kept.entries.first?.author == home.laterID)
        #expect(!kept.holdsBackSnapshots(retired: [home.laterID]))
        let upgraded = await home.upgraded()
        let after = try await upgraded.sync()
        #expect(after.unknownEntriesProcessed == 1)
        #expect(try await VersionedHousehold.rows(upgraded, .scanStatus)[item.id] == result)
    }

    @Test("a snapshot's lower version of a result already held from its writer's stream is not kept again")
    func supersededSnapshotEntryIsNotKept() async throws {
        let home = await VersionedHousehold.make()
        let item = try await home.later.save(Household.login(title: "Bank"))
        let older = try await home.scan(item, "first")
        let newer = try await home.scan(item, "second")
        // The stream carries the newer version; a snapshot by the same device (a stale one) the older.
        try await home.plant(
            SyncPayload(
                kind: .segment, vaultID: SyncFixtures.vault, author: home.laterID, number: 1, vector: [:],
                entries: [SyncEntry(newer)]),
            as: home.later)
        try await home.earlier.sync()
        try await home.plant(
            SyncPayload(
                kind: .snapshot, vaultID: SyncFixtures.vault, author: home.laterID, number: 1, vector: [:],
                entries: [SyncEntry(older)]),
            as: home.later)
        let report = try await home.earlier.sync()
        #expect(report.rejected.isEmpty && report.unknownEntriesKept == 0)
        let kept = await home.earlier.stash()
        #expect(kept.count == 1 && kept.entries.first?.entry.envelope == newer.envelope)
    }

    @Test("a critical segment a merged snapshot covers is passed without asking for a newer version")
    func coveredCriticalSegmentIsNoStop() async throws {
        let home = await VersionedHousehold.make()
        let first = try await home.later.save(Household.login(title: "First"))
        try await home.later.sync()
        try await home.later.saveRecord(
            Array("Household".utf8), recordID: SyncFixtures.vault, kind: .vaultMetadata,
            schemaVersion: VersionedHousehold.schema)
        try await home.later.sync()
        // A snapshot that covers both segments and carries only the item (as one whose author dropped the record).
        let row = try #require(try await home.later.store.record(RecordKey(recordID: first.id, kind: .item)))
        try await home.plant(
            SyncPayload(
                kind: .snapshot, vaultID: SyncFixtures.vault, author: home.laterID, number: 9,
                vector: [home.laterID: 2], entries: [SyncEntry(row)]),
            as: home.later)
        let report = try await home.earlier.sync()
        #expect(!report.requiresNewerVersion)
        #expect(report.waiting.isEmpty)
        #expect(Set(try await home.earlier.items().keys) == [first.id])
    }

    @Test("a stash that may not have been saved after a sync is rebuilt by replaying the log")
    func unsavedStashIsRebuilt() async throws {
        let home = await VersionedHousehold.make()
        let item = try await home.later.save(Household.login(title: "Bank"))
        try await home.scan(item, "found")
        try await home.later.sync()
        try await home.earlier.sync()
        let saved = await home.earlier.stash()
        #expect(saved.count == 1)
        // As after a crash between counting the segment merged and saving the stash.
        var state = try #require(await home.earlier.state())
        state.stashUnsaved = true
        await home.earlierState.tamper(state)
        await home.earlierState.tamperStash(SyncStash().encoded(), vaultID: SyncFixtures.vault)
        let report = try await home.earlier.sync()
        #expect(report.fetched > 0, "replayed")
        #expect(await home.earlier.stash().entries == saved.entries)
        #expect(await home.earlier.state()?.stashUnsaved == false)
    }
}

/// A shared vault's judge, scripted: holds aside the segments it is told to, and admits or refuses every erasure.
actor ScriptedJudge: WriteJudge {
    private var heldAside: Set<SyncObjectLocation> = []
    private var refusesErasures = false

    func holdAside(_ location: SyncObjectLocation) {
        heldAside.insert(location)
    }

    func refuseErasures() {
        refusesErasures = true
    }

    func record(segment location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8], entries: [SyncEntry]) {}

    func admitsSegment(_ location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8]) -> SegmentAdmission {
        heldAside.contains(location) ? .holdAside : .apply
    }

    func admits(_ record: StoredRecord) -> Bool {
        true
    }

    func admitsErasure(_ entry: SyncEntry, in location: SyncObjectLocation, sealedUnder keyID: UUID) -> Bool {
        !refusesErasures
    }

    func passesOverSegment(sealedUnder keyID: UUID, vaultID: UUID) -> Bool {
        false
    }
}

extension VersionedHousehold {
    /// The earlier device's engine as a shared vault runs it (a judge, no snapshots, no collection), of the earlier
    /// version or, `upgraded`, the later.
    func judgedEngine(_ judge: ScriptedJudge, upgraded: Bool = false) -> SyncEngine {
        let keyring = FakeSyncKeyring(deviceID: earlierID, keys: keys)
        var configuration = upgraded ? Self.laterConfiguration() : Self.earlierConfiguration()
        configuration.maintainsLog = false
        var mergers: [EnvelopeKind: any RecordMerger] = [.item: FakeItemMerger(keyring: keyring)]
        if upgraded {
            for (kind, schema) in Self.laterKinds {
                mergers[kind] = OpaqueRecordMerger(keyring: keyring, schemaVersion: schema)
            }
        }
        return SyncEngine(
            vaultID: SyncFixtures.vault, deviceID: earlierID, store: earlierStore, syncState: earlierState,
            transport: transport, keyring: keyring, merger: KindRoutingMerger(mergers), configuration: configuration,
            judge: judge)
    }

    /// Permanently deletes a scan record on the later device, as the session does: a pending deletion to publish.
    func deleteScan(_ itemID: UUID) async throws {
        let key = RecordKey(recordID: itemID, kind: .scanStatus)
        let row = try #require(try await later.sessionStore.record(key))
        try await later.sessionStore.commit(StoreChange(conditionalDeletions: [key: row.version]))
    }
}

/// How kept entries meet a shared vault's judge (the late-writes rules, docs/10 §9; ADR 0009).
@Suite("Record kinds a device does not know, in a shared vault")
struct SyncUnknownKindJudgedTests {
    @Test("a segment the judge holds aside puts nothing in the stash")
    func heldAsideSegmentKeepsNothing() async throws {
        let home = await VersionedHousehold.make()
        let judge = ScriptedJudge()
        let item = try await home.later.save(Household.login(title: "Late"))
        try await home.scan(item, "late result")
        try await home.later.sync()
        await judge.holdAside(.segment(vaultID: SyncFixtures.vault, author: home.laterID, sequence: 1))
        let report = try await home.judgedEngine(judge).sync(publishing: false)
        #expect(report.heldAside == [RecordKey(recordID: item.id, kind: .item)])
        #expect(report.unknownEntriesKept == 0)
        #expect(await home.earlier.stash().isEmpty)
        #expect(await home.earlier.state()?.merged[home.laterID] == 1, "the stream went on past it")
    }

    /// A tombstone is judged by the segment that carried it (`admitsErasure`, S45). In a shared vault only a revoked
    /// device's kept entries are processed without a replay, and a kept tombstone has no segment left to judge it by,
    /// so it is held aside like a tombstone the judge refused: the record stays. The device's live versions are judged
    /// by `admits` as usual.
    @Test("a revoked device's kept tombstone is held aside in a shared vault, its live versions judged as usual")
    func keptTombstoneIsHeldAside() async throws {
        let home = await VersionedHousehold.make()
        let judge = ScriptedJudge()
        let item = try await home.later.save(Household.login(title: "Bank"))
        let result = try await home.scan(item, "found")
        try await home.later.sync()
        try await home.deleteScan(item.id)
        try await home.later.sync()
        try await home.judgedEngine(judge).sync(publishing: false)
        #expect(await home.earlier.stash().count == 2, "the version and the tombstone")
        await home.keys.retire(device: home.laterID)

        let report = try await home.judgedEngine(judge, upgraded: true).sync(publishing: false)
        let key = RecordKey(recordID: item.id, kind: .scanStatus)
        #expect(report.heldAside == [key])
        #expect(report.unknownEntriesProcessed == 2 && !report.replayNeeded)
        #expect(try await VersionedHousehold.rows(home.earlier, .scanStatus)[item.id] == result)
        #expect(await home.earlierState.quarantined(vaultID: SyncFixtures.vault).contains { $0.isDeletion })
        #expect(await home.earlier.stash().isEmpty)
    }

    /// The session's take-out ends in a replay (`needsReconcile`, §8.10). A replay rebuilds the stash from the log,
    /// except a revoked device's own versions, which no replay reads: those are kept across it and processed once,
    /// and entries of a trusted device are processed by the replay itself, not also from the stash.
    @Test("a replay neither drops a revoked device's kept versions nor processes any kept entry twice")
    func replayKeepsAndProcessesOnce() async throws {
        let home = await VersionedHousehold.make()
        let judge = ScriptedJudge()
        let other = await home.newcomer(SyncFixtures.deviceC)
        let fromRevoked = try await home.later.save(Household.login(title: "Revoked's"))
        let revokedResult = try await home.scan(fromRevoked, "revoked's result")
        try await home.later.sync()
        let fromTrusted = try await other.save(Household.login(title: "Trusted's"))
        let trustedResult = try await other.saveRecord(
            Array("trusted's result".utf8), recordID: fromTrusted.id, kind: .scanStatus,
            schemaVersion: VersionedHousehold.schema)
        try await other.sync()
        try await home.judgedEngine(judge).sync(publishing: false)
        #expect(await home.earlier.stash().count == 2)
        await home.keys.retire(device: home.laterID)

        // A take-out's replay on the earlier version: the revoked device's own entry survives it.
        try await home.judgedEngine(judge).sync(reconcile: true, publishing: false)
        let kept = await home.earlier.stash()
        #expect(kept.count == 2 && kept.entries.contains { $0.author == home.laterID })

        // Upgraded: the revoked device's entry is processed now, the trusted one waits for the replay.
        let upgraded = home.judgedEngine(judge, upgraded: true)
        let first = try await upgraded.sync(publishing: false)
        #expect(first.replayNeeded && first.unknownEntriesProcessed == 1)
        let second = try await upgraded.sync(reconcile: true, publishing: false)
        #expect(second.unknownEntriesProcessed == 0 && !second.replayNeeded)
        #expect(await home.earlier.stash().isEmpty)
        let rows = try await VersionedHousehold.rows(home.earlier, .scanStatus)
        #expect(rows[fromRevoked.id] == revokedResult && rows[fromTrusted.id] == trustedResult)
        let third = try await upgraded.sync(publishing: false)
        #expect(third.unknownEntriesProcessed == 0 && third.applied == 0 && !third.replayNeeded)
    }
}

/// The second review of the stash (docs/06 §N, N14 to N19).
@Suite("Record kinds a device does not know: the stash under review")
struct SyncStashReviewTests {
    /// An insider's snapshot attributes a version far above the real one to another device's record. Held, it must
    /// not stop the genuine version that another carrier's snapshot holds from being kept: once the insider is revoked
    /// its entry is forgotten, and the genuine one would be gone with it.
    @Test("an entry another carrier attributed to a device does not keep out that device's genuine version")
    func foreignAttributionSuppressesNothing() async throws {
        let home = await VersionedHousehold.make()
        let insider = UUID(uuidString: "D0000000-0000-4000-8000-0000000000E0")!
        await home.keys.trust(device: insider)
        let carrier = await home.newcomer(SyncFixtures.deviceC)
        let bad = SyncTestClient(
            deviceID: insider, vaultID: SyncFixtures.vault, keys: home.keys, transport: home.transport,
            configuration: VersionedHousehold.laterConfiguration(), opaqueKinds: VersionedHousehold.laterKinds)
        let item = try await home.later.save(Household.login(title: "Bank"))
        let genuine = try await home.scan(item, "genuine")
        var bogus = UnknownSyncEntry(SyncEntry(genuine))
        bogus.version = 1 << 40
        try await home.plant(
            SyncPayload(
                kind: .snapshot, vaultID: SyncFixtures.vault, author: insider, number: 1, vector: [:], entries: [],
                unknownEntries: [bogus]),
            as: bad)
        try await home.plant(
            SyncPayload(
                kind: .snapshot, vaultID: SyncFixtures.vault, author: SyncFixtures.deviceC, number: 2, vector: [:],
                entries: [SyncEntry(genuine)]),
            as: carrier)
        try await home.earlier.sync()
        await home.keys.retire(device: insider)
        try await home.earlier.sync()
        let kept = await home.earlier.stash()
        #expect(kept.entries.map(\.entry.envelope) == [genuine.envelope])
        #expect(kept.entries.first?.author == SyncFixtures.deviceC)
    }

    /// Two insiders fill the vault's cap between them, within their own shares. What an honest device's objects
    /// carried and could not be kept is not held against that device (it is not named, and it is not tied to it), and
    /// once the insiders are revoked the room they took is freed and the log replayed to bring it back.
    @Test("entries crowded out by others are not blamed on their carrier, and come back once room is freed")
    func crowdedOutIsNotBlamed() async throws {
        let home = await VersionedHousehold.make {
            $0.maximumStashedEntries = 4
            $0.maximumStashedEntriesPerAuthor = 2
        }
        let insiders = [
            UUID(uuidString: "D0000000-0000-4000-8000-000000000010")!,
            UUID(uuidString: "D0000000-0000-4000-8000-000000000011")!,
        ]
        for insider in insiders {
            await home.keys.trust(device: insider)
            let bad = SyncTestClient(
                deviceID: insider, vaultID: SyncFixtures.vault, keys: home.keys, transport: home.transport)
            try await home.plant(
                SyncPayload(
                    kind: .segment, vaultID: SyncFixtures.vault, author: insider, number: 1, vector: [:], entries: [],
                    unknownEntries: (1...2).map {
                        UnknownSyncEntry(
                            recordID: UUID(), rawKind: 99, keyID: SyncPayload.zeroUUID, version: $0, device: insider,
                            envelope: nil, erasure: [1])
                    }),
                as: bad)
        }
        let item = try await home.later.save(Household.login(title: "Bank"))
        let result = try await home.scan(item, "honest")
        try await home.later.sync()
        let report = try await home.earlier.sync()
        #expect(report.unknownEntriesDropped == 1)
        let crowded = await home.earlier.stash()
        #expect(crowded.overflow[home.laterID] == nil, "not held against the honest device")
        for insider in insiders { await home.keys.retire(device: insider) }
        let after = try await home.earlier.sync()
        #expect(after.fetched > 0, "the freed room is filled again from the log")
        let kept = await home.earlier.stash()
        #expect(kept.entries.map(\.entry.envelope) == [result.envelope])
        #expect(kept.authorsHoldingBackSnapshots(retired: Set(insiders)) == [home.laterID])
    }

    /// A8 replaces the stash row with an empty one that parses, while the state says entries were kept: the device
    /// would forget them and write ordinary snapshots again. The row carries the generation the state names.
    @Test("a stash row that is not the generation the state names is rebuilt, not taken as empty")
    func staleOrMissingRowIsRebuilt() async throws {
        let home = await VersionedHousehold.make()
        let item = try await home.later.save(Household.login(title: "Bank"))
        try await home.scan(item, "found")
        try await home.later.sync()
        try await home.earlier.sync()
        let saved = await home.earlier.stash()
        #expect(saved.count == 1)
        await home.earlierState.tamperStash(SyncStash().encoded(), vaultID: SyncFixtures.vault)
        let report = try await home.earlier.sync()
        #expect(report.fetched > 0, "replayed")
        #expect(await home.earlier.stash().entries == saved.entries)
    }
}
