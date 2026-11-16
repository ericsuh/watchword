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
        #expect(state.stashed.count == 1, "the second result replaced the first: its author's later version")
        #expect(state.stashed.first?.envelope == latest.envelope, "kept byte for byte")

        let upgraded = await home.upgraded()
        let after = try await upgraded.sync()
        #expect(after.fetched == 0, "nothing downloaded again")
        #expect(after.unknownEntriesProcessed == 1 && after.quarantined.isEmpty)
        #expect(try await VersionedHousehold.rows(upgraded, .scanStatus)[bank.id] == latest)
        #expect(await upgraded.state()?.stashed.isEmpty == true)
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
        #expect(await upgraded.state()?.stashed.isEmpty == true)
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
        #expect(await home.earlier.state()?.stashOverflow == [EnvelopeKind.scanStatus.rawValue])

        let upgraded = await home.upgraded { $0.maximumStashedEntries = 2 }
        let after = try await upgraded.sync()
        #expect(after.fetched > 0, "the log replayed")
        #expect(try await VersionedHousehold.rows(upgraded, .scanStatus) == latest)
        let state = try #require(await upgraded.state())
        #expect(state.stashed.isEmpty && state.stashOverflow.isEmpty)
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
