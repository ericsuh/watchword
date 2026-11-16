import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// ADR 0009: a reader that does not know a record kind keeps an ignorable entry aside and carries on, and stops at a
/// critical one. The readers here are the fixture's own (they carry items only), so `scanStatus` (10) and raw values
/// no version defines yet are unknown to them.
extension AdversarialSyncTests {
    static let scanSchema: UInt64 = 1

    /// Where the first entry's kind byte sits in a segment's sealed envelope, and the segment's parts.
    static func kindByteOffset(of name: String, in f: Fixture) async throws -> (SignedObject, Int) {
        let object = try SignedObject.parse(try #require(await f.transport.allObjects[name]))
        let location = try #require(SyncObjectLocation(name: name))
        let (header, payloadOffset) = try EnvelopeHeader.parse(object.envelope, expecting: .logSegment)
        let plaintext = try await f.writer.keyring.open(
            object.envelope, context: location.envelopeContext(keyID: header.keyID))
        let payload = try SyncPayload.parse(plaintext, allowedKinds: [.item])
        // magic, format version, object kind, vault, author, number; the vector; the entry count; the record ID.
        let offset = 4 + 1 + 1 + 16 + 16 + 8 + 4 + 24 * payload.vector.count + 4 + 16
        #expect(plaintext[offset] == payload.entries[0].kind.rawValue)
        return (object, payloadOffset + offset)
    }

    /// Threat: A1, with write access to the store and no key, wants an item skipped by a device of an earlier version.
    /// The ciphertext is malleable bit for bit, so A1 flips the bits that turn the entry's kind byte from `item` (0,
    /// critical) into `scanStatus` (10, ignorable), or into 200 (critical, unknown) to stall the stream instead.
    /// Criticality is the kind byte, which the signature and the AEAD both cover: each flip is refused, nothing is
    /// applied or kept aside, and the stream waits, as for any tampering.
    @Test(
        "flipping an entry's kind, and with it its criticality, fails authentication",
        arguments: [EnvelopeKind.scanStatus.rawValue, 77, 200])
    func kindFlip(_ flippedKind: UInt8) async throws {
        let f = try await Self.fixture()
        try await f.writer.save(Self.login("Bank", password: "kind-flip"))
        try await f.writer.sync()
        let name = f.segmentName(1)
        let (object, position) = try await Self.kindByteOffset(of: name, in: f)
        var envelope = object.envelope
        envelope[position] ^= EnvelopeKind.item.rawValue ^ flippedKind
        await f.transport.tamper(
            name, contents: SignedObject(signature: object.signature, envelope: envelope).serialized())

        let reader = await f.reader()
        let report = try await reader.sync()
        #expect(report.rejected == [SyncRejection(name: name, reason: .keyring(.authenticationFailed))])
        #expect(report.applied == 0 && report.unknownEntriesKept == 0 && !report.requiresNewerVersion)
        #expect(report.waiting[Self.a] == 1)
        #expect(try await reader.items().isEmpty)
        #expect(await reader.stash().isEmpty)
    }

    /// Threat: an insider device (or A4 in a shared vault), holding the vault key and a trusted signing key, files an
    /// item's envelope under an ignorable kind byte, so that devices of an earlier version keep it aside unread while
    /// later ones see an item. The record's own header names its kind, so the earlier reader refuses the segment as a
    /// relabelled record, as a later one does, and the stream waits rather than passing over the item.
    @Test("an item filed under an ignorable kind is refused, not passed over")
    func itemUnderIgnorableLabel() async throws {
        let f = try await Self.fixture()
        let item = try await f.writer.save(Self.login("Bank", password: "relabelled"))
        let row = try #require(try await f.writer.store.record(RecordKey(recordID: item.id, kind: .item)))
        var relabelled = UnknownSyncEntry(SyncEntry(row))
        relabelled.rawKind = EnvelopeKind.scanStatus.rawValue
        let payload = SyncPayload(
            kind: .segment, vaultID: Self.vault, author: Self.a, number: 1, vector: [:], entries: [],
            unknownEntries: [relabelled])
        try await f.plant(payload, signedBy: await f.writer.keyring)

        let reader = await f.reader()
        let report = try await reader.sync()
        #expect(
            report.rejected == [SyncRejection(name: f.segmentName(1), reason: .recordContextMismatch(item.id))])
        #expect(report.unknownEntriesKept == 0 && report.waiting[Self.a] == 1)
        #expect(await reader.stash().isEmpty)
    }

    /// Threat: an insider device (or A4), with the vault key and a trusted signing key, floods its stream with
    /// entries of an ignorable kind no version reads (raw 99), to fill other devices' storage, stall their streams,
    /// or crowd out honest results. A1 cannot do this at all: every entry is inside a signed, sealed segment. The stash
    /// stops at the flooder's own share of its cap; past it the flooder's entries are dropped and the kind recorded
    /// against it; every stream still merges (the flooder's own items included); honest results keep their room and are
    /// processed after an update without a download; the device writes no snapshot that could cover what it dropped,
    /// and the flood never makes it replay.
    @Test("flooding ignorable unknown entries hits the cap without stalling or losing honest data")
    func flood() async throws {
        let f = try await Self.fixture()
        // Below the honest device's ID, so its stream is merged first and the flood fills the stash before the honest
        // results arrive.
        let flooder = UUID(uuidString: "D0000000-0000-4000-8000-000000000010")!
        await f.keys.trust(device: flooder)
        let later: [EnvelopeKind: UInt64] = [.scanStatus: Self.scanSchema]
        var laterConfiguration = SyncTestClient.configuration
        laterConfiguration.schemaVersions[.scanStatus] = Self.scanSchema
        // The honest device writes items and results in the later version.
        let honest = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: laterConfiguration, opaqueKinds: later)
        var results: [UUID: StoredRecord] = [:]
        for index in 0..<3 {
            let item = try await honest.save(Self.login("Honest \(index)", password: "honest-\(index)"))
            results[item.id] = try await honest.saveRecord(
                Array("result \(index)".utf8), recordID: item.id, kind: .scanStatus, schemaVersion: Self.scanSchema)
        }
        try await honest.sync()

        // The flooder's stream: an ordinary item, then a segment of 200 entries of kind 99.
        let flooding = SyncTestClient(deviceID: flooder, vaultID: Self.vault, keys: f.keys, transport: f.transport)
        let own = try await flooding.save(Self.login("Flooder's own", password: "own"))
        try await flooding.sync()
        let keyring = await flooding.keyring
        let junk = (0..<200).map { index in
            UnknownSyncEntry(
                recordID: UUID(), rawKind: 99, keyID: SyncPayload.zeroUUID, version: UInt64(index + 1),
                device: flooder, envelope: nil, erasure: Array(repeating: 0xAA, count: 512))
        }
        try await f.plant(
            SyncPayload(
                kind: .segment, vaultID: Self.vault, author: flooder, number: 2, vector: [:], entries: [],
                unknownEntries: junk),
            signedBy: keyring)

        func tune(_ configuration: inout SyncConfiguration) {
            configuration.maximumStashedEntries = 16
            configuration.maximumStashedBytes = 6 << 10
            // The flooder's own share is half the vault's: honest results keep their room (N17).
            configuration.maximumStashedEntriesPerAuthor = 8
        }
        var earlierConfiguration = SyncTestClient.configuration
        tune(&earlierConfiguration)
        await f.keys.trust(device: Self.b)
        let store = InMemoryRecordStore()
        let state = InMemorySyncStateStore()
        let reader = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: earlierConfiguration, store: store, syncState: state)
        let report = try await reader.sync()
        #expect(report.rejected.isEmpty && report.waiting.isEmpty, "no stream stalls")
        #expect(report.unknownEntriesDropped > 0)
        #expect(Set(try await reader.items().keys) == Set(results.keys).union([own.id]), "every item merged")
        let held = try #require(await reader.state())
        let kept = await reader.stash()
        #expect(kept.count <= 16 && kept.bytes <= 6 << 10)
        #expect(held.merged[flooder] == 2 && held.merged[Self.a] == 1)
        #expect(kept.overflow[flooder]?.contains(99) == true)
        // One stash write for the whole pass, not one per merged segment.
        #expect(await state.stashWrites[Self.vault] == 1)

        // Updated to read scan results: the honest ones are all there, the flood is still capped, and the replay
        // it needed is not repeated on the next sync.
        tune(&laterConfiguration)
        let upgraded = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: laterConfiguration, store: store, syncState: state, opaqueKinds: later)
        try await upgraded.sync()
        let scans = await store.records(in: Self.vault, kind: .scanStatus)
        #expect(Dictionary(uniqueKeysWithValues: scans.map { ($0.recordID, $0) }) == results)
        #expect(await upgraded.stash().overflow == [flooder: [99]])
        #expect(try await upgraded.sync().fetched == 0)
    }

    /// Threat: an insider device with the vault key and a trusted signing key publishes one entry of a kind no
    /// version defines (raw 99), then is revoked. Every device keeps the entry aside; were that to hold back
    /// snapshots, none would be written again — collection would stop for good, and the snapshot that hands on the
    /// revoked device's work from before its revocation (§7.8) would never come, so a device joining later would lack
    /// that work. A revoked device's objects are not read, and what it carried does not hold back snapshots.
    @Test("an entry kept aside from a device since revoked does not stop snapshots or the hand-on of its work")
    func revokedAuthorsStashDoesNotStopSnapshots() async throws {
        let f = try await Self.fixture()
        let insider = UUID(uuidString: "D0000000-0000-4000-8000-0000000000E0")!
        await f.keys.trust(device: insider)
        await f.keys.trust(device: Self.b)
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 4
        func client(_ id: UUID) -> SyncTestClient {
            SyncTestClient(
                deviceID: id, vaultID: Self.vault, keys: f.keys, transport: f.transport, configuration: configuration)
        }
        let (a, b, bad) = (client(Self.a), client(Self.b), client(insider))
        let handedOn = try await bad.save(Self.login("Written before the revocation", password: "kept"))
        try await bad.sync()
        let unknown = UnknownSyncEntry(
            recordID: UUID(), rawKind: 99, keyID: SyncPayload.zeroUUID, version: 1, device: insider, envelope: nil,
            erasure: [1])
        try await f.plant(
            SyncPayload(
                kind: .segment, vaultID: Self.vault, author: insider, number: 2, vector: [:], entries: [],
                unknownEntries: [unknown]),
            signedBy: await bad.keyring)
        try await a.sync()
        try await b.sync()
        await f.keys.retire(device: insider)

        var snapshots = 0
        for round in 0..<40 {
            try await a.save(Self.login("Round \(round)", password: "round-\(round)"))
            snapshots += try await a.sync().snapshotsWritten
            snapshots += try await b.sync().snapshotsWritten
        }
        #expect(snapshots > 0)
        let newcomer = client(Self.former)
        await f.keys.trust(device: Self.former)
        try await newcomer.sync()
        #expect(try await newcomer.items()[handedOn.id] != nil, "the revoked device's earlier work was handed on")
    }

    /// Threat: an insider device that is still trusted keeps every device holding an entry it cannot read (raw 99), so
    /// no device writes an ordinary snapshot. Another device is then revoked, and its earlier work exists only on
    /// devices that merged it. The snapshot that hands that work on must still be written: it covers only the revoked
    /// device's stream, so no segment the kept entry came from can be collected on its strength.
    @Test("a trusted insider's unreadable entry does not stop the hand-on of a revoked device's work")
    func handOnDespiteStash() async throws {
        let f = try await Self.fixture()
        let insider = UUID(uuidString: "D0000000-0000-4000-8000-0000000000E0")!
        let lost = UUID(uuidString: "D0000000-0000-4000-8000-0000000000E1")!
        for id in [insider, lost, Self.b, Self.former] { await f.keys.trust(device: id) }
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 4
        func client(_ id: UUID) -> SyncTestClient {
            SyncTestClient(
                deviceID: id, vaultID: Self.vault, keys: f.keys, transport: f.transport, configuration: configuration)
        }
        let (a, b, bad, phone) = (client(Self.a), client(Self.b), client(insider), client(lost))
        try await bad.save(Self.login("Insider", password: "insider"))
        try await bad.sync()
        try await f.plant(
            SyncPayload(
                kind: .segment, vaultID: Self.vault, author: insider, number: 2, vector: [:], entries: [],
                unknownEntries: [
                    UnknownSyncEntry(
                        recordID: UUID(), rawKind: 99, keyID: SyncPayload.zeroUUID, version: 1, device: insider,
                        envelope: nil, erasure: [1])
                ]),
            signedBy: await bad.keyring)
        let handedOn = try await phone.save(Self.login("Only on the lost phone", password: "phone"))
        try await phone.sync()
        try await a.sync()
        try await b.sync()
        await f.keys.retire(device: lost)
        for round in 0..<12 {
            try await a.save(Self.login("Round \(round)", password: "round-\(round)"))
            try await a.sync()
            try await b.sync()
        }
        let names = await f.transport.list(prefix: SyncObjectLocation.vaultPrefix(Self.vault))
        let snapshots = names.compactMap(SyncObjectLocation.init(name:)).filter { $0.kind == .snapshot }
        #expect(!snapshots.isEmpty, "the hand-on snapshot was written")
        let newcomer = client(Self.former)
        try await newcomer.sync()
        #expect(try await newcomer.items()[handedOn.id] != nil)
        // Nothing of the insider's stream was collected on the strength of it: its segment is still there.
        #expect(names.contains(f.segmentName(2, author: insider)))
    }

    /// Threat: A8, who can write this device's files while it is locked, plants a stash row that keeps aside an
    /// *item* deletion, so that the next sync applies it and erases or trashes an item; or a row over this engine's
    /// caps. A critical kind is never kept aside, so the row is refused when parsed, dropped, and the log replayed to
    /// rebuild the stash; nothing in it reaches the store.
    @Test("a planted stash row naming a critical kind, or over the caps, is dropped and rebuilt, and erases nothing")
    func plantedStash() async throws {
        let f = try await Self.fixture()
        let item = try await f.writer.save(Self.login("Bank", password: "planted"))
        try await f.writer.sync()
        let reader = await f.reader()
        try await reader.sync()
        // The current layout and the generation the state names (none saved yet): only the kind is wrong.
        var planted = Array("WWSK".utf8) + [2] + SyncPayload.littleEndian(UInt64(0))
        planted += SyncPayload.littleEndian(UInt32(0)) + SyncPayload.littleEndian(UInt32(0))
        planted += SyncPayload.littleEndian(UInt32(1))
        planted += SyncPayload.bytes(Self.a) + SyncPayload.bytes(item.id) + [EnvelopeKind.item.rawValue]
        planted += SyncPayload.bytes(SyncPayload.zeroUUID) + SyncPayload.littleEndian(UInt64(1 << 40))
        planted += SyncPayload.bytes(Self.a) + [1] + SyncPayload.littleEndian(UInt32(0))
        await reader.syncState.tamperStash(planted, vaultID: Self.vault)
        let report = try await reader.sync()
        #expect(report.fetched > 0, "the log was replayed to rebuild the stash")
        let row = try #require(try await reader.store.record(RecordKey(recordID: item.id, kind: .item)))
        #expect(try await reader.keyring.openItem(row).trashedAt == nil, "neither erased nor trashed")
        #expect(await reader.stash().isEmpty)

        // Over the caps: as many entries as the default configuration's cap, plus one.
        var over = SyncStash()
        for index in 0...4096 {
            over.insert(
                .init(
                    entry: UnknownSyncEntry(
                        recordID: UUID(), rawKind: 99, keyID: SyncPayload.zeroUUID, version: UInt64(index + 1),
                        device: Self.a, envelope: nil),
                    author: Self.a))
        }
        await reader.syncState.tamperStash(over.encoded(), vaultID: Self.vault)
        #expect(try await reader.sync().fetched > 0)
        #expect(await reader.stash().isEmpty)
    }
}
