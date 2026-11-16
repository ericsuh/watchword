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
        #expect(await reader.state()?.stashed.isEmpty ?? true)
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
        #expect(await reader.state()?.stashed.isEmpty ?? true)
    }

    /// Threat: an insider device (or A4), with the vault key and a trusted signing key, floods its stream with
    /// entries of an ignorable kind no version reads (raw 99), to fill other devices' storage, stall their streams,
    /// or crowd out honest results. A1 cannot do this at all: every entry is inside a signed, sealed segment. The stash
    /// stops at its cap; past it entries are dropped and the kind recorded; every stream still merges (the flooder's
    /// own items included); the device writes no snapshot that could cover what it dropped; honest results it dropped
    /// come back from the log once it reads their kind, and the flood never makes it replay twice.
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
        #expect(held.stashed.count <= 16 && held.stashed.reduce(0) { $0 + $1.length } <= 6 << 10)
        #expect(held.merged[flooder] == 2 && held.merged[Self.a] == 1)
        #expect(held.stashOverflow.contains(99))

        // Updated to read scan results: the honest ones are all there, the flood is still capped, and the replay
        // it needed is not repeated on the next sync.
        laterConfiguration.maximumStashedEntries = 16
        laterConfiguration.maximumStashedBytes = 6 << 10
        let upgraded = SyncTestClient(
            deviceID: Self.b, vaultID: Self.vault, keys: f.keys, transport: f.transport,
            configuration: laterConfiguration, store: store, syncState: state, opaqueKinds: later)
        try await upgraded.sync()
        let scans = await store.records(in: Self.vault, kind: .scanStatus)
        #expect(Dictionary(uniqueKeysWithValues: scans.map { ($0.recordID, $0) }) == results)
        #expect(await upgraded.state()?.stashOverflow == [99])
        #expect(try await upgraded.sync().fetched == 0)
    }
}
