import Foundation
import Testing
import WatchwordEnvelope
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

enum SyncFixtures {
    static let vault = UUID(uuidString: "0A0A0A0A-0000-4000-8000-00000000000A")!
    static let otherVault = UUID(uuidString: "0B0B0B0B-0000-4000-8000-00000000000B")!
    static let deviceA = UUID(uuidString: "D0000000-0000-4000-8000-0000000000A0")!
    static let deviceB = UUID(uuidString: "D0000000-0000-4000-8000-0000000000B0")!
    static let deviceC = UUID(uuidString: "D0000000-0000-4000-8000-0000000000C0")!

    static func entry(_ n: UInt8, version: UInt64 = 1, device: UUID = deviceA, deleted: Bool = false) -> SyncEntry {
        SyncEntry(
            recordID: UUID(uuid: (n, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, n)), kind: .item,
            keyID: deleted
                ? SyncPayload.zeroUUID : UUID(uuid: (0xEE, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1)),
            version: version, device: device, envelope: deleted ? nil : Array(repeating: n, count: Int(n) + 1))
    }

    static func payload(entries: [SyncEntry] = [entry(1), entry(2), entry(3, deleted: true)]) -> SyncPayload {
        SyncPayload(
            kind: .segment, vaultID: vault, author: deviceA, number: 7, vector: [deviceA: 6, deviceB: 3],
            entries: entries)
    }
}

@Suite("Sync object names")
struct SyncObjectLocationTests {
    @Test("segment and snapshot names round-trip and sort numerically")
    func roundTrip() throws {
        let segment = SyncObjectLocation.segment(
            vaultID: SyncFixtures.vault, author: SyncFixtures.deviceA, sequence: 42)
        #expect(
            segment.name
                == "vault/\(SyncFixtures.vault.uuidString)/log/\(SyncFixtures.deviceA.uuidString)/00000000000000000042")
        #expect(SyncObjectLocation(name: segment.name) == segment)
        let snapshot = SyncObjectLocation.snapshot(
            vaultID: SyncFixtures.vault, author: SyncFixtures.deviceB, lamport: .max)
        #expect(SyncObjectLocation(name: snapshot.name) == snapshot)
        let names = [9, 10, 100, 2].map {
            SyncObjectLocation.segment(vaultID: SyncFixtures.vault, author: SyncFixtures.deviceA, sequence: $0).name
        }
        #expect(
            names.sorted()
                == [2, 9, 10, 100].map {
                    SyncObjectLocation.segment(vaultID: SyncFixtures.vault, author: SyncFixtures.deviceA, sequence: $0)
                        .name
                })
    }

    @Test(
        "anything but a canonical name is not a sync object",
        arguments: [
            "", "vault", "vault/x/log/y/1",
            "vault/0A0A0A0A-0000-4000-8000-00000000000A/log/D0000000-0000-4000-8000-0000000000A0/42",
            "vault/0a0a0a0a-0000-4000-8000-00000000000a/log/D0000000-0000-4000-8000-0000000000A0/00000000000000000042",
            "vault/0A0A0A0A-0000-4000-8000-00000000000A/log/D0000000-0000-4000-8000-0000000000A0/0000000000000000004x",
            "vault/0A0A0A0A-0000-4000-8000-00000000000A/log/D0000000-0000-4000-8000-0000000000A0/99999999999999999999",
            "vault/0A0A0A0A-0000-4000-8000-00000000000A/log/D0000000-0000-4000-8000-0000000000A0/00000000000000000042/",
            "vault/0A0A0A0A-0000-4000-8000-00000000000A/log/../00000000000000000042",
            "vault/0A0A0A0A-0000-4000-8000-00000000000A/snapshot/00000000000000000042",
            "vault/0A0A0A0A-0000-4000-8000-00000000000A/members/D0000000-0000-4000-8000-0000000000A0",
            "/vault/0A0A0A0A-0000-4000-8000-00000000000A/log/D0000000-0000-4000-8000-0000000000A0/00000000000000000042",
        ])
    func rejects(_ name: String) {
        #expect(SyncObjectLocation(name: name) == nil)
    }

    @Test("the envelope context binds kind, author, vault and number")
    func context() {
        let keyID = UUID()
        let segment = SyncObjectLocation.segment(vaultID: SyncFixtures.vault, author: SyncFixtures.deviceA, sequence: 3)
        let context = segment.envelopeContext(keyID: keyID)
        #expect(context.kind == .logSegment)
        #expect(context.recordID == SyncFixtures.deviceA)
        #expect(context.vaultID == SyncFixtures.vault)
        #expect(context.recordVersion == 3)
        let snapshot = SyncObjectLocation.snapshot(
            vaultID: SyncFixtures.vault, author: SyncFixtures.deviceA, lamport: 3)
        #expect(snapshot.envelopeContext(keyID: keyID).canonicalAAD() != context.canonicalAAD())
    }
}

@Suite("Sync payload format")
struct SyncPayloadTests {
    @Test("a payload round-trips, whatever order its entries were given in")
    func roundTrip() throws {
        let payload = SyncFixtures.payload()
        let shuffled = SyncFixtures.payload(entries: payload.entries.reversed())
        #expect(shuffled.encoded() == payload.encoded())
        let parsed = try SyncPayload.parse(payload.encoded(), allowedKinds: [.item])
        #expect(parsed.entries == payload.entries.sorted(by: SyncPayload.entryOrder))
        #expect(parsed.vector == payload.vector)
        #expect(parsed.location == payload.location)
        #expect(parsed.entries.filter(\.isDeletion).count == 1)
    }

    @Test("every truncation is refused with a typed error")
    func truncation() {
        let bytes = SyncFixtures.payload().encoded()
        for length in 0..<bytes.count {
            #expect(throws: SyncFormatError.self) {
                try SyncPayload.parse(Array(bytes[..<length]), allowedKinds: [.item])
            }
        }
        #expect(throws: SyncFormatError.trailingBytes) { try SyncPayload.parse(bytes + [0], allowedKinds: [.item]) }
    }

    @Test("record kinds sync does not carry are refused")
    func kinds() {
        var entry = SyncFixtures.entry(1)
        entry.kind = .vaultKeyWrap
        #expect(throws: SyncFormatError.unsupportedRecordKind(EnvelopeKind.vaultKeyWrap.rawValue)) {
            try SyncPayload.parse(SyncFixtures.payload(entries: [entry]).encoded(), allowedKinds: [.item])
        }
    }

    @Test("duplicate entries are not canonical")
    func duplicates() {
        let bytes = SyncFixtures.payload(entries: [SyncFixtures.entry(1), SyncFixtures.entry(1, version: 2)]).encoded()
        #expect(throws: SyncFormatError.notCanonical) { try SyncPayload.parse(bytes, allowedKinds: [.item]) }
    }

    @Test("declared counts larger than the payload are refused before allocating")
    func counts() {
        var bytes = SyncFixtures.payload(entries: []).encoded()
        bytes.replaceSubrange((bytes.count - 4)..., with: [0xFF, 0xFF, 0xFF, 0x7F])
        #expect(throws: SyncFormatError.countTooLarge) { try SyncPayload.parse(bytes, allowedKinds: [.item]) }
    }

    @Test("oversized entry envelopes, unknown flags and keyed deletions are refused")
    func malformedEntries() {
        let large = SyncFixtures.payload(entries: [SyncFixtures.entry(1)]).encoded()
        #expect(throws: SyncFormatError.entryTooLarge(2)) {
            try SyncPayload.parse(large, allowedKinds: [.item], maximumEntryEnvelopeLength: 1)
        }
        var flagged = SyncFixtures.payload(entries: [SyncFixtures.entry(1, deleted: true)]).encoded()
        flagged[flagged.count - 1] = 0x03
        #expect(throws: SyncFormatError.unknownFlags(3)) { try SyncPayload.parse(flagged, allowedKinds: [.item]) }
        var keyed = SyncFixtures.entry(1, deleted: true)
        keyed.keyID = UUID()
        #expect(throws: SyncFormatError.malformedEntry) {
            try SyncPayload.parse(SyncFixtures.payload(entries: [keyed]).encoded(), allowedKinds: [.item])
        }
    }

    @Test("a signed object round-trips and bounds its signature")
    func signedObject() throws {
        let object = SignedObject(signature: [1, 2, 3], envelope: Array(repeating: 9, count: 40))
        #expect(try SignedObject.parse(object.serialized()) == object)
        let long = SignedObject(signature: Array(repeating: 0, count: 600), envelope: [])
        #expect(throws: SyncFormatError.signatureTooLong(600)) { try SignedObject.parse(long.serialized()) }
        #expect(throws: SyncFormatError.badMagic) { try SignedObject.parse(Array("WWSX".utf8) + [1, 0, 0]) }
    }
}
