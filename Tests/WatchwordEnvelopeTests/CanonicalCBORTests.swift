import Foundation
import Testing
import WatchwordTestSupport

@testable import WatchwordEnvelope

@Suite("Canonical CBOR")
struct CanonicalCBORTests {
    /// RFC 8949 Appendix A examples for the major types the encoder supports.
    @Test(
        "matches RFC 8949 Appendix A",
        arguments: zip(
            [
                CBORValue.unsigned(0), .unsigned(23), .unsigned(24), .unsigned(100), .unsigned(1000),
                .unsigned(1_000_000), .unsigned(1_000_000_000_000), .unsigned(UInt64.max), .bytes([]),
                .bytes([1, 2, 3, 4]), .array([]),
                .array([.unsigned(1), .unsigned(2), .unsigned(3)]), .map([:]),
                .map([1: .unsigned(2), 3: .unsigned(4)]),
            ],
            [
                "00", "17", "1818", "1864", "1903e8", "1a000f4240", "1b000000e8d4a51000", "1bffffffffffffffff", "40",
                "4401020304", "80", "83010203", "a0", "a201020304",
            ]
        ))
    func rfcExamples(_ value: CBORValue, _ expected: String) {
        #expect(value.encoded().hex == expected)
    }

    @Test("map keys are sorted regardless of insertion order")
    func deterministicMaps() {
        let map: [UInt64: CBORValue] = [300: .unsigned(1), 2: .unsigned(2), 24: .unsigned(3), 1: .unsigned(4)]
        #expect(CBORValue.map(map).encoded().hex == "a4" + "0104" + "0202" + "181803" + "19012c01")
    }
}

@Suite("Envelope context and full envelope")
struct EnvelopeContextTests {
    static let context = EnvelopeContext(
        recordID: UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!,
        vaultID: UUID(uuidString: "FFEEDDCC-BBAA-9988-7766-554433221100")!,
        schemaVersion: 1,
        kind: .item,
        keyID: UUID(uuidString: "0F0E0D0C-0B0A-0908-0706-050403020100")!,
        recordVersion: 1000
    )

    /// Expected bytes produced by an independent CBOR encoder (Python, in the PR's validation notes).
    @Test("authenticated data is the canonical CBOR map of the six context fields")
    func canonicalAADKnownAnswer() {
        #expect(
            EnvelopeContextTests.context.canonicalAAD().hex
                == "a6015000112233445566778899aabbccddeeff0250ffeeddccbbaa998877665544332211000301040005500f0e0d0c0b0a"
                + "09080706050403020100061903e8")
    }

    @Test("every context field changes the authenticated data")
    func everyFieldIsBound() {
        let base = EnvelopeContextTests.context
        var variants: [EnvelopeContext] = []
        var c = base
        c.recordID = UUID()
        variants.append(c)
        c = base
        c.vaultID = UUID()
        variants.append(c)
        c = base
        c.schemaVersion = 2
        variants.append(c)
        c = base
        c.kind = .logSegment
        variants.append(c)
        c = base
        c.keyID = UUID()
        variants.append(c)
        c = base
        c.recordVersion = 1001
        variants.append(c)
        for variant in variants {
            #expect(variant.canonicalAAD() != base.canonicalAAD())
        }
    }

    @Test("an envelope round-trips through parse with its own context")
    func roundTrip() throws {
        let context = EnvelopeContextTests.context
        let header = try EnvelopeHeader(
            kind: context.kind, keyID: context.keyID, nonce: Array(0..<12), aad: context.canonicalAAD())
        let envelope = try Envelope(header: header, ciphertext: Array(repeating: 0xCC, count: 40))
        let parsed = try Envelope.parse(envelope.serialized(), expecting: context)
        #expect(parsed == envelope)
        #expect(parsed.authenticatedData == header.serialized())
    }
}
