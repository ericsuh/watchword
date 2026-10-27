import Foundation
import Testing

@testable import WatchwordEnvelope

@Suite("Envelope header")
struct EnvelopeHeaderTests {
    @Test("round-trips through serialization", arguments: EnvelopeKind.allCases)
    func roundTrip(_ kind: EnvelopeKind) throws {
        let keyID = UUID()
        let nonce = (0..<12).map { UInt8($0) }
        let aad = Array("record:vault:1".utf8)
        let header = try EnvelopeHeader(kind: kind, keyID: keyID, nonce: nonce, aad: aad)
        let bytes = header.serialized() + [0xAA, 0xBB, 0xCC]

        let (parsed, offset) = try EnvelopeHeader.parse(bytes, expecting: kind)
        #expect(parsed == header)
        #expect(offset == EnvelopeHeader.fixedPrefixLength + aad.count)
        #expect(Array(bytes[offset...]) == [0xAA, 0xBB, 0xCC])
    }

    @Test("rejects a nonce of the wrong length", arguments: [0, 11, 13, 16])
    func badNonce(_ length: Int) {
        #expect(throws: EnvelopeError.badNonceLength(length)) {
            try EnvelopeHeader(kind: .item, keyID: UUID(), nonce: [UInt8](repeating: 0, count: length), aad: [])
        }
    }
}

@Suite("KDF parameters")
struct KDFParametersTests {
    @Test("baseline validates")
    func baseline() throws {
        try KDFParameters.baseline.validate()
    }

    @Test("JSON round trip keeps values")
    func json() throws {
        let params = KDFParameters(iterations: 1_000_000, saltLength: 32)
        let data = try JSONEncoder().encode(params)
        let decoded = try JSONDecoder().decode(KDFParameters.self, from: data)
        #expect(decoded == params)
    }
}
