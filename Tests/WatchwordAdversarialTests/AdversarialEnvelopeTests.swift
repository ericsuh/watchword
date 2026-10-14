import Foundation
import Testing

@testable import WatchwordEnvelope

@Suite("Adversarial: envelope and KDF", .tags(.adversarial))
struct AdversarialEnvelopeTests {
    private func validHeader(kind: EnvelopeKind = .item) throws -> [UInt8] {
        let header = try EnvelopeHeader(
            kind: kind, keyID: UUID(), nonce: [UInt8](repeating: 7, count: 12), aad: Array("aad".utf8))
        return header.serialized()
    }

    @Test(
        "KDF downgrade: iterations below the floor are rejected",
        arguments: [UInt32(0), 1, 1_000, 100_000, 649_999])
    func kdfDowngradeIterations(_ iterations: UInt32) {
        let params = KDFParameters(iterations: iterations)
        let expected = KDFValidationError.iterationsBelowMinimum(iterations, minimum: KDFParameters.minimumIterations)
        #expect(throws: expected) { try params.validate() }
    }

    /// A compromised sync store setting an absurd iteration count would make every unlock grind
    /// for hours. Availability is a security property too (threat model A1).
    @Test(
        "KDF: iterations above the ceiling are rejected",
        arguments: [KDFParameters.maximumIterations + 1, 100_000_000, UInt32.max])
    func kdfIterationsAboveMaximumRejected(_ iterations: UInt32) {
        let params = KDFParameters(iterations: iterations)
        let expected = KDFValidationError.iterationsAboveMaximum(iterations, maximum: KDFParameters.maximumIterations)
        #expect(throws: expected) { try params.validate() }
    }

    @Test("KDF: a header with a hostile iteration count never decodes")
    func kdfCeilingEnforcedAtDecode() {
        let json = #"{"algorithm":"PBKDF2-HMAC-SHA256","iterations":4294967295,"saltLength":32,"outputLength":32}"#
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(KDFParameters.self, from: Data(json.utf8))
        }
    }

    @Test("KDF: an absurd salt length is rejected", arguments: [1025, 1_000_000])
    func kdfSaltCeiling(_ saltLength: Int) {
        let params = KDFParameters(iterations: KDFParameters.minimumIterations, saltLength: saltLength)
        let expected = KDFValidationError.saltTooLong(saltLength, maximum: KDFParameters.maximumSaltLength)
        #expect(throws: expected) { try params.validate() }
    }

    @Test("KDF: the ceiling leaves real headroom above the floor")
    func kdfCeilingIsNotTooTight() throws {
        #expect(KDFParameters.maximumIterations > KDFParameters.minimumIterations * 10)
        try KDFParameters(iterations: KDFParameters.minimumIterations * 10).validate()
    }

    @Test("KDF downgrade: short salt is rejected", arguments: [0, 1, 8, 15])
    func kdfDowngradeSalt(_ saltLength: Int) {
        let params = KDFParameters(iterations: KDFParameters.minimumIterations, saltLength: saltLength)
        #expect(throws: KDFValidationError.saltTooShort(saltLength, minimum: KDFParameters.minimumSaltLength)) {
            try params.validate()
        }
    }

    @Test("KDF downgrade: a tampered JSON header never decodes")
    func kdfDowngradeViaDecoding() {
        let json = #"{"algorithm":"PBKDF2-HMAC-SHA256","iterations":1000,"saltLength":32,"outputLength":32}"#
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(KDFParameters.self, from: Data(json.utf8))
        }
    }

    @Test("KDF: unknown algorithm name is rejected at decode time")
    func kdfUnknownAlgorithm() {
        let json = #"{"algorithm":"MD5","iterations":650000,"saltLength":32,"outputLength":32}"#
        #expect(throws: (any Error).self) {
            try JSONDecoder().decode(KDFParameters.self, from: Data(json.utf8))
        }
    }

    @Test("envelope: wrong magic is rejected")
    func badMagic() throws {
        var bytes = try validHeader()
        bytes[0] = 0x00
        #expect(throws: EnvelopeError.badMagic) { try EnvelopeHeader.parse(bytes, expecting: .item) }
    }

    @Test("envelope: version downgrade/upgrade is rejected", arguments: [UInt16(0), 2, 0xFFFF])
    func badVersion(_ version: UInt16) throws {
        var bytes = try validHeader()
        bytes[4] = UInt8(version & 0xff)
        bytes[5] = UInt8(version >> 8)
        #expect(throws: EnvelopeError.unsupportedVersion(version)) { try EnvelopeHeader.parse(bytes, expecting: .item) }
    }

    @Test("envelope: kind confusion is rejected before any payload is touched")
    func kindMismatch() throws {
        let bytes = try validHeader(kind: .vaultKeyWrap)
        #expect(throws: EnvelopeError.kindMismatch(expected: .item, actual: .vaultKeyWrap)) {
            try EnvelopeHeader.parse(bytes, expecting: .item)
        }
    }

    @Test("envelope: unknown kind byte is rejected")
    func unknownKind() throws {
        var bytes = try validHeader()
        bytes[6] = 0xEE
        #expect(throws: EnvelopeError.unknownKind(0xEE)) { try EnvelopeHeader.parse(bytes, expecting: .item) }
    }

    @Test("envelope: truncation anywhere in the header fails closed")
    func truncation() throws {
        let bytes = try validHeader()
        for cut in 0..<bytes.count {
            #expect(throws: EnvelopeError.truncated) {
                try EnvelopeHeader.parse(Array(bytes[0..<cut]), expecting: .item)
            }
        }
    }

    @Test("envelope: a declared AAD length longer than the data is rejected")
    func aadLengthLie() throws {
        var bytes = try validHeader()
        bytes[35] = 0xFF
        bytes[36] = 0xFF
        #expect(throws: EnvelopeError.truncated) { try EnvelopeHeader.parse(bytes, expecting: .item) }
    }

    @Test("envelope: every single-byte flip in the header is detected or changes a bound field")
    func bitFlipsChangeHeader() throws {
        let original = try validHeader()
        let (reference, _) = try EnvelopeHeader.parse(original, expecting: .item)
        for i in 0..<original.count {
            var mutated = original
            mutated[i] ^= 0x01
            do {
                let (parsed, _) = try EnvelopeHeader.parse(mutated, expecting: .item)
                // A flip that still parses must have altered a field the AAD/decryption binds.
                #expect(parsed != reference, "flip at byte \(i) was silently ignored")
            } catch {
                // Rejected: fine.
            }
        }
    }

    // MARK: - Context binding (milestone 1)

    private static let context = EnvelopeContext(
        recordID: UUID(), vaultID: UUID(), schemaVersion: 2, kind: .item, keyID: UUID(), recordVersion: 7)

    private func envelope(for context: EnvelopeContext) throws -> [UInt8] {
        let header = try EnvelopeHeader(
            kind: context.kind, keyID: context.keyID, nonce: [UInt8](repeating: 1, count: 12),
            aad: context.canonicalAAD())
        return try Envelope(header: header, ciphertext: [UInt8](repeating: 0xCC, count: 32)).serialized()
    }

    @Test("envelope: a record found in another vault fails closed before decryption")
    func movedToAnotherVault() throws {
        var elsewhere = Self.context
        elsewhere.vaultID = UUID()
        let bytes = try envelope(for: Self.context)
        #expect(throws: EnvelopeError.contextMismatch) { try Envelope.parse(bytes, expecting: elsewhere) }
    }

    @Test("envelope: a record relabelled as another record ID fails closed")
    func relabelledRecord() throws {
        var other = Self.context
        other.recordID = UUID()
        let bytes = try envelope(for: Self.context)
        #expect(throws: EnvelopeError.contextMismatch) { try Envelope.parse(bytes, expecting: other) }
    }

    @Test("envelope: an old version presented as a newer one fails closed", arguments: [UInt64(8), 1_000, .max])
    func replayedAsNewer(_ claimedVersion: UInt64) throws {
        var newer = Self.context
        newer.recordVersion = claimedVersion
        let bytes = try envelope(for: Self.context)
        #expect(throws: EnvelopeError.contextMismatch) { try Envelope.parse(bytes, expecting: newer) }
    }

    @Test("envelope: a schema downgrade fails closed", arguments: [UInt64(0), 1, 3])
    func schemaDowngrade(_ schema: UInt64) throws {
        var expected = Self.context
        expected.schemaVersion = schema
        let bytes = try envelope(for: Self.context)
        #expect(throws: EnvelopeError.contextMismatch) { try Envelope.parse(bytes, expecting: expected) }
    }

    @Test("envelope: a record under another key ID is rejected before the context is compared")
    func otherKeyEpoch() throws {
        var rotated = Self.context
        rotated.keyID = UUID()
        let bytes = try envelope(for: Self.context)
        #expect(throws: EnvelopeError.keyMismatch(expected: rotated.keyID, actual: Self.context.keyID)) {
            try Envelope.parse(bytes, expecting: rotated)
        }
    }

    @Test("envelope: a ciphertext shorter than a tag is rejected")
    func shortCiphertext() throws {
        let bytes = Array(try envelope(for: Self.context).dropLast(17))
        #expect(throws: EnvelopeError.ciphertextTooShort(15)) { try Envelope.parse(bytes, expecting: Self.context) }
    }

    @Test("envelope: an oversized envelope is rejected before it is copied")
    func oversized() {
        let bytes = [UInt8](repeating: 0, count: Envelope.maximumLength + 1)
        #expect(throws: EnvelopeError.tooLarge(Envelope.maximumLength + 1)) {
            try Envelope.parse(bytes, expecting: Self.context)
        }
    }
}
