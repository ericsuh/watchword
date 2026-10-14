import Foundation

/// A complete record: header plus AEAD ciphertext with its tag appended (docs/02-architecture.md §5).
///
/// This module does no cryptography; it owns the format and every check that can be made before decryption.
/// `WatchwordCrypto.RecordCipher` seals and opens envelopes, using `authenticatedData` as the AEAD's associated data.
public struct Envelope: Sendable, Hashable {
    /// AES-GCM tag length in bytes.
    public static let tagLength = 16

    /// Upper bound on a serialized envelope. Item records are kilobytes and log segments batch many items, so 64 MiB
    /// is generous; its job is to bound what a hostile sync store can make one parse allocate (SEC9).
    public static let maximumLength = 64 << 20

    public let header: EnvelopeHeader
    /// Ciphertext followed by the 16-byte tag.
    public let ciphertext: [UInt8]

    public init(header: EnvelopeHeader, ciphertext: [UInt8]) throws {
        guard ciphertext.count >= Envelope.tagLength else { throw EnvelopeError.ciphertextTooShort(ciphertext.count) }
        let length = EnvelopeHeader.fixedPrefixLength + header.aad.count + ciphertext.count
        guard length <= Envelope.maximumLength else { throw EnvelopeError.tooLarge(length) }
        self.header = header
        self.ciphertext = ciphertext
    }

    /// The bytes the AEAD authenticates: the entire serialized header, not only the context. A byte flipped anywhere
    /// before the ciphertext then fails decryption, including in a field no parser check happens to cover.
    public var authenticatedData: [UInt8] {
        header.serialized()
    }

    public func serialized() -> [UInt8] {
        header.serialized() + ciphertext
    }

    /// Parses an envelope and checks it against the context the caller derived from the storage location.
    ///
    /// Order: size, magic, version, kind (in `EnvelopeHeader.parse`), key ID, full authenticated-data comparison,
    /// ciphertext length. Every one of these fails before any decryption is attempted.
    public static func parse(_ bytes: [UInt8], expecting context: EnvelopeContext) throws -> Envelope {
        guard bytes.count <= maximumLength else { throw EnvelopeError.tooLarge(bytes.count) }
        let (header, payloadOffset) = try EnvelopeHeader.parse(bytes, expecting: context.kind)
        guard header.keyID == context.keyID else {
            throw EnvelopeError.keyMismatch(expected: context.keyID, actual: header.keyID)
        }
        guard header.aad == context.canonicalAAD() else { throw EnvelopeError.contextMismatch }
        return try Envelope(header: header, ciphertext: Array(bytes[payloadOffset...]))
    }
}
