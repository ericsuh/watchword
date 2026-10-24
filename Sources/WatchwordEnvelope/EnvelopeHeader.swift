import Foundation

/// What a ciphertext envelope contains. Checked before any decryption is attempted.
public enum EnvelopeKind: UInt8, Sendable, Hashable, CaseIterable {
    case item = 0
    case vaultKeyWrap = 1
    case membership = 2
    case accountHeader = 3
    case logSegment = 4
    /// A vault snapshot written by the sync layer (docs/02-architecture.md §7.1). A kind of its own, so a snapshot can
    /// never be presented as a log segment or the reverse.
    case snapshot = 5
}

public enum EnvelopeError: Error, Equatable, Sendable {
    case badMagic
    case unsupportedVersion(UInt16)
    case unknownKind(UInt8)
    case kindMismatch(expected: EnvelopeKind, actual: EnvelopeKind)
    case truncated
    case badNonceLength(Int)
    case aadTooLong(Int)
    /// The header names a different key from the one the storage location says the record is under.
    case keyMismatch(expected: UUID, actual: UUID)
    /// The embedded authenticated data differs from the context re-derived from the storage location: the record was
    /// moved, relabelled, replayed as a newer version, or downgraded (SEC2).
    case contextMismatch
    /// Shorter than an AEAD tag, so it cannot be a ciphertext.
    case ciphertextTooShort(Int)
    /// Larger than `Envelope.maximumLength`; rejected before any copy (SEC9).
    case tooLarge(Int)
}

/// The authenticated, unencrypted prefix of every record (architecture §5).
///
/// Layout (little-endian):
/// `magic(4) version(2) kind(1) keyID(16) nonce(12) aadLength(2) aad(aadLength) ciphertext(...)`.
///
/// `aad` carries `EnvelopeContext.canonicalAAD()`: record ID, vault ID, schema version, kind, key ID and record
/// version. `Envelope.parse` re-derives the expected AAD from where it found the record and compares before
/// decrypting, so a record moved between vaults or key epochs fails closed. The AEAD then authenticates the whole
/// serialized header, not only `aad`.
public struct EnvelopeHeader: Sendable, Hashable {
    public static let magic: [UInt8] = Array("WWE1".utf8)
    public static let currentVersion: UInt16 = 1
    public static let nonceLength = 12
    public static let maxAADLength = Int(UInt16.max)

    public var version: UInt16
    public var kind: EnvelopeKind
    public var keyID: UUID
    public var nonce: [UInt8]
    public var aad: [UInt8]

    public init(
        version: UInt16 = EnvelopeHeader.currentVersion,
        kind: EnvelopeKind,
        keyID: UUID,
        nonce: [UInt8],
        aad: [UInt8]
    ) throws {
        guard nonce.count == EnvelopeHeader.nonceLength else { throw EnvelopeError.badNonceLength(nonce.count) }
        guard aad.count <= EnvelopeHeader.maxAADLength else { throw EnvelopeError.aadTooLong(aad.count) }
        self.version = version
        self.kind = kind
        self.keyID = keyID
        self.nonce = nonce
        self.aad = aad
    }

    /// Fixed-size prefix length before the variable AAD.
    public static let fixedPrefixLength = 4 + 2 + 1 + 16 + nonceLength + 2

    public func serialized() -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(EnvelopeHeader.fixedPrefixLength + aad.count)
        out.append(contentsOf: EnvelopeHeader.magic)
        out.append(contentsOf: EnvelopeHeader.littleEndian(version))
        out.append(kind.rawValue)
        out.append(contentsOf: EnvelopeHeader.bytes(of: keyID))
        out.append(contentsOf: nonce)
        out.append(contentsOf: EnvelopeHeader.littleEndian(UInt16(aad.count)))
        out.append(contentsOf: aad)
        return out
    }

    /// Parses a header, enforcing magic, version and the caller's expected kind in that order.
    /// Returns the header and the offset at which the ciphertext begins.
    public static func parse(
        _ bytes: [UInt8],
        expecting expected: EnvelopeKind
    ) throws -> (header: EnvelopeHeader, payloadOffset: Int) {
        guard bytes.count >= fixedPrefixLength else { throw EnvelopeError.truncated }
        guard Array(bytes[0..<4]) == magic else { throw EnvelopeError.badMagic }

        let version = UInt16(bytes[4]) | (UInt16(bytes[5]) << 8)
        guard version == currentVersion else { throw EnvelopeError.unsupportedVersion(version) }

        guard let kind = EnvelopeKind(rawValue: bytes[6]) else { throw EnvelopeError.unknownKind(bytes[6]) }
        guard kind == expected else { throw EnvelopeError.kindMismatch(expected: expected, actual: kind) }

        let keyID = uuid(from: Array(bytes[7..<23]))
        let nonce = Array(bytes[23..<35])
        let aadLength = Int(UInt16(bytes[35]) | (UInt16(bytes[36]) << 8))
        let aadEnd = fixedPrefixLength + aadLength
        guard bytes.count >= aadEnd else { throw EnvelopeError.truncated }
        let aad = Array(bytes[fixedPrefixLength..<aadEnd])

        let header = try EnvelopeHeader(version: version, kind: kind, keyID: keyID, nonce: nonce, aad: aad)
        return (header, aadEnd)
    }

    static func littleEndian(_ value: UInt16) -> [UInt8] {
        [UInt8(value & 0xff), UInt8(value >> 8)]
    }

    static func bytes(of uuid: UUID) -> [UInt8] {
        let u = uuid.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }

    static func uuid(from b: [UInt8]) -> UUID {
        precondition(b.count == 16)
        return UUID(
            uuid: (
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
            ))
    }
}
