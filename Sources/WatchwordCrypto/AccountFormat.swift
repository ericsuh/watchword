import Crypto
import Foundation
import WatchwordEnvelope

/// Why an account-level object (a registry entry, a published account header) did not parse. These objects come
/// from the sync store before anything authenticates them (A1), so the parsers are exact: every length is capped
/// and checked against the bytes that remain, and anything but the one canonical encoding is refused.
public enum AccountFormatError: Error, Equatable, Sendable {
    case truncated
    case badMagic
    case unsupportedVersion(UInt8)
    case unknownType(UInt8)
    case tooLong(Int)
    case trailingBytes
    /// Parents out of order or repeated, a count out of range, a field that cannot be what a writer produces.
    case notCanonical
    /// KDF parameters outside the two-sided bounds (PRD SEC5, SEC9).
    case kdf(KDFValidationError)
    case unsupportedKDF(UInt8)
    case invalidPublicKey
}

/// A cursor over hostile bytes; every read is bounds-checked and throws `truncated` rather than trapping.
struct AccountByteReader {
    private let bytes: [UInt8]
    private(set) var offset = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var remaining: Int {
        bytes.count - offset
    }

    mutating func read(_ count: Int) throws -> [UInt8] {
        guard count >= 0, count <= remaining else { throw AccountFormatError.truncated }
        defer { offset += count }
        return Array(bytes[offset..<(offset + count)])
    }

    mutating func byte() throws -> UInt8 {
        try read(1)[0]
    }

    mutating func uint16() throws -> UInt16 {
        try integer()
    }

    mutating func uint32() throws -> UInt32 {
        try integer()
    }

    mutating func uint64() throws -> UInt64 {
        try integer()
    }

    private mutating func integer<T: FixedWidthInteger>() throws -> T {
        let raw = try read(T.bitWidth / 8)
        return raw.enumerated().reduce(T.zero) { $0 | (T(truncatingIfNeeded: $1.element) << (8 * $1.offset)) }
    }

    mutating func uuid() throws -> UUID {
        UUID(byteArray: try read(16))
    }

    /// A field with a one-byte length, at most `maximum` bytes.
    mutating func shortField(maximum: Int) throws -> [UInt8] {
        let length = Int(try byte())
        guard length <= maximum else { throw AccountFormatError.tooLong(length) }
        return try read(length)
    }

    /// A field with a two-byte length, at most `maximum` bytes.
    mutating func field(maximum: Int) throws -> [UInt8] {
        let length = Int(try uint16())
        guard length <= maximum else { throw AccountFormatError.tooLong(length) }
        return try read(length)
    }
}

enum AccountBytes {
    static func littleEndian<T: FixedWidthInteger>(_ value: T) -> [UInt8] {
        (0..<(T.bitWidth / 8)).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }

    static func shortField(_ bytes: [UInt8]) -> [UInt8] {
        precondition(bytes.count <= 0xFF)
        return [UInt8(bytes.count)] + bytes
    }

    static func field(_ bytes: [UInt8]) -> [UInt8] {
        precondition(bytes.count <= 0xFFFF)
        return littleEndian(UInt16(bytes.count)) + bytes
    }

    static func sha256(_ bytes: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: bytes))
    }
}

/// A SHA-256 digest used as a name: of a registry entry (its ID), and of the entries other objects point at.
public struct ObjectDigest: Hashable, Sendable, Comparable, CustomStringConvertible {
    public static let byteCount = 32

    public let bytes: [UInt8]

    public init?(bytes: [UInt8]) {
        guard bytes.count == Self.byteCount else { return nil }
        self.bytes = bytes
    }

    /// The digest of `content`.
    public init(hashing content: [UInt8]) {
        bytes = AccountBytes.sha256(content)
    }

    /// Parses exactly 64 lower-case hexadecimal digits; anything else is not a digest.
    public init?(hex: String) {
        let digits = Array(hex.utf8)
        guard digits.count == 2 * Self.byteCount else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(Self.byteCount)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let high = Self.value(digits[index]), let low = Self.value(digits[index + 1]) else { return nil }
            bytes.append(high << 4 | low)
        }
        self.bytes = bytes
    }

    public var hex: String {
        let digits = Array("0123456789abcdef".utf8)
        return String(decoding: bytes.flatMap { [digits[Int($0 >> 4)], digits[Int($0 & 0x0F)]] }, as: UTF8.self)
    }

    public var description: String { hex }

    public static func < (lhs: ObjectDigest, rhs: ObjectDigest) -> Bool {
        lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
    }

    private static func value(_ digit: UInt8) -> UInt8? {
        switch digit {
        case 0x30...0x39: return digit - 0x30
        case 0x61...0x66: return digit - 0x61 + 10
        default: return nil
        }
    }
}
