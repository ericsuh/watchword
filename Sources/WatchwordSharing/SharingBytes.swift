import Crypto
import Foundation

/// A cursor over hostile bytes: every read is bounds-checked and throws `SharingFormatError.truncated` rather than
/// trapping. Every sharing format is parsed through it, and every parser ends with `finish()`, so nothing may follow
/// the last field (docs/02-architecture.md §8.2, PRD SEC9).
struct SharingReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var remaining: Int {
        bytes.count - offset
    }

    mutating func read(_ count: Int) throws -> [UInt8] {
        guard count >= 0, count <= remaining else { throw SharingFormatError.truncated }
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
        UUID(sharingBytes: try read(16))
    }

    /// Checks the four-byte magic and the one-byte format version every sharing format begins with.
    mutating func header(magic: [UInt8], version: UInt8) throws {
        guard try read(4) == magic else { throw SharingFormatError.badMagic }
        let found = try byte()
        guard found == version else { throw SharingFormatError.unsupportedFormatVersion(found) }
    }

    func finish() throws {
        guard remaining == 0 else { throw SharingFormatError.trailingBytes }
    }
}

enum SharingBytes {
    static func littleEndian<T: FixedWidthInteger>(_ value: T) -> [UInt8] {
        (0..<(T.bitWidth / 8)).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }

    static func sha256(_ parts: [UInt8]...) -> [UInt8] {
        var hasher = SHA256()
        for part in parts {
            hasher.update(data: part)
        }
        return Array(hasher.finalize())
    }

    static func hex(_ bytes: [UInt8], uppercase: Bool = false) -> String {
        let digits = Array((uppercase ? "0123456789ABCDEF" : "0123456789abcdef").utf8)
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Decodes hex of exactly one case; `nil` for anything else, including the other case, so that a name or a scanned
    /// code has one spelling.
    static func bytes(hex text: some StringProtocol, uppercase: Bool = false) -> [UInt8]? {
        let utf8 = Array(text.utf8)
        guard utf8.count.isMultiple(of: 2) else { return nil }
        func value(_ character: UInt8) -> UInt8? {
            switch character {
            case 0x30...0x39: return character - 0x30
            case 0x41...0x46: return uppercase ? character - 0x41 + 10 : nil
            case 0x61...0x66: return uppercase ? nil : character - 0x61 + 10
            default: return nil
            }
        }
        var out: [UInt8] = []
        out.reserveCapacity(utf8.count / 2)
        for index in stride(from: 0, to: utf8.count, by: 2) {
            guard let high = value(utf8[index]), let low = value(utf8[index + 1]) else { return nil }
            out.append(high << 4 | low)
        }
        return out
    }
}

extension UUID {
    static let sharingZero = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    var sharingBytes: [UInt8] {
        let u = uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }

    init(sharingBytes b: [UInt8]) {
        precondition(b.count == 16)
        self.init(
            uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
        )
    }

    /// Bytewise order, which is the order of the canonical encodings.
    func sharingPrecedes(_ other: UUID) -> Bool {
        sharingBytes.lexicographicallyPrecedes(other.sharingBytes)
    }
}
