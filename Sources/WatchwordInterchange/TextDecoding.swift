import Foundation

/// Strict UTF-8 validation for import files (PRD SEC7).
///
/// Foundation's decoders repair what they cannot read, and a U+FFFD where a byte of a password used to be is a
/// different password that looks imported. So text is validated here first and refused whole, with the offset of
/// the first bad byte, and only then turned into `String`s, which by then cannot be repaired into something else.
enum UTF8Text {
    /// The offset of the first byte in `range` that is not part of a well-formed UTF-8 sequence, or `nil`. Overlong
    /// forms, surrogates and code points above U+10FFFF are malformed (RFC 3629).
    static func firstInvalidOffset(in bytes: [UInt8], range: Range<Int>) -> Int? {
        var index = range.lowerBound
        let end = range.upperBound
        while index < end {
            let lead = bytes[index]
            if lead < 0x80 {
                index += 1
                continue
            }
            let length: Int
            var lower: UInt8 = 0x80
            var upper: UInt8 = 0xBF
            switch lead {
            case 0xC2...0xDF:
                length = 2
            case 0xE0:
                length = 3
                lower = 0xA0
            case 0xE1...0xEC, 0xEE...0xEF:
                length = 3
            case 0xED:
                length = 3
                upper = 0x9F
            case 0xF0:
                length = 4
                lower = 0x90
            case 0xF1...0xF3:
                length = 4
            case 0xF4:
                length = 4
                upper = 0x8F
            default:
                return index
            }
            guard index + length <= end else { return index }
            guard (lower...upper).contains(bytes[index + 1]) else { return index }
            for offset in 2..<max(length, 2) where !(0x80...0xBF).contains(bytes[index + offset]) {
                return index
            }
            index += length
        }
        return nil
    }

    /// The range of `bytes` to parse as UTF-8 text: everything after an optional UTF-8 byte-order mark. Throws for a
    /// UTF-16 or UTF-32 mark and for any malformed sequence.
    static func validatedRange(of bytes: [UInt8]) throws -> Range<Int> {
        if bytes.starts(with: [0xFF, 0xFE]) || bytes.starts(with: [0xFE, 0xFF]) {
            throw InterchangeError.unsupportedTextEncoding
        }
        let start = bytes.starts(with: [0xEF, 0xBB, 0xBF]) ? 3 : 0
        let range = start..<bytes.count
        if let offset = firstInvalidOffset(in: bytes, range: range) {
            throw InterchangeError.invalidUTF8(byteOffset: offset)
        }
        return range
    }

    /// The text of bytes already validated. `String(decoding:)` repairs, so it is only ever given validated input.
    static func string(_ bytes: some Collection<UInt8>) -> String {
        String(decoding: bytes, as: UTF8.self)
    }
}

/// A UUID drawn from an injected generator (RFC 4122 version 4), so imports are reproducible in tests and take
/// their identifiers from the system generator in production: an item's ID is never taken from an import file.
enum RandomUUID {
    static func make(using generator: inout some RandomNumberGenerator) -> UUID {
        let high = generator.next()
        let low = generator.next()
        var bytes: [UInt8] = []
        bytes.reserveCapacity(16)
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: high >> UInt64(shift)))
        }
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: low >> UInt64(shift)))
        }
        bytes[6] = (bytes[6] & 0x0F) | 0x40
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(
            uuid: (
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            ))
    }

    /// The 16 bytes of `uuid`, in order.
    static func bytes(of uuid: UUID) -> [UInt8] {
        let value = uuid.uuid
        return [
            value.0, value.1, value.2, value.3, value.4, value.5, value.6, value.7, value.8, value.9, value.10,
            value.11, value.12, value.13, value.14, value.15,
        ]
    }
}
