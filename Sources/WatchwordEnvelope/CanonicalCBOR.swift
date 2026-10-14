import Foundation

/// The subset of CBOR (RFC 8949) that Watchword authenticates and signs, with a deterministic encoder.
///
/// Encoding follows the core deterministic encoding requirements of RFC 8949 §4.2.1: shortest-form integers and
/// lengths, definite lengths only, and map keys in bytewise lexicographic order of their encodings (for unsigned keys
/// that is numeric order). Two equal values therefore always encode to the same bytes, which is what lets a decoder
/// re-derive authenticated data from where it found a record and compare bytes (docs/02-architecture.md §5).
///
/// There is deliberately no decoder here. Authenticated data is compared, never parsed, so attacker-supplied CBOR
/// never reaches a parser.
public indirect enum CBORValue: Sendable, Hashable {
    case unsigned(UInt64)
    case bytes([UInt8])
    case text(String)
    case array([CBORValue])
    /// Maps are keyed by small unsigned integers, which is all the record formats need.
    case map([UInt64: CBORValue])

    public static func uuid(_ value: UUID) -> CBORValue {
        .bytes(EnvelopeHeader.bytes(of: value))
    }

    public func encoded() -> [UInt8] {
        var out: [UInt8] = []
        encode(into: &out)
        return out
    }

    private func encode(into out: inout [UInt8]) {
        switch self {
        case .unsigned(let value):
            CBORValue.appendHead(major: 0, argument: value, to: &out)
        case .bytes(let bytes):
            CBORValue.appendHead(major: 2, argument: UInt64(bytes.count), to: &out)
            out.append(contentsOf: bytes)
        case .text(let string):
            let utf8 = Array(string.utf8)
            CBORValue.appendHead(major: 3, argument: UInt64(utf8.count), to: &out)
            out.append(contentsOf: utf8)
        case .array(let elements):
            CBORValue.appendHead(major: 4, argument: UInt64(elements.count), to: &out)
            for element in elements {
                element.encode(into: &out)
            }
        case .map(let entries):
            CBORValue.appendHead(major: 5, argument: UInt64(entries.count), to: &out)
            for key in entries.keys.sorted() {
                CBORValue.appendHead(major: 0, argument: key, to: &out)
                entries[key]!.encode(into: &out)
            }
        }
    }

    /// Initial byte plus the shortest argument encoding (RFC 8949 §3, §4.2.1).
    private static func appendHead(major: UInt8, argument: UInt64, to out: inout [UInt8]) {
        let type = major << 5
        switch argument {
        case 0..<24:
            out.append(type | UInt8(argument))
        case 24...0xFF:
            out.append(type | 24)
            out.append(UInt8(argument))
        case 0x100...0xFFFF:
            out.append(type | 25)
            appendBigEndian(argument, byteCount: 2, to: &out)
        case 0x1_0000...0xFFFF_FFFF:
            out.append(type | 26)
            appendBigEndian(argument, byteCount: 4, to: &out)
        default:
            out.append(type | 27)
            appendBigEndian(argument, byteCount: 8, to: &out)
        }
    }

    private static func appendBigEndian(_ value: UInt64, byteCount: Int, to out: inout [UInt8]) {
        for shift in stride(from: (byteCount - 1) * 8, through: 0, by: -8) {
            out.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }
}
