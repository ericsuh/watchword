import Foundation

/// Base64url without padding (RFC 4648 §5), the text form of binary values in WebAuthn, CXF and passkey fields.
///
/// Stricter than Foundation's decoder on purpose: padding, whitespace, the standard alphabet's `+` and `/`, and
/// non-canonical trailing bits are all refused, so one value has exactly one spelling.
public enum Base64URL {
    public static func encode(_ bytes: some Sequence<UInt8>) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// The decoded bytes, or `nil` if `text` is not canonical unpadded base64url.
    public static func decode(_ text: String) -> Data? {
        let allowed = text.utf8.allSatisfy { byte in
            (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
                || (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
                || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
                || byte == UInt8(ascii: "-") || byte == UInt8(ascii: "_")
        }
        guard allowed, text.utf8.count % 4 != 1 else { return nil }
        var standard = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4)
        guard let data = Data(base64Encoded: standard), encode(data) == text else { return nil }
        return data
    }
}

/// Base32 (RFC 4648 §6), the encoding of TOTP secrets in `otpauth://` URIs.
public enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    /// Upper-case, unpadded.
    public static func encode(_ bytes: some Sequence<UInt8>) -> String {
        var output: [UInt8] = []
        var buffer: UInt32 = 0
        var bits: UInt32 = 0
        for byte in bytes {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                output.append(alphabet[Int((buffer >> bits) & 31)])
            }
            buffer &= (1 << bits) - 1
        }
        if bits > 0 {
            output.append(alphabet[Int((buffer << (5 - bits)) & 31)])
        }
        return String(decoding: output, as: UTF8.self)
    }

    /// Decodes either case, with or without `=` padding at the end. Anything else — other characters, padding in the
    /// middle, a length no byte string encodes to, non-zero trailing bits — is `nil`.
    public static func decode(_ text: String) -> Data? {
        var symbols = Array(text.utf8)
        while symbols.last == UInt8(ascii: "=") {
            symbols.removeLast()
        }
        // 1, 3 and 6 symbols past a multiple of 8 encode no whole number of bytes.
        guard ![1, 3, 6].contains(symbols.count % 8) else { return nil }
        var output = Data()
        output.reserveCapacity(symbols.count * 5 / 8)
        var buffer: UInt32 = 0
        var bits: UInt32 = 0
        for symbol in symbols {
            let value: UInt32
            switch symbol {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"): value = UInt32(symbol - UInt8(ascii: "A"))
            case UInt8(ascii: "a")...UInt8(ascii: "z"): value = UInt32(symbol - UInt8(ascii: "a"))
            case UInt8(ascii: "2")...UInt8(ascii: "7"): value = UInt32(symbol - UInt8(ascii: "2")) + 26
            default: return nil
            }
            buffer = (buffer << 5) | value
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((buffer >> bits) & 0xFF))
                buffer &= (1 << bits) - 1
            }
        }
        guard buffer == 0 else { return nil }
        return output
    }
}
