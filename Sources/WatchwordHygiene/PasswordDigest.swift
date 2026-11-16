import Crypto
import Foundation
import SecureMemory

/// The first five hexadecimal characters of a password's SHA-1: the only thing derived from a password that ever
/// leaves the device (PRD F9.1).
///
/// Twenty bits, held as a number, so a value of this type cannot carry more of the hash than that, whatever it was
/// built from.
///
/// The service is meant to see it; nobody else is. Twenty bits of a password's hash reject all but one guess in a
/// million, so a prefix prints as redacted and `hex`, which the request path is built from, is the one accessor
/// to search for (PRD N5, docs/adr/0005-hibp-while-locked.md).
public struct PwnedRangePrefix: Hashable, Sendable {
    public static let hexLength = 5

    /// 0 ..< 2^20.
    public let value: UInt32

    init(firstBytesOfDigest b0: UInt8, _ b1: UInt8, _ b2: UInt8) {
        value = UInt32(b0) << 12 | UInt32(b1) << 4 | UInt32(b2 >> 4)
    }

    /// `nil` unless `text` is exactly five hexadecimal digits, in either case.
    public init?(_ text: String) {
        let bytes = Array(text.utf8)
        guard bytes.count == Self.hexLength else { return nil }
        var value: UInt32 = 0
        for byte in bytes {
            guard let nibble = HexNibble.value(byte) else { return nil }
            value = value << 4 | UInt32(nibble)
        }
        self.value = value
    }

    /// `nil` unless `value` fits in twenty bits.
    public init?(value: UInt32) {
        guard value < 1 << 20 else { return nil }
        self.value = value
    }

    /// Five upper-case hexadecimal digits, as the API's path takes them.
    public var hex: String {
        let digits = (0..<Self.hexLength).map { index in
            HexNibble.upperCase[Int(value >> UInt32(4 * (Self.hexLength - 1 - index)) & 0x0F)]
        }
        return String(decoding: digits, as: UTF8.self)
    }
}

extension PwnedRangePrefix: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "PwnedRangePrefix(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

enum HexNibble {
    static let upperCase = Array("0123456789ABCDEF".utf8)

    static func value(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return byte - UInt8(ascii: "A") + 10
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
        default: return nil
        }
    }
}

/// A password's SHA-1, split the way the Pwned Passwords range API needs it (PRD F9.1): the public five-character
/// prefix, and the other 35 characters, which stay on the device.
///
/// The suffix is held in `SecureBytes`: with the prefix it is an unsalted SHA-1 of a password, an offline-crackable
/// artefact (docs/adr/0005-hibp-while-locked.md). The type has no `Codable`, `Hashable` or `Equatable` conformance
/// and prints nothing, so it cannot be stored or logged by accident; nothing in this module persists or returns it.
///
/// Making one *is* hashing a password, so one is only ever made while keys are resident: `HygieneEngine` makes them
/// after checking that it is unlocked, and nothing else in the module does.
public struct PasswordDigest: Sendable {
    /// 35 hexadecimal characters of suffix, packed.
    static let suffixByteCount = 18

    public let prefix: PwnedRangePrefix
    /// The low nibble of digest byte 2 and bytes 3 to 19, packed into 18 bytes with the last low nibble zero: the same
    /// layout `PwnedRange` stores each line in.
    let suffix: SecureBytes

    /// Hashes the UTF-8 bytes of `password`, exactly as typed: no normalisation, because the breach corpora hold
    /// whatever bytes the breached site stored.
    ///
    /// A `String` cannot be zeroised, and item fields are `String`s (PRD SEC4), so this is the entry point the
    /// vault's items use. The copy made here to feed the hash is in `SecureBytes` and wiped before returning.
    public init(utf8Of password: String) {
        let bytes = SecureBytes(copying: password.utf8)
        defer { bytes.zeroise() }
        self.init(password: bytes)
    }

    /// Hashes `password`, which stays the caller's to zeroise.
    public init(password: SecureBytes) {
        var hasher = Insecure.SHA1()
        hasher.update(data: password)
        var digest = Array(hasher.finalize())
        prefix = PwnedRangePrefix(firstBytesOfDigest: digest[0], digest[1], digest[2])
        var packed = [UInt8](repeating: 0, count: Self.suffixByteCount)
        for index in 0..<Self.suffixByteCount {
            let high = digest[2 + index] & 0x0F
            let low = index + 3 < digest.count ? digest[3 + index] >> 4 : 0
            packed[index] = high << 4 | low
        }
        suffix = SecureBytes(wiping: &packed)
        // The digest array is this function's only other copy; the wipe is what `init(wiping:)` exists for.
        SecureBytes(wiping: &digest).zeroise()
    }
}

extension PasswordDigest: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "PasswordDigest(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}
