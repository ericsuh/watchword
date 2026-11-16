import Crypto
import Foundation
import SecureMemory

public enum ScanBindingKeyError: Error, Equatable, Sendable {
    /// Fewer than 32 bytes: not a key.
    case tooShort
    /// Already zeroised.
    case zeroised
}

/// What ties a breach result to the exact password it judged (docs/adr/0005-hibp-while-locked.md, amendment of
/// 2026-11-16; docs/02-architecture.md §13.9): `HMAC-SHA-256(key, "WW-scan-binding-v1" ‖ 0x00 ‖ item ID ‖ password)`.
///
/// A result is about a password, not about an item version: an edit of an item's notes leaves its password's binding,
/// and so its result, as it was, and a changed password has another binding, so no earlier result covers it. The item
/// ID is in the message, so a binding copied from one item's record to another's matches nothing there.
///
/// Never a bare hash: without the key a binding confirms no guess, so it can sit inside a sealed record (the scan
/// ledger, or a vault's synced scan results) without being an offline-crackable artefact if that record were ever
/// read. It prints as redacted, is compared in full, and is not `Codable`; the two encodings that carry it are the
/// ledger's and `SyncedScanRecord`'s, both sealed.
public struct ScanBinding: Hashable, Sendable, Comparable {
    public static let length = 32
    let bytes: [UInt8]

    init?(bytes: [UInt8]) {
        guard bytes.count == Self.length else { return nil }
        self.bytes = bytes
    }

    init?(hex: String) {
        let digits = Array(hex.utf8)
        guard digits.count == Self.length * 2 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(Self.length)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let high = Self.nibble(digits[index]), let low = Self.nibble(digits[index + 1]) else { return nil }
            bytes.append(high << 4 | low)
        }
        self.bytes = bytes
    }

    var hex: String {
        let alphabet = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(Self.length * 2)
        for byte in bytes {
            out.append(alphabet[Int(byte >> 4)])
            out.append(alphabet[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    private static func nibble(_ digit: UInt8) -> UInt8? {
        switch digit {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return digit - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return digit - UInt8(ascii: "a") + 10
        default: return nil
        }
    }

    /// Byte order: the canonical order of an encoding, nothing more.
    public static func < (lhs: ScanBinding, rhs: ScanBinding) -> Bool {
        lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
    }
}

extension ScanBinding: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "ScanBinding(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// The key bindings are computed under: 32 bytes or more, held in `SecureBytes` and zeroised by whoever holds it.
///
/// Two keys are in use, for two readers. This device's scan ledger binds its own results under a key derived from the
/// reuse key (`ReuseKey.scanBinding`), which no vault rotation changes, so a breach this device saw stays bound to its
/// password whatever happens to the vault's keys. A vault's synced results bind under a key every member derives from
/// the vault key the result names (`HygieneKeys.scanBindingKey` in `WatchwordCrypto`), so each member can tell
/// whether a result is about the password they hold.
public struct ScanBindingKey: Sendable {
    public static let minimumLength = 32
    static let domain = Array("WW-scan-binding-v1".utf8)

    let bytes: SecureBytes

    /// Takes over `bytes`; `zeroise()` wipes them.
    public init(_ bytes: SecureBytes) throws {
        guard bytes.count >= Self.minimumLength else { throw ScanBindingKeyError.tooShort }
        guard !bytes.isZeroised else { throw ScanBindingKeyError.zeroised }
        self.bytes = bytes
    }

    /// The binding of `password` (its UTF-8 bytes, as typed) on item `item`.
    public func binding(item: UUID, utf8Of password: String) -> ScanBinding {
        let message = SecureBytes(copying: Self.domain + [0x00] + item.scanBindingBytes + Array(password.utf8))
        defer { message.zeroise() }
        let code = HMAC<SHA256>.authenticationCode(for: message, using: bytes.symmetricKey)
        return ScanBinding(bytes: Array(code))!
    }

    public func zeroise() {
        bytes.zeroise()
    }
}

extension ReuseKey {
    static let scanBindingLabel = Array("WW-ledger-binding-key-v1".utf8)

    /// The binding of `password` on `item` for this device's own scan ledger: under a key derived from the reuse key
    /// (`HMAC(reuse key, "WW-ledger-binding-key-v1")`), so neither key stands in for the other and a binding is not a
    /// reuse token.
    func scanBinding(item: UUID, utf8Of password: String) -> ScanBinding {
        var code = Array(HMAC<SHA256>.authenticationCode(for: Self.scanBindingLabel, using: bytes.symmetricKey))
        let derived = SecureBytes(wiping: &code)
        // A fresh 32-byte buffer is always a key.
        let key = try! ScanBindingKey(derived)
        defer { key.zeroise() }
        return key.binding(item: item, utf8Of: password)
    }
}

extension UUID {
    var scanBindingBytes: [UInt8] {
        let u = uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }

    init(scanBindingBytes bytes: ArraySlice<UInt8>) {
        let b = Array(bytes)
        self.init(
            uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
        )
    }
}
