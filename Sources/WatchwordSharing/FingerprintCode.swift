import Foundation
import SecureMemory
import WatchwordCrypto

extension Fingerprint {
    /// The longest input `matches(safetyNumber:)` looks at: sixty digits and generous separators.
    static let maximumTypedLength = 256

    /// Whether a safety number someone typed, pasted or read aloud is this fingerprint's (PRD F4.2).
    ///
    /// Exactly sixty ASCII digits, with ASCII spaces, tabs and line breaks between them ignored. Anything else is not
    /// a match: other digits (a different script's numerals), other separators, a shorter number, a longer one. The
    /// comparison is constant-time.
    public func matches(safetyNumber typed: String) -> Bool {
        guard typed.utf8.count <= Fingerprint.maximumTypedLength else { return false }
        var digits: [UInt8] = []
        for byte in typed.utf8 {
            switch byte {
            case 0x30...0x39: digits.append(byte)
            case 0x20, 0x09, 0x0A, 0x0D: continue
            default: return false
            }
        }
        let own = safetyNumber.utf8.filter { $0 != 0x20 }
        guard digits.count == Fingerprint.groupCount * 5 else { return false }
        return ConstantTime.equal(digits, own)
    }
}

/// What a person's device shows as a QR code for someone else to scan: their account ID and the fingerprint of their
/// key bundle (docs/02-architecture.md §8.4, PRD F4.2).
///
/// ```
/// "WWFP1-" ‖ upper-case hex of (accountID 16 ‖ fingerprint digest 60)        158 characters
/// ```
///
/// Digits, capitals and a hyphen only, so it fits a QR code's compact alphanumeric mode. The account ID is there so
/// that one scan both names the account to look up and authenticates the bundle the directory returns for it.
///
/// The code is not a secret and not a key: it authenticates a bundle obtained elsewhere, exactly as reading the
/// safety number aloud does. A scanned payload is hostile input (anything can be put in a QR code), so the parser
/// accepts exactly one spelling of exactly one length and looks at nothing longer.
public struct FingerprintCode: Sendable, Equatable {
    static let prefix = Array("WWFP1-".utf8)
    static let digestLength = Fingerprint.groupCount * 5
    public static let payloadLength = prefix.count + 2 * (16 + digestLength)

    public let accountID: UUID
    let digest: [UInt8]

    public init(bundle: PublicKeyBundle) {
        accountID = bundle.accountID
        digest = bundle.fingerprint.digest
    }

    /// The text to encode as a QR code.
    public var payload: String {
        String(decoding: FingerprintCode.prefix, as: UTF8.self)
            + SharingBytes.hex(accountID.sharingBytes + digest, uppercase: true)
    }

    /// Parses a scanned payload.
    public init(scanned payload: String) throws {
        let utf8 = Array(payload.utf8.prefix(FingerprintCode.payloadLength + 1))
        guard utf8.count == FingerprintCode.payloadLength,
            Array(utf8.prefix(FingerprintCode.prefix.count)) == FingerprintCode.prefix,
            let bytes = SharingBytes.bytes(
                hex: String(decoding: utf8.dropFirst(FingerprintCode.prefix.count), as: UTF8.self), uppercase: true)
        else { throw SharingFormatError.malformedText }
        accountID = UUID(sharingBytes: Array(bytes[0..<16]))
        digest = Array(bytes[16...])
    }

    /// Whether this code was made from `bundle`: the same account and, in constant time, the same fingerprint.
    public func matches(_ bundle: PublicKeyBundle) -> Bool {
        let sameFingerprint = ConstantTime.equal(digest, bundle.fingerprint.digest)
        return accountID == bundle.accountID && sameFingerprint
    }

    public static func == (lhs: FingerprintCode, rhs: FingerprintCode) -> Bool {
        let sameDigest = ConstantTime.equal(lhs.digest, rhs.digest)
        return lhs.accountID == rhs.accountID && sameDigest
    }
}
