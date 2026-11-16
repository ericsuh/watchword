import Foundation
import WatchwordCrypto
import WatchwordKit
import WatchwordSharing

/// Turning what people send each other into the values the session takes, and back (PRD F4.1, F4.2). Every parser
/// here is exact and bounded: what a person pastes is hostile input, and anything that is not exactly one spelling is
/// refused rather than repaired.
public enum SharingCodes {
    /// An invitation as text, to send to the invitee: the upper-case hexadecimal of `Invitation.encoded()` (which
    /// starts with its own magic). It names a vault and its owner only, and is not a secret.
    public static func text(for invitation: Invitation) -> String {
        hex(invitation.encoded())
    }

    /// The invitation in `text`, ignoring spaces and line breaks around and between its digits; `nil` for anything
    /// else.
    public static func invitation(from text: String) -> Invitation? {
        let compact = text.filter { !$0.isWhitespace }
        guard compact.utf8.count == 2 * Invitation.encodedLength, let bytes = bytes(hex: compact) else { return nil }
        return try? Invitation.parse(bytes)
    }

    /// The account a person means by `text`: a fingerprint code (`WWFP1-…`, which also names the fingerprint to check
    /// against) or an account ID as a UUID.
    public static func account(from text: String) -> AccountReference? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.utf8.count <= FingerprintCode.payloadLength else { return nil }
        if let code = try? FingerprintCode(scanned: trimmed) {
            return AccountReference(accountID: code.accountID, fingerprintCode: trimmed)
        }
        return UUID(uuidString: trimmed).map { AccountReference(accountID: $0, fingerprintCode: nil) }
    }

    /// The safety number in groups, for display one group per cell.
    public static func groups(of safetyNumber: String) -> [String] {
        safetyNumber.split(separator: " ").map(String.init)
    }

    static func hex(_ bytes: [UInt8]) -> String {
        let digits = Array("0123456789ABCDEF")
        var out = ""
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return out
    }

    /// Upper- or lower-case hexadecimal digits only, an even number of them.
    static func bytes(hex text: String) -> [UInt8]? {
        let utf8 = Array(text.utf8)
        guard utf8.count % 2 == 0 else { return nil }
        func value(_ byte: UInt8) -> UInt8? {
            switch byte {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
            case UInt8(ascii: "A")...UInt8(ascii: "F"): return byte - UInt8(ascii: "A") + 10
            case UInt8(ascii: "a")...UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
            default: return nil
            }
        }
        var out: [UInt8] = []
        out.reserveCapacity(utf8.count / 2)
        var index = 0
        while index < utf8.count {
            guard let high = value(utf8[index]), let low = value(utf8[index + 1]) else { return nil }
            out.append(high << 4 | low)
            index += 2
        }
        return out
    }
}

/// Who a person means: an account, and the fingerprint code they were given for it, if that is how they named it.
public struct AccountReference: Hashable, Sendable {
    public let accountID: UUID
    /// The `WWFP1-…` text, to check the directory's bundle against (`VerificationEvidence.scannedCode`).
    public let fingerprintCode: String?

    public init(accountID: UUID, fingerprintCode: String?) {
        self.accountID = accountID
        self.fingerprintCode = fingerprintCode
    }
}

/// This account's own fingerprint, for the person to read out or show to someone inviting them (PRD F4.2).
public struct OwnFingerprint: Hashable, Sendable {
    public let accountID: UUID
    public let safetyNumber: String
    /// The text a QR code shows (`FingerprintCode.payload`): the account ID and the fingerprint together.
    public let code: String

    public init(_ bundle: PublicKeyBundle) {
        accountID = bundle.accountID
        safetyNumber = bundle.fingerprint.safetyNumber
        code = FingerprintCode(bundle: bundle).payload
    }

    public var groups: [String] { SharingCodes.groups(of: safetyNumber) }
}

/// Another account as the key directory gives it, for the person to compare out of band.
public struct ContactSummary: Hashable, Sendable {
    public let accountID: UUID
    public let safetyNumber: String
    /// Already pinned: compared before, and the directory's keys are the ones compared.
    public let isVerified: Bool

    public init(_ candidate: ContactCandidate) {
        accountID = candidate.accountID
        safetyNumber = candidate.fingerprint.safetyNumber
        if case .verified = candidate.trust {
            isVerified = true
        } else {
            isVerified = false
        }
    }

    public var groups: [String] { SharingCodes.groups(of: safetyNumber) }
}

/// How the person confirms a fingerprint (PRD F4.2): what they typed, the code they were given, or their own
/// comparison. Exactly one is used, in that order of preference, and the session checks it.
public struct FingerprintConfirmation: Hashable, Sendable {
    public var typedSafetyNumber = ""
    public var comparedByEye = false

    public init() {}

    /// The evidence to offer, or `nil` while the person has given none.
    public func evidence(code: String?) -> VerificationEvidence? {
        let typed = typedSafetyNumber.trimmingCharacters(in: .whitespacesAndNewlines)
        if !typed.isEmpty { return .safetyNumber(typed) }
        if let code { return .scannedCode(code) }
        if comparedByEye { return .comparedByEye }
        return nil
    }
}
