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

    /// The full vault sharing code (the 60-digit fingerprint) in groups, for display one group per cell.
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

/// This account's own fingerprint, the full vault sharing code, for the fallback: read out or shown to someone who
/// cannot be at their device at the same time (PRD F4.2; ADR 0010).
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

/// Another account as the key directory gives it: which account, and whether this device pinned it before.
///
/// It carries none of the directory's digits for that account on purpose. The full-code fallback asks the person to
/// type the other device's sixty digits, and the directory's copy shown beside the field would be what they type: a
/// directory that publishes its own keys under the account (A1) would then pass the check it is meant to fail
/// (docs/06-adversarial-review.md, V17). A step that checks a fingerprint shows this device's own code instead
/// (`FullCodeComparison`).
public struct ContactSummary: Hashable, Sendable {
    public let accountID: UUID
    /// Already pinned: checked before, and the directory's keys are the ones checked.
    public let isVerified: Bool

    public init(_ candidate: ContactCandidate) {
        accountID = candidate.accountID
        if case .verified = candidate.trust {
            isVerified = true
        } else {
            isVerified = false
        }
    }
}

/// A step of the full-code fallback (ADR 0010): the account whose sixty digits the person types, from that account's
/// own device, and this device's own full vault sharing code, shown for the other person to type in turn. Nothing
/// here is the value being checked: the device compares what was typed with the directory's bundle, which no screen
/// shows (docs/06-adversarial-review.md, V17).
public struct FullCodeComparison: Hashable, Sendable {
    /// The other account, as the person named it (invite) or as the invitation names its owner (accept).
    public let accountID: UUID
    /// This account's own fingerprint, to read out or show.
    public let own: OwnFingerprint

    public init(accountID: UUID, own: OwnFingerprint) {
        self.accountID = accountID
        self.own = own
    }
}

/// How the person confirms a fingerprint by the fallback, the full vault sharing code (PRD F4.2; ADR 0010): the sixty
/// digits typed from the other person's screen or message, which the session checks. There is no "they match" switch:
/// a person's unchecked word is not evidence (ADR 0010, G3).
///
/// A fingerprint code is never evidence here. One pasted from a message names an account and nothing more: anyone who
/// can message the person can send a code for an account of their own (review of the account screens, finding 2).
/// `VerificationEvidence.scannedCode` comes only from the camera, through the scanning screens' own entry points
/// (`cameraScanned`), never from a text field.
public struct FingerprintConfirmation: Hashable, Sendable {
    public var typedSafetyNumber = ""

    public init() {}

    /// The evidence to offer, or `nil` while the person has typed nothing.
    public func evidence() -> VerificationEvidence? {
        let typed = typedSafetyNumber.trimmingCharacters(in: .whitespacesAndNewlines)
        return typed.isEmpty ? nil : .safetyNumber(typed)
    }

    /// What the person did, for the step after it.
    public static func describe(_ evidence: VerificationEvidence) -> String {
        switch evidence {
        case .safetyNumber: return "You typed their full vault sharing code, and it matched."
        case .scannedCode: return "You scanned their code, and it matched."
        }
    }

    /// What a vault sharing code session did, for the step after it.
    public static func describe(_ status: SharingCodeStatus) -> String {
        status.scanned ? "You scanned their code, and it matched." : "Their confirmation code matched."
    }
}

/// The words of a vault sharing code session (ADR 0010): what each screen says the person does, and why a session
/// stopped. The session decides; these only say it.
public enum SharingCodeWording {
    /// What a wrong confirmation code says, with the attempts left.
    public static func wrongCode(attemptsLeft: Int) -> String {
        let tries =
            attemptsLeft == 1
            ? "That code does not match. One try left; check each digit with them."
            : "That code does not match. \(attemptsLeft) tries left; check each digit with them."
        return tries + " If their screen now shows other digits than before, stop and start a new code."
    }

    public static func failure(_ error: SharingCodeError) -> String {
        switch error {
        case .sessionNotFound:
            return "No one is sharing under that code. Check the eight digits with the other person, or ask them to "
                + "start again."
        case .sessionTaken:
            return "Someone else answered that code first, so it was stopped. Start again with a new code."
        case .numbersExhausted:
            return "A vault sharing code could not be made. Try again in a moment."
        case .sameAccount:
            return "That code is from your own account. Use the other person's device."
        case .malformedMessage, .commitmentMismatch, .boardInterference:
            return "Something between your devices changed the exchange, so it was stopped and nothing was shared. "
                + "Start again; if it happens again, use the full vault sharing code."
        case .tooManyAttempts:
            return "The confirmation code was wrong three times, so this was stopped and nothing was shared. If you "
                + "typed it right, someone may be between your devices. Start again."
        case .expired:
            return "This took more than ten minutes and was stopped. Start again."
        case .scannedCodeMismatch:
            return "The code you scanned is not this account's. Scan the other person's screen."
        case .malformedCode:
            return "Type the digits exactly as the other screen shows them."
        case .notReady:
            return "That step is not ready yet. Wait for the other device, then try again."
        case .invitationInvalid:
            return "The invitation did not come from the person you checked, and was refused. Ask them to send it as "
                + "text, and paste it instead."
        case .busy:
            return ""
        case .numberAlreadyAnswered:
            return "You already answered this code on this device. Ask them to start a new one."
        }
    }

    /// A code as VoiceOver should read it: each digit on its own, a pause between groups ("1 2 3, 4 5 6"), so it is
    /// heard as digits and not as a number in the hundreds of thousands.
    public static func spoken(_ code: String) -> String {
        code.split(separator: " ").map { group in group.map(String.init).joined(separator: " ") }
            .joined(separator: ", ")
    }

    /// Whose screen the digits come from: the one protection the protocol cannot give (ADR 0010, "The people's
    /// channel").
    public static let channelWarning =
        "Only use digits you read on their screen yourself, or hear from them in person or on a call you know is "
        + "them. Never type digits someone sends you in a message."
}
