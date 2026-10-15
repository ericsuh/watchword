import Foundation

/// What the Emergency Kit shows (PRD F5.1, F10.2): the account ID and the Secret Key, plus a setup code for the QR.
///
/// The account password is never on it. Losing the kit and every device is unrecoverable by design, and the kit says
/// so. The formatted Secret Key is a Swift `String` and cannot be zeroised (PRD SEC4); this value should live only as
/// long as the screen or document that shows it.
public struct EmergencyKit: Sendable, Hashable {
    /// Prefix of the QR payload. Deliberately not a URL: a registered URL scheme can be claimed by any installed app,
    /// and the OS would hand the Secret Key to whichever app it routed the link to.
    public static let setupCodePrefix = "WWKIT1"

    public let accountID: UUID
    /// `WW-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-CC`.
    public let secretKey: String
    public let createdAt: Date

    public init(accountID: UUID, secretKey: String, createdAt: Date) {
        self.accountID = accountID
        self.secretKey = secretKey
        self.createdAt = createdAt
    }

    /// `WWKIT1:<account UUID>:<Secret Key>`, encoded in the kit's QR code for second-device enrolment (F5.2).
    public var setupCode: String {
        "\(EmergencyKit.setupCodePrefix):\(accountID.uuidString):\(secretKey)"
    }

    /// Parses a scanned setup code. Returns `nil` for anything that is not exactly the format above; the Secret Key
    /// part is validated (checksum included) when it is turned into a `SecretKey`.
    public static func parseSetupCode(_ text: String) -> (accountID: UUID, secretKey: String)? {
        let parts = text.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == setupCodePrefix, let accountID = UUID(uuidString: String(parts[1])) else {
            return nil
        }
        return (accountID, String(parts[2]))
    }
}

/// Redacted, so the Secret Key never reaches a log, `print`, `dump` or a crash report's mirror by accident.
extension EmergencyKit: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "EmergencyKit(account: \(accountID), secretKey: redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["accountID": accountID], displayStyle: .struct) }
}

/// The plain-language warnings the kit and onboarding carry (F10.2: "the UI must say so at setup").
public enum EmergencyKitText {
    public static let title = "Watchword Emergency Kit"
    public static let instructions =
        "Keep this document somewhere safe, such as with your important papers. You need it, together with your "
        + "account password, to sign in on a new device or if you lose all of your devices."
    public static let unrecoverableWarning =
        "Watchword cannot recover your account. If you lose this kit and every device that is signed in, and you "
        + "forget your account password, your data is gone. Nobody, including the makers of Watchword, can reset it."
    public static let passwordLine = "Account password: write it here by hand, or keep it only in your memory."
}
