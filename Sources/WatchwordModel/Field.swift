import Foundation

/// The kinds of values an account item can hold (PRD F1.2).
public enum FieldKind: String, Codable, Sendable, CaseIterable {
    case username
    case email
    case phoneNumber
    case password
    case totp
    case passkey
    case securityQuestion
    case apiKey
    case pin
    case recoveryCodes
    case accountNumber
    case url
    case date
    case text
    case custom

    /// Whether values of this kind are secrets that must be concealed by default and never indexed.
    public var isSecret: Bool {
        switch self {
        case .password, .totp, .passkey, .securityQuestion, .apiKey, .pin, .recoveryCodes, .custom:
            return true
        case .username, .email, .phoneNumber, .accountNumber, .url, .date, .text:
            return false
        }
    }
}

/// One typed field inside an item. `value` is a plaintext string in memory only; on disk the whole
/// item is a single ciphertext (see `docs/02-architecture.md` §5).
public struct Field: Hashable, Codable, Sendable, Identifiable {
    public var id: UUID
    public var kind: FieldKind
    public var label: String
    public var value: String
    /// For `securityQuestion`, the question text; for `recoveryCodes`, a JSON array of used flags, etc.
    public var meta: [String: String]

    public init(id: UUID = UUID(), kind: FieldKind, label: String, value: String, meta: [String: String] = [:]) {
        self.id = id
        self.kind = kind
        self.label = label
        self.value = value
        self.meta = meta
    }
}
