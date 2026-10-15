import Foundation

/// An account item: one real-world account, with the scopes it applies to and its fields.
///
/// The whole value, metadata included, is one ciphertext on disk (docs/02-architecture.md §5): titles, hosts and
/// timestamps are as private as the passwords.
public struct Item: Hashable, Codable, Sendable, Identifiable {
    public var id: UUID
    public var vaultID: UUID
    public var title: String
    public var scopes: [ServiceScope]
    public var fields: [Field]
    public var tags: Set<String>
    public var notes: String
    public var createdAt: Date
    public var modifiedAt: Date
    /// Lamport version, bound into the record's authenticated data (SEC2). Assigned by the vault on save.
    public var version: UInt64
    public var archived: Bool
    /// When the item was moved to the trash; it is purged 30 days later (PRD F1.5).
    public var trashedAt: Date?
    /// Earlier field values, newest first, retained for 90 days (PRD F1.4).
    public var history: [ItemHistoryEntry]
    /// Keeps the item out of the OS QuickType identity store (PRD F6.8).
    public var excludedFromSuggestions: Bool

    public init(
        id: UUID = UUID(),
        vaultID: UUID,
        title: String,
        scopes: [ServiceScope],
        fields: [Field],
        tags: Set<String> = [],
        notes: String = "",
        createdAt: Date = Date(timeIntervalSince1970: 0),
        modifiedAt: Date = Date(timeIntervalSince1970: 0),
        version: UInt64 = 0,
        archived: Bool = false,
        trashedAt: Date? = nil,
        history: [ItemHistoryEntry] = [],
        excludedFromSuggestions: Bool = false
    ) {
        self.id = id
        self.vaultID = vaultID
        self.title = title
        self.scopes = scopes
        self.fields = fields
        self.tags = tags
        self.notes = notes
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.version = version
        self.archived = archived
        self.trashedAt = trashedAt
        self.history = history
        self.excludedFromSuggestions = excludedFromSuggestions
    }

    /// The first field of a given kind, if any.
    public func field(_ kind: FieldKind) -> Field? {
        fields.first { $0.kind == kind }
    }

    /// Usernames and emails, in field order, for identity publishing.
    public var loginNames: [String] {
        fields.filter { $0.kind == .username || $0.kind == .email }.map(\.value)
    }

    public var isTrashed: Bool {
        trashedAt != nil
    }
}

/// One earlier version of an item's fields (PRD F1.4).
public struct ItemHistoryEntry: Hashable, Codable, Sendable {
    /// When these values stopped being current.
    public var replacedAt: Date
    /// The item version these fields belonged to.
    public var version: UInt64
    public var fields: [Field]

    public init(replacedAt: Date, version: UInt64, fields: [Field]) {
        self.replacedAt = replacedAt
        self.version = version
        self.fields = fields
    }
}
