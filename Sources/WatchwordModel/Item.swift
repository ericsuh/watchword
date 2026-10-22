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
    /// Who last wrote each attribute and each field, and what they had seen, for field-level merging across devices
    /// (PRD F7.4, docs/02-architecture.md §7.5). A field removed from `fields` keeps its entry, which is what records
    /// the removal. Empty on items written before sync; the merge then treats every group as written by the record's
    /// own version.
    public var revisions: [ItemGroup: GroupStamp]
    /// Values written concurrently with the ones shown, per group, kept until the person chooses (PRD F7.6). Sync
    /// never discards one; an edit of the group, made where these are shown, resolves them.
    public var conflicts: [ItemGroup: [ConflictingValue]]
    /// Conflicting values that an edit of their group superseded: the person edited the field while the conflict
    /// stood, which settles what is shown but is not a choice to discard the others (PRD F7.7). Kept until the person
    /// explicitly discards them.
    public var retainedValues: [ConflictingValue]
    /// For each device, the highest of its edits this copy of the item contains (merge results are not edits).
    public var clock: VersionVector
    /// `notes` as a line-level sequence, so concurrent edits to different lines merge (PRD F7.6). Empty on items
    /// written before sync, and for empty notes.
    public var noteLines: [NoteLine]

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
        excludedFromSuggestions: Bool = false,
        revisions: [ItemGroup: GroupStamp] = [:],
        conflicts: [ItemGroup: [ConflictingValue]] = [:],
        retainedValues: [ConflictingValue] = [],
        clock: VersionVector = VersionVector(),
        noteLines: [NoteLine] = []
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
        self.revisions = revisions
        self.conflicts = conflicts
        self.retainedValues = retainedValues
        self.clock = clock
        self.noteLines = noteLines
    }

    enum CodingKeys: String, CodingKey {
        case id, vaultID, title, scopes, fields, tags, notes, createdAt, modifiedAt, version, archived, trashedAt
        case history, excludedFromSuggestions, revisions, conflicts, retainedValues, clock, noteLines
    }

    /// Synthesised decoding, except that the sync metadata may be absent: payloads written before it existed still open.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        vaultID = try container.decode(UUID.self, forKey: .vaultID)
        title = try container.decode(String.self, forKey: .title)
        scopes = try container.decode([ServiceScope].self, forKey: .scopes)
        fields = try container.decode([Field].self, forKey: .fields)
        tags = try container.decode(Set<String>.self, forKey: .tags)
        notes = try container.decode(String.self, forKey: .notes)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        modifiedAt = try container.decode(Date.self, forKey: .modifiedAt)
        version = try container.decode(UInt64.self, forKey: .version)
        archived = try container.decode(Bool.self, forKey: .archived)
        trashedAt = try container.decodeIfPresent(Date.self, forKey: .trashedAt)
        history = try container.decode([ItemHistoryEntry].self, forKey: .history)
        excludedFromSuggestions = try container.decode(Bool.self, forKey: .excludedFromSuggestions)
        revisions = try container.decodeIfPresent([ItemGroup: GroupStamp].self, forKey: .revisions) ?? [:]
        conflicts = try container.decodeIfPresent([ItemGroup: [ConflictingValue]].self, forKey: .conflicts) ?? [:]
        retainedValues = try container.decodeIfPresent([ConflictingValue].self, forKey: .retainedValues) ?? []
        clock = try container.decodeIfPresent(VersionVector.self, forKey: .clock) ?? VersionVector()
        noteLines = try container.decodeIfPresent([NoteLine].self, forKey: .noteLines) ?? []
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

    /// Whether any group holds values written concurrently with the one shown (PRD F7.6).
    public var hasConflicts: Bool {
        conflicts.contains { !$0.value.isEmpty }
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
