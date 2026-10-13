import Foundation

/// An account item: one real-world account, with the scopes it applies to and its fields.
public struct Item: Hashable, Codable, Sendable, Identifiable {
    public var id: UUID
    public var vaultID: UUID
    public var title: String
    public var scopes: [ServiceScope]
    public var fields: [Field]
    public var tags: Set<String>
    public var notes: String

    public init(
        id: UUID = UUID(),
        vaultID: UUID,
        title: String,
        scopes: [ServiceScope],
        fields: [Field],
        tags: Set<String> = [],
        notes: String = ""
    ) {
        self.id = id
        self.vaultID = vaultID
        self.title = title
        self.scopes = scopes
        self.fields = fields
        self.tags = tags
        self.notes = notes
    }

    /// The first field of a given kind, if any.
    public func field(_ kind: FieldKind) -> Field? {
        fields.first { $0.kind == kind }
    }

    /// Usernames and emails, in field order, for identity publishing.
    public var loginNames: [String] {
        fields.filter { $0.kind == .username || $0.kind == .email }.map(\.value)
    }
}
