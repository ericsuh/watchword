import Foundation

/// When one part of an item last changed: the item version that changed it and the device that wrote that version
/// (docs/02-architecture.md §7.1, PRD F7.4).
///
/// Revisions are totally ordered by version, then by device ID compared byte by byte, so every device that sees the
/// same two revisions picks the same later one.
public struct Revision: Hashable, Codable, Sendable, Comparable {
    public var version: UInt64
    public var device: UUID

    public init(version: UInt64, device: UUID) {
        self.version = version
        self.device = device
    }

    public static func < (lhs: Revision, rhs: Revision) -> Bool {
        if lhs.version != rhs.version { return lhs.version < rhs.version }
        return lhs.device.precedes(rhs.device)
    }
}

/// A part of an item that sync merges as a unit (a "field group", docs/02-architecture.md §7.1): each item attribute
/// on its own, and each field by its ID. Two devices that edit different groups of the same item both keep their
/// change; two that edit the same group resolve by `Revision`, and the loser goes to the item's history (PRD F7.4).
///
/// The raw value is the encoded form. Unknown raw values from a newer client are kept and merged like any other group.
public struct ItemGroup: Hashable, Sendable, Comparable, RawRepresentable, Codable, CodingKeyRepresentable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static let title = ItemGroup(rawValue: "title")
    public static let scopes = ItemGroup(rawValue: "scopes")
    public static let tags = ItemGroup(rawValue: "tags")
    public static let notes = ItemGroup(rawValue: "notes")
    public static let archived = ItemGroup(rawValue: "archived")
    public static let trashedAt = ItemGroup(rawValue: "trashedAt")
    public static let excludedFromSuggestions = ItemGroup(rawValue: "excludedFromSuggestions")
    /// The order of `Item.fields`, separately from their contents.
    public static let fieldOrder = ItemGroup(rawValue: "fieldOrder")

    /// Every item-level group; fields add one group each.
    public static let attributes: [ItemGroup] = [
        .title, .scopes, .tags, .notes, .archived, .trashedAt, .excludedFromSuggestions, .fieldOrder,
    ]

    static let fieldPrefix = "field."

    public static func field(_ id: UUID) -> ItemGroup {
        ItemGroup(rawValue: fieldPrefix + id.uuidString)
    }

    /// The field this group stands for, if it is a field group.
    public var fieldID: UUID? {
        guard rawValue.hasPrefix(Self.fieldPrefix) else { return nil }
        return UUID(uuidString: String(rawValue.dropFirst(Self.fieldPrefix.count)))
    }

    public static func < (lhs: ItemGroup, rhs: ItemGroup) -> Bool {
        Array(lhs.rawValue.utf8).lexicographicallyPrecedes(Array(rhs.rawValue.utf8))
    }

    public var codingKey: any CodingKey {
        GroupKey(stringValue: rawValue)
    }

    public init?<T: CodingKey>(codingKey: T) {
        self.init(rawValue: codingKey.stringValue)
    }

    public init(from decoder: any Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    private struct GroupKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }

        init(stringValue: String) {
            self.stringValue = stringValue
        }

        init?(intValue: Int) {
            nil
        }
    }
}

extension UUID {
    /// Byte-wise order, identical on every platform (unlike anything that goes through a locale).
    public func precedes(_ other: UUID) -> Bool {
        uuidBytes(self).lexicographicallyPrecedes(uuidBytes(other))
    }
}

private func uuidBytes(_ id: UUID) -> [UInt8] {
    let u = id.uuid
    return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
}
