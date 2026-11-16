import Foundation

/// One write of an item: the item version and the device that wrote it (docs/02-architecture.md §7.1, PRD F7.4).
///
/// Revisions are totally ordered by version, then by device ID compared byte by byte, so every device that sees the
/// same two revisions picks the same later one. That order only breaks ties; whether one write *knew about* another is
/// a `VersionVector` question.
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

    /// The revision with its version lowered to `limit` if it is above it (see `VersionVector.clamped`).
    public func clamped(to limit: UInt64) -> Revision {
        version > limit ? Revision(version: limit, device: device) : self
    }
}

/// For each device, the highest of its edits of an item that a copy of the item contains.
///
/// A device's edits of one item are each made on a copy containing its earlier ones (merges never drop anything), so
/// containing edit `n` from a device means containing all of that device's earlier edits too. That is what makes `contains` exact:
/// a write whose vector contains another write's revision was made by someone who had seen it. Two writes neither of
/// which contains the other are concurrent — a conflict — and sync keeps both (PRD F7.6).
///
/// Vectors under `merging` are a join-semilattice (entry-wise maximum), which is what every other part of the item
/// merge is built on (docs/10-sync-correctness.md §2).
public struct VersionVector: Hashable, Sendable, Codable {
    public private(set) var entries: [UUID: UInt64]

    public init(_ entries: [UUID: UInt64] = [:]) {
        self.entries = entries.filter { $0.value > 0 }
    }

    public func contains(_ revision: Revision) -> Bool {
        (entries[revision.device] ?? 0) >= revision.version
    }

    /// Every entry of `self` is at most the same entry of `other`.
    public func isCovered(by other: VersionVector) -> Bool {
        entries.allSatisfy { (other.entries[$0.key] ?? 0) >= $0.value }
    }

    public func merging(_ other: VersionVector) -> VersionVector {
        VersionVector(entries.merging(other.entries, uniquingKeysWith: max))
    }

    public mutating func record(_ revision: Revision) {
        guard revision.version > 0 else { return }
        entries[revision.device] = max(entries[revision.device] ?? 0, revision.version)
    }

    /// `merging`, in place.
    public mutating func formUnion(_ other: VersionVector) {
        for (device, count) in other.entries where count > (entries[device] ?? 0) { entries[device] = count }
    }

    public var isEmpty: Bool {
        entries.isEmpty
    }

    /// Whether `other` covers this vector and holds something more: the strict order of the semilattice. Unlike
    /// `contains`, it is a strict partial order on *any* two vectors, honest or crafted, which is what lets the item
    /// merge stay a join on hostile input (docs/10-sync-correctness.md §3.2).
    public func isStrictlyCovered(by other: VersionVector) -> Bool {
        self != other && isCovered(by: other)
    }

    /// The vector with every entry above `limit` lowered to it. A record written at version `limit` cannot contain
    /// an edit newer than itself, so a count above it is a claim about the future and is read as the most it can
    /// honestly be (docs/10-sync-correctness.md §6).
    public func clamped(to limit: UInt64) -> VersionVector {
        guard entries.values.contains(where: { $0 > limit }) else { return self }
        return VersionVector(entries.mapValues { min($0, limit) })
    }

    // Encoded as an object keyed by UUID string, so it reads the same on every platform.
    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode([String: UInt64].self)
        var entries: [UUID: UInt64] = [:]
        for (key, value) in raw {
            guard let id = UUID(uuidString: key) else {
                throw DecodingError.dataCorrupted(
                    DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "device ID"))
            }
            // Two spellings of one device ID (upper and lower case) are two keys of the object: the higher count
            // wins, whichever the dictionary yields first, so every device reads the same vector.
            entries[id] = max(entries[id] ?? 0, value)
        }
        self.init(entries)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(Dictionary(uniqueKeysWithValues: entries.map { ($0.key.uuidString, $0.value) }))
    }
}

/// Who wrote a group's value, and what that writer had seen of the item when it did.
public struct GroupStamp: Hashable, Sendable, Codable {
    public var revision: Revision
    /// The item's `VersionVector` at the write, including the write itself.
    public var seen: VersionVector

    public init(revision: Revision, seen: VersionVector) {
        self.revision = revision
        var seen = seen
        seen.record(revision)
        self.seen = seen
    }

    /// Whether this write was made knowing about `other`: everything `other`'s writer had seen, this writer had
    /// seen too, and something more.
    ///
    /// Between honest writes this is the same as "`seen` contains `other.revision`", because a copy that contains a
    /// write contains everything that write was made on. It is stated on the vectors because that is a strict partial
    /// order whatever the stamps hold — transitive, never mutual — so "keep the values nothing supersedes" is a join
    /// even when a stamp was crafted (docs/10-sync-correctness.md §3.2).
    public func supersedes(_ other: GroupStamp) -> Bool {
        other.seen.isStrictlyCovered(by: seen)
    }

    /// The stamp as read from a record written at version `limit`: no count above it, and `seen` containing the
    /// write itself. `init` records the revision, but `seen` can be set and a stamp decodes as it was encoded, so a
    /// record can carry one whose vector omits its own revision; read as written, a resolution made on a copy that
    /// held the value would not cover it (docs/10-sync-correctness.md §6, review finding Y34).
    public func clamped(to limit: UInt64) -> GroupStamp {
        let clamped = seen.clamped(to: limit)
        if revision.version <= limit, clamped == seen, seen.contains(revision) { return self }
        return GroupStamp(revision: revision.clamped(to: limit), seen: clamped)
    }
}

/// A part of an item that sync merges as a unit (a "field group", docs/02-architecture.md §7.1): each item attribute
/// on its own, and each field by its ID. Two devices that edit different groups of the same item both keep their
/// change; two that edit the same group concurrently keep both values, one shown and the others as conflicts, until
/// the person resolves them (PRD F7.4, F7.6). Notes are not a group of this kind: they merge line by line.
///
/// The raw value is the encoded form.
public struct ItemGroup: Hashable, Sendable, Comparable, RawRepresentable, Codable, CodingKeyRepresentable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static let title = ItemGroup(rawValue: "title")
    public static let scopes = ItemGroup(rawValue: "scopes")
    public static let tags = ItemGroup(rawValue: "tags")
    public static let archived = ItemGroup(rawValue: "archived")
    public static let trashedAt = ItemGroup(rawValue: "trashedAt")
    public static let keptAfterDeletion = ItemGroup(rawValue: "keptAfterDeletion")
    public static let excludedFromSuggestions = ItemGroup(rawValue: "excludedFromSuggestions")
    /// The order of `Item.fields`, separately from their contents.
    public static let fieldOrder = ItemGroup(rawValue: "fieldOrder")

    /// Every item-level group; fields add one group each.
    public static let attributes: [ItemGroup] = [
        .title, .scopes, .tags, .archived, .trashedAt, .keptAfterDeletion, .excludedFromSuggestions, .fieldOrder,
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

    /// Whether this is a group this client merges: an item attribute, or a field group spelt exactly as `field(_:)`
    /// spells it. Anything else in an item's sync metadata — an unknown name, a second spelling of a field's group —
    /// is not interpreted (docs/10-sync-correctness.md §6).
    public var isKnown: Bool {
        if let id = fieldID { return self == .field(id) }
        return Self.attributes.contains(self)
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

/// The value of one group, as kept for a conflicting version.
///
/// Two values are equal when their bytes are (`ExactEquality.swift`): a title respelt in another normalisation form
/// is another value, which sync keeps beside the first rather than taking for the same.
public enum ItemGroupValue: Hashable, Sendable, Codable {
    case title(String)
    case scopes([ServiceScope])
    case tags(Set<String>)
    case archived(Bool)
    case trashedAt(Date?)
    case keptAfterDeletion(Bool)
    case excludedFromSuggestions(Bool)
    case fieldOrder([UUID])
    /// A field's contents, or `nil` where that version had removed the field.
    case field(Field?)
}

/// A value written concurrently with the one an item shows: kept, with who wrote it, until the person chooses
/// (PRD F7.6). Never discarded by sync.
public struct ConflictingValue: Hashable, Sendable, Codable {
    public var stamp: GroupStamp
    public var value: ItemGroupValue

    public init(stamp: GroupStamp, value: ItemGroupValue) {
        self.stamp = stamp
        self.value = value
    }
}

/// One line of an item's notes, in the line-level sequence CRDT that lets concurrent edits to different parts of the
/// notes all survive (PRD F7.6; an RGA over lines). A line is never edited in place: changing it removes it and inserts
/// the new text, so two devices changing the same line concurrently both keep their version.
///
/// `text` never contains a line break when an honest device wrote the line. Where two copies give one ID different
/// texts (only a writer reusing an ID does), the merge keeps both, one per line of `text`, rather than choose.
///
/// Two lines are equal when their texts are equal byte for byte (`ExactEquality.swift`).
public struct NoteLine: Hashable, Sendable, Codable {
    /// The edit that inserted the line, its place among the lines that edit inserted, and a number drawn at random
    /// for that edit.
    ///
    /// The revision and index are enough to tell honest lines apart. The nonce is there because both can be
    /// predicted: a device's next revision is one above the highest version it has seen, so without it another writer
    /// could publish *removed* lines under the IDs a device's next edit will use, and what the person then typed
    /// would merge with them and vanish (review finding Y21, docs/10-sync-correctness.md §6). With it, naming a line
    /// takes having seen it. It is zero for the lines of a new item and for lines read from notes written before
    /// lines were stored, which every device must number alike; those lines exist before anyone could aim at them.
    public struct ID: Hashable, Sendable, Codable, Comparable {
        public var revision: Revision
        public var index: UInt32
        public var nonce: UInt64

        public init(revision: Revision, index: UInt32, nonce: UInt64 = 0) {
            self.revision = revision
            self.index = index
            self.nonce = nonce
        }

        public static func < (lhs: ID, rhs: ID) -> Bool {
            if lhs.revision != rhs.revision { return lhs.revision < rhs.revision }
            if lhs.index != rhs.index { return lhs.index < rhs.index }
            return lhs.nonce < rhs.nonce
        }

        enum CodingKeys: String, CodingKey {
            case revision, index, nonce
        }

        /// Synthesised decoding, except that the nonce may be absent: lines written before it existed still open.
        public init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            revision = try container.decode(Revision.self, forKey: .revision)
            index = try container.decode(UInt32.self, forKey: .index)
            nonce = try container.decodeIfPresent(UInt64.self, forKey: .nonce) ?? 0
        }
    }

    public var id: ID
    /// The line this one was inserted after; `nil` for the start of the notes.
    public var after: ID?
    /// Empty once removed: the person removed it, so its text is not kept, only its place.
    public var text: String
    public var removed: Bool

    public init(id: ID, after: ID?, text: String, removed: Bool = false) {
        self.id = id
        self.after = after
        self.text = text
        self.removed = removed
    }
}

extension UUID {
    /// Byte-wise order, identical on every platform (unlike anything that goes through a locale).
    public func precedes(_ other: UUID) -> Bool {
        byteArray.lexicographicallyPrecedes(other.byteArray)
    }

    /// The sixteen bytes, in order.
    public var byteArray: [UInt8] {
        let u = uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }
}
