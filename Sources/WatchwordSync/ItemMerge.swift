import Foundation
import WatchwordModel

/// Field-level merging of two versions of one item (PRD F7.4, docs/02-architecture.md §7.1).
///
/// Every item attribute and every field is a group (`ItemGroup`) carrying the `Revision` that last changed it. The
/// merge takes, group by group, the value with the later revision, so two devices that edited different fields both
/// keep their edit, and two that edited the same field agree on one winner — the later version, then the higher device
/// ID. The losing values are kept in the item's history.
///
/// Current values merge as a join: the result does not depend on the order versions arrive in, on how often one is
/// applied, or — except for one corner of field order — on how they are grouped, which is what lets devices that see
/// the same versions in any order converge. Revisions are kept in the merged item, so a later merge compares the same
/// revisions an earlier one did.
///
/// The corner: `Item.fields` records the order of present fields only, so a field removed in an intermediate merge and
/// revived by a later edit is placed after the ordered ones rather than at its old position. Two devices can then hold
/// the same fields in different orders under the same `fieldOrder` revision; the equal-revision tie-break picks one
/// order for both on their next exchange. The history is a bounded union and is not order-independent in every corner
/// either, but every losing value reaches it.
///
/// Pure and portable; the production caller opens both versions under the vault key first (milestone 3's Mac half).
public enum ItemMerge {
    /// The revision of a group nobody has stamped: older than every real one.
    public static let unstamped = Revision(
        version: 0, device: UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)))

    // MARK: - Stamping on save

    /// `edited` with its revisions brought up to date: every group whose value differs from `previous` is stamped with
    /// `revision`; the others keep `previous`'s revision. A new item (`previous == nil`) has every group stamped. The
    /// caller's own `revisions` are ignored — the vault owns them, as it owns `version`.
    ///
    /// `previousOrigin` is the version and device of the row `previous` was read from; it stands in for the
    /// revisions of an item written before revisions existed.
    public static func stamped(_ edited: Item, previous: Item?, previousOrigin: Revision? = nil, revision: Revision)
        -> Item
    {
        var item = edited
        guard let previous else {
            item.revisions = [:]
            for group in groups(of: edited) {
                item.revisions[group] = revision
            }
            return item
        }
        let fallback = previousOrigin ?? Revision(version: previous.version, device: unstamped.device)
        var revisions = previous.revisions
        for group in groups(of: previous).union(groups(of: edited)) {
            if value(of: group, in: previous) != value(of: group, in: edited) {
                revisions[group] = revision
            } else if previous.revisions.isEmpty {
                revisions[group] = fallback
            }
        }
        item.revisions = revisions
        // A new version must contain its predecessor in every merged value, or a device holding the predecessor's
        // merge would see nothing new in it. Device clocks disagree, so `modifiedAt` never moves backwards.
        item.modifiedAt = max(edited.modifiedAt, previous.modifiedAt)
        return item
    }

    // MARK: - Merging

    /// Merges two versions of the same item. `originA` and `originB` are the version and device of the rows each was
    /// read from. The result's `version` is the higher of the two; the writer assigns the real one.
    ///
    /// - Parameter historyLimit: at most this many history entries are kept, newest first
    ///   (`VaultConfiguration.maximumHistoryEntries`). Pruning by age (PRD F1.4) is left to the device that saves:
    ///   measured against anything in the versions themselves, one device's wrong clock would empty everyone's history.
    public static func merge(
        _ a: Item, origin originA: Revision, _ b: Item, origin originB: Revision, historyLimit: Int = 100
    ) -> Item {
        precondition(a.id == b.id && a.vaultID == b.vaultID, "merging versions of different items")
        var merged = a
        merged.revisions = [:]
        var mergedFields: [UUID: Field] = [:]
        var order: [UUID] = []

        let allGroups = groups(of: a).union(groups(of: b)).union(a.revisions.keys).union(b.revisions.keys)
        for group in allGroups.sorted() {
            let revisionA = effectiveRevision(of: group, in: a, origin: originA)
            let revisionB = effectiveRevision(of: group, in: b, origin: originB)
            let valueA = value(of: group, in: a)
            let valueB = value(of: group, in: b)
            let takeB: Bool
            if revisionA != revisionB {
                takeB = revisionA < revisionB
            } else {
                // Only a device that wrote two different values under one revision (a restored backup reusing a device
                // ID, or a misbehaving member) gets here. Any deterministic choice keeps devices converging.
                takeB = valueA.canonicalBytes.lexicographicallyPrecedes(valueB.canonicalBytes)
            }
            let (revision, value) = takeB ? (revisionB, valueB) : (revisionA, valueA)
            merged.revisions[group] = revision
            switch value {
            case .field(let field?): mergedFields[field.id] = field
            case .fieldOrder(let ids): order = ids
            default: apply(value, to: &merged)
            }
        }

        // Fields in the winning order first, then any it does not mention (added on the losing side), by ID.
        var fields = order.compactMap { mergedFields.removeValue(forKey: $0) }
        fields += mergedFields.values.sorted { $0.id.precedes($1.id) }
        merged.fields = fields
        merged.createdAt = min(a.createdAt, b.createdAt)
        merged.modifiedAt = max(a.modifiedAt, b.modifiedAt)
        merged.version = max(a.version, b.version)
        merged.history = mergedHistory(a, b, mergedFields: merged.fields, limit: historyLimit)
        return merged
    }

    /// Whether two versions hold the same state: everything but `version`, with histories compared as sets.
    public static func sameState(_ a: Item, _ b: Item) -> Bool {
        var a = a
        var b = b
        a.version = 0
        b.version = 0
        guard Set(a.history) == Set(b.history) else { return false }
        a.history = []
        b.history = []
        return a == b
    }

    // MARK: - Groups

    static func effectiveRevision(of group: ItemGroup, in item: Item, origin: Revision) -> Revision {
        // An item from before revisions existed: every group changed with the record itself (record-level
        // last-writer-wins). Otherwise a group nobody stamped is older than anything.
        item.revisions.isEmpty ? origin : item.revisions[group] ?? unstamped
    }

    static func groups(of item: Item) -> Set<ItemGroup> {
        Set(ItemGroup.attributes).union(item.fields.map { ItemGroup.field($0.id) })
    }

    enum GroupValue: Equatable {
        case title(String)
        case scopes([ServiceScope])
        case tags(Set<String>)
        case notes(String)
        case archived(Bool)
        case trashedAt(Date?)
        case excludedFromSuggestions(Bool)
        case fieldOrder([UUID])
        case field(Field?)
        /// A group this client does not know (written by a newer one): only its revision is merged.
        case unknown

        /// A deterministic encoding, for breaking ties identically on every device. Sets are sorted and dictionaries
        /// encoded with sorted keys, so it never depends on hashing order.
        var canonicalBytes: [UInt8] {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            encoder.dateEncodingStrategy = .secondsSince1970
            let text: String
            switch self {
            case .title(let value), .notes(let value): text = value
            case .scopes(let scopes):
                text = scopes.map { "\($0.host)|\($0.includeSubdomains)|\($0.excludedHosts.sorted())" }.joined(
                    separator: "\n")
            case .tags(let tags): text = tags.sorted().joined(separator: "\n")
            case .archived(let value), .excludedFromSuggestions(let value): text = String(value)
            case .trashedAt(let date): text = date.map { String($0.timeIntervalSince1970) } ?? "-"
            case .fieldOrder(let ids): text = ids.map(\.uuidString).joined(separator: ",")
            case .field(let field):
                text = field.flatMap { (try? encoder.encode($0)).flatMap { String(data: $0, encoding: .utf8) } } ?? "-"
            case .unknown: text = ""
            }
            return Array(text.utf8)
        }
    }

    static func value(of group: ItemGroup, in item: Item) -> GroupValue {
        if let id = group.fieldID { return .field(item.fields.first { $0.id == id }) }
        switch group {
        case .title: return .title(item.title)
        case .scopes: return .scopes(item.scopes)
        case .tags: return .tags(item.tags)
        case .notes: return .notes(item.notes)
        case .archived: return .archived(item.archived)
        case .trashedAt: return .trashedAt(item.trashedAt)
        case .excludedFromSuggestions: return .excludedFromSuggestions(item.excludedFromSuggestions)
        case .fieldOrder: return .fieldOrder(item.fields.map(\.id))
        default: return .unknown
        }
    }

    static func apply(_ value: GroupValue, to item: inout Item) {
        switch value {
        case .title(let title): item.title = title
        case .scopes(let scopes): item.scopes = scopes
        case .tags(let tags): item.tags = tags
        case .notes(let notes): item.notes = notes
        case .archived(let archived): item.archived = archived
        case .trashedAt(let date): item.trashedAt = date
        case .excludedFromSuggestions(let excluded): item.excludedFromSuggestions = excluded
        case .fieldOrder, .field, .unknown: break
        }
    }

    // MARK: - History

    /// Both histories, plus the fields of whichever version lost (F7.4), deduplicated, newest first and capped: a
    /// bounded union, so the same entries survive whichever device merges.
    static func mergedHistory(_ a: Item, _ b: Item, mergedFields: [Field], limit: Int) -> [ItemHistoryEntry] {
        var entries = a.history + b.history
        for version in [a, b] where !sameFields(version.fields, mergedFields) {
            entries.append(
                ItemHistoryEntry(replacedAt: version.modifiedAt, version: version.version, fields: version.fields))
        }
        // One entry per (version, fields); the latest replacement time wins.
        struct Key: Hashable {
            let version: UInt64
            let fields: [Field]
        }
        var unique: [Key: ItemHistoryEntry] = [:]
        for entry in entries {
            let key = Key(version: entry.version, fields: entry.fields)
            if let existing = unique[key], existing.replacedAt >= entry.replacedAt { continue }
            unique[key] = entry
        }
        return Array(unique.values.sorted(by: historyOrder).prefix(limit))
    }

    static func historyOrder(_ x: ItemHistoryEntry, _ y: ItemHistoryEntry) -> Bool {
        if x.replacedAt != y.replacedAt { return x.replacedAt > y.replacedAt }
        if x.version != y.version { return x.version > y.version }
        let bytesX =
            GroupValue.fieldOrder(x.fields.map(\.id)).canonicalBytes
            + x.fields.flatMap { GroupValue.field($0).canonicalBytes }
        let bytesY =
            GroupValue.fieldOrder(y.fields.map(\.id)).canonicalBytes
            + y.fields.flatMap { GroupValue.field($0).canonicalBytes }
        return bytesY.lexicographicallyPrecedes(bytesX)
    }

    /// Equal contents regardless of order: a reordering alone is not a lost value.
    static func sameFields(_ x: [Field], _ y: [Field]) -> Bool {
        x.count == y.count && Set(x) == Set(y)
    }
}
