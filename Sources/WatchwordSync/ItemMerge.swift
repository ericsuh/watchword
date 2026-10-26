import Foundation
import WatchwordModel

/// Field-level merging of versions of one item (PRD F7.4, F7.6, docs/02-architecture.md §7.5).
///
/// Every item attribute and every field is a group (`ItemGroup`), and each group is a multi-value register: its
/// value carries a `GroupStamp` — who wrote it, and the `VersionVector` of everything that writer had seen. Merging
/// takes the union of both versions' values for the group and drops only those a later write was made *knowing
/// about*. So:
///
/// - two devices editing different fields, or different items, both keep their edit;
/// - an edit made after seeing another replaces it;
/// - two concurrent edits of the same group both stay: one is shown, chosen the same way on every device (a deletion
///   first, then the later revision), and the others are kept in `Item.conflicts` until the person resolves them by
///   editing the group (`stamped`) or choosing (`resolve`). Sync never discards a conflicting value.
///
/// Moving to the trash is the `trashedAt` group, so trashing and a concurrent edit of anything else resolve to a
/// trashed item that contains the edit; a concurrent restore and trash keep both, showing the trash. Neither is a
/// trash the 30-day purge may remove (`Item.isTrashedByPerson`). Notes merge line by line (`NoteText`).
///
/// The result is a join — independent of the order versions arrive in, how they are grouped and how often one is
/// applied — except for field order. The latest reorder wins and a concurrent one is not kept (order holds no field's
/// contents), and a field removed in an intermediate merge and revived later goes after the ordered ones; the
/// deterministic choice settles that one exchange later.
///
/// Pure and portable; the production caller opens both versions under the vault key first (milestone 3's Mac half).
public enum ItemMerge {
    static let zeroDevice = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    // MARK: - Saving

    /// `edited` as a new version written by `revision`: every group whose value differs from `previous` is stamped
    /// with what this device has seen (which supersedes, and so resolves, any conflict the group held — the person
    /// edited it where the conflict is shown); unchanged groups keep their stamps and conflicts; the notes are diffed
    /// line by line. A new item (`previous == nil`) has every group stamped. The caller's own sync metadata is
    /// ignored — the vault owns it, as it owns `version`.
    ///
    /// `previousOrigin` is the version and device of the row `previous` was read from; it stands in for the stamps
    /// of an item written before sync existed.
    public static func stamped(_ edited: Item, previous: Item?, previousOrigin: Revision? = nil, revision: Revision)
        -> Item
    {
        var item = edited
        guard let previous else {
            var clock = VersionVector()
            clock.record(revision)
            let stamp = GroupStamp(revision: revision, seen: clock)
            item.clock = clock
            item.revisions = Dictionary(uniqueKeysWithValues: groups(of: edited).map { ($0, stamp) })
            item.conflicts = [:]
            item.noteLines = NoteText.initial(edited.notes, revision: revision)
            item.notes = NoteText.text(item.noteLines)
            return item
        }
        let origin = previousOrigin ?? Revision(version: previous.version, device: zeroDevice)
        var clock = effectiveClock(previous, origin: origin)
        clock.record(revision)
        let stamp = GroupStamp(revision: revision, seen: clock)
        item.clock = clock

        var revisions: [ItemGroup: GroupStamp] = [:]
        var conflicts = previous.conflicts
        var retained = previous.retainedValues
        for group in groups(of: previous).union(groups(of: edited)).union(previous.revisions.keys) {
            if value(of: group, in: previous) != value(of: group, in: edited) {
                revisions[group] = stamp
                // The edit settles what is shown; the conflicting values it supersedes are kept, not discarded.
                retained += conflicts[group] ?? []
                conflicts[group] = nil
            } else if let existing = effectiveStamp(of: group, in: previous, origin: origin) {
                revisions[group] = existing
            }
        }
        item.revisions = revisions
        item.conflicts = conflicts
        item.retainedValues = canonicalSet(retained)
        item.noteLines = NoteText.edit(effectiveLines(previous, origin: origin), to: edited.notes, revision: revision)
        item.notes = NoteText.text(item.noteLines)
        // A new version must contain its predecessor in every merged value. Device clocks disagree, so `modifiedAt`
        // never moves backwards.
        item.modifiedAt = max(edited.modifiedAt, previous.modifiedAt)
        return item
    }

    /// Resolves a conflict by the person's explicit choice: `group` takes `value` (the one shown or one of the
    /// conflicting ones), written by `revision` — the result is that version, ready to seal — superseding every value
    /// the item holds for the group. The person chose, so the values not chosen are discarded (PRD F7.7), as are any
    /// earlier ones retained for the group.
    public static func resolve(
        _ item: Item, group: ItemGroup, choosing value: ItemGroupValue, origin: Revision, revision: Revision
    ) -> Item {
        var chosen = item
        apply(value, to: &chosen, group: group)
        var resolved = stamped(chosen, previous: item, previousOrigin: origin, revision: revision)
        resolved.revisions[group] = GroupStamp(revision: revision, seen: resolved.clock)
        resolved.conflicts[group] = nil
        resolved.retainedValues = item.retainedValues.filter { Self.group(of: $0.value) != group }
        return written(resolved, as: revision)
    }

    /// Every conflicting value a person should be shown, by group.
    public static func conflicts(of item: Item) -> [ItemGroup: [ConflictingValue]] {
        item.conflicts.filter { !$0.value.isEmpty }
    }

    // MARK: - Merging

    /// Merges two versions of the same item. `originA` and `originB` are the version and device of the rows each was
    /// read from. The result's `version` is the higher of the two; the writer assigns the real one.
    public static func merge(_ a: Item, origin originA: Revision, _ b: Item, origin originB: Revision) -> Item {
        precondition(a.id == b.id && a.vaultID == b.vaultID, "merging versions of different items")
        var merged = a
        merged.revisions = [:]
        merged.conflicts = [:]
        var mergedFields: [UUID: Field] = [:]
        var order: [UUID] = []

        var allGroups = groups(of: a).union(groups(of: b))
        for item in [a, b] {
            allGroups.formUnion(item.revisions.keys)
            allGroups.formUnion(item.conflicts.keys)
        }
        for group in allGroups.sorted() {
            let candidates =
                candidates(for: group, in: a, origin: originA) + candidates(for: group, in: b, origin: originB)
            let maximal = maximalValues(candidates)
            guard let shown = maximal.max(by: shownOrder) else { continue }
            merged.revisions[group] = shown.stamp
            let others = maximal.filter { $0 != shown }.sorted(by: canonicalOrder)
            // Field order is the one group whose concurrent values are not kept: it arranges fields, it holds none of
            // their contents, and a stored order lists only the fields present when it was stored.
            if !others.isEmpty, group != .fieldOrder { merged.conflicts[group] = others }
            switch shown.value {
            case .field(let field?): mergedFields[field.id] = field
            case .field(nil): break
            case .fieldOrder(let ids): order = ids
            default: apply(shown.value, to: &merged, group: group)
            }
        }

        // Fields in the shown order first, then any it does not mention (added on the other side), by ID.
        var fields = order.compactMap { mergedFields.removeValue(forKey: $0) }
        fields += mergedFields.values.sorted { $0.id.precedes($1.id) }
        merged.fields = fields
        merged.noteLines = NoteText.merge(effectiveLines(a, origin: originA), effectiveLines(b, origin: originB))
        merged.notes = NoteText.text(merged.noteLines)
        merged.clock = effectiveClock(a, origin: originA).merging(effectiveClock(b, origin: originB))
        merged.createdAt = min(a.createdAt, b.createdAt)
        merged.modifiedAt = max(a.modifiedAt, b.modifiedAt)
        merged.version = max(a.version, b.version)
        // Both histories, whole: merging never shortens a history (PRD F1.4, F7.7).
        merged.history = Array(Set(a.history + b.history)).sorted(by: historyOrder)
        merged.retainedValues = canonicalSet(a.retainedValues + b.retainedValues)
        return merged
    }

    /// `item` as the version `revision` writes, for a merge result a device stores. Only the version changes: the
    /// clock records edits, not the versions that carry them, so devices that merged the same edits hold the same
    /// state whichever of them wrote it down — and do not keep exchanging versions that differ in nothing else.
    public static func written(_ item: Item, as revision: Revision) -> Item {
        var item = item
        item.version = revision.version
        return item
    }

    /// Values without duplicates, in a fixed order.
    static func canonicalSet(_ values: [ConflictingValue]) -> [ConflictingValue] {
        Array(Set(values)).sorted(by: canonicalOrder)
    }

    /// The group a value belongs to; `nil` for a removed field, which names none.
    static func group(of value: ItemGroupValue) -> ItemGroup? {
        switch value {
        case .title: return .title
        case .scopes: return .scopes
        case .tags: return .tags
        case .archived: return .archived
        case .trashedAt: return .trashedAt
        case .keptAfterDeletion: return .keptAfterDeletion
        case .excludedFromSuggestions: return .excludedFromSuggestions
        case .fieldOrder: return .fieldOrder
        case .field(let field): return field.map { .field($0.id) }
        }
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

    /// Whether everything in `item` was known to the device that erased it, whose version vector for the item was then
    /// `erased`. An erasure removes only what its author had seen (PRD F7.6).
    public static func isCovered(_ item: Item, origin: Revision, byErasure erased: VersionVector) -> Bool {
        effectiveClock(item, origin: origin).isCovered(by: erased)
    }

    /// The edits the item contains. An item from before sync has no clock; the row it was read from stands in.
    public static func effectiveClock(_ item: Item, origin: Revision) -> VersionVector {
        guard item.clock.isEmpty else { return item.clock }
        var clock = VersionVector()
        clock.record(origin)
        return clock
    }

    // MARK: - Groups

    /// The stamp of a group; for an item from before sync, the record's own origin.
    static func effectiveStamp(of group: ItemGroup, in item: Item, origin: Revision) -> GroupStamp? {
        if let stamp = item.revisions[group] { return stamp }
        guard holds(group, item) else { return nil }
        return GroupStamp(revision: origin, seen: VersionVector([origin.device: origin.version]))
    }

    static func effectiveLines(_ item: Item, origin: Revision) -> [NoteLine] {
        item.noteLines.isEmpty ? NoteText.initial(item.notes, revision: origin) : item.noteLines
    }

    /// Whether the item itself has a value for the group: always for attributes, for a field while it is present.
    static func holds(_ group: ItemGroup, _ item: Item) -> Bool {
        if let id = group.fieldID { return item.fields.contains { $0.id == id } }
        return ItemGroup.attributes.contains(group)
    }

    static func candidates(for group: ItemGroup, in item: Item, origin: Revision) -> [ConflictingValue] {
        var result = item.conflicts[group] ?? []
        if let stamp = effectiveStamp(of: group, in: item, origin: origin), let value = value(of: group, in: item) {
            result.append(ConflictingValue(stamp: stamp, value: value))
        }
        return result
    }

    /// The values no other value supersedes. Concurrent writes of the *same* value are one value, not a conflict:
    /// the latest stamp is kept, and nothing anyone typed is lost.
    static func maximalValues(_ candidates: [ConflictingValue]) -> [ConflictingValue] {
        let unique = Array(Set(candidates))
        let maximal = unique.filter { candidate in !unique.contains { $0.stamp.supersedes(candidate.stamp) } }
        var byValue: [ItemGroupValue: ConflictingValue] = [:]
        for candidate in maximal {
            if let existing = byValue[candidate.value], !canonicalOrder(existing, candidate) { continue }
            byValue[candidate.value] = candidate
        }
        return Array(byValue.values)
    }

    /// Which of several concurrent values is shown: a deletion (a removed field, a trashed item) first, so a deletion
    /// and a concurrent edit resolve to the deletion with the edit kept; then the later revision; then a fixed order.
    static func shownOrder(_ x: ConflictingValue, _ y: ConflictingValue) -> Bool {
        let (deletionX, deletionY) = (isDeletion(x.value), isDeletion(y.value))
        if deletionX != deletionY { return deletionY }
        return canonicalOrder(x, y)
    }

    static func canonicalOrder(_ x: ConflictingValue, _ y: ConflictingValue) -> Bool {
        if x.stamp.revision != y.stamp.revision { return x.stamp.revision < y.stamp.revision }
        return canonicalBytes(x.value).lexicographicallyPrecedes(canonicalBytes(y.value))
    }

    static func isDeletion(_ value: ItemGroupValue) -> Bool {
        switch value {
        case .field(nil): return true
        case .trashedAt(let date): return date != nil
        default: return false
        }
    }

    static func groups(of item: Item) -> Set<ItemGroup> {
        Set(ItemGroup.attributes).union(item.fields.map { ItemGroup.field($0.id) })
    }

    /// The group's value in `item`; `nil` for a group this client does not know.
    static func value(of group: ItemGroup, in item: Item) -> ItemGroupValue? {
        if let id = group.fieldID { return .field(item.fields.first { $0.id == id }) }
        switch group {
        case .title: return .title(item.title)
        case .scopes: return .scopes(item.scopes)
        case .tags: return .tags(item.tags)
        case .archived: return .archived(item.archived)
        case .trashedAt: return .trashedAt(item.trashedAt)
        case .keptAfterDeletion: return .keptAfterDeletion(item.keptAfterDeletion)
        case .excludedFromSuggestions: return .excludedFromSuggestions(item.excludedFromSuggestions)
        case .fieldOrder: return .fieldOrder(item.fields.map(\.id))
        default: return nil
        }
    }

    static func apply(_ value: ItemGroupValue, to item: inout Item, group: ItemGroup) {
        switch value {
        case .title(let title): item.title = title
        case .scopes(let scopes): item.scopes = scopes
        case .tags(let tags): item.tags = tags
        case .archived(let archived): item.archived = archived
        case .trashedAt(let date): item.trashedAt = date
        case .keptAfterDeletion(let kept): item.keptAfterDeletion = kept
        case .excludedFromSuggestions(let excluded): item.excludedFromSuggestions = excluded
        case .fieldOrder(let ids):
            let byID = Dictionary(item.fields.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
            item.fields = ids.compactMap { byID[$0] } + item.fields.filter { !ids.contains($0.id) }
        case .field(let field):
            guard let id = group.fieldID else { return }
            if let field, let index = item.fields.firstIndex(where: { $0.id == id }) {
                item.fields[index] = field
            } else if let field {
                item.fields.append(field)
            } else {
                item.fields.removeAll { $0.id == id }
            }
        }
    }

    /// A deterministic encoding, for ordering identically on every device. Sets are sorted and dictionaries encoded
    /// with sorted keys, so it never depends on hashing order.
    static func canonicalBytes(_ value: ItemGroupValue) -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .secondsSince1970
        let text: String
        switch value {
        case .title(let value): text = "title:" + value
        case .scopes(let scopes):
            text =
                "scopes:"
                + scopes.map { "\($0.host)|\($0.includeSubdomains)|\($0.excludedHosts.sorted())" }.joined(
                    separator: "\n")
        case .tags(let tags): text = "tags:" + tags.sorted().joined(separator: "\n")
        case .archived(let value): text = "archived:\(value)"
        case .excludedFromSuggestions(let value): text = "excluded:\(value)"
        case .trashedAt(let date): text = "trashed:" + (date.map { String($0.timeIntervalSince1970) } ?? "-")
        case .keptAfterDeletion(let value): text = "kept:\(value)"
        case .fieldOrder(let ids): text = "order:" + ids.map(\.uuidString).joined(separator: ",")
        case .field(let field):
            let encoded = field.flatMap { (try? encoder.encode($0)).flatMap { String(data: $0, encoding: .utf8) } }
            text = "field:" + (encoded ?? "-")
        }
        return Array(text.utf8)
    }

    // MARK: - History

    static func historyOrder(_ x: ItemHistoryEntry, _ y: ItemHistoryEntry) -> Bool {
        if x.replacedAt != y.replacedAt { return x.replacedAt > y.replacedAt }
        if x.version != y.version { return x.version > y.version }
        let bytesX = x.fields.flatMap { canonicalBytes(.field($0)) }
        let bytesY = y.fields.flatMap { canonicalBytes(.field($0)) }
        return bytesY.lexicographicallyPrecedes(bytesX)
    }
}
