import Foundation
import WatchwordModel

/// Field-level merging of versions of one item (PRD F7.4, F7.6, docs/02-architecture.md §7.5). The model, and the
/// argument that it converges, are in docs/10-sync-correctness.md; `ItemState` is the state it describes.
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
/// trash the 30-day purge may remove (`Item.isTrashedByPerson`). Notes merge line by line (`NoteText`). The order of
/// the fields is a last-writer-wins register of its own (`Item.fieldOrder`): it holds no field's contents, so the
/// later arrangement stands and a concurrent one is not kept.
///
/// The merge is a join: commutative, associative and idempotent, so the result is independent of the order versions
/// arrive in, how they are grouped and how often one is applied. Every update (`stamped`, `resolve`, and a deletion
/// applied by `settle` to a version it does not cover) gives a state that contains the one it was made on. Both hold for any two items, not only for
/// ones honest devices wrote, because every item is read through `ItemState.init`, which bounds what crafted metadata
/// can claim (docs/10-sync-correctness.md §6).
///
/// Pure and portable; the production caller opens both versions under the vault key first (`ItemRecordMerger`).
public enum ItemMerge {
    static let zeroDevice = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    /// The stamp of a value nothing records the writing of: superseded by every write that has seen anything.
    static let zeroStamp = GroupStamp(revision: Revision(version: 0, device: zeroDevice), seen: VersionVector())

    /// The highest version an erasure may name (the engine's `SyncConfiguration.maximumVersion`). One naming a higher
    /// version is not an honest device's, and is read as having seen nothing.
    public static let maximumCounter: UInt64 = 1 << 62

    // MARK: - Saving

    /// `edited` as a new version written by `revision`: every group whose value differs from `previous` is stamped
    /// with what this device has seen (which supersedes, and so resolves, any conflict the group held — the person
    /// edited it where the conflict is shown); unchanged groups keep their stamps and conflicts; the notes are diffed
    /// line by line; the field order is restamped only if the fields are arranged differently. A new item
    /// (`previous == nil`) has every group stamped. The caller's own sync metadata is ignored — the vault owns it, as
    /// it owns `version`.
    ///
    /// The result contains `previous`: merging the two gives the result again. For that, `revision` must be new to
    /// the item — above the version of the row `previous` was read from, as every version the vault assigns is — and
    /// the history and dates only ever grow (the history is the union of both, `createdAt` the earlier, `modifiedAt`
    /// the later; device clocks disagree, so `modifiedAt` never moves backwards).
    ///
    /// `previousOrigin` is the version and device of the row `previous` was read from; it stands in for the stamps
    /// of an item written before sync existed, and bounds every count `previous` holds.
    public static func stamped(_ edited: Item, previous: Item?, previousOrigin: Revision? = nil, revision: Revision)
        -> Item
    {
        guard let previous else {
            // Read as an item without sync metadata written by `revision`: every group and line is stamped with it.
            var fresh = edited
            fresh.revisions = [:]
            fresh.conflicts = [:]
            fresh.retainedValues = []
            fresh.clock = VersionVector()
            fresh.noteLines = []
            fresh.fieldOrder = nil
            fresh.discards = [:]
            return ItemState(fresh, origin: revision).item
        }
        let origin = previousOrigin ?? Revision(version: previous.version, device: zeroDevice)
        var state = ItemState(previous, origin: origin)
        var clock = state.clock
        clock.record(revision)
        let stamp = GroupStamp(revision: revision, seen: clock)

        var desired: [ItemGroup: ItemGroupValue] = [:]
        for group in ItemGroup.attributes where group != .fieldOrder { desired[group] = edited.value(of: group) }
        var fieldIDs: [UUID] = []
        for field in edited.fields where desired[.field(field.id)] == nil {
            desired[.field(field.id)] = .field(field)
            fieldIDs.append(field.id)
        }
        for group in Set(state.registers.keys).union(desired.keys) {
            // A field group the edit does not hold is a removed field.
            let new = desired[group] ?? .field(nil)
            let old = state.shown(group)?.value
            guard old != new else { continue }
            // The edit settles what is shown; the conflicting values it supersedes are kept, not discarded. Those
            // equal to the value shown were replaced with it, knowingly.
            for value in state.registers[group] ?? [] where value.value != old { state.retain(value) }
            state.registers[group] = [ConflictingValue(stamp: stamp, value: new)]
        }
        // Adding or removing a field is not a reorder: the stored order stands unless the fields no longer follow it.
        if ItemState.arranged(Set(fieldIDs), order: state.order.ids) != fieldIDs {
            state.order = ItemState.FieldOrder(stamp: stamp, ids: fieldIDs)
        }
        state.lines = NoteText.edit(state.lines, to: edited.notes, revision: revision)
        state.history.formUnion(edited.history)
        state.clock = clock
        state.base = edited
        state.base.createdAt = min(edited.createdAt, previous.createdAt)
        state.base.modifiedAt = max(edited.modifiedAt, previous.modifiedAt)
        return state.item
    }

    /// Resolves a conflict by the person's explicit choice: `group` takes `value` (the one shown or one of the
    /// conflicting ones), written by `revision` — the result is that version, ready to seal — superseding every value
    /// the item holds for the group. The person chose, so the values not chosen are discarded (PRD F7.7), as are any
    /// earlier ones retained for the group; `Item.discards` records what the person had before them, so the discard
    /// holds when a copy that still has those values is merged in.
    ///
    /// A `value` that does not belong to `group` changes nothing but the version.
    public static func resolve(
        _ item: Item, group: ItemGroup, choosing value: ItemGroupValue, origin: Revision, revision: Revision
    ) -> Item {
        var state = ItemState(item, origin: origin)
        guard group != .fieldOrder, belongs(value, to: group) else { return written(state.item, as: revision) }
        let seen = state.clock
        var clock = seen
        clock.record(revision)
        state.registers[group] = [ConflictingValue(stamp: GroupStamp(revision: revision, seen: clock), value: value)]
        // What the person had before them: everything the item held when they chose, not the choice itself, which a
        // later edit may yet retain.
        if !seen.isEmpty { state.discards[group] = (state.discards[group] ?? VersionVector()).merging(seen) }
        state.retained = state.retained.filter { Self.group(of: $0.value) != group }
        state.clock = clock
        return written(state.item, as: revision)
    }

    /// Every conflict a person should be shown, by group: the values written concurrently with the one shown and
    /// different from it, each once. Concurrent writes of the *same* value are all kept in `Item.conflicts` (dropping
    /// one would make the merge depend on the order versions arrive in) but are not a conflict to resolve.
    public static func conflicts(of item: Item) -> [ItemGroup: [ConflictingValue]] {
        var result: [ItemGroup: [ConflictingValue]] = [:]
        for (group, values) in item.conflicts where group.isKnown && group != .fieldOrder {
            guard let shown = item.value(of: group) else { continue }
            var distinct: [ItemGroupValue: ConflictingValue] = [:]
            // In order, so the stamp kept for a value written more than once is the latest.
            for value in sortedCanonically(values) where value.value != shown { distinct[value.value] = value }
            if !distinct.isEmpty { result[group] = sortedCanonically(distinct.values) }
        }
        return result
    }

    /// The value `item` shows for `group`, for showing beside its conflicting values; `nil` for a group this client
    /// does not know.
    public static func currentValue(of group: ItemGroup, in item: Item) -> ItemGroupValue? {
        item.value(of: group)
    }

    // MARK: - Merging

    /// Merges two versions of the same item: the join of their states. `originA` and `originB` are the version and
    /// device of the rows each was read from. The result's `version` is the higher of the two; the writer assigns the
    /// real one.
    ///
    /// Traps on versions of different items: a caller checks identity first, as `ItemRecordMerger` does.
    public static func merge(_ a: Item, origin originA: Revision, _ b: Item, origin originB: Revision) -> Item {
        precondition(a.id == b.id && a.vaultID == b.vaultID, "merging versions of different items")
        return ItemState(a, origin: originA).joined(ItemState(b, origin: originB)).item
    }

    /// `item` as the merge reads it from a row written as `origin`, in the one form the merge writes: what `merge`
    /// with itself gives. The identity on anything `stamped`, `resolve` or `merge` produced. On anything else it is
    /// the reading every device makes of it (docs/10-sync-correctness.md §6): no count above the row's version,
    /// no value under a group it does not belong to, one field and one note line per ID, `fields` and `notes` as the
    /// metadata arranges them.
    public static func canonical(_ item: Item, origin: Revision) -> Item {
        ItemState(item, origin: origin).item
    }

    /// `item` as the version `revision` writes, for a merge result a device stores. Only the version changes: the
    /// clock records edits, not the versions that carry them, so devices that merged the same edits hold the same
    /// state whichever of them wrote it down — and do not keep exchanging versions that differ in nothing else.
    public static func written(_ item: Item, as revision: Revision) -> Item {
        var item = item
        item.version = revision.version
        return item
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

    // MARK: - Permanent deletion

    /// Whether everything in `item` was known to the device that erased it, whose version vector for the item was then
    /// `erased`. An erasure removes only what its author had seen (PRD F7.6).
    public static func isCovered(_ item: Item, origin: Revision, byErasure erased: VersionVector) -> Bool {
        effectiveClock(item, origin: origin).isCovered(by: erased)
    }

    /// The edits the item contains. An item from before sync has no clock; the row it was read from stands in.
    public static func effectiveClock(_ item: Item, origin: Revision) -> VersionVector {
        ItemState(item, origin: origin).clock
    }

    /// What a permanent deletion does to a version of the item it erased.
    public enum Settlement: Hashable, Sendable {
        /// The deletion's author had seen everything in this version: it is erased.
        case erase
        /// This version has already met the deletion (it descends from one kept after it): it stands as it is.
        case keep
        /// This version holds an edit the deletion's author never saw. It is kept, in the trash, as this item — which
        /// the caller stores as a new version above both the row and the tombstone (`written`).
        case kept(Item)
    }

    /// Settles a version of an item against a permanent deletion of it (PRD F7.6, docs/10-sync-correctness.md §5).
    ///
    /// A version the deletion covers is erased. For any other, the deletion is a write by the deleting device, at the
    /// tombstone's revision, having seen what the erasure had seen: it moves the item to the trash and marks it
    /// `keptAfterDeletion`, so the 30-day purge leaves it. That write is the same on every device — it is a function
    /// of the erasure alone — so applying a deletion to an item is a join with a constant: it commutes with merging,
    /// applying it twice changes nothing, and devices that kept the same edits hold the same item. A trash or restore
    /// the deletion had not seen stays as a conflict beside it, the deletion shown; a restore made *after* it (on a
    /// copy that had met it) supersedes it like any later write, and is never undone by meeting the tombstone again.
    public static func settle(_ item: Item, origin: Revision, against erasure: ItemErasure) -> Settlement {
        var state = ItemState(item, origin: origin)
        if state.clock.isCovered(by: erasure.seen) { return .erase }
        let revision = erasure.revision
        if state.clock.contains(revision) { return .keep }
        var seen = erasure.seen
        seen.record(revision)
        let stamp = GroupStamp(revision: revision, seen: seen)
        let writes: [ItemGroupValue] = [.trashedAt(erasure.date ?? ItemErasure.undatedTrash), .keptAfterDeletion(true)]
        for value in writes {
            guard let group = group(of: value) else { continue }
            state.registers[group] = ItemState.maximal(
                Set(state.registers[group] ?? []).union([ConflictingValue(stamp: stamp, value: value)]))
        }
        state.clock.formUnion(seen)
        return .kept(state.item)
    }

    // MARK: - Groups

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

    /// Whether `value` is one `group` can hold. A value filed under another group (a title among a field's
    /// conflicts, one field's contents under another's ID) is never read: applying it would overwrite a value its
    /// stamp says nothing about.
    static func belongs(_ value: ItemGroupValue, to group: ItemGroup) -> Bool {
        if case .field(nil) = value { return group.fieldID != nil && group.isKnown }
        return Self.group(of: value) == group
    }

    /// The values a deletion writes: a removed field, a trashed item, and the mark of a version kept after a
    /// permanent deletion — so that the two things such a deletion writes are shown together.
    static func isDeletion(_ value: ItemGroupValue) -> Bool {
        switch value {
        case .field(nil): return true
        case .trashedAt(let date): return date != nil
        case .keptAfterDeletion(let kept): return kept
        default: return false
        }
    }

    /// Values in a fixed total order: by revision, then by the canonical encoding of the value and of what its writer
    /// had seen. Between honest writes the revision decides; the rest makes the order total on anything.
    static func sortedCanonically(_ values: some Collection<ConflictingValue>) -> [ConflictingValue] {
        guard values.count > 1 else { return Array(values) }
        // Two values of one revision are rare (one write gives one value), so the encoding is made only then.
        func bytes(_ value: ConflictingValue) -> [UInt8] {
            var writer = CanonicalWriter()
            writer.append(value.value)
            writer.append(value.stamp.seen)
            return writer.bytes
        }
        return values.sorted { x, y in
            if x.stamp.revision != y.stamp.revision { return x.stamp.revision < y.stamp.revision }
            return bytes(x).lexicographicallyPrecedes(bytes(y))
        }
    }
}

/// What a permanent deletion says about the item it erased (docs/02-architecture.md §7.5, PRD F7.6): the erasure
/// summary a tombstone carries, opaque to the engine.
///
/// It arrives from another device, so `init(summary:)` reads it as hostile input: a summary that does not decode, or
/// that names a version no honest device could have reached (`ItemMerge.maximumCounter`), or whose vector claims
/// more than the row it erased could hold, is `void` — it claims to have seen nothing, so nothing is erased because
/// of it — and no arithmetic is done on a number chosen to overflow it.
public struct ItemErasure: Hashable, Sendable, Codable {
    /// The eraser's version vector for the item: an erasure removes only versions this covers.
    public var seen: VersionVector
    /// The version of the row erased. The tombstone is one above it, and a version kept after the deletion is written
    /// above that. It can be far above every count in `seen` (a merge result is written above both versions it merged
    /// and records no edit), which is why it is carried rather than derived.
    public var row: UInt64
    /// The device that erased the item.
    public var device: UUID
    /// When the erased version was last modified: the time a version kept after the deletion is trashed at, the same
    /// on every device that keeps one.
    public var date: Date?

    public init(seen: VersionVector, row: UInt64, device: UUID, date: Date?) {
        self.seen = seen
        self.row = row
        self.device = device
        self.date = date
    }

    /// The deletion as a write of the item: the tombstone's stamp, one above the row erased.
    public var revision: Revision {
        Revision(version: row < UInt64.max ? row + 1 : row, device: device)
    }

    /// An erasure that claims to have seen nothing.
    public static let void = ItemErasure(seen: VersionVector(), row: 0, device: voidDevice, date: nil)

    /// Reads a tombstone's erasure summary. `tombstone`, when the caller knows it, is the version of the tombstone
    /// that carried the summary; a summary that does not name the row just below it is `void`.
    public init(summary: [UInt8], tombstone: UInt64? = nil) {
        let data = Data(summary)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        if let erasure = try? decoder.decode(ItemErasure.self, from: data) {
            self = erasure
        } else if let seen = try? decoder.decode(VersionVector.self, from: data) {
            // The first form: the vector alone. The row erased was at or above every count in it.
            self.init(seen: seen, row: seen.entries.values.max() ?? 0, device: Self.voidDevice, date: nil)
        } else {
            self = .void
        }
        let plausible =
            row <= ItemMerge.maximumCounter && seen.entries.values.allSatisfy { $0 <= row }
            && (tombstone.map { $0 > 0 && $0 - 1 == row } ?? true)
        if !plausible { self = .void }
    }

    /// The erasure summary: JSON with sorted keys.
    public func summary() throws -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .secondsSince1970
        return Array(try encoder.encode(self))
    }

    /// Stands in for the device of an erasure that names none.
    static let voidDevice = UUID(
        uuid: (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
    /// When a version kept after an erasure that names no time is trashed: one fixed time, so that every device
    /// writes the same value. Such an item is never purged (`keptAfterDeletion`), whatever this says.
    static let undatedTrash = Date(timeIntervalSince1970: 0)
}

extension ConflictingValue {
    /// The value with no count in its stamp above `limit`, the version of the record it was read from.
    func clamped(to limit: UInt64) -> ConflictingValue {
        ConflictingValue(stamp: stamp.clamped(to: limit), value: value)
    }
}
