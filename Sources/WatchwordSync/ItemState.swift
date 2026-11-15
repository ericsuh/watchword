import Foundation
import WatchwordModel

/// The replicated state of one item, as the merge sees it (docs/10-sync-correctness.md §2): a product of
/// join-semilattices, one per component, so that `joined` is commutative, associative and idempotent and devices that
/// have received the same versions hold the same item, whatever order they arrived in.
///
/// | Component | Lattice | Join |
/// | --- | --- | --- |
/// | `registers` | per group, an antichain of stamped values under `GroupStamp.supersedes` | union, then the maximal ones |
/// | `order` | a chain: the latest reorder | the later of the two |
/// | `clock` | version vectors | entry-wise maximum |
/// | `lines` | per line ID, `NoteText.join` | union, joined line by line |
/// | `history` | sets of entries | union |
/// | `retained`, `discards` | a set that grows, less what a growing vector covers | union less the covered; maximum |
/// | `createdAt`, `modifiedAt` | chains | earliest; latest |
///
/// `Item` is the stored form of the same thing: `init(_:origin:)` reads one, `item` writes one, and the round trip is
/// the identity on anything this code wrote. Reading is also where a record's metadata is first interpreted, so it is
/// where the bounds are applied (§6 of that document): counts are clamped to the record's own version, values filed
/// under a group they do not belong to are not read, and repeated identifiers are joined rather than picked from.
struct ItemState {
    /// The latest arrangement of the fields and who made it (a last-writer-wins register).
    struct FieldOrder: Hashable {
        var stamp: GroupStamp
        var ids: [UUID]

        /// The later of two arrangements: by revision, which follows causality between honest writes (a write's
        /// version is above everything its writer had seen), then by a fixed order, so that it is a maximum in a
        /// total order — a join — whatever the stamps hold.
        static func later(_ x: FieldOrder, _ y: FieldOrder) -> FieldOrder {
            if x == y { return x }
            if x.stamp.revision != y.stamp.revision { return x.stamp.revision < y.stamp.revision ? y : x }
            let (bytesX, bytesY) = (x.canonicalBytes, y.canonicalBytes)
            return bytesX.lexicographicallyPrecedes(bytesY) ? y : x
        }

        private var canonicalBytes: [UInt8] {
            var writer = CanonicalWriter()
            writer.append(UInt64(ids.count))
            for id in ids { writer.append(id) }
            writer.append(stamp.seen)
            return writer.bytes
        }
    }

    /// Identity and the plain attributes (`id`, `vaultID`, `version`, `createdAt`, `modifiedAt`); everything else in
    /// it is overwritten by `item`.
    var base: Item
    /// Every value no other value of its group supersedes; never empty for a group it lists.
    var registers: [ItemGroup: [ConflictingValue]]
    var order: FieldOrder
    var clock: VersionVector
    /// One line per ID, in document order.
    var lines: [NoteLine]
    var history: Set<ItemHistoryEntry>
    var retained: Set<ConflictingValue>
    var discards: [ItemGroup: VersionVector]

    // MARK: - Reading

    /// The state `item` holds, read from a record written as `origin` (its version and device).
    init(_ item: Item, origin: Revision) {
        let limit = origin.version
        // An item from before sync has no clock; the row it was read from stands in for its one write.
        let legacy = item.clock.isEmpty
        var clock = legacy ? VersionVector([origin.device: origin.version]) : item.clock.clamped(to: limit)
        // A group without a stamp, in an item that has sync metadata, was written before anything the item records.
        let fallback = legacy ? GroupStamp(revision: origin, seen: clock) : ItemMerge.zeroStamp
        func stamp(_ group: ItemGroup) -> GroupStamp {
            item.revisions[group]?.clamped(to: limit) ?? fallback
        }

        var registers: [ItemGroup: [ConflictingValue]] = [:]
        for group in ItemGroup.attributes where group != .fieldOrder {
            guard let value = item.value(of: group) else { continue }
            registers[group] = [ConflictingValue(stamp: stamp(group), value: value)]
        }
        // A field ID given twice is one field: the first.
        var present: Set<UUID> = []
        for field in item.fields where present.insert(field.id).inserted {
            let group = ItemGroup.field(field.id)
            registers[group] = [ConflictingValue(stamp: stamp(group), value: .field(field))]
        }
        // A stamp for a field that is not present records its removal.
        for (group, removal) in item.revisions {
            guard let id = group.fieldID, group.isKnown, !present.contains(id) else { continue }
            registers[group] = [ConflictingValue(stamp: removal.clamped(to: limit), value: .field(nil))]
        }
        for (group, values) in item.conflicts where group.isKnown && group != .fieldOrder {
            var candidates = Set(registers[group] ?? [])
            for conflict in values where ItemMerge.belongs(conflict.value, to: group) {
                candidates.insert(conflict.clamped(to: limit))
            }
            if !candidates.isEmpty { registers[group] = Self.maximal(candidates) }
        }
        self.registers = registers

        var listed: Set<UUID> = []
        order = FieldOrder(
            stamp: stamp(.fieldOrder),
            ids: (item.fieldOrder ?? item.fields.map(\.id)).filter { listed.insert($0).inserted })

        var discards: [ItemGroup: VersionVector] = [:]
        for (group, vector) in item.discards where group.isKnown && group != .fieldOrder {
            let clamped = vector.clamped(to: limit)
            if !clamped.isEmpty { discards[group] = clamped }
        }
        self.discards = discards
        retained = []
        for value in item.retainedValues {
            let value = value.clamped(to: limit)
            guard let group = ItemMerge.group(of: value.value), group != .fieldOrder,
                !Self.covers(discards[group], value)
            else { continue }
            retained.insert(value)
        }

        // The clock contains everything the item holds: every stamp in it was written on a copy the item descends
        // from. Between honest devices this changes nothing; it is what lets the next edit supersede all of it.
        for values in registers.values {
            for value in values { clock.formUnion(value.stamp.seen) }
        }
        clock.formUnion(order.stamp.seen)
        for value in retained { clock.formUnion(value.stamp.seen) }
        self.clock = clock

        lines = NoteText.ordered(
            item.noteLines.isEmpty
                ? NoteText.initial(item.notes, revision: origin) : NoteText.clamped(item.noteLines, to: limit))
        history = Set(item.history)
        base = item
    }

    // MARK: - The join

    /// The least state that contains both.
    func joined(_ other: ItemState) -> ItemState {
        var result = self
        for (group, values) in other.registers {
            guard let mine = registers[group] else {
                result.registers[group] = values
                continue
            }
            // Most groups are the same on both sides.
            if mine.count == 1, mine == values { continue }
            result.registers[group] = Self.joined(mine, values)
        }
        result.order = FieldOrder.later(order, other.order)
        result.clock = clock.merging(other.clock)
        if lines != other.lines { result.lines = NoteText.merge(lines, other.lines) }
        // Both histories, whole: merging never shortens a history (PRD F1.4, F7.7).
        if history != other.history { result.history = history.union(other.history) }
        if discards != other.discards { result.discards = discards.merging(other.discards) { $0.merging($1) } }
        if retained != other.retained || discards != other.discards {
            result.retained = retained.union(other.retained).filter { value in
                !Self.covers(ItemMerge.group(of: value.value).flatMap { result.discards[$0] }, value)
            }
        }
        result.base.createdAt = min(base.createdAt, other.base.createdAt)
        result.base.modifiedAt = max(base.modifiedAt, other.base.modifiedAt)
        result.base.version = max(base.version, other.base.version)
        return result
    }

    /// The values no other value supersedes. `supersedes` is a strict partial order on the stamps' vectors, so this
    /// is the set of maximal elements, and taking it of a union is a join. Values with the same vector are compared
    /// once; a vector can only be covered by a heavier one, and only the uncovered ones need checking against.
    static func maximal(_ candidates: Set<ConflictingValue>) -> [ConflictingValue] {
        guard candidates.count > 1 else { return Array(candidates) }
        let vectors = Set(candidates.map(\.stamp.seen))
        guard vectors.count > 1 else { return Array(candidates) }
        var packing = Packing()
        let byWeight = vectors.map { packing.pack($0) }.sorted { $1.weight < $0.weight }
        var uncovered: [Packed] = []
        var covered: Set<VersionVector> = []
        for vector in byWeight {
            if uncovered.contains(where: { vector.isStrictlyCovered(by: $0) }) {
                covered.insert(vector.vector)
            } else {
                uncovered.append(vector)
            }
        }
        return candidates.filter { !covered.contains($0.stamp.seen) }
    }

    /// `maximal` of the union of two sets that are each already maximal: a value can then only be superseded by one
    /// from the other set, and two equal sets need no comparing at all.
    static func joined(_ a: [ConflictingValue], _ b: [ConflictingValue]) -> [ConflictingValue] {
        let (setA, setB) = (Set(a), Set(b))
        if setA == setB { return a }
        var packing = Packing()
        let vectorsA = Set(a.map(\.stamp.seen)).map { packing.pack($0) }.sorted { $1.weight < $0.weight }
        let vectorsB = Set(b.map(\.stamp.seen)).map { packing.pack($0) }.sorted { $1.weight < $0.weight }
        func covered(_ vectors: [Packed], by others: [Packed]) -> Set<VersionVector> {
            var result: Set<VersionVector> = []
            for vector in vectors {
                // `others` is heaviest first, and only a heavier vector can cover.
                for other in others {
                    guard vector.weight < other.weight else { break }
                    if vector.isStrictlyCovered(by: other) {
                        result.insert(vector.vector)
                        break
                    }
                }
            }
            return result
        }
        let (coveredA, coveredB) = (covered(vectorsA, by: vectorsB), covered(vectorsB, by: vectorsA))
        return Array(
            setA.filter { !coveredA.contains($0.stamp.seen) }.union(setB.filter { !coveredB.contains($0.stamp.seen) }))
    }

    /// A version vector laid out for comparing with many others: its entries in a fixed order of devices, so that
    /// coverage is one pass over two arrays with no hashing. Comparing is the one step of a merge that is not linear
    /// in the size of the item (docs/10-sync-correctness.md §6), so it is the one worth making cheap.
    struct Packed {
        let vector: VersionVector
        let weight: Weight
        let devices: [Int]
        let counts: [UInt64]

        func isStrictlyCovered(by other: Packed) -> Bool {
            guard weight < other.weight, devices.count <= other.devices.count else { return false }
            var index = 0
            for (device, count) in zip(devices, counts) {
                while index < other.devices.count, other.devices[index] < device { index += 1 }
                guard index < other.devices.count, other.devices[index] == device, other.counts[index] >= count
                else { return false }
                index += 1
            }
            return true
        }
    }

    /// Numbers devices as they are first met, so that vectors packed by one `Packing` are comparable.
    struct Packing {
        private var numbers: [UUID: Int] = [:]

        mutating func pack(_ vector: VersionVector) -> Packed {
            var entries: [(device: Int, count: UInt64)] = []
            entries.reserveCapacity(vector.entries.count)
            for (device, count) in vector.entries {
                let number = numbers[device] ?? numbers.count
                numbers[device] = number
                entries.append((number, count))
            }
            entries.sort { $0.device < $1.device }
            return Packed(
                vector: vector, weight: Weight(vector), devices: entries.map(\.device), counts: entries.map(\.count))
        }
    }

    /// The sum of a vector's counts, in 128 bits: strictly greater for a vector that strictly covers another.
    struct Weight: Comparable {
        var high: UInt64 = 0
        var low: UInt64 = 0

        init(_ vector: VersionVector) {
            for count in vector.entries.values {
                let (sum, overflow) = low.addingReportingOverflow(count)
                low = sum
                if overflow { high &+= 1 }
            }
        }

        static func < (lhs: Weight, rhs: Weight) -> Bool {
            lhs.high != rhs.high ? lhs.high < rhs.high : lhs.low < rhs.low
        }
    }

    /// Whether a resolution that had `vector` before it discarded `value`.
    static func covers(_ vector: VersionVector?, _ value: ConflictingValue) -> Bool {
        vector?.contains(value.stamp.revision) ?? false
    }

    // MARK: - Updates

    /// The value shown for `group`, if the item has any.
    func shown(_ group: ItemGroup) -> ConflictingValue? {
        registers[group].flatMap { Self.arranged($0).shown }
    }

    /// Keeps a value an edit superseded without the person choosing to discard it (PRD F7.7).
    mutating func retain(_ value: ConflictingValue) {
        guard value.value != .field(nil), let group = ItemMerge.group(of: value.value),
            !Self.covers(discards[group], value)
        else { return }
        retained.insert(value)
    }

    // MARK: - Writing

    /// The stored form.
    var item: Item {
        var item = base
        var fields: [UUID: Field] = [:]
        item.revisions = [:]
        item.conflicts = [:]
        for (group, values) in registers {
            let (shown, others) = Self.arranged(values)
            guard let shown else { continue }
            item.revisions[group] = shown.stamp
            if !others.isEmpty { item.conflicts[group] = others }
            switch shown.value {
            case .title(let title): item.title = title
            case .scopes(let scopes): item.scopes = scopes
            case .tags(let tags): item.tags = tags
            case .archived(let archived): item.archived = archived
            case .trashedAt(let date): item.trashedAt = date
            case .keptAfterDeletion(let kept): item.keptAfterDeletion = kept
            case .excludedFromSuggestions(let excluded): item.excludedFromSuggestions = excluded
            case .field(let field?): fields[field.id] = field
            case .field(nil), .fieldOrder: break
            }
        }
        item.revisions[.fieldOrder] = order.stamp
        item.fieldOrder = order.ids
        item.fields = Self.arranged(fields, order: order.ids)
        item.clock = clock
        item.noteLines = lines
        item.notes = lines.filter { !$0.removed }.map(\.text).joined(separator: "\n")
        item.history = Self.sorted(history)
        item.retainedValues = ItemMerge.sortedCanonically(retained)
        item.discards = discards
        return item
    }

    /// Which of a group's values is shown, and the others in a fixed order. A deletion (a removed field, a trashed
    /// item) is shown first, so a deletion and a concurrent edit resolve to the deletion with the edit kept; then the
    /// later revision; then a fixed order. A function of the set alone, so every device shows the same one.
    static func arranged(_ values: [ConflictingValue]) -> (shown: ConflictingValue?, others: [ConflictingValue]) {
        guard values.count > 1 else { return (values.first, []) }
        var sorted = ItemMerge.sortedCanonically(values)
        let index = sorted.lastIndex { ItemMerge.isDeletion($0.value) } ?? sorted.count - 1
        let shown = sorted.remove(at: index)
        return (shown, sorted)
    }

    /// The fields in the stored order, then any it does not list (added on another device since), by ID.
    static func arranged(_ fields: [UUID: Field], order: [UUID]) -> [Field] {
        arranged(Set(fields.keys), order: order).compactMap { fields[$0] }
    }

    static func arranged(_ present: Set<UUID>, order: [UUID]) -> [UUID] {
        var remaining = present
        var result = order.filter { remaining.remove($0) != nil }
        result += remaining.sorted { $0.precedes($1) }
        return result
    }

    /// Newest first, in a fixed order.
    static func sorted(_ history: Set<ItemHistoryEntry>) -> [ItemHistoryEntry] {
        guard history.count > 1 else { return Array(history) }
        // Entries replaced at the same time by the same version are told apart by their fields; that is rare, so the
        // encoding is made only then.
        func bytes(_ entry: ItemHistoryEntry) -> [UInt8] {
            var writer = CanonicalWriter()
            for field in entry.fields { writer.append(field) }
            return writer.bytes
        }
        return history.sorted { x, y in
            if x.replacedAt != y.replacedAt { return x.replacedAt > y.replacedAt }
            if x.version != y.version { return x.version > y.version }
            return bytes(y).lexicographicallyPrecedes(bytes(x))
        }
    }
}

/// An encoding of sync metadata that is injective and the same on every platform, for ordering values identically on
/// every device. Everything is length-prefixed or fixed-width and collections are written in byte order, so it never
/// depends on hashing order, a locale, or how a JSON encoder escapes a string.
struct CanonicalWriter {
    private(set) var bytes: [UInt8] = []

    mutating func append(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) { bytes.append(UInt8(truncatingIfNeeded: value >> shift)) }
    }

    mutating func append(_ value: Bool) {
        bytes.append(value ? 1 : 0)
    }

    mutating func append(_ value: String) {
        append(UInt64(value.utf8.count))
        bytes.append(contentsOf: value.utf8)
    }

    mutating func append(_ value: UUID) {
        bytes.append(contentsOf: value.byteArray)
    }

    mutating func append(_ value: Date?) {
        guard let value else {
            bytes.append(0)
            return
        }
        bytes.append(1)
        let seconds = value.timeIntervalSinceReferenceDate
        // One encoding per value `==` tells apart: zero has two bit patterns and "not a number" many.
        append(seconds == 0 ? 0 : seconds.isNaN ? Double.nan.bitPattern : seconds.bitPattern)
    }

    mutating func append(sorted strings: some Collection<String>) {
        append(UInt64(strings.count))
        for string in strings.map({ Array($0.utf8) }).sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            append(UInt64(string.count))
            bytes.append(contentsOf: string)
        }
    }

    mutating func append(_ field: Field) {
        append(field.id)
        append(field.kind.rawValue)
        append(field.label)
        append(field.value)
        append(UInt64(field.meta.count))
        let meta = field.meta.map { (key: Array($0.key.utf8), value: $0.value) }
        for entry in meta.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }) {
            append(UInt64(entry.key.count))
            bytes.append(contentsOf: entry.key)
            append(entry.value)
        }
    }

    mutating func append(_ vector: VersionVector) {
        append(UInt64(vector.entries.count))
        for (device, count) in vector.entries.sorted(by: { $0.key.precedes($1.key) }) {
            append(device)
            append(count)
        }
    }

    mutating func append(_ value: ItemGroupValue) {
        switch value {
        case .title(let title):
            bytes.append(1)
            append(title)
        case .scopes(let scopes):
            bytes.append(2)
            append(UInt64(scopes.count))
            for scope in scopes {
                append(scope.host)
                append(scope.includeSubdomains)
                append(sorted: scope.excludedHosts)
            }
        case .tags(let tags):
            bytes.append(3)
            append(sorted: tags)
        case .archived(let archived):
            bytes.append(4)
            append(archived)
        case .trashedAt(let date):
            bytes.append(5)
            append(date)
        case .keptAfterDeletion(let kept):
            bytes.append(6)
            append(kept)
        case .excludedFromSuggestions(let excluded):
            bytes.append(7)
            append(excluded)
        case .fieldOrder(let ids):
            bytes.append(8)
            append(UInt64(ids.count))
            for id in ids { append(id) }
        case .field(let field):
            bytes.append(9)
            append(field != nil)
            if let field { append(field) }
        }
    }
}
