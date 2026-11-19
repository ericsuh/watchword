import Foundation
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordSync

/// A pure model of several devices editing and exchanging one item, for checking `ItemMerge` against its
/// specification (docs/10-sync-correctness.md) without an engine, a store or keys.
///
/// Each device is a `Replica`: the version of the item it stores, and the erasures it knows. Edits are made the way
/// `VaultSession` makes them (`ItemMerge.stamped` at a version above everything the device has seen, with the replaced
/// fields pushed to the history), exchanges the way `ItemRecordMerger` and the engine make them (merge, then adopt,
/// keep or write a new version; settle against every known erasure).
///
/// Beside the item, the model keeps what the item's own metadata is *supposed* to say, worked out independently of
/// it: for every copy, the set of writes delivered to it (`Replica.delivered`) and the set it counts as seen
/// (`Replica.seen`: those, and what any deletion it was kept after had seen), and for every write, the value written
/// and what its writer's copy had seen (`writes`). From those the specification of a multi-value register can be
/// computed directly — the values of a group a copy holds are the writes delivered to it that no other write
/// delivered to it was made knowing about — and compared with what the item shows and keeps (`checkSpecification`).
struct MergeModel {
    /// One operation by one device. What it acts on (which field, which line, which spelling, which of the values in
    /// conflict) is chosen by `pick`.
    ///
    /// The `respell…` operations write one of two spellings of the same text that Swift's `String` takes for equal
    /// and whose bytes differ (`spellings`): the merge must treat them as two values everywhere (review finding Y31).
    enum Operation: Hashable, CaseIterable, Sendable {
        case setField, addField, removeField, reorder
        case setTitle, toggleTag, setScopes, toggleArchived
        case insertLine, replaceLine, removeLine
        case trash, restore, resolve, delete
        case respellField, respellTitle, respellLine
    }

    /// "café" with the accent as one scalar (63 61 66 C3 A9) and as a combining mark (63 61 66 65 CC 81): canonically
    /// equivalent, so `==` on `String` says equal, and different bytes.
    static let spellings = ["caf\u{E9}", "cafe\u{301}"]

    static func bytes(_ text: String) -> [UInt8] {
        Array(text.utf8)
    }

    struct Write {
        var value: ItemGroupValue
        /// Every edit the writer's copy descended from, the write itself included.
        var history: Set<Revision>
    }

    struct Replica {
        let device: UUID
        /// The stored version; its `version` is the row's.
        var item: Item?
        /// The device that wrote the stored row.
        var writer: UUID
        /// The highest version this device has seen.
        var highest: UInt64 = 0
        var erasures: [ItemErasure] = []
        /// The writes whose versions were merged into the stored copy. Not read from the item.
        var delivered: Set<Revision> = []
        /// What the stored copy counts as seen: `delivered`, and everything seen by a deletion it was kept after
        /// (which erased what it covered, so the copy may never have held those writes).
        var seen: Set<Revision> = []

        var origin: Revision? {
            item.map { Revision(version: $0.version, device: writer) }
        }
    }

    /// A stored version and the row it was stored as.
    struct Version: Hashable {
        var item: Item
        var origin: Revision
    }

    static let itemID = UUID(uuidString: "17E00000-0000-4000-8000-0000000000AA")!
    static let vaultID = SyncFixtures.vault

    var replicas: [Replica]
    private(set) var tick = 0.0
    /// Every version any device stored, in the order first stored.
    private(set) var versions: [Version] = []
    private var stored: Set<Version> = []

    // What the metadata is supposed to say.
    private(set) var writes: [ItemGroup: [Revision: Write]] = [:]
    private(set) var orderWrites: [Revision: [UUID]] = [:]
    private var erasureKnowledge: [Revision: Set<Revision>] = [:]

    // What a person typed, and what a person explicitly discarded.
    private(set) var fieldsWritten: Set<Field> = []
    private(set) var fieldsDiscarded: Set<Field> = []
    // Lines by their bytes: a `Set<String>` would take two spellings of a line for one.
    private(set) var linesTyped: Set<[UInt8]> = []
    private(set) var linesRemoved: Set<[UInt8]> = []

    // Coverage, so a test can assert that the cases it exists for occurred.
    private(set) var conflictsSeen = 0
    private(set) var resolutions = 0
    private(set) var erased = 0
    private(set) var keptAfterDeletion = 0
    private(set) var mergesWritten = 0

    /// The first few failures, each with enough context to replay.
    private(set) var failures: [String] = []
    var context = ""

    /// `count` devices, the first of which creates the item; the others receive it.
    init(devices count: Int, notes: String = "first\nsecond") {
        let devices = (0..<count).map {
            UUID(uuid: (0xD0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, UInt8($0 + 1)))
        }
        replicas = devices.map { Replica(device: $0, writer: $0) }
        let revision = Revision(version: 1, device: devices[0])
        let item = ItemMerge.stamped(
            Item(
                id: Self.itemID, vaultID: Self.vaultID, title: "Bank",
                scopes: [ServiceScope(host: "firstbank.co.uk")],
                fields: [
                    Field(id: Self.fieldID(1), kind: .username, label: "Username", value: "pat"),
                    Field(id: Self.fieldID(2), kind: .password, label: "Password", value: "initial"),
                ],
                notes: notes, createdAt: date(), modifiedAt: date(), version: 1),
            previous: nil, revision: revision)
        for group in ItemGroup.attributes + item.fields.map({ ItemGroup.field($0.id) }) where group != .fieldOrder {
            writes[group, default: [:]][revision] = Write(value: item.value(of: group)!, history: [revision])
        }
        orderWrites[revision] = item.fields.map(\.id)
        fieldsWritten.formUnion(item.fields)
        linesTyped.formUnion(NoteText.lines(of: notes).map(Self.bytes))
        for index in replicas.indices {
            replicas[index].item = item
            replicas[index].writer = devices[0]
            replicas[index].highest = 1
            replicas[index].delivered = [revision]
            replicas[index].seen = [revision]
        }
        record(Version(item: item, origin: revision))
    }

    static func fieldID(_ n: UInt8) -> UUID {
        UUID(uuid: (0xF1, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, n))
    }

    /// A field added at `tick`: an ID no other field has.
    static func addedFieldID(_ tick: Int) -> UUID {
        UUID(
            uuid: (
                0xF2, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, UInt8(truncatingIfNeeded: tick >> 16),
                UInt8(truncatingIfNeeded: tick >> 8), UInt8(truncatingIfNeeded: tick), 0
            ))
    }

    private func date() -> Date {
        Date(timeIntervalSince1970: 1_800_000_000 + tick)
    }

    mutating func fail(_ message: @autoclosure () -> String) {
        if failures.count < 5 { failures.append("\(context): \(message())") }
    }

    private mutating func record(_ version: Version) {
        if stored.insert(version).inserted { versions.append(version) }
    }

    // MARK: - Operations

    /// Device `index` performs `operation`; `pick(n)` chooses among `n` things. Returns whether anything was written.
    @discardableResult
    mutating func perform(_ operation: Operation, by index: Int, pick: (Int) -> Int) -> Bool {
        guard let previous = replicas[index].item else { return false }
        tick += 1
        let unique = "\(Int(tick))"
        switch operation {
        case .resolve: return resolve(by: index, pick: pick)
        case .delete: return delete(by: index)
        default: break
        }
        var edited = previous
        var lines = NoteText.lines(of: edited.notes)
        switch operation {
        case .setField:
            guard !edited.fields.isEmpty else { return false }
            edited.fields[pick(edited.fields.count)].value = "value-" + unique
        case .addField:
            edited.fields.append(
                Field(id: Self.addedFieldID(Int(tick)), kind: .text, label: "Extra", value: "extra-" + unique))
        case .removeField:
            guard !edited.fields.isEmpty else { return false }
            edited.fields.remove(at: pick(edited.fields.count))
        case .reorder:
            guard edited.fields.count > 1 else { return false }
            edited.fields.append(edited.fields.remove(at: pick(edited.fields.count - 1)))
        case .setTitle: edited.title = "Title " + unique
        case .toggleTag:
            let tag = "tag\(pick(3))"
            if edited.tags.remove(tag) == nil { edited.tags.insert(tag) }
        case .setScopes: edited.scopes = [ServiceScope(host: "host\(unique).example.com")]
        case .toggleArchived: edited.archived.toggle()
        case .insertLine:
            lines.insert("line-" + unique, at: pick(lines.count + 1))
        case .replaceLine:
            guard !lines.isEmpty else { return false }
            lines[pick(lines.count)] = "line-" + unique
        case .removeLine:
            guard !lines.isEmpty else { return false }
            lines.remove(at: pick(lines.count))
        case .trash:
            // As `VaultSession.trash`: an item sync kept in the trash becomes the person's.
            if edited.trashedAt == nil || edited.keptAfterDeletion { edited.trashedAt = date() }
            edited.keptAfterDeletion = false
        case .restore:
            guard edited.isTrashed else { return false }
            edited.trashedAt = nil
            edited.keptAfterDeletion = false
        case .respellField:
            guard !edited.fields.isEmpty else { return false }
            let field = pick(edited.fields.count)
            let spelling = Self.spellings[pick(Self.spellings.count)]
            guard Self.bytes(edited.fields[field].value) != Self.bytes(spelling) else { return false }
            edited.fields[field].value = spelling
        case .respellTitle:
            let spelling = Self.spellings[pick(Self.spellings.count)]
            guard Self.bytes(edited.title) != Self.bytes(spelling) else { return false }
            edited.title = spelling
        case .respellLine:
            guard !lines.isEmpty else { return false }
            let line = pick(lines.count)
            let spelling = Self.spellings[pick(Self.spellings.count)]
            guard Self.bytes(lines[line]) != Self.bytes(spelling) else { return false }
            lines[line] = spelling
        case .resolve, .delete: return false
        }
        edited.notes = lines.joined(separator: "\n")
        save(edited, by: index)
        return true
    }

    /// A save, as `VaultSession.write` makes one.
    private mutating func save(_ draft: Item, by index: Int) {
        guard let previous = replicas[index].item, let origin = replicas[index].origin else { return }
        let device = replicas[index].device
        let revision = Revision(version: max(replicas[index].highest, previous.version) + 1, device: device)
        var edited = draft
        edited.version = revision.version
        edited.modifiedAt = date()
        if previous.fields != edited.fields {
            edited.history.insert(
                ItemHistoryEntry(replacedAt: edited.modifiedAt, version: previous.version, fields: previous.fields),
                at: 0)
        }
        // The line nonce, drawn as the vault draws it but from a seed, so that a history is the same on every run.
        var generator = SeededGenerator(seed: UInt64(tick))
        let saved = ItemMerge.stamped(
            edited, previous: previous, previousOrigin: origin, revision: revision, using: &generator)

        // The specification's side: which groups this edit wrote, with what the writer had seen.
        let history = replicas[index].seen.union([revision])
        let groups = Set(ItemGroup.attributes + (previous.fields + edited.fields).map { ItemGroup.field($0.id) })
        for group in groups where group != .fieldOrder && previous.value(of: group) != edited.value(of: group) {
            writes[group, default: [:]][revision] = Write(value: edited.value(of: group)!, history: history)
        }
        if saved.revisions[.fieldOrder]?.revision == revision { orderWrites[revision] = saved.fieldOrder ?? [] }
        fieldsWritten.formUnion(edited.fields)
        let before = Set(NoteText.lines(of: previous.notes).map(Self.bytes))
        let after = Set(NoteText.lines(of: saved.notes).map(Self.bytes))
        linesTyped.formUnion(after)
        linesRemoved.formUnion(before.subtracting(after))

        checkUpdate(from: previous, origin: origin, to: saved, what: "an edit")
        // What is saved is what was typed, byte for byte, in the order it was arranged.
        if saved.fields != edited.fields { fail("the saved fields are not the fields saved, in the order saved") }
        if Self.bytes(saved.notes) != Self.bytes(edited.notes) { fail("the saved notes are not the notes saved") }
        if Self.bytes(saved.title) != Self.bytes(edited.title) { fail("the saved title is not the title saved") }
        if saved.tags != edited.tags || saved.scopes != edited.scopes {
            fail("the saved attributes are not those saved")
        }
        store(saved, writer: device, at: index, delivered: replicas[index].delivered.union([revision]), seen: history)
    }

    /// The person resolves one of the conflicts the item shows, as `VaultSession.resolveConflict` does.
    private mutating func resolve(by index: Int, pick: (Int) -> Int) -> Bool {
        guard let item = replicas[index].item, let origin = replicas[index].origin else { return false }
        let conflicts = ItemMerge.conflicts(of: item).sorted { $0.key < $1.key }
        guard !conflicts.isEmpty else { return false }
        let (group, values) = conflicts[pick(conflicts.count)]
        let choices = [item.value(of: group)!] + values.map(\.value)
        let chosen = choices[pick(choices.count)]
        let device = replicas[index].device
        let revision = Revision(version: max(replicas[index].highest, item.version) + 1, device: device)
        let resolved = ItemMerge.resolve(item, group: group, choosing: chosen, origin: origin, revision: revision)

        let history = replicas[index].seen.union([revision])
        writes[group, default: [:]][revision] = Write(value: chosen, history: history)
        // The person saw every value the item held for the group and chose one: the others are theirs to discard.
        let held =
            choices + item.retainedValues.map(\.value).filter { ItemMerge.group(of: $0) == group }
        for case .field(let field?) in held where chosen != .field(field) { fieldsDiscarded.insert(field) }
        resolutions += 1

        checkUpdate(from: item, origin: origin, to: resolved, what: "a resolution")
        if resolved.value(of: group) != chosen { fail("a resolution does not show the value chosen") }
        if ItemMerge.conflicts(of: resolved)[group] != nil { fail("a resolved group still shows a conflict") }
        store(
            resolved, writer: device, at: index, delivered: replicas[index].delivered.union([revision]), seen: history)
        return true
    }

    /// A permanent deletion, as `VaultSession.deletePermanently` and `DeletionRecordingStore` make one: only of a
    /// trashed item, leaving a tombstone one above the row erased.
    private mutating func delete(by index: Int) -> Bool {
        guard let item = replicas[index].item, let origin = replicas[index].origin, item.isTrashed else { return false }
        let erasure = ItemErasure(
            seen: ItemMerge.effectiveClock(item, origin: origin), row: item.version, device: replicas[index].device,
            date: item.modifiedAt)
        // Through the summary a tombstone carries, as every other device reads it.
        guard let summary = try? erasure.summary(), ItemErasure(summary: summary) == erasure else {
            fail("an erasure does not survive its summary")
            return false
        }
        // The person deleted everything this copy held: none of it is "lost".
        for conflict in Array(item.conflicts.values.joined()) + item.retainedValues {
            if case .field(let field?) = conflict.value { fieldsDiscarded.insert(field) }
        }
        fieldsDiscarded.formUnion(item.fields + item.history.flatMap(\.fields))
        linesRemoved.formUnion(NoteText.lines(of: item.notes).map(Self.bytes))
        let revision = erasure.revision
        let history = replicas[index].seen.union([revision])
        erasureKnowledge[revision] = history
        writes[.trashedAt, default: [:]][revision] = Write(value: .trashedAt(erasure.date), history: history)
        writes[.keptAfterDeletion, default: [:]][revision] = Write(value: .keptAfterDeletion(true), history: history)
        replicas[index].erasures.append(erasure)
        replicas[index].highest = max(replicas[index].highest, revision.version)
        replicas[index].item = nil
        replicas[index].delivered = []
        replicas[index].seen = []
        erased += 1
        return true
    }

    /// Device `index` receives everything device `source` holds: its version of the item and the erasures it knows.
    @discardableResult
    mutating func receive(at index: Int, from source: Int) -> Bool {
        guard index != source else { return false }
        let before = replicas[index]
        for erasure in replicas[source].erasures where !replicas[index].erasures.contains(erasure) {
            replicas[index].erasures.append(erasure)
            replicas[index].highest = max(replicas[index].highest, erasure.revision.version)
        }
        if let theirs = replicas[source].item, let theirOrigin = replicas[source].origin {
            replicas[index].highest = max(replicas[index].highest, theirs.version)
            if let mine = replicas[index].item, let myOrigin = replicas[index].origin {
                // The same row is no news (the engine compares envelopes before it asks the merger).
                if mine == theirs, myOrigin == theirOrigin { return replicas[index].erasures != before.erasures }
                // As `ItemRecordMerger.merge` decides.
                let merged = ItemMerge.merge(mine, origin: myOrigin, theirs, origin: theirOrigin)
                let delivered = replicas[index].delivered.union(replicas[source].delivered)
                let seen = replicas[index].seen.union(replicas[source].seen)
                if ItemMerge.sameState(merged, theirs), theirs.version > mine.version {
                    store(theirs, writer: theirOrigin.device, at: index, delivered: delivered, seen: seen)
                } else if !ItemMerge.sameState(merged, mine) {
                    let revision = Revision(
                        version: max(mine.version, theirs.version) + 1, device: replicas[index].device)
                    mergesWritten += 1
                    store(
                        ItemMerge.written(merged, as: revision), writer: revision.device, at: index,
                        delivered: delivered, seen: seen)
                } else {
                    replicas[index].delivered = delivered
                    replicas[index].seen = seen
                }
            } else {
                store(
                    theirs, writer: theirOrigin.device, at: index, delivered: replicas[source].delivered,
                    seen: replicas[source].seen)
            }
        }
        settle(at: index)
        return replicas[index].item != before.item || replicas[index].erasures != before.erasures
    }

    /// Settles the stored version against every erasure the device knows, as the engine does with a tombstone and
    /// with a version that arrives after one: against their join (`ItemErasures`, `ItemRecordMerger.resolveErasure`),
    /// so which of them the device learned of first decides nothing.
    private mutating func settle(at index: Int) {
        guard !replicas[index].erasures.isEmpty, let item = replicas[index].item, let origin = replicas[index].origin
        else { return }
        let erasures = ItemErasures(replicas[index].erasures)
        switch ItemMerge.settle(item, origin: origin, against: erasures) {
        case .erase:
            replicas[index].item = nil
            replicas[index].delivered = []
            replicas[index].seen = []
        case .keep:
            break
        case .kept(let kept):
            let device = replicas[index].device
            let tombstone = erasures.elements.map(\.revision.version).max() ?? 0
            let revision = Revision(version: max(item.version, tombstone) + 1, device: device)
            // Each deletion is a write delivered to this copy; what they had seen, the copy now counts as seen.
            let revisions = erasures.elements.map(\.revision)
            let delivered = replicas[index].delivered.union(revisions)
            var seen = replicas[index].seen
            for erased in revisions { seen.formUnion(erasureKnowledge[erased] ?? []) }
            let written = ItemMerge.written(kept, as: revision)
            keptAfterDeletion += 1
            checkUpdate(from: item, origin: origin, to: written, what: "a deletion that did not cover the item")
            if !written.isTrashed || written.isTrashedByPerson {
                fail("a version kept after a deletion is not in the trash, or is one the purge would remove")
            }
            store(written, writer: device, at: index, delivered: delivered, seen: seen)
        }
    }

    private mutating func store(
        _ item: Item, writer: UUID, at index: Int, delivered: Set<Revision>, seen: Set<Revision>
    ) {
        replicas[index].item = item
        replicas[index].writer = writer
        replicas[index].highest = max(replicas[index].highest, item.version)
        replicas[index].delivered = delivered
        replicas[index].seen = seen
        record(Version(item: item, origin: Revision(version: item.version, device: writer)))
        if ItemMerge.conflicts(of: item).isEmpty == false { conflictsSeen += 1 }
        checkSpecification(at: index)
    }

    /// Exchanges until nothing changes. Returns whether it settled within `rounds`.
    mutating func settleAll(rounds: Int = 12) -> Bool {
        for _ in 0..<rounds {
            var changed = false
            for index in replicas.indices {
                for source in replicas.indices where receive(at: index, from: source) { changed = true }
            }
            if !changed { return true }
        }
        return false
    }

    // MARK: - Checks

    /// Every update is inflationary: the new state contains the one it was made on, so merging the old one back in
    /// changes nothing — and it is in the one form the merge writes.
    private mutating func checkUpdate(from previous: Item, origin: Revision, to updated: Item, what: String) {
        let after = Revision(version: updated.version, device: origin.device)
        if ItemMerge.merge(updated, origin: after, previous, origin: origin) != updated {
            fail("\(what) does not contain the version it was made on")
        }
        if ItemMerge.canonical(updated, origin: after) != updated { fail("\(what) is not in canonical form") }
    }

    /// The copy at `index` against the specification: each group holds exactly the writes delivered to the copy that
    /// no other write delivered to it was made knowing about; the field order is the latest reorder delivered; its
    /// clock is exactly what it counts as seen.
    mutating func checkSpecification(at index: Int) {
        guard let item = replicas[index].item else { return }
        let knowledge = replicas[index].delivered
        for (group, groupWrites) in writes {
            let seen = groupWrites.filter { knowledge.contains($0.key) }
            let expected = seen.filter { candidate in
                !seen.contains { $0.key != candidate.key && $0.value.history.contains(candidate.key) }
            }.mapValues(\.value)
            var actual: [Revision: ItemGroupValue] = [:]
            if let stamp = item.revisions[group], let value = item.value(of: group) { actual[stamp.revision] = value }
            for conflict in item.conflicts[group] ?? [] { actual[conflict.stamp.revision] = conflict.value }
            if actual != expected {
                fail(
                    "\(group.rawValue) holds \(Self.describe(actual)) where the specification has \(Self.describe(expected))"
                )
            }
        }
        for group in item.revisions.keys where group != .fieldOrder && writes[group] == nil {
            fail("\(group.rawValue) is stamped but was never written")
        }
        if let latest = orderWrites.keys.filter(knowledge.contains).max() {
            let order = orderWrites[latest] ?? []
            let present = Set(item.fields.map(\.id))
            let expected = order.filter(present.contains) + present.subtracting(order).sorted { $0.precedes($1) }
            if item.fieldOrder != order || item.fields.map(\.id) != expected {
                fail("the fields are not in the order of the latest reorder")
            }
        }
        var clock = VersionVector()
        for revision in replicas[index].seen { clock.record(revision) }
        if item.clock != clock { fail("the clock is not what the copy has seen") }
    }

    private static func describe(_ values: [Revision: ItemGroupValue]) -> String {
        values.sorted { $0.key < $1.key }.map { "\($0.key.version)@\($0.key.device.uuidString.suffix(2)): \($0.value)" }
            .joined(separator: "; ")
    }

    /// After `settleAll`: every device holds the same item, as sealed, or none does; and nothing a person typed is
    /// gone unless a person discarded it (PRD F7.7).
    mutating func checkConverged() {
        let normal = Revision(version: 0, device: replicas[0].device)
        let states = replicas.map { $0.item.map { ItemMerge.written($0, as: normal) } }
        if Set(states).count != 1 { fail("devices hold different items after exchanging everything") }
        guard let item = replicas[0].item else { return }
        var present = Set(item.fields)
        present.formUnion(item.history.flatMap(\.fields))
        for conflict in Array(item.conflicts.values.joined()) + item.retainedValues {
            if case .field(let field?) = conflict.value { present.insert(field) }
        }
        let lost = fieldsWritten.subtracting(present).subtracting(fieldsDiscarded)
        if !lost.isEmpty { fail("field values lost: \(lost.map(\.value).sorted())") }
        let lines = linesTyped.subtracting(NoteText.lines(of: item.notes).map(Self.bytes)).subtracting(linesRemoved)
        if !lines.isEmpty { fail("note lines lost: \(lines.map { String(decoding: $0, as: UTF8.self) }.sorted())") }
    }

    /// The join of two versions, as a version: a merge result claims no write of its own, so it is read back at its
    /// own version.
    static func join(_ x: Version, _ y: Version) -> Version {
        let item = ItemMerge.merge(x.item, origin: x.origin, y.item, origin: y.origin)
        return Version(item: item, origin: Revision(version: item.version, device: ItemMerge.zeroDevice))
    }

    /// The laws of a join-semilattice on three stored versions, each compared as the whole item.
    mutating func checkLaws(_ a: Version, _ b: Version, _ c: Version) {
        let ab = Self.join(a, b)
        if ab.item != Self.join(b, a).item { fail("merge is not commutative") }
        if Self.join(a, a).item != a.item { fail("merge is not idempotent") }
        if Self.join(ab, a).item != ab.item || Self.join(ab, b).item != ab.item {
            fail("a merge does not contain its inputs")
        }
        let left = Self.join(ab, c).item
        if left != Self.join(a, Self.join(b, c)).item || left != Self.join(Self.join(a, c), b).item {
            fail("merge is not associative")
        }
    }

    /// Folds `versions` in the order given, as a device receiving them one at a time would.
    static func fold(_ versions: [Version]) -> Item? {
        guard var result = versions.first else { return nil }
        for next in versions.dropFirst() { result = join(result, next) }
        return result.item
    }
}

// MARK: - A restore's carry (`ItemMerge.reattributed`, docs/10-sync-correctness.md §9)

extension MergeModel {
    /// A new ID for a restored installation of the model's last device, drawn at random (review of round 14, L1):
    /// a tie-break between two concurrent field orders at one version goes by device ID, so where it falls among the
    /// model's devices decides which of them a renamed order wins against. One chosen above every device, as the
    /// earlier ID is, hid that.
    static func restoredDevice(using generator: inout some RandomNumberGenerator) -> UUID {
        var bytes = (0..<16).map { _ in UInt8.random(in: 0...255, using: &generator) }
        bytes[6] = 0x40 | (bytes[6] & 0x0F)
        bytes[8] = 0x80 | (bytes[8] & 0x3F)
        return UUID(
            uuid: (
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            ))
    }

    /// Restored IDs below and above every device the model makes (`devices(…)` ends at 0xD0…0xFF): the two places a
    /// renamed field order can rank, for the exhaustive exploration.
    static let restoredBelow = UUID(uuid: (0x00, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x01))
    static let restoredAbove = UUID(uuid: (0xFF, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xFF))

    /// The most of `replicas[index]`'s writes any other copy has seen so far: what its stream can have carried.
    func seenByOthers(of index: Int) -> UInt64 {
        let device = replicas[index].device
        return replicas.indices.filter { $0 != index }.flatMap { replicas[$0].seen }.filter { $0.device == device }
            .map(\.version).max() ?? 0
    }

    /// `version` carried over from `device` to the restored ID above `bound`, as the row the restored ID writes.
    static func carried(_ version: Version, from device: UUID, above bound: UInt64, to restored: UUID) -> Version {
        let item = ItemMerge.reattributed(
            version.item, origin: version.origin, from: device, above: bound, to: restored)
        return Version(item: item, origin: Revision(version: item.version, device: restored))
    }

    /// A version's stamped parts, by group and revision: every value a register, conflict or retained value holds,
    /// the field order, and every discard (as a stamp: its resolution and what it had seen).
    static func stampedParts(_ version: Version) -> [String: [GroupStamp]] {
        let state = ItemState(version.item, origin: version.origin)
        var parts: [String: [GroupStamp]] = [:]
        func add(_ group: ItemGroup, _ stamp: GroupStamp, discard: Bool = false) {
            let key = "\(discard ? "discard " : "")\(group.rawValue) \(stamp.revision.version)@\(stamp.revision.device)"
            parts[key, default: []].append(stamp)
        }
        for (group, values) in state.registers { for value in values { add(group, value.stamp) } }
        for value in state.retained {
            if let group = ItemMerge.group(of: value.value) { add(group, value.stamp) }
        }
        add(.fieldOrder, state.order.stamp)
        for (group, discards) in state.discards {
            for discard in discards {
                if let revision = discard.revision {
                    add(group, GroupStamp(revision: revision, seen: discard.seen), discard: true)
                }
            }
        }
        return parts
    }

    /// The key `stampedParts` files a part under once the carry has renamed its revision.
    static func renamedKey(_ key: String, from device: UUID, above bound: UInt64, to restored: UUID) -> String {
        guard let at = key.lastIndex(of: "@"), let space = key[..<at].lastIndex(of: " "),
            let version = UInt64(key[key.index(after: space)..<at]), key[key.index(after: at)...] == device.uuidString,
            version > bound
        else { return key }
        return String(key[...space]) + "\(version)@\(restored)"
    }

    /// What the carry of the earlier ID's copy `a` must satisfy (docs/10 §9), with `published` the most of the
    /// earlier ID's writes any other copy has seen and `given` a bound at or below it (a state that says too little was
    /// published: lost, rolled back, saved before a later publish), against `others`, versions other devices stored:
    ///
    /// 1. the carry commutes with merges outside the field order: for every `b` that holds nothing of the earlier ID
    ///    above `published`, `R(a ⊔ b)` equals `R(a) ⊔ b`, and in the field order too unless `a`'s renamed order
    ///    and `b`'s tie at one version; where they tie, only `R(a) ⊔ b` is what every device holding `b` holds once
    ///    it merges the carry, so the carry is made before the merge (`checkCarryOrder`, review of round 14, L1, and
    ///    of round 15, Z210);
    /// 2. it is idempotent: `R(R(a)) == R(a)`, for `given` too;
    /// 3. it keeps supersession and coverage: for every pair of stamped parts of `a` and `b`, one contains the other's
    ///    revision exactly when their images do;
    /// 4. it never rewrites a third device (review of round 13, M1): with `given`, every stamp, discard and line of a
    ///    device other than the earlier ID and the restored one is unchanged, byte for byte.
    ///
    /// Returns whether `a` held anything to rename above `published`, whether a third device's part had seen the
    /// earlier ID above `given` (the case M1 broke), and whether a field order's tie made the two orders of law 1
    /// differ (the case L1 found).
    mutating func checkReattribution(
        _ a: Version, of device: UUID, published: UInt64, given: UInt64, others: [Version], restored: UUID
    ) -> (renamed: Bool, raised: Bool, tied: Bool) {
        let state = ItemState(a.item, origin: a.origin)
        if ItemMerge.seenByOthers(state, of: device, besides: restored) > published {
            fail("the model's published bound is below what another device's part shows")
        }
        let carried = Self.carried(a, from: device, above: published, to: restored)
        // 2.
        if Self.carried(carried, from: device, above: published, to: restored).item != carried.item {
            fail("a carry is not idempotent")
        }
        let low = Self.carried(a, from: device, above: given, to: restored)
        if Self.carried(low, from: device, above: given, to: restored).item != low.item {
            fail("a carry from a bound read too low is not idempotent")
        }
        // 1. and 3.
        let parts = Self.stampedParts(a)
        let renamedParts = Self.stampedParts(carried)
        var tied = false
        for b in others {
            guard (ItemMerge.effectiveClock(b.item, origin: b.origin).entries[device] ?? 0) <= published else {
                continue
            }
            if checkCarryOrder(a, b, carried: carried, of: device, above: published, restored: restored) { tied = true }
            var pairs: [(GroupStamp, GroupStamp)] = []
            for (key, stamps) in parts {
                let images = renamedParts[Self.renamedKey(key, from: device, above: published, to: restored)] ?? []
                guard images.count == stamps.count, let stamp = stamps.first, let image = images.first else {
                    fail("a carry lost or doubled a stamped part: \(key)")
                    continue
                }
                pairs.append((stamp, image))
            }
            for stamps in Self.stampedParts(b).values { for stamp in stamps { pairs.append((stamp, stamp)) } }
            for (x, xImage) in pairs {
                for (y, yImage) in pairs
                where x.seen.contains(y.revision) != xImage.seen.contains(yImage.revision) {
                    fail("a carry changed whether a part supersedes or covers another")
                }
            }
        }
        // 4.
        let raised = checkThirdDevicesUnchanged(a, of: device, given: given, restored: restored)
        let renamed = (ItemMerge.effectiveClock(a.item, origin: a.origin).entries[device] ?? 0) > published
        return (renamed, raised, tied)
    }
}

extension MergeModel {
    /// Law 4 of `checkReattribution`: carried above `given`, every stamp, discard and note line of `a` that a device
    /// other than the earlier ID and the restored one wrote is unchanged, byte for byte (review of round 13, M1).
    /// Returns whether one of them had seen the earlier ID above `given`: the case the code before M1 rewrote.
    mutating func checkThirdDevicesUnchanged(_ a: Version, of device: UUID, given: UInt64, restored: UUID) -> Bool {
        func third(_ owner: UUID) -> Bool { owner != device && owner != restored }
        let low = Self.carried(a, from: device, above: given, to: restored)
        let parts = Self.stampedParts(a)
        let lowParts = Self.stampedParts(low)
        var raised = false
        for (key, stamps) in parts where stamps.contains(where: { third($0.revision.device) }) {
            if lowParts[key] != stamps { fail("a carry rewrote another device's part: \(key)") }
            if stamps.contains(where: { ($0.seen.entries[device] ?? 0) > given }) { raised = true }
        }
        let lowLines = Dictionary(
            ItemState(low.item, origin: low.origin).lines.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        for line in ItemState(a.item, origin: a.origin).lines where third(line.id.revision.device) {
            guard let kept = lowLines[line.id], kept.after == line.after, Self.bytes(kept.text) == Self.bytes(line.text)
            else {
                fail("a carry rewrote another device's note line")
                continue
            }
            if let after = line.after, after.revision.device == device, after.revision.version > given { raised = true }
        }
        return raised
    }

    /// The carry of a version `a` the earlier ID `device` stored, against a version `b` another device stored, at the
    /// least bound both allow (what `b` holds of the earlier ID, and what `a` shows a third device saw of it): carried
    /// before their merge it is what a device holding `b` holds (`checkCarryOrder`), it is idempotent, and, from a
    /// bound of 0, rewrites no third device's part. Returns whether anything was renamed, and whether the field
    /// orders tied.
    mutating func checkCarry(_ a: Version, against b: Version, of device: UUID, restored: UUID) -> (
        renamed: Bool, tied: Bool
    ) {
        let bound = max(
            ItemMerge.effectiveClock(b.item, origin: b.origin).entries[device] ?? 0,
            ItemMerge.seenByOthers(ItemState(a.item, origin: a.origin), of: device, besides: restored))
        let carried = Self.carried(a, from: device, above: bound, to: restored)
        if Self.carried(carried, from: device, above: bound, to: restored).item != carried.item {
            fail("a carry is not idempotent")
        }
        let tie = checkCarryOrder(a, b, carried: carried, of: device, above: bound, restored: restored)
        _ = checkThirdDevicesUnchanged(a, of: device, given: 0, restored: restored)
        return (carried.item != a.item, tie)
    }

    /// Law 1 of `checkReattribution`, for one `b` (review of round 14, L1; review of round 15, Z210). The reference is
    /// what every device holding `b` holds once it merges the published carry, `b ⊔ R(a)`; the restored device that
    /// carries before it merges (`VaultSession.syncAll`) holds `R(a) ⊔ b`. That the two agree, and that merging `b`
    /// again changes nothing, is the join's commutativity and idempotence: checked, but true of any renaming. The law
    /// proper is about the other order: renamed after the merge, `R(a ⊔ b)` must equal the reference in every part
    /// but the field order, and in the order too unless `a`'s renamed order and `b`'s tie at one version (the order is
    /// a register whose later write wins, two concurrent orders at one version are ordered by device ID, and the new
    /// ID can rank otherwise against a third device than the earlier ID did). Where they tie it differs, which is why
    /// the session carries first; the exhaustive exploration asserts that such cases occur (`tiedCarries`), so that
    /// the model goes on showing that order to be wrong. No model law sees the session's own order:
    /// `carryBeforeTheMergeKeepsTheFieldOrder` (the shared-vault adversarial suite) fails if the session merges first.
    /// Returns whether they tied.
    mutating func checkCarryOrder(
        _ a: Version, _ b: Version, carried: Version, of device: UUID, above bound: UInt64, restored: UUID
    ) -> Bool {
        let before = Self.join(carried, b)
        if Self.join(before, b).item != before.item || Self.join(b, carried).item != before.item {
            fail("the carry before the merge is not what a device holding the pulled version holds")
        }
        let after = Self.carried(Self.join(a, b), from: device, above: bound, to: restored)
        guard after.item != before.item else { return false }
        var aligned = ItemState(after.item, origin: after.origin)
        let expected = ItemState(before.item, origin: before.origin)
        let orders = (ItemState(a.item, origin: a.origin).order, ItemState(b.item, origin: b.origin).order)
        let tied =
            orders.0.stamp.revision.version == orders.1.stamp.revision.version
            && orders.0.stamp.revision.device == device && orders.0.stamp.revision.version > bound
            && orders.1.stamp.revision.device != device
        aligned.order = expected.order
        if !tied || aligned.item != expected.item {
            fail("renaming after the merge differs from renaming before it beyond a field order's tie")
        }
        return tied
    }
}
