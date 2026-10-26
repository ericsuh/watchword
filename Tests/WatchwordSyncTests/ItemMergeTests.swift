import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordSync

enum MergeFixtures {
    static let vault = SyncFixtures.vault
    static let a = SyncFixtures.deviceA
    static let b = SyncFixtures.deviceB
    static let c = SyncFixtures.deviceC

    static let longNotes = (1...12).map { "Paragraph \($0): account details line \($0)." }.joined(separator: "\n")

    static func base(notes: String = "") -> Item {
        let item = Item(
            id: UUID(uuidString: "17E00000-0000-4000-8000-000000000001")!, vaultID: vault, title: "Bank",
            scopes: [ServiceScope(host: "firstbank.co.uk")],
            fields: [
                Field(id: fieldID(1), kind: .username, label: "Username", value: "pat"),
                Field(id: fieldID(2), kind: .password, label: "Password", value: "old-password"),
            ],
            notes: notes,
            createdAt: Date(timeIntervalSince1970: 1_800_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_800_000_000),
            version: 1)
        return ItemMerge.stamped(item, previous: nil, revision: Revision(version: 1, device: a))
    }

    static func fieldID(_ n: UInt8) -> UUID {
        UUID(uuid: (0xF1, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, n))
    }

    /// `previous` edited by `device` at `version`, stamped as the vault would stamp it.
    static func edit(_ previous: Item, by device: UUID, at version: UInt64, _ change: (inout Item) -> Void) -> Item {
        var item = previous
        change(&item)
        item.version = version
        item.modifiedAt = Date(timeIntervalSince1970: 1_800_000_000 + Double(version))
        if previous.fields != item.fields {
            item.history.insert(
                ItemHistoryEntry(replacedAt: item.modifiedAt, version: previous.version, fields: previous.fields), at: 0
            )
        }
        return ItemMerge.stamped(
            item, previous: previous, previousOrigin: origin(previous, device),
            revision: Revision(version: version, device: device))
    }

    /// The origin of a version: the version it carries and, for the fixtures, the device given.
    static func origin(_ item: Item, _ device: UUID) -> Revision {
        Revision(version: item.version, device: device)
    }

    static func merge(_ x: (Item, UUID), _ y: (Item, UUID)) -> Item {
        ItemMerge.merge(x.0, origin: origin(x.0, x.1), y.0, origin: origin(y.0, y.1))
    }

    /// Everything that must agree across devices: all but `version` and the history's order.
    static func current(_ item: Item) -> Item {
        var item = item
        item.version = 0
        item.history = item.history.sorted(by: ItemMerge.historyOrder)
        return item
    }

    static func unordered(_ item: Item) -> Item {
        var item = current(item)
        item.fields.sort { $0.id.precedes($1.id) }
        return item
    }

    static func conflictValues(_ item: Item, _ group: ItemGroup) -> [ItemGroupValue] {
        (item.conflicts[group] ?? []).map(\.value)
    }

    static func password(_ value: String) -> ItemGroupValue {
        .field(Field(id: fieldID(2), kind: .password, label: "Password", value: value))
    }
}

@Suite("Field-level item merge")
struct ItemMergeTests {
    typealias F = MergeFixtures

    @Test("a new item has every group stamped; an edit stamps only what changed and never moves modifiedAt back")
    func stamping() {
        let base = F.base(notes: "one\ntwo")
        #expect(Set(base.revisions.keys) == Set(ItemGroup.attributes + [.field(F.fieldID(1)), .field(F.fieldID(2))]))
        #expect(base.revisions.values.allSatisfy { $0.revision == Revision(version: 1, device: F.a) })
        #expect(base.noteLines.count == 2 && base.notes == "one\ntwo")
        let edited = F.edit(base, by: F.b, at: 2) { $0.title = "First Bank" }
        #expect(edited.revisions[.title]?.revision == Revision(version: 2, device: F.b))
        #expect(edited.revisions[.title]?.seen.contains(Revision(version: 1, device: F.a)) == true)
        #expect(edited.revisions[.field(F.fieldID(2))]?.revision == Revision(version: 1, device: F.a))
        let removed = F.edit(edited, by: F.a, at: 3) { $0.fields.removeAll { $0.id == F.fieldID(1) } }
        #expect(removed.revisions[.field(F.fieldID(1))]?.revision == Revision(version: 3, device: F.a))
        var slowClock = removed
        slowClock.modifiedAt = Date(timeIntervalSince1970: 0)
        let saved = ItemMerge.stamped(slowClock, previous: removed, revision: Revision(version: 4, device: F.c))
        #expect(saved.modifiedAt == removed.modifiedAt, "a device with a slow clock never moves modifiedAt back")
    }

    @Test("concurrent edits to separate fields both survive, with no conflict")
    func separateFields() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "new-password" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields[0].value = "pat.smith" }
        for merged in [F.merge((onA, F.a), (onB, F.b)), F.merge((onB, F.b), (onA, F.a))] {
            #expect(merged.field(.password)?.value == "new-password")
            #expect(merged.field(.username)?.value == "pat.smith")
            #expect(!merged.hasConflicts)
        }
    }

    @Test("concurrent edits to the same field keep both values: one shown, the other kept as a conflict (F7.6)")
    func sameFieldKeepsBoth() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "password-from-A" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "password-from-B" }
        let ab = F.merge((onA, F.a), (onB, F.b))
        let ba = F.merge((onB, F.b), (onA, F.a))
        #expect(F.current(ab) == F.current(ba))
        // Same version: the higher device ID (B) is shown; A's value is kept.
        #expect(ab.field(.password)?.value == "password-from-B")
        #expect(F.conflictValues(ab, .field(F.fieldID(2))) == [F.password("password-from-A")])
        #expect(ItemMerge.conflicts(of: ab).count == 1)
    }

    @Test("three devices editing one field concurrently: all three values kept, whatever the merge order")
    func threeWayConflict() {
        let base = F.base()
        let versions = [(F.a, "from-A"), (F.b, "from-B"), (F.c, "from-C")].map { device, value in
            (F.edit(base, by: device, at: 2) { $0.fields[1].value = value }, device)
        }
        var results: [Item] = []
        for order in [[0, 1, 2], [2, 1, 0], [1, 0, 2], [2, 0, 1]] {
            var merged = versions[order[0]]
            for index in order.dropFirst() {
                merged = (F.merge(merged, versions[index]), merged.1)
            }
            results.append(merged.0)
        }
        for result in results {
            #expect(F.current(result) == F.current(results[0]))
            let kept = F.conflictValues(result, .field(F.fieldID(2))).compactMap { value -> String? in
                if case .field(let field?) = value { return field.value }
                return nil
            }
            #expect(Set([result.field(.password)!.value] + kept) == ["from-A", "from-B", "from-C"])
        }
    }

    @Test("an edit made after seeing another replaces it: no conflict")
    func sequentialEdits() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "first" }
        let onB = F.edit(onA, by: F.b, at: 3) { $0.fields[1].value = "second" }
        let merged = F.merge((onA, F.a), (onB, F.b))
        #expect(merged.field(.password)?.value == "second")
        #expect(!merged.hasConflicts)
    }

    @Test("identical concurrent values are not a conflict")
    func identicalValues() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.title = "Same" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.title = "Same" }
        #expect(!F.merge((onA, F.a), (onB, F.b)).hasConflicts)
    }

    @Test("conflicts persist through unrelated edits and merges until the person resolves them")
    func resolutionIsExplicit() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "from-A" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "from-B" }
        var merged = F.merge((onA, F.a), (onB, F.b))
        for version in UInt64(3)...UInt64(150) {
            merged = F.edit(merged, by: F.a, at: version) { $0.notes = "edit \(version)" }
        }
        #expect(F.conflictValues(merged, .field(F.fieldID(2))) == [F.password("from-A")], "kept through 148 saves")

        // Choosing A's value: it is shown, and the choice supersedes B's on a device that still has the conflict.
        let resolved = ItemMerge.resolve(
            merged, group: .field(F.fieldID(2)), choosing: F.password("from-A"), origin: F.origin(merged, F.a),
            revision: Revision(version: 151, device: F.a))
        #expect(resolved.field(.password)?.value == "from-A")
        #expect(!resolved.hasConflicts)
        let stale = F.merge((onB, F.b), (onA, F.a))
        let everywhere = F.merge((stale, F.b), (resolved, F.a))
        #expect(everywhere.field(.password)?.value == "from-A")
        #expect(!everywhere.hasConflicts)
    }

    /// Found by the long simulation: an ordinary edit of a field that held a conflict superseded the conflicting value
    /// and dropped it. Editing settles what is shown; it is not a choice to discard the other value.
    @Test("editing a field that holds a conflict keeps the conflicting value, retained")
    func editKeepsConflictingValue() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "from-A" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "from-B" }
        let merged = F.merge((onA, F.a), (onB, F.b))
        let edited = F.edit(merged, by: F.a, at: 3) { $0.fields[1].value = "typed-later" }
        #expect(edited.field(.password)?.value == "typed-later")
        #expect(!edited.hasConflicts)
        #expect(edited.retainedValues.map(\.value) == [F.password("from-A")])
        #expect(edited.history.flatMap(\.fields).contains { $0.value == "from-B" }, "the shown value went to history")
        // Retained values survive merges with versions that never had them.
        let elsewhere = F.merge((onB, F.b), (edited, F.a))
        #expect(elsewhere.retainedValues.map(\.value) == [F.password("from-A")])
    }

    /// Found by the long simulation: devices that merged the same edits wrote their results as different versions,
    /// each recording its own write in the clock, so every exchange looked like news and sync never settled.
    @Test("devices that merge the same edits hold the same state, whoever writes the result down")
    func mergeResultsAreTheSameState() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "from-A" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.notes = "from-B" }
        let writtenByA = ItemMerge.written(F.merge((onA, F.a), (onB, F.b)), as: Revision(version: 3, device: F.a))
        let writtenByB = ItemMerge.written(F.merge((onB, F.b), (onA, F.a)), as: Revision(version: 3, device: F.b))
        #expect(ItemMerge.sameState(writtenByA, writtenByB))
        let again = ItemMerge.merge(
            writtenByA, origin: Revision(version: 3, device: F.a), writtenByB, origin: Revision(version: 3, device: F.b)
        )
        #expect(ItemMerge.sameState(again, writtenByA))
    }

    @Test("removing a field while another device edits it: removed, with the edit kept as a conflict")
    func fieldDeleteVersusEdit() {
        let base = F.base()
        let removed = F.edit(base, by: F.a, at: 2) { $0.fields.removeAll { $0.kind == .password } }
        let edited = F.edit(base, by: F.b, at: 3) { $0.fields[1].value = "edited-meanwhile" }
        for merged in [F.merge((removed, F.a), (edited, F.b)), F.merge((edited, F.b), (removed, F.a))] {
            #expect(merged.field(.password) == nil, "the deletion is shown")
            #expect(F.conflictValues(merged, .field(F.fieldID(2))) == [F.password("edited-meanwhile")])
        }
        let restored = ItemMerge.resolve(
            F.merge((removed, F.a), (edited, F.b)), group: .field(F.fieldID(2)),
            choosing: F.password("edited-meanwhile"), origin: Revision(version: 3, device: F.a),
            revision: Revision(version: 4, device: F.a))
        #expect(restored.field(.password)?.value == "edited-meanwhile")
    }

    @Test("trashing while another device edits: trashed, with the edit in the item")
    func trashVersusEdit() {
        let base = F.base()
        let trashed = F.edit(base, by: F.a, at: 2) { $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_100) }
        let edited = F.edit(base, by: F.b, at: 5) { $0.fields[1].value = "edited-meanwhile" }
        let merged = F.merge((trashed, F.a), (edited, F.b))
        #expect(merged.isTrashed)
        #expect(merged.field(.password)?.value == "edited-meanwhile")
        let restoredMeanwhile = F.edit(trashed, by: F.b, at: 6) { $0.trashedAt = nil }
        let trashedAgain = F.edit(trashed, by: F.c, at: 6) { $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_200) }
        #expect(F.merge((restoredMeanwhile, F.b), (trashedAgain, F.c)).isTrashed, "a deletion is shown over a restore")
    }

    /// The 30-day purge removes only a trash that a person chose knowing everything in the item (PRD F1.5, F7.7).
    @Test("only a trash written knowing the whole item is one the purge may remove")
    func trashedByPerson() {
        let base = F.base()
        let trashed = F.edit(base, by: F.a, at: 2) { $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_100) }
        #expect(trashed.isTrashedByPerson)
        #expect(F.merge((trashed, F.a), (base, F.b)).isTrashedByPerson, "a device that only receives the trash agrees")
        #expect(!base.isTrashedByPerson)

        let edited = F.edit(base, by: F.b, at: 5) { $0.fields[1].value = "edited-meanwhile" }
        #expect(!F.merge((trashed, F.a), (edited, F.b)).isTrashedByPerson, "an edit the trash never saw")
        #expect(!F.edit(trashed, by: F.b, at: 3) { $0.title = "Renamed" }.isTrashedByPerson, "an edit after the trash")

        let restoredMeanwhile = F.edit(trashed, by: F.b, at: 6) { $0.trashedAt = nil }
        let trashedAgain = F.edit(trashed, by: F.c, at: 6) { $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_200) }
        let disputed = F.merge((restoredMeanwhile, F.b), (trashedAgain, F.c))
        #expect(!disputed.isTrashedByPerson, "a concurrent restore is the person's too")
        #expect(
            F.edit(disputed, by: F.a, at: 7) { $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_300) }
                .isTrashedByPerson, "trashing again where the conflict is shown settles it")

        var kept = F.edit(edited, by: F.b, at: 8) {
            $0.trashedAt = $0.modifiedAt
            $0.keptAfterDeletion = true
        }
        #expect(!kept.isTrashedByPerson, "kept after a deletion that had not seen it")
        kept = F.edit(kept, by: F.a, at: 9) {
            $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_400)
            $0.keptAfterDeletion = false
        }
        #expect(kept.isTrashedByPerson, "moved to the trash by a person, as `VaultSession.trash` writes it")
    }

    @Test("notes edited in different places on two devices merge line by line")
    func notesDifferentLines() {
        let base = F.base(notes: F.longNotes)
        let onA = F.edit(base, by: F.a, at: 2) {
            $0.notes = $0.notes.replacingOccurrences(of: "Paragraph 2:", with: "Paragraph 2 (A edited):")
        }
        let onB = F.edit(base, by: F.b, at: 2) {
            $0.notes =
                $0.notes.replacingOccurrences(of: "Paragraph 11:", with: "Paragraph 11 (B edited):") + "\nB's new line"
        }
        let merged = F.merge((onA, F.a), (onB, F.b))
        #expect(merged.notes == F.merge((onB, F.b), (onA, F.a)).notes)
        let lines = merged.notes.split(separator: "\n").map(String.init)
        #expect(lines.count == 13)
        #expect(lines[1].hasPrefix("Paragraph 2 (A edited):"))
        #expect(lines[10].hasPrefix("Paragraph 11 (B edited):"))
        #expect(lines.last == "B's new line")
        #expect(!merged.notes.contains("Paragraph 2: "), "the edited line is replaced, not duplicated")
    }

    @Test("the same line of the notes edited on two devices: both versions are kept")
    func notesSameLine() {
        let base = F.base(notes: F.longNotes)
        let onA = F.edit(base, by: F.a, at: 2) {
            $0.notes = $0.notes.replacingOccurrences(of: "line 5.", with: "line 5, as A wrote it.")
        }
        let onB = F.edit(base, by: F.b, at: 2) {
            $0.notes = $0.notes.replacingOccurrences(of: "line 5.", with: "line 5, as B wrote it.")
        }
        let merged = F.merge((onA, F.a), (onB, F.b))
        #expect(merged.notes == F.merge((onB, F.b), (onA, F.a)).notes)
        #expect(merged.notes.contains("as A wrote it") && merged.notes.contains("as B wrote it"))
        #expect(merged.notes.split(separator: "\n").count == 13)
    }

    @Test("a paragraph deleted on one device while another edits it: the edit is kept")
    func notesDeleteVersusEdit() {
        let base = F.base(notes: F.longNotes)
        let deleted = F.edit(base, by: F.a, at: 2) {
            $0.notes = $0.notes.split(separator: "\n").filter { !$0.contains("Paragraph 7") }.joined(separator: "\n")
        }
        let edited = F.edit(base, by: F.b, at: 2) {
            $0.notes = $0.notes.replacingOccurrences(of: "Paragraph 7:", with: "Paragraph 7 (edited):")
        }
        let merged = F.merge((deleted, F.a), (edited, F.b))
        #expect(merged.notes.contains("Paragraph 7 (edited):"))
        #expect(merged.notes.split(separator: "\n").count == 12)
    }

    @Test("items from before sync merge without losing either version")
    func legacy() {
        var old = F.base()
        old.revisions = [:]
        old.clock = VersionVector()
        old.noteLines = []
        var newer = old
        newer.title = "Newer"
        newer.version = 5
        let merged = ItemMerge.merge(
            old, origin: Revision(version: 1, device: F.c), newer, origin: Revision(version: 5, device: F.a))
        #expect(merged.title == "Newer")
        #expect(F.conflictValues(merged, .title) == [.title("Bank")], "without history, the older title is kept")
        #expect(merged.revisions[.title]?.revision == Revision(version: 5, device: F.a))
    }

    @Test("sync metadata survives the item payload codec, and payloads without it still decode")
    func codec() throws {
        let base = F.base(notes: "a\nb")
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "x" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "y" }
        let item = F.merge((onA, F.a), (onB, F.b))
        let encoder = JSONEncoder()
        #expect(try JSONDecoder().decode(Item.self, from: encoder.encode(item)) == item)
        var object = try JSONSerialization.jsonObject(with: encoder.encode(item)) as! [String: Any]
        for key in ["revisions", "conflicts", "clock", "noteLines"] { object[key] = nil }
        let legacy = try JSONDecoder().decode(Item.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(legacy.revisions.isEmpty && legacy.conflicts.isEmpty && legacy.noteLines.isEmpty)
        #expect(legacy.notes == "a\nb")
    }

    /// The property convergence rests on: merging is a join, so order, grouping and repetition do not matter.
    @Test("merging is commutative, idempotent, and associative up to field order, under random concurrent edits")
    func joinProperties() {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0xC0FFEE))
        for _ in 0..<TestEnvironment.iterations(standard: 300, long: 20_000) {
            var versions: [(Item, UUID)] = []
            for device in [F.a, F.b, F.c] {
                var item = F.base(notes: "one\ntwo\nthree")
                var version: UInt64 = 1
                for _ in 0..<Int.random(in: 1...4, using: &generator) {
                    version += UInt64.random(in: 1...3, using: &generator)
                    item = F.edit(item, by: device, at: version) { Self.randomEdit(&$0, using: &generator) }
                }
                versions.append((item, device))
            }
            let (x, y, z) = (versions[0], versions[1], versions[2])
            // A merge result fed back in claims no write of its own (version 0): its origins are already in its clock.
            let xy = ItemMerge.merge(x.0, origin: F.origin(x.0, x.1), y.0, origin: F.origin(y.0, y.1))
            let none = Revision(version: 0, device: F.a)
            #expect(F.current(xy) == F.current(F.merge(y, x)))
            let yz = ItemMerge.merge(y.0, origin: F.origin(y.0, y.1), z.0, origin: F.origin(z.0, z.1))
            let left = ItemMerge.merge(xy, origin: none, z.0, origin: F.origin(z.0, z.1))
            let right = ItemMerge.merge(x.0, origin: F.origin(x.0, x.1), yz, origin: none)
            #expect(F.unordered(left) == F.unordered(right))
            #expect(F.current(F.merge(x, x)) == F.current(x.0))
            #expect(F.current(ItemMerge.merge(xy, origin: none, x.0, origin: F.origin(x.0, x.1))) == F.current(xy))
        }
    }

    static func randomEdit(_ item: inout Item, using generator: inout SeededGenerator) {
        let word = ["alpha", "beta", "gamma", "delta"].randomElement(using: &generator)!
        switch Int.random(in: 0..<10, using: &generator) {
        case 0: item.title = word
        case 1:
            var lines = NoteText.lines(of: item.notes)
            lines.insert(word, at: Int.random(in: 0...lines.count, using: &generator))
            item.notes = lines.joined(separator: "\n")
        case 2:
            var lines = NoteText.lines(of: item.notes)
            if !lines.isEmpty { lines[Int.random(in: 0..<lines.count, using: &generator)] = word }
            item.notes = lines.joined(separator: "\n")
        case 3: item.tags.insert(word)
        case 4: item.archived.toggle()
        case 5:
            if !item.fields.isEmpty {
                item.fields[Int.random(in: 0..<item.fields.count, using: &generator)].value = word
            }
        case 6:
            item.fields.append(
                Field(id: F.fieldID(UInt8.random(in: 3...9, using: &generator)), kind: .text, label: word, value: word))
            var seen: Set<UUID> = []
            item.fields = item.fields.filter { seen.insert($0.id).inserted }
        case 7:
            if !item.fields.isEmpty { item.fields.remove(at: Int.random(in: 0..<item.fields.count, using: &generator)) }
        case 8: item.trashedAt = item.trashedAt == nil ? Date(timeIntervalSince1970: 1_800_000_500) : nil
        default: item.fields.shuffle(using: &generator)
        }
    }
}
