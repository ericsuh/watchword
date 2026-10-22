import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// The everyday multi-device cases, end to end through the engine (PRD F7.4, F7.6, F7.7): devices edit at the same
/// time, then sync, and every device must end with the same vault and with nothing anyone typed lost.
@Suite("Simultaneous edits across devices")
struct SyncMergeCaseTests {
    typealias F = MergeFixtures

    /// Three devices, all holding `item`.
    static func household(with item: Item) async throws -> (Household, Item) {
        let home = await Household.make(3)
        let saved = try await home.devices[0].save(item)
        try await home.settle()
        return (home, saved)
    }

    static func everywhere(_ home: Household, _ id: UUID) async throws -> [Item] {
        var items: [Item] = []
        for device in home.devices { items.append(try await device.item(id)) }
        return items
    }

    @Test("edits to separate fields on two devices both arrive everywhere, with no conflict")
    func separateFields() async throws {
        let (home, item) = try await Self.household(with: Household.login())
        try await home.devices[0].edit(item.id) { $0.fields[1].value = "new-password" }
        try await home.devices[1].edit(item.id) { $0.fields[0].value = "pat.smith" }
        try await home.settle()
        try await home.expectConverged()
        for copy in try await Self.everywhere(home, item.id) {
            #expect(copy.field(.password)?.value == "new-password")
            #expect(copy.field(.username)?.value == "pat.smith")
            #expect(!copy.hasConflicts)
        }
    }

    @Test("items created and edited on separate devices at the same time all arrive everywhere")
    func separateItems() async throws {
        let (home, item) = try await Self.household(with: Household.login())
        let fromB = try await home.devices[1].save(Household.login(title: "Library", password: "b"))
        let fromC = try await home.devices[2].save(Household.login(title: "Gym", password: "c"))
        try await home.devices[0].edit(item.id) { $0.title = "Bank (renamed)" }
        try await home.settle()
        try await home.expectConverged()
        let items = try await home.devices[0].items()
        #expect(Set(items.keys) == [item.id, fromB.id, fromC.id])
        #expect(items[item.id]?.title == "Bank (renamed)")
        #expect(items.values.allSatisfy { !$0.hasConflicts })
    }

    @Test("a long note edited in different places on three devices merges line by line everywhere")
    func largeTextBlock() async throws {
        var note = Household.login()
        note.notes = F.longNotes
        let (home, item) = try await Self.household(with: note)
        try await home.devices[0].edit(item.id) {
            $0.notes = $0.notes.replacingOccurrences(of: "Paragraph 1:", with: "Paragraph 1 (from A):")
        }
        try await home.devices[1].edit(item.id) {
            $0.notes = $0.notes.replacingOccurrences(of: "Paragraph 6:", with: "Paragraph 6 (from B):")
        }
        try await home.devices[2].edit(item.id) { $0.notes += "\nA closing line from C" }
        try await home.settle()
        try await home.expectConverged()
        let notes = try await home.devices[0].item(item.id).notes
        #expect(notes.contains("Paragraph 1 (from A):"))
        #expect(notes.contains("Paragraph 6 (from B):"))
        #expect(notes.hasSuffix("A closing line from C"))
        #expect(notes.split(separator: "\n").count == 13)
    }

    @Test("the same line edited on two devices at once: both versions are kept everywhere")
    func sameLineOfText() async throws {
        var note = Household.login()
        note.notes = F.longNotes
        let (home, item) = try await Self.household(with: note)
        try await home.devices[0].edit(item.id) {
            $0.notes = $0.notes.replacingOccurrences(of: "line 3.", with: "line 3 — A's wording.")
        }
        try await home.devices[1].edit(item.id) {
            $0.notes = $0.notes.replacingOccurrences(of: "line 3.", with: "line 3 — B's wording.")
        }
        try await home.settle()
        try await home.expectConverged()
        let notes = try await home.devices[2].item(item.id).notes
        #expect(notes.contains("A's wording") && notes.contains("B's wording"))
    }

    @Test("one field edited on three devices at once: all three values are kept everywhere until resolved")
    func conflictsKeepEveryVersion() async throws {
        let (home, item) = try await Self.household(with: Household.login())
        for (device, value) in zip(home.devices, ["from-A", "from-B", "from-C"]) {
            try await device.edit(item.id) { $0.fields[1].value = value }
        }
        #expect(try await home.settle() <= 4, "merging the same edits settles in a few rounds")
        try await home.expectConverged()
        for copy in try await Self.everywhere(home, item.id) {
            let kept = (copy.conflicts[.field(F.fieldID(2))] ?? []).compactMap { conflict -> String? in
                if case .field(let field?) = conflict.value { return field.value }
                return nil
            }
            #expect(Set([copy.field(.password)!.value] + kept) == ["from-A", "from-B", "from-C"])
        }

        // Unrelated edits and further syncs do not discard them.
        for round in 0..<5 {
            try await home.devices[round % 3].edit(item.id) { $0.title = "Bank \(round)" }
            try await home.settle()
        }
        #expect(try await home.devices[1].item(item.id).conflicts[.field(F.fieldID(2))]?.count == 2)

        // The person chooses on one device; the choice reaches every device and the conflict is gone everywhere.
        let a = home.devices[0]
        let current = try await a.item(item.id)
        let row = try #require(await a.store.record(RecordKey(recordID: item.id, kind: .item)))
        let deviceA = await a.deviceID
        let resolved = ItemMerge.resolve(
            current, group: .field(F.fieldID(2)), choosing: F.password("from-B"),
            origin: Revision(version: row.version, device: row.deviceID),
            revision: Revision(version: row.version + 1, device: deviceA))
        try await a.commitResolved(resolved)
        try await home.settle()
        try await home.expectConverged()
        for copy in try await Self.everywhere(home, item.id) {
            #expect(copy.field(.password)?.value == "from-B")
            #expect(!copy.hasConflicts)
        }
    }

    @Test("moving to the trash while another device edits: trashed everywhere, with the edit in the item")
    func trashAndEdit() async throws {
        let (home, item) = try await Self.household(with: Household.login())
        try await home.devices[0].edit(item.id) { $0.trashedAt = Date(timeIntervalSince1970: 1_900_000_000) }
        try await home.devices[1].edit(item.id) { $0.fields[1].value = "edited-while-trashed" }
        try await home.settle()
        try await home.expectConverged()
        for copy in try await Self.everywhere(home, item.id) {
            #expect(copy.isTrashed)
            #expect(copy.field(.password)?.value == "edited-while-trashed")
        }
    }

    @Test(
        "a permanent delete while another device edits: deleted, with the edit kept as the last version, in the trash")
    func deleteAndEdit() async throws {
        let (home, item) = try await Self.household(with: Household.login())
        try await home.devices[0].delete(item.id)
        try await home.devices[1].edit(item.id) { $0.fields[1].value = "typed-after-the-delete-was-made" }
        try await home.settle()
        try await home.expectConverged()
        for copy in try await Self.everywhere(home, item.id) {
            #expect(copy.isTrashed, "the deletion wins: the item is not back in the vault")
            #expect(copy.field(.password)?.value == "typed-after-the-delete-was-made", "the edit is its last version")
        }
    }

    @Test("a permanent delete made after seeing every edit removes the item everywhere")
    func deleteAfterSeeingEdits() async throws {
        let (home, item) = try await Self.household(with: Household.login())
        try await home.devices[1].edit(item.id) { $0.fields[1].value = "seen-by-A" }
        try await home.settle()
        try await home.devices[0].delete(item.id)
        try await home.settle()
        for device in home.devices { #expect(try await device.items().isEmpty) }
    }

    @Test("removing a field while another device edits it: removed everywhere, with the edit kept as a conflict")
    func removeFieldAndEdit() async throws {
        let (home, item) = try await Self.household(with: Household.login())
        try await home.devices[0].edit(item.id) { $0.fields.removeAll { $0.kind == .password } }
        try await home.devices[1].edit(item.id) { $0.fields[1].value = "edited-while-removed" }
        try await home.settle()
        try await home.expectConverged()
        for copy in try await Self.everywhere(home, item.id) {
            #expect(copy.field(.password) == nil)
            #expect(copy.conflicts[.field(F.fieldID(2))]?.map(\.value) == [F.password("edited-while-removed")])
        }
    }
}
