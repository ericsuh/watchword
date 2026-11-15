import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// Regression tests for the audit of the item merge as a CRDT (docs/06-adversarial-review.md §H, Y18–Y27;
/// docs/10-sync-correctness.md). Each is the smallest history that showed the finding; the laws themselves are
/// checked at large in `LongRunningItemMergeLawTests` and `LongRunningItemMergeExhaustiveTests`.
@Suite("Item merge audit regressions")
struct ItemMergeAuditTests {
    typealias F = MergeFixtures

    /// A merge result fed back into a merge: it is read at its own version, and claims no write of its own.
    static func again(_ item: Item) -> (Item, UUID) {
        (item, ItemMerge.zeroDevice)
    }

    // MARK: - Registers

    /// Y18. Two devices wrote the same title concurrently; the merge kept one stamp and dropped the other. A third
    /// device that had seen only the kept one then replaced the title — and whether the first device's write survived
    /// as a conflict depended on the order the three versions were merged in.
    @Test("concurrent writes of one value are each kept: merging in any order gives the same item")
    func sameValueWrittenTwice() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.title = "Same" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.title = "Same" }
        let onC = F.edit(onB, by: F.c, at: 3) { $0.title = "Changed, having seen only B's" }

        let both = F.merge((onA, F.a), (onB, F.b))
        #expect(!both.hasConflicts && ItemMerge.conflicts(of: both).isEmpty, "the same value twice is not a conflict")
        #expect(both.conflicts[.title]?.count == 1, "but both writes are kept")

        let left = F.merge(Self.again(both), (onC, F.c))
        let right = F.merge((onA, F.a), Self.again(F.merge((onB, F.b), (onC, F.c))))
        #expect(left == right)
        // A's write was concurrent with C's, so it is a conflict, whichever way round the merges were made.
        #expect(left.title == "Changed, having seen only B's")
        #expect(ItemMerge.conflicts(of: left)[.title]?.map(\.value) == [.title("Same")])
    }

    /// Y19. Resolving a conflict discarded the values retained for the group — on the resolving device only. Merging
    /// any other copy brought them back, so the discard was undone by the next sync, and the resolved version did not
    /// contain the version it was made on.
    @Test("a resolution discards retained values for good: a copy that still holds them does not bring them back")
    func resolutionDiscardsEverywhere() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "from-A" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "from-B" }
        let merged = F.merge((onA, F.a), (onB, F.b))
        // Both devices edit the field while the conflict stands (each retains the value not shown), concurrently.
        let editedOnA = F.edit(merged, by: F.a, at: 3) { $0.fields[1].value = "typed-on-A" }
        let editedOnB = F.edit(merged, by: F.b, at: 3) { $0.fields[1].value = "typed-on-B" }
        let stale = F.merge((editedOnA, F.a), (editedOnB, F.b))
        #expect(stale.retainedValues.map(\.value) == [F.password("from-A")])
        #expect(ItemMerge.conflicts(of: stale).count == 1)

        let resolved = ItemMerge.resolve(
            stale, group: .field(F.fieldID(2)), choosing: F.password("typed-on-A"), origin: F.origin(stale, F.a),
            revision: Revision(version: 5, device: F.a))
        #expect(resolved.retainedValues.isEmpty && !resolved.hasConflicts)
        #expect(F.merge((resolved, F.a), (stale, F.b)) == resolved, "the stale copy adds nothing")
        #expect(F.merge((resolved, F.a), (editedOnB, F.b)).retainedValues.isEmpty)

        // What the resolver had not seen is not discarded: a value retained by an edit made concurrently stays.
        let concurrent = F.edit(stale, by: F.c, at: 5) { $0.fields[1].value = "typed-on-C" }
        let all = F.merge((resolved, F.a), (concurrent, F.c))
        #expect(all.retainedValues.isEmpty, "C retained the conflict the resolver had before them, and discarded")
        #expect(
            Set([all.field(.password)!.value] + F.conflictValues(all, .field(F.fieldID(2))).map(Self.text)) == [
                "typed-on-A", "typed-on-C",
            ])
        // The value the resolver chose, retained by a later edit, is kept: the discard covers only what came before.
        let later = F.edit(all, by: F.b, at: 7) { $0.fields[1].value = "typed-last" }
        #expect(later.retainedValues.count == 1)
        #expect(F.merge((later, F.b), (resolved, F.a)).retainedValues == later.retainedValues)
    }

    static func text(_ value: ItemGroupValue) -> String {
        if case .field(let field?) = value { return field.value }
        return ""
    }

    // MARK: - Field order

    /// Y4, now fixed. The order of the fields was read off `fields`, which lists only the fields present, so a field
    /// removed in an intermediate merge and brought back later lost its place, and the result depended on the order of
    /// merges. The order is stored (`Item.fieldOrder`) and is a last-writer-wins register.
    @Test("field order is an exact join: a field removed and brought back returns to its place, whatever the order")
    func fieldOrderIsAJoin() {
        let base = F.base()
        let reordered = F.edit(base, by: F.a, at: 2) { $0.fields.reverse() }
        #expect(reordered.fieldOrder == [F.fieldID(2), F.fieldID(1)])
        let removed = F.edit(reordered, by: F.b, at: 3) { $0.fields.removeAll { $0.id == F.fieldID(2) } }
        #expect(removed.revisions[.fieldOrder] == reordered.revisions[.fieldOrder], "removing a field is no reorder")
        #expect(removed.fieldOrder == [F.fieldID(2), F.fieldID(1)], "the order still lists the field removed")
        let edited = F.edit(reordered, by: F.c, at: 3) { $0.fields[0].value = "edited-while-removed" }
        let conflict = F.merge((removed, F.b), (edited, F.c))
        #expect(conflict.fields.map(\.id) == [F.fieldID(1)])
        let restored = ItemMerge.resolve(
            conflict, group: .field(F.fieldID(2)), choosing: F.password("edited-while-removed"),
            origin: F.origin(conflict, F.b), revision: Revision(version: 5, device: F.b))
        #expect(restored.fields.map(\.id) == [F.fieldID(2), F.fieldID(1)], "back in its place, not at the end")

        let versions = [(removed, F.b), (edited, F.c), (restored, F.b), (reordered, F.a)]
        let reference = F.merge(
            Self.again(F.merge(versions[0], versions[1])), Self.again(F.merge(versions[2], versions[3])))
        #expect(reference == restored)
        #expect(
            F.merge(versions[0], Self.again(F.merge(versions[1], Self.again(F.merge(versions[2], versions[3])))))
                == reference)
        #expect(
            F.merge(Self.again(F.merge(versions[3], versions[2])), Self.again(F.merge(versions[1], versions[0])))
                == reference)
    }

    @Test("concurrent reorders: the later one stands on every device; additions and removals do not compete with it")
    func fieldOrderLastWriterWins() {
        var base = F.base()
        base = F.edit(base, by: F.a, at: 2) {
            $0.fields.append(Field(id: F.fieldID(3), kind: .text, label: "Memorable word", value: "heron"))
        }
        #expect(base.revisions[.fieldOrder]?.revision.version == 1, "a field appended is where the order puts it")
        let onA = F.edit(base, by: F.a, at: 3) { $0.fields.swapAt(0, 2) }
        let onB = F.edit(base, by: F.b, at: 4) { $0.fields.swapAt(0, 1) }
        for merged in [F.merge((onA, F.a), (onB, F.b)), F.merge((onB, F.b), (onA, F.a))] {
            #expect(merged.fields.map(\.id) == onB.fields.map(\.id), "the later reorder")
            #expect(merged.conflicts[.fieldOrder] == nil, "an arrangement holds no contents: the other is not kept")
        }
        // A device that adds a field and one that removes one, concurrently with a reorder: the reorder stands, the
        // new field follows it, the removed one is gone.
        let added = F.edit(base, by: F.b, at: 3) {
            $0.fields.append(Field(id: F.fieldID(4), kind: .text, label: "Branch", value: "Leeds"))
        }
        let removed = F.edit(base, by: F.c, at: 5) { $0.fields.remove(at: 0) }
        let all = F.merge(Self.again(F.merge((onA, F.a), (added, F.b))), (removed, F.c))
        #expect(all.fields.map(\.id) == [F.fieldID(3), F.fieldID(2), F.fieldID(4)])
        #expect(all == F.merge((removed, F.c), Self.again(F.merge((added, F.b), (onA, F.a)))))
    }

    // MARK: - Notes

    @Test("every line break ends a line, the one in a CR-LF pair too, and the text round-trips exactly")
    func lineBreaks() {
        #expect(NoteText.lines(of: "one\r\ntwo\r\n\nfour") == ["one\r", "two\r", "", "four"])
        for text in ["", "one", "one\n", "\n", "one\r\ntwo", "é\ne\u{301}"] {
            let lines = NoteText.initial(text, revision: Revision(version: 1, device: F.a))
            #expect(NoteText.text(lines).utf8.elementsEqual(text.utf8))
            #expect(lines.allSatisfy { !$0.text.utf8.contains(UInt8(ascii: "\n")) })
        }
    }

    @Test("saving without touching the notes writes no line, and an edit never drops one")
    func noteEditsContainTheirPredecessor() {
        let base = F.base(notes: F.longNotes)
        let renamed = F.edit(base, by: F.b, at: 2) { $0.title = "Renamed" }
        #expect(renamed.noteLines == base.noteLines)
        let edited = F.edit(renamed, by: F.b, at: 3) { $0.notes = "replaced entirely" }
        #expect(NoteText.merge(edited.noteLines, base.noteLines) == edited.noteLines)
        #expect(edited.noteLines.count == base.noteLines.count + 1)
    }

    // MARK: - Reading

    @Test(
        "an item this code wrote reads back unchanged; one written before the order was stored takes it from its fields"
    )
    func canonicalForm() throws {
        let base = F.base(notes: "a\nb")
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "x" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields.reverse() }
        let merged = F.merge((onA, F.a), (onB, F.b))
        for item in [base, onA, onB, merged] {
            #expect(ItemMerge.canonical(item, origin: F.origin(item, F.a)) == item)
            #expect(try JSONDecoder().decode(Item.self, from: JSONEncoder().encode(item)) == item)
        }
        // A payload from before `fieldOrder` and `discards` existed.
        var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(onB)) as! [String: Any]
        object["fieldOrder"] = nil
        object["discards"] = nil
        let older = try JSONDecoder().decode(Item.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(older.fieldOrder == nil && older.discards.isEmpty)
        #expect(ItemMerge.canonical(older, origin: F.origin(older, F.b)) == onB)
        #expect(F.merge((older, F.b), (onA, F.a)) == merged)
    }

    // MARK: - Permanent deletion

    static func erasure(of item: Item, by device: UUID) -> ItemErasure {
        ItemErasure(
            seen: ItemMerge.effectiveClock(item, origin: F.origin(item, device)), row: item.version, device: device,
            date: item.modifiedAt)
    }

    /// Y25. A version kept after a deletion was a fresh edit by each device that kept one, so devices that kept the
    /// same edit held different items until they had exchanged them; and a kept item a person then restored was put
    /// back in the trash whenever its device met the tombstone again (a reconciling sync, a device joining), which
    /// undid the restore everywhere. The deletion is now one write, the same on every device.
    @Test("a deletion that did not see an edit is one write: every device keeps the same item, and a restore stands")
    func deletionIsOneWrite() throws {
        let base = F.base()
        let trashed = F.edit(base, by: F.a, at: 2) { $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_100) }
        let erasure = Self.erasure(of: trashed, by: F.a)
        #expect(erasure.revision == Revision(version: 3, device: F.a))
        #expect(ItemMerge.settle(trashed, origin: F.origin(trashed, F.a), against: erasure) == .erase)
        #expect(ItemMerge.settle(base, origin: F.origin(base, F.a), against: erasure) == .erase)

        let edited = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "typed-meanwhile" }
        guard case .kept(let kept) = ItemMerge.settle(edited, origin: F.origin(edited, F.b), against: erasure) else {
            Issue.record("an edit the deletion had not seen was not kept")
            return
        }
        #expect(kept.isTrashed && kept.keptAfterDeletion && !kept.isTrashedByPerson)
        #expect(kept.trashedAt == trashed.modifiedAt, "trashed when the erased version was last modified")
        #expect(kept.field(.password)?.value == "typed-meanwhile")
        #expect(kept.revisions[.trashedAt]?.revision == erasure.revision, "the deletion's write, not this device's")
        // Whichever device keeps it, and at whatever version, the state is the same; and it is settled.
        let onB = ItemMerge.written(kept, as: Revision(version: 4, device: F.b))
        let onC = ItemMerge.written(kept, as: Revision(version: 9, device: F.c))
        #expect(ItemMerge.sameState(onB, onC))
        #expect(F.merge((onB, F.b), (onC, F.c)) == onC)
        #expect(ItemMerge.settle(onB, origin: F.origin(onB, F.b), against: erasure) == .keep)
        #expect(F.merge((onB, F.b), (edited, F.b)) == onB, "it contains the version it was made from")

        // The person takes it out of the trash, having seen the deletion: no later meeting with the tombstone puts
        // it back.
        let restored = F.edit(onB, by: F.c, at: 5) {
            $0.trashedAt = nil
            $0.keptAfterDeletion = false
        }
        #expect(!restored.isTrashed && !restored.hasConflicts)
        #expect(ItemMerge.settle(restored, origin: F.origin(restored, F.c), against: erasure) == .keep)
        #expect(!F.merge((restored, F.c), (onC, F.c)).isTrashed)

        // A restore the deletion had not seen, and that had not seen the deletion, is a conflict; the deletion shown.
        let restoredMeanwhile = F.edit(trashed, by: F.c, at: 3) { $0.trashedAt = nil }
        guard
            case .kept(let disputed) = ItemMerge.settle(
                restoredMeanwhile, origin: F.origin(restoredMeanwhile, F.c), against: erasure)
        else {
            Issue.record("a concurrent restore was not kept")
            return
        }
        #expect(disputed.isTrashed && disputed.keptAfterDeletion)
        #expect(ItemMerge.conflicts(of: disputed)[.trashedAt]?.map(\.value) == [.trashedAt(nil)])
        // Kept after one deletion and restored, then met by a second deletion that had seen neither: the second
        // deletion's trash and its mark are shown together, the restore beside them.
        let second = ItemErasure(
            seen: VersionVector([F.a: 1]), row: 6, device: F.c, date: Date(timeIntervalSince1970: 1_800_000_200))
        guard case .kept(let twice) = ItemMerge.settle(restored, origin: F.origin(restored, F.c), against: second)
        else {
            Issue.record("a restore the second deletion had not seen was not kept")
            return
        }
        #expect(twice.isTrashed && twice.keptAfterDeletion && !twice.isTrashedByPerson)
        #expect(twice.trashedAt == second.date)
        #expect(Set(ItemMerge.conflicts(of: twice).keys) == [.trashedAt, .keptAfterDeletion])
    }

    @Test("an erasure survives its summary; one that does not decode or is implausible has seen nothing")
    func erasureSummaries() throws {
        let item = F.edit(F.base(), by: F.b, at: 7) { $0.title = "Seen" }
        let erasure = Self.erasure(of: item, by: F.b)
        let summary = try erasure.summary()
        #expect(ItemErasure(summary: summary) == erasure)
        #expect(ItemErasure(summary: summary, tombstone: 8) == erasure)
        #expect(ItemErasure(summary: summary, tombstone: 9) == .void, "not the summary of the tombstone carrying it")
        #expect(ItemErasure(summary: []) == .void)
        #expect(ItemErasure(summary: Array("{\"seen\":[1]}".utf8)) == .void)
        // The first form, a bare vector, is still read: it erases what it covers.
        let bare = try JSONEncoder().encode(erasure.seen)
        #expect(ItemErasure(summary: Array(bare)).seen == erasure.seen)
        #expect(ItemErasure(summary: Array(bare)).row == 7)
    }

    /// Y26. The version kept after a deletion was guessed from the highest count in the summary. A device that had
    /// merged two versions (a row above every edit in it) and then deleted the item wrote a tombstone above that
    /// guess, so every device holding an edit it had not seen returned a version *below* the tombstone, which the
    /// engine refuses: the deleting device's stream stopped there. The summary now names the row erased.
    @Test("a version kept after a deletion is written above the tombstone, though the row erased was a merge result")
    func keptVersionIsAboveTheTombstone() async throws {
        let keys = FakeAccountKeys(seed: 7)
        await keys.addVaultKey(vaultID: F.vault)
        let eraser = FakeSyncKeyring(deviceID: F.c, keys: keys)
        let keeper = FakeSyncKeyring(deviceID: F.b, keys: keys)
        let base = F.base()
        let trashed = F.edit(base, by: F.a, at: 2) { $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_100) }
        // The eraser's row: the trash, written down again several merges later. No edit in it is above version 2.
        let row = try await eraser.sealItem(ItemMerge.written(trashed, as: Revision(version: 9, device: F.c)))
        let summary = try await ItemRecordMerger(sealer: eraser, deviceID: F.c).erasureSummary(of: row)
        let tombstone = row.version + 1

        let unseen = try await keeper.sealItem(F.edit(base, by: F.b, at: 2) { $0.title = "Renamed meanwhile" })
        let merger = ItemRecordMerger(sealer: keeper, deviceID: F.b)
        guard case .replace(let kept) = try await merger.resolveErasure(summary, of: unseen) else {
            Issue.record("an edit the deletion had not seen was not kept")
            return
        }
        #expect(kept.version > tombstone && kept.deviceID == F.b)
        let item = try await keeper.openItem(kept)
        #expect(item.title == "Renamed meanwhile" && item.isTrashed && item.keptAfterDeletion)
        #expect(try await merger.resolveErasure(summary, of: kept) == .keep, "settled: not kept a second time")
        #expect(try await merger.resolveErasure(summary, of: row) == .erase)
        // The same, for an engine that passes the tombstone's version.
        guard case .replace(let exact) = try await merger.resolveErasure(summary, of: unseen, tombstone: tombstone)
        else {
            Issue.record("an edit the deletion had not seen was not kept")
            return
        }
        #expect(exact.version == tombstone + 1)
        #expect(ItemMerge.sameState(try await keeper.openItem(exact), item))
    }

    /// Y25, end to end: the item a person restored after a deletion stays restored when the tombstone is met again.
    @Test("an item restored after a deletion kept it stays restored when every device replays the log")
    func restoreAfterDeletionStands() async throws {
        let (home, item) = try await SyncMergeCaseTests.household(with: Household.login())
        try await home.devices[0].delete(item.id)
        try await home.devices[1].edit(item.id) { $0.fields[1].value = "typed-after-the-delete-was-made" }
        try await home.settle()
        try await home.expectConverged()
        try await home.devices[1].edit(item.id) {
            $0.trashedAt = nil
            $0.keptAfterDeletion = false
        }
        try await home.settle()
        // Every device replays the whole log, tombstone included.
        for device in home.devices { try await device.sync(reconcile: true) }
        try await home.settle()
        try await home.expectConverged()
        for copy in try await SyncMergeCaseTests.everywhere(home, item.id) {
            #expect(!copy.isTrashed, "the restore was made knowing about the deletion")
            #expect(copy.field(.password)?.value == "typed-after-the-delete-was-made")
        }
    }
}
