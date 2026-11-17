import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// Regression tests for the audit of the item merge as a CRDT (docs/06-adversarial-review.md §H, Y18–Y27, Y31–Y35;
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

    /// W13 and W18 meet Y25. A record erased on two devices is judged against the join of both erasures, which the
    /// engine keeps as one summary. The join must be a join — or which erasure a device heard of first, and how its
    /// summaries were grouped, would decide what it keeps — with one encoding, so that "the join adds nothing" can be
    /// decided by comparing bytes; and a summary that does not decode must be a deletion that had seen nothing.
    @Test("the join of a record's erasures is commutative, associative and idempotent, in one canonical encoding")
    func erasureJoin() async throws {
        let onA = F.edit(F.base(), by: F.a, at: 2) { $0.title = "Seen by A" }
        let onB = F.edit(F.base(), by: F.b, at: 5) { $0.fields[1].value = "seen-by-B" }
        let first = Self.erasure(of: onA, by: F.a)
        let second = Self.erasure(of: onB, by: F.b)
        let late = ItemErasure(
            seen: VersionVector([F.a: 2, F.b: 5]), row: 9, device: F.c, date: Date(timeIntervalSince1970: 1_800_000_300)
        )
        let keys = FakeAccountKeys(seed: 31)
        let merger = ItemRecordMerger(sealer: FakeSyncKeyring(deviceID: F.c, keys: keys), deviceID: F.c)
        func join(_ x: [UInt8], _ y: [UInt8]) async throws -> [UInt8] {
            try await merger.joinErasureSummaries(x, y, kind: .item)
        }
        let summaries = [
            try first.summary(), try second.summary(), try late.summary(), [], Array("[]".utf8), [0xFF],
            try ItemErasures([first, second]).summary(),
        ]
        // One erasure is encoded as a tombstone carries it, and reads back as itself.
        #expect(try ItemErasures([first]).summary() == first.summary())
        #expect(ItemErasures(summary: try first.summary()).elements == [first])
        for x in summaries {
            let canonical = try ItemErasures(summary: x).summary()
            #expect(try await join(x, x) == canonical, "idempotent")
            #expect(try await join(canonical, canonical) == canonical)
            for y in summaries {
                #expect(try await join(x, y) == join(y, x), "commutative")
                for z in summaries {
                    #expect(try await join(join(x, y), z) == join(x, join(y, z)), "associative")
                }
            }
        }
        // Anything that does not decode is a deletion that had seen nothing: it adds a deletion, and no coverage.
        let undecodable = ItemErasures(summary: [0xFF])
        #expect(undecodable == ItemErasures([.void]) && undecodable.seen.isEmpty)
        let joined = ItemErasures(summary: try await join(first.summary(), [0xFF]))
        #expect(joined.elements.contains(.void) && joined.seen == first.seen)
        // An implausible element of an array is read as `void`, like a summary of its own.
        let lying = ItemErasure(seen: VersionVector([F.a: 99]), row: 3, device: F.b, date: nil)
        let planted =
            Array("[".utf8) + (try first.summary()) + Array(",".utf8) + (try lying.summary()) + Array("]".utf8)
        #expect(ItemErasures(summary: planted) == ItemErasures([first, .void]))
        // Above the stamp the engine passes, a deletion is not believed (Y28); at or below it, it is.
        let both = ItemErasures([first, second])
        #expect(both.believed(atOrBelow: second.revision.version) == both)
        #expect(both.believed(atOrBelow: first.revision.version) == ItemErasures([first, .void]))
    }

    /// A join that would not fit in a tombstone is refused, so that no snapshot carries one every reader refuses
    /// (`SyncPayload.maximumErasureLength`); the engine then keeps the erasure with the later stamp.
    @Test("a join of erasure summaries over the tombstone limit is refused")
    func erasureJoinOverTheLimit() async throws {
        func erasure(_ marker: UInt8, by device: UUID) throws -> [UInt8] {
            var claimed: [UUID: UInt64] = [:]
            for n in 0..<900 {
                claimed[
                    UUID(uuid: (marker, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, UInt8(n >> 8), UInt8(n & 0xFF)))] =
                    1
            }
            return try ItemErasure(seen: VersionVector(claimed), row: 4, device: device, date: nil).summary()
        }
        let (x, y) = (try erasure(0xD1, by: F.a), try erasure(0xD2, by: F.b))
        #expect(x.count <= SyncPayload.maximumErasureLength && y.count <= SyncPayload.maximumErasureLength)
        let keys = FakeAccountKeys(seed: 32)
        let merger = ItemRecordMerger(sealer: FakeSyncKeyring(deviceID: F.c, keys: keys), deviceID: F.c)
        await #expect(throws: ItemMergeError.self) {
            _ = try await merger.joinErasureSummaries(x, y, kind: .item)
        }
    }

    /// W13 and Y25 together. Two devices delete the item, each having seen an edit the other had not; a third holds an
    /// edit neither saw. A version that the two deletions had seen *between them* is erased: each of its edits was in a
    /// copy a person deleted. A version holding the third edit is kept, and receives each deletion's own write — not
    /// one write standing for both, which no device made — so the item kept is the same whichever deletion a device
    /// learned of first, and whether it learned of them one at a time or together.
    @Test("two deletions of one item: covered between them, erased; kept, the same item in either order")
    func deletionsInEitherOrder() throws {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.title = "Renamed on A" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "typed-on-B" }
        let first = Self.erasure(of: onA, by: F.a)
        let second = Self.erasure(of: onB, by: F.b)
        let both = ItemErasures([first, second])

        let seenBetweenThem = F.merge((onA, F.a), (onB, F.b))
        let mergedOrigin = Revision(version: seenBetweenThem.version, device: ItemMerge.zeroDevice)
        #expect(ItemMerge.settle(seenBetweenThem, origin: mergedOrigin, against: both) == .erase)
        guard case .kept = ItemMerge.settle(seenBetweenThem, origin: mergedOrigin, against: first) else {
            Issue.record("one deletion alone erased an edit it had not seen")
            return
        }

        let onC = F.edit(base, by: F.c, at: 2) { $0.fields[1].value = "typed-on-C" }
        func kept(_ item: Item, origin: Revision, against erasures: ItemErasures) -> (Item, Revision)? {
            guard case .kept(let kept) = ItemMerge.settle(item, origin: origin, against: erasures) else { return nil }
            let tombstone = erasures.elements.map(\.revision.version).max() ?? 0
            let revision = Revision(version: max(item.version, tombstone) + 1, device: F.c)
            return (ItemMerge.written(kept, as: revision), revision)
        }
        let origin = F.origin(onC, F.c)
        let together = try #require(kept(onC, origin: origin, against: both))
        let afterFirst = try #require(kept(onC, origin: origin, against: ItemErasures([first])))
        let firstThenSecond = try #require(kept(afterFirst.0, origin: afterFirst.1, against: both))
        let afterSecond = try #require(kept(onC, origin: origin, against: ItemErasures([second])))
        let secondThenFirst = try #require(kept(afterSecond.0, origin: afterSecond.1, against: both))
        #expect(ItemMerge.sameState(firstThenSecond.0, secondThenFirst.0))
        #expect(ItemMerge.sameState(firstThenSecond.0, together.0))
        #expect(ItemMerge.settle(together.0, origin: together.1, against: both) == .keep, "settled")

        let item = together.0
        #expect(item.field(.password)?.value == "typed-on-C")
        #expect(item.isTrashed && item.keptAfterDeletion && !item.isTrashedByPerson)
        // Both deletions' own writes, at their own revisions: neither is credited with what the other had seen.
        let trashes = [try #require(item.revisions[.trashedAt])] + (item.conflicts[.trashedAt] ?? []).map(\.stamp)
        #expect(trashes.count == 2)
        #expect(Set(trashes.map(\.revision)) == [first.revision, second.revision])
        for stamp in trashes {
            let erasure = stamp.revision == first.revision ? first : second
            var seen = erasure.seen
            seen.record(erasure.revision)
            #expect(stamp.seen == seen)
        }
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
        // The engine passes the tombstone's version (Y28); the copy is written just above it.
        guard case .replace(let kept) = try await merger.resolveErasure(summary, of: unseen, above: tombstone) else {
            Issue.record("an edit the deletion had not seen was not kept")
            return
        }
        #expect(kept.version > tombstone && kept.deviceID == F.b)
        #expect(kept.version == tombstone + 1)
        let item = try await keeper.openItem(kept)
        #expect(item.title == "Renamed meanwhile" && item.isTrashed && item.keptAfterDeletion)
        #expect(
            try await merger.resolveErasure(summary, of: kept, above: tombstone) == .keep,
            "settled: not kept a second time")
        #expect(try await merger.resolveErasure(summary, of: row, above: tombstone) == .erase)
        // Another device keeps the same item, at a version of its own.
        let other = ItemRecordMerger(sealer: eraser, deviceID: F.c)
        guard case .replace(let elsewhere) = try await other.resolveErasure(summary, of: unseen, above: tombstone)
        else {
            Issue.record("an edit the deletion had not seen was not kept")
            return
        }
        #expect(elsewhere.deviceID == F.c)
        #expect(ItemMerge.sameState(try await eraser.openItem(elsewhere), item))
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

    // MARK: - Text is its bytes (Y31)

    /// "café" with the accent as one scalar, and as "e" with a combining mark: equal as Swift `String`s, different
    /// bytes — and so different passwords to the site that hashes them.
    static let composed = "caf\u{E9}-pass"
    static let decomposed = "cafe\u{301}-pass"

    static func bytes(_ text: String) -> [UInt8] {
        Array(text.utf8)
    }

    /// Y31. `stamped` decided whether a group changed with `==`, under which the two spellings are one value, and
    /// rebuilt the item from the values it already held: a person who retyped a password in the form the site
    /// accepts saved the old bytes, with no stamp and no history entry.
    @Test("a value retyped in another normalisation form is an edit: saved as typed, stamped, and in the history")
    func respeltValuesAreSavedAsTyped() {
        var start = F.base(notes: "line \(Self.decomposed)\nlast")
        start = F.edit(start, by: F.a, at: 2) {
            $0.fields[1].value = Self.decomposed
            $0.title = Self.decomposed
        }
        let saved = F.edit(start, by: F.a, at: 3) {
            $0.fields[1].value = Self.composed
            $0.title = Self.composed
            $0.notes = "line \(Self.composed)\nlast"
        }
        #expect(Self.bytes(saved.fields[1].value) == Self.bytes(Self.composed))
        #expect(Self.bytes(saved.title) == Self.bytes(Self.composed))
        #expect(Self.bytes(saved.notes) == Self.bytes("line \(Self.composed)\nlast"))
        let revision = Revision(version: 3, device: F.a)
        #expect(saved.revisions[.field(F.fieldID(2))]?.revision == revision)
        #expect(saved.revisions[.title]?.revision == revision)
        #expect(saved.noteLines.contains { $0.id.revision == revision && !$0.removed })
        #expect(saved.noteLines.filter(\.removed).count == 1, "the line respelt was replaced, the other kept")
        // The spelling replaced is in the history, as any replaced value is.
        #expect(saved.history.first?.fields[1].value.utf8.elementsEqual(Self.decomposed.utf8) == true)
        #expect(F.merge((saved, F.a), (start, F.a)) == saved, "and the edit contains the version it was made on")
    }

    /// Y31. Two devices saved the two spellings of one password concurrently. Both were kept, but the views compared
    /// with `==`: no conflict was reported, and the next edit of the field dropped the hidden spelling without
    /// retaining it.
    @Test("two spellings written concurrently are a conflict the person is shown, and an edit retains the other")
    func twoSpellingsAreAConflict() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = Self.composed }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = Self.decomposed }
        let merged = F.merge((onA, F.a), (onB, F.b))
        #expect(merged == F.merge((onB, F.b), (onA, F.a)))
        let group = ItemGroup.field(F.fieldID(2))
        #expect(merged.hasConflicts)
        let hidden = ItemMerge.conflicts(of: merged)[group]?.map(\.value) ?? []
        #expect(hidden.count == 1)
        let held = Set(([merged.value(of: group)!] + hidden).map { Self.bytes(Self.text($0)) })
        #expect(held == [Self.bytes(Self.composed), Self.bytes(Self.decomposed)])

        let edited = F.edit(merged, by: F.a, at: 4) { $0.fields[1].value = "typed-after" }
        #expect(edited.retainedValues.map(\.value) == hidden, "the spelling not shown is retained, not dropped")
    }

    /// Y31. One stamp, two spellings — what an insider gets by republishing another device's write respelt, and what
    /// a rolled-back device can do by accident. The merge kept whichever spelling the receiving device already held
    /// and reported the two results equal, so two devices filled different bytes for good.
    @Test("one stamp carrying two spellings: both are kept, and every merge order gives the same bytes")
    func oneStampTwoSpellings() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) {
            $0.fields[1].value = Self.composed
            $0.title = Self.composed
        }
        var respelt = onA
        respelt.fields[1].value = Self.decomposed
        respelt.title = Self.decomposed
        respelt.version = 3
        let (first, second) = ((onA, F.a), (respelt, F.c))
        let left = F.merge(first, second)
        let right = F.merge(second, first)
        #expect(left == right)
        #expect(Self.bytes(left.title) == Self.bytes(right.title))
        #expect(Self.bytes(left.fields[1].value) == Self.bytes(right.fields[1].value))
        #expect(!ItemMerge.sameState(left, onA) && !ItemMerge.sameState(left, respelt))
        for group in [ItemGroup.title, .field(F.fieldID(2))] {
            #expect(left.conflicts[group]?.count == 1, "both spellings are held")
            #expect(ItemMerge.conflicts(of: left)[group]?.count == 1, "and shown as a conflict")
        }
        // A device that already holds either spelling ends where the others do.
        #expect(F.merge(Self.again(left), first) == left && F.merge(Self.again(left), second) == left)
        // Versions that differ only in a spelling are not the same state.
        #expect(!ItemMerge.sameState(onA, ItemMerge.written(respelt, as: Revision(version: 2, device: F.a))))
    }

    @Test("note lines are compared by their bytes: a respelt line is replaced, an untouched one keeps its ID")
    func noteLinesByBytes() {
        let revision = Revision(version: 1, device: F.a)
        let lines = NoteText.initial("keep\n\(Self.decomposed)\nkeep too", revision: revision)
        let edited = NoteText.edit(
            lines, to: "keep\n\(Self.composed)\nkeep too", revision: Revision(version: 2, device: F.a), nonce: 9)
        #expect(Self.bytes(NoteText.text(edited)) == Self.bytes("keep\n\(Self.composed)\nkeep too"))
        #expect(edited.filter(\.removed).map(\.id) == [lines[1].id])
        #expect(edited.filter { $0.id.nonce == 9 }.count == 1)
        #expect(NoteText.merge(edited, lines) == edited)
    }

    // MARK: - Note lines (Y32, Y33)

    /// Y32. Copies of one line ID were folded in one at a time, re-splitting and re-sorting the text so far at each
    /// step. The one-pass join must give what the fold gave, in any order.
    @Test("joining many copies of one line at once gives what joining them pairwise in any order gives")
    func joiningCopiesOfOneLine() {
        let revision = Revision(version: 2, device: F.c)
        let id = NoteLine.ID(revision: revision, index: 0)
        func anchor(_ index: UInt32) -> NoteLine.ID { NoteLine.ID(revision: revision, index: index) }
        let texts = ["b\na", "b\na", "a", "", "c\nb", "a\nb", Self.composed, Self.decomposed]
        var generator = SeededGenerator(seed: 0x32)
        for round in 0..<200 {
            let count = Int.random(in: 1...6, using: &generator)
            let copies = (0..<count).map { _ in
                NoteLine(
                    id: id,
                    after: Bool.random(using: &generator) ? anchor(UInt32.random(in: 1...3, using: &generator)) : nil,
                    text: texts.randomElement(using: &generator)!,
                    removed: round % 4 == 0 && Int.random(in: 0..<5, using: &generator) == 0)
            }
            let normal = copies.map { $0.removed ? NoteText.removed($0, by: nil) : $0 }
            let together = NoteText.join(normal)
            var folded = normal[0]
            for copy in normal.dropFirst() { folded = NoteText.join(folded, copy) }
            var backwards = normal[normal.count - 1]
            for copy in normal.dropLast().reversed() { backwards = NoteText.join(backwards, copy) }
            #expect(together == folded && together == backwards, "round \(round)")
            #expect(
                NoteText.ordered(copies) == [together]
                    && NoteText.ordered(copies.shuffled(using: &generator)) == [together])
        }
        // The same text everywhere stays as written, unsorted; texts that differ are kept line by line.
        let same = NoteLine(id: id, after: nil, text: "b\na")
        #expect(NoteText.join([same, same, same]).text == "b\na")
        #expect(NoteText.join([same, NoteLine(id: id, after: nil, text: "c")]).text == "a\nb\nc")
    }

    /// Y33. The lines an edit inserts carry a nonce drawn for that edit, so that their IDs cannot be named by a
    /// writer that has not seen them.
    @Test("every edit of an existing item draws a nonce for its lines; a new item's lines are numbered from zero")
    func lineNonces() {
        let base = F.base(notes: "one")
        #expect(base.noteLines.allSatisfy { $0.id.nonce == 0 })
        var item = base
        item.notes = "one\ntwo"
        item.version = 2
        let revision = Revision(version: 2, device: F.a)
        let first = ItemMerge.stamped(item, previous: base, previousOrigin: F.origin(base, F.a), revision: revision)
        let second = ItemMerge.stamped(item, previous: base, previousOrigin: F.origin(base, F.a), revision: revision)
        let nonces = [first, second].map { $0.noteLines.first { $0.id.revision == revision }?.id.nonce }
        #expect(nonces[0] != nil && nonces[1] != nil && nonces[0] != nonces[1], "drawn afresh by the system generator")
        var seeded = SeededGenerator(seed: 5)
        var again = SeededGenerator(seed: 5)
        #expect(
            ItemMerge.stamped(
                item, previous: base, previousOrigin: F.origin(base, F.a), revision: revision, using: &seeded)
                == ItemMerge.stamped(
                    item, previous: base, previousOrigin: F.origin(base, F.a), revision: revision, using: &again),
            "and reproducible from a seed")
    }

    /// Y33. Clamping a record's line IDs to its version lowers the revision of an anchor too; it rebuilt the anchor
    /// from revision and index alone, dropping the nonce, so a line written after a nonced line no longer named it and
    /// moved to the start of the notes.
    @Test("clamping keeps an anchor's nonce: a line still follows the line it was written after")
    func clampingKeepsAnchors() {
        let revision = Revision(version: 5, device: F.c)
        let first = NoteLine(id: NoteLine.ID(revision: revision, index: 0, nonce: 7), after: nil, text: "first")
        let second = NoteLine(id: NoteLine.ID(revision: revision, index: 1, nonce: 7), after: first.id, text: "second")
        let clamped = NoteText.clamped([first, second], to: 3)
        #expect(clamped.allSatisfy { $0.id.revision.version == 3 && $0.id.nonce == 7 })
        #expect(clamped[1].after == clamped[0].id)
        #expect(NoteText.text(clamped) == "first\nsecond")
    }

    // MARK: - Updates on any metadata (Y34)

    /// Y34. A retained value whose stamp did not record its own revision (a stamp decodes as written) was removed by
    /// a resolution on the resolving device but not covered by the discard it recorded, so merging the version the
    /// resolution was made on brought it back: the update was not inflationary and the discard did not hold.
    @Test("a resolution holds against a retained value whose stamp omits its own revision")
    func resolutionCoversMalformedStamps() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "from-A" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "from-B" }
        var held = F.merge((onA, F.a), (onB, F.b))
        var stamp = GroupStamp(revision: Revision(version: 1, device: F.c), seen: VersionVector([F.a: 1]))
        stamp.seen = VersionVector([F.a: 1])
        #expect(!stamp.seen.contains(stamp.revision))
        held.retainedValues = [ConflictingValue(stamp: stamp, value: F.password("retained"))]
        held.version = 3
        let origin = Revision(version: 3, device: F.c)

        let group = ItemGroup.field(F.fieldID(2))
        let resolved = ItemMerge.resolve(
            held, group: group, choosing: F.password("from-A"), origin: origin,
            revision: Revision(version: 4, device: F.a))
        #expect(resolved.retainedValues.isEmpty && !resolved.hasConflicts)
        let back = ItemMerge.merge(resolved, origin: Revision(version: 4, device: F.a), held, origin: origin)
        #expect(back == resolved, "merging the version it was made on changes nothing")
        #expect(back.retainedValues.isEmpty)
    }

    /// A record whose clock claims the tombstone's revision without holding the deletion's write (only crafted
    /// metadata does) took a shortcut that skipped the write, so settling did not commute with merging. Whether a
    /// version has met a deletion is now read from what it holds.
    @Test("settling against a deletion is the same join on a record whose clock merely claims the tombstone")
    func settlingIsAJoinOnAnyClock() throws {
        let base = F.base()
        let trashed = F.edit(base, by: F.a, at: 2) { $0.trashedAt = Date(timeIntervalSince1970: 1_800_000_002) }
        let erasure = Self.erasure(of: trashed, by: F.a)
        let edited = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "unseen" }
        var claiming = edited
        claiming.clock = claiming.clock.merging(VersionVector([F.a: erasure.revision.version]))
        claiming.version = erasure.revision.version
        let origin = Revision(version: claiming.version, device: F.b)

        guard case .kept(let kept) = ItemMerge.settle(claiming, origin: origin, against: erasure) else {
            Issue.record("a version that does not hold the deletion's write was taken to have met it")
            return
        }
        #expect(kept.isTrashed && kept.keptAfterDeletion && !kept.isTrashedByPerson)
        let keptOrigin = Revision(version: kept.version, device: F.b)
        #expect(
            ItemMerge.settle(kept, origin: keptOrigin, against: erasure) == .keep, "applying it twice changes nothing")
        // It commutes with merging: settle either side first, or the merge.
        guard case .kept(let plain) = ItemMerge.settle(edited, origin: F.origin(edited, F.b), against: erasure) else {
            Issue.record("an unseen edit was not kept")
            return
        }
        let mergedFirst = ItemMerge.merge(claiming, origin: origin, edited, origin: F.origin(edited, F.b))
        guard
            case .kept(let settledAfter) = ItemMerge.settle(
                mergedFirst, origin: Revision(version: mergedFirst.version, device: ItemMerge.zeroDevice),
                against: erasure)
        else {
            Issue.record("the merge of two uncovered versions was not kept")
            return
        }
        let settledFirst = ItemMerge.merge(
            kept, origin: keptOrigin, plain, origin: Revision(version: plain.version, device: F.b))
        #expect(ItemMerge.sameState(settledAfter, settledFirst))
    }
}
