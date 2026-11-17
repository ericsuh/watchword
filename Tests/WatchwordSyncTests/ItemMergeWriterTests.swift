import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordSync

/// The three parts of an item that once named no writer — a note line's removal, a resolution's discard and a history
/// entry — and the attribution a shared vault's judge reads from them (docs/10-sync-correctness.md §9, review findings
/// S32 and S43).
@Suite("Item merge: writers of removals, discards and history")
struct ItemMergeWriterTests {
    typealias F = MergeFixtures

    static func revision(_ version: UInt64, _ device: UUID) -> Revision {
        Revision(version: version, device: device)
    }

    /// The attributed values of `item` read as written by `origin`, by the tag that opens their encoding.
    static func attributed(_ item: Item, origin: Revision, tag: UInt64) -> [AttributedValue] {
        var prefix = CanonicalWriter()
        prefix.append(tag)
        return ItemMerge.attributedValues(item, origin: origin).filter { $0.bytes.starts(with: prefix.bytes) }
    }

    @Test("an edit's removal of a line names the edit, and concurrent removals of one line are both kept")
    func removalsNameTheirWriter() {
        let base = F.base(notes: "one\ntwo\nthree")
        let byA = F.edit(base, by: F.a, at: 2) { $0.notes = "one\nthree" }
        let byB = F.edit(base, by: F.b, at: 2) { $0.notes = "one\nthree" }
        let removedByA = byA.noteLines.filter(\.removed)
        #expect(removedByA.count == 1 && removedByA[0].removedBy == [Self.revision(2, F.a)])
        // The shown lines name no removal; the stored form leaves the key out.
        #expect(byA.noteLines.filter { !$0.removed }.allSatisfy { $0.removedBy.isEmpty })

        let merged = F.merge((byA, F.a), (byB, F.b))
        #expect(merged == F.merge((byB, F.b), (byA, F.a)))
        #expect(merged.notes == "one\nthree")
        let line = merged.noteLines.first { $0.removed }
        #expect(line?.removedBy == [Self.revision(2, F.a), Self.revision(2, F.b)].sorted())
        // One attributed value per removal, each at its writer's revision.
        let removals = Self.attributed(merged, origin: Self.revision(3, F.a), tag: 7)
        #expect(Set(removals.map(\.revision)) == [Self.revision(2, F.a), Self.revision(2, F.b)])
        // Merging again changes nothing: the removals are a set.
        #expect(F.merge((merged, F.a), (byA, F.a)) == merged)
    }

    @Test("a removal, a discard or a history entry that names no writer is read as the work of the row carrying it")
    func unnamedPartsAreTheRowsOwn() throws {
        let row = Self.revision(5, F.c)
        var legacy = F.base(notes: "one\ntwo")
        legacy.version = 5
        legacy.noteLines[1].removed = true
        legacy.noteLines[1].text = ""
        legacy.history = [ItemHistoryEntry(replacedAt: Date(timeIntervalSince1970: 7), version: 1, fields: [])]
        legacy.discards[.title] = [ItemDiscard(revision: nil, seen: VersionVector([F.a: 1]))]

        let read = ItemMerge.canonical(legacy, origin: row)
        #expect(read.noteLines.first { $0.removed }?.removedBy == [row])
        #expect(read.history.map(\.writtenBy) == [[row]])
        #expect(read.discards[.title] == [ItemDiscard(revision: row, seen: VersionVector([F.a: 1]))])
        #expect(ItemMerge.canonical(read, origin: Self.revision(9, F.a)) == read, "once named, read the same anywhere")
        for tag: UInt64 in [7, 8, 9] {
            #expect(Self.attributed(read, origin: row, tag: tag).map(\.revision) == [row])
            #expect(Self.attributed(legacy, origin: row, tag: tag) == Self.attributed(read, origin: row, tag: tag))
        }
    }

    @Test("a writer named above the record's own version is read at it")
    func writersAreClamped() {
        let row = Self.revision(3, F.c)
        var item = F.base(notes: "one\ntwo")
        item.version = 3
        item.noteLines[1].removed = true
        item.noteLines[1].removedBy = [Self.revision(1 << 40, F.b)]
        item.history = [
            ItemHistoryEntry(
                replacedAt: Date(timeIntervalSince1970: 7), version: 1, fields: [],
                writtenBy: [Self.revision(.max, F.b)])
        ]
        item.discards[.title] = [ItemDiscard(revision: Self.revision(99, F.b), seen: VersionVector([F.a: 50]))]
        let read = ItemMerge.canonical(item, origin: row)
        #expect(read.noteLines.first { $0.removed }?.removedBy == [Self.revision(3, F.b)])
        #expect(read.history.map(\.writtenBy) == [[Self.revision(3, F.b)]])
        #expect(read.discards[.title] == [ItemDiscard(revision: Self.revision(3, F.b), seen: VersionVector([F.a: 3]))])
    }

    @Test("a line shown in a record but naming a removal is read as removed: the removal is the claim that counts")
    func namedRemovalRemoves() {
        var item = F.base(notes: "one\ntwo")
        item.noteLines[1].removedBy = [Self.revision(1, F.b)]
        let read = ItemMerge.canonical(item, origin: Self.revision(1, F.a))
        #expect(read.notes == "one")
        #expect(read.noteLines.first { $0.removed }?.removedBy == [Self.revision(1, F.b)])
    }

    @Test(
        "a history entry recorded by two writes is shown once and names both; an entry carried over is not re-recorded")
    func historyEntriesNameEveryWriter() {
        let base = F.base()
        let entry = ItemHistoryEntry(replacedAt: Date(timeIntervalSince1970: 9), version: 1, fields: base.fields)
        var x = base
        x.history = [entry]
        x.version = 2
        var y = x
        let merged = ItemMerge.merge(x, origin: Self.revision(2, F.a), y, origin: Self.revision(2, F.b))
        #expect(merged.history.count == 1)
        #expect(merged.history[0].writtenBy == [Self.revision(2, F.a), Self.revision(2, F.b)].sorted())

        // A save carries the history over: the edit records only the entry it adds, and a caller's writers are not
        // taken (the vault owns them).
        let saved = F.edit(merged, by: F.c, at: 3) { item in
            item.fields[1].value = "new-password"
            item.history = item.history.map {
                var forged = $0
                forged.writtenBy = [Self.revision(3, F.c)]
                return forged
            }
        }
        #expect(saved.history.count == 2)
        #expect(
            saved.history.first { $0.version == 1 && $0.replacedAt == entry.replacedAt }?.writtenBy
                == merged.history[0].writtenBy)
        #expect(saved.history.contains { $0.writtenBy == [Self.revision(3, F.c)] && $0.version == merged.version })
    }

    @Test("a new item's history is its creator's, whatever a copied entry named")
    func newItemsOwnTheirHistory() {
        var copy = F.base()
        copy.history = [
            ItemHistoryEntry(
                replacedAt: Date(timeIntervalSince1970: 9), version: 1, fields: [], writtenBy: [Self.revision(1, F.b)])
        ]
        let created = ItemMerge.stamped(copy, previous: nil, revision: Self.revision(1, F.c))
        #expect(created.history.map(\.writtenBy) == [[Self.revision(1, F.c)]])
    }

    @Test("a resolution's discard names the resolution; two resolutions' discards are both kept, and both hold")
    func discardsNameTheirWriter() throws {
        let base = F.base()
        // A conflict on the password, then an edit of it on each side over the conflict: each retains a value.
        let a2 = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "a-password" }
        let b2 = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "b-password" }
        let both = F.merge((a2, F.a), (b2, F.b))
        let a3 = F.edit(ItemMerge.written(both, as: Self.revision(3, F.a)), by: F.a, at: 4) {
            $0.fields[1].value = "a-again"
        }
        let b3 = F.edit(ItemMerge.written(both, as: Self.revision(3, F.b)), by: F.b, at: 4) {
            $0.fields[1].value = "b-again"
        }
        try #require(!a3.retainedValues.isEmpty && !b3.retainedValues.isEmpty)
        let group = ItemGroup.field(F.fieldID(2))
        let resolvedA = ItemMerge.resolve(
            a3, group: group, choosing: F.password("a-again"), origin: Self.revision(4, F.a),
            revision: Self.revision(5, F.a))
        let resolvedB = ItemMerge.resolve(
            b3, group: group, choosing: F.password("b-again"), origin: Self.revision(4, F.b),
            revision: Self.revision(5, F.b))
        #expect(resolvedA.discards[group]?.map(\.revision) == [Self.revision(5, F.a)])
        let merged = F.merge((resolvedA, F.a), (resolvedB, F.b))
        #expect(
            Set(merged.discards[group]?.compactMap(\.revision) ?? []) == [Self.revision(5, F.a), Self.revision(5, F.b)])
        // What each had before it stays discarded, whichever copy still holds it.
        #expect(F.merge((merged, F.a), (a3, F.a)).retainedValues == merged.retainedValues)
        #expect(F.merge((merged, F.a), (b3, F.b)).retainedValues == merged.retainedValues)
        #expect(
            Set(Self.attributed(merged, origin: Self.revision(6, F.a), tag: 8).map(\.revision))
                == [Self.revision(5, F.a), Self.revision(5, F.b)])
    }

    @Test("discards of the first form, one vector per group, still decode, naming no resolution")
    func legacyDiscardsDecode() throws {
        let item = F.base()
        let encoder = JSONEncoder()
        var json = try #require(
            try JSONSerialization.jsonObject(with: encoder.encode(item)) as? [String: Any])
        json["discards"] = ["title": [F.a.uuidString: 2]]
        let data = try JSONSerialization.data(withJSONObject: json)
        let decoded = try JSONDecoder().decode(Item.self, from: data)
        #expect(decoded.discards == [.title: [ItemDiscard(revision: nil, seen: VersionVector([F.a: 2]))]])
        // And the second form round-trips.
        var stamped = item
        stamped.discards = [.title: [ItemDiscard(revision: Self.revision(2, F.b), seen: VersionVector([F.a: 2]))]]
        #expect(try JSONDecoder().decode(Item.self, from: encoder.encode(stamped)) == stamped)
    }

    @Test("an empty writer list is left out of the stored form, so lines shown and old entries encode as before")
    func emptyWritersAreNotEncoded() throws {
        let line = NoteLine(id: NoteLine.ID(revision: Self.revision(1, F.a), index: 0), after: nil, text: "x")
        let entry = ItemHistoryEntry(replacedAt: Date(timeIntervalSince1970: 1), version: 1, fields: [])
        let encoder = JSONEncoder()
        let (lineJSON, entryJSON) = (try encoder.encode(line), try encoder.encode(entry))
        #expect(!String(decoding: lineJSON, as: UTF8.self).contains("removedBy"))
        #expect(!String(decoding: entryJSON, as: UTF8.self).contains("writtenBy"))
        var removed = line
        removed.removed = true
        removed.removedBy = [Self.revision(2, F.b)]
        #expect(try JSONDecoder().decode(NoteLine.self, from: encoder.encode(removed)) == removed)
    }

    @Test("the attributed parts only grow: a merge holds every removal, discard and history writer of its inputs")
    func attributionIsInflationary() {
        var generator = SeededGenerator(seed: 0x543)
        for _ in 0..<200 {
            var x = F.base(notes: F.longNotes)
            var y = x
            var xVersion: UInt64 = 1
            var yVersion: UInt64 = 1
            for _ in 0..<6 {
                if Bool.random(using: &generator) {
                    xVersion += 1
                    x = F.edit(x, by: F.a, at: xVersion) { ItemMergeTests.randomEdit(&$0, using: &generator) }
                } else {
                    yVersion += 1
                    y = F.edit(y, by: F.b, at: yVersion) { ItemMergeTests.randomEdit(&$0, using: &generator) }
                }
            }
            let merged = F.merge((x, F.a), (y, F.b))
            let origin = Self.revision(max(xVersion, yVersion) + 1, F.c)
            for tag: UInt64 in [7, 8, 9] {
                let inputs = Set(
                    Self.attributed(x, origin: F.origin(x, F.a), tag: tag)
                        + Self.attributed(y, origin: F.origin(y, F.b), tag: tag))
                #expect(Set(Self.attributed(merged, origin: origin, tag: tag)) == inputs)
            }
        }
    }
}
