import Foundation
import Testing
import WatchwordKit
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// Hostile sync metadata (docs/10-sync-correctness.md §6, docs/04-test-plan.md §6.4).
///
/// The adversary throughout is **an insider device**: one of the account's own devices gone wrong, or — from
/// milestone 4 — a current member of a shared vault (A4, docs/02-architecture.md §2). It holds the vault key and a
/// trusted signing key, so it can publish *any* item payload that decodes, in a record whose version passes the
/// engine's plausibility check. Sealing and signing prove who wrote the record, not that what it says about history is
/// true: every stamp, vector, line ID and conflict inside it is a claim. What it may do is what any writer may —
/// replace values, remove fields and lines, discard what it resolves. What it must not be able to do is crash a
/// reader, make a merge cost more than the payload limit allows, make two honest devices disagree for good, or make an
/// honest device's data disappear by any route other than those.
@Suite("Adversarial: sync log, item metadata", .tags(.adversarial))
struct AdversarialItemMergeTests {
    static let vault = UUID(uuidString: "0A0A0A0A-0000-4000-8000-00000000000A")!
    static let honest = UUID(uuidString: "D0000000-0000-4000-8000-0000000000A0")!
    static let other = UUID(uuidString: "D0000000-0000-4000-8000-0000000000B0")!
    static let insider = UUID(uuidString: "D0000000-0000-4000-8000-0000000000E0")!
    static let itemID = UUID(uuidString: "17E00000-0000-4000-8000-0000000000EE")!
    static let username = UUID(uuidString: "F1000000-0000-4000-8000-000000000001")!
    static let password = UUID(uuidString: "F1000000-0000-4000-8000-000000000002")!

    /// An honest item at version 1, written by the honest device.
    static func base(notes: String = "first\nsecond\nthird") -> Item {
        ItemMerge.stamped(
            Item(
                id: itemID, vaultID: vault, title: "Bank", scopes: [ServiceScope(host: "firstbank.co.uk")],
                fields: [
                    Field(id: username, kind: .username, label: "Username", value: "pat"),
                    Field(id: password, kind: .password, label: "Password", value: "honest-password"),
                ],
                notes: notes, createdAt: Date(timeIntervalSince1970: 1_800_000_000),
                modifiedAt: Date(timeIntervalSince1970: 1_800_000_000), version: 1),
            previous: nil, revision: Revision(version: 1, device: honest))
    }

    /// An edit, as the vault makes one.
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
        // The line nonce is drawn as the vault draws it, from a seed so that the test is the same on every run.
        var generator = SeededGenerator(seed: version ^ 0x4E0C_E5EE_D000_0000)
        return ItemMerge.stamped(
            item, previous: previous, previousOrigin: origin(previous),
            revision: Revision(version: version, device: device), using: &generator)
    }

    /// The row an item was read from. Who wrote it matters only for an item without sync metadata.
    static func origin(_ item: Item) -> Revision {
        Revision(version: item.version, device: insider)
    }

    static func merge(_ a: Item, _ b: Item) -> Item {
        ItemMerge.merge(a, origin: origin(a), b, origin: origin(b))
    }

    static func stamp(_ version: UInt64, _ device: UUID, seen: [UUID: UInt64] = [:]) -> GroupStamp {
        GroupStamp(revision: Revision(version: version, device: device), seen: VersionVector(seen))
    }

    /// Every field value an item holds anywhere a person can get it back from.
    static func fieldValues(_ item: Item) -> Set<String> {
        var values = Set(item.fields.map(\.value) + item.history.flatMap(\.fields).map(\.value))
        for conflict in Array(item.conflicts.values.joined()) + item.retainedValues {
            if case .field(let field?) = conflict.value { values.insert(field.value) }
        }
        return values
    }

    // MARK: - Counters

    /// Threat: the insider writes stamps, a clock and line IDs whose counts are far above the record's own version —
    /// up to `UInt64.max` — so that arithmetic on them traps, or so that its values claim to have seen every write any
    /// device will ever make: nothing an honest device writes afterwards could then supersede them, and the insider's
    /// value would sit in the item as a conflict no edit or resolution can clear.
    @Test("counts above the record's version are read as the record's version: no trap, and later edits supersede")
    func absurdCounters() {
        let base = Self.base()
        var hostile = Self.edit(base, by: Self.insider, at: 2) { $0.title = "Planted" }
        let everything = Dictionary(
            uniqueKeysWithValues: [Self.honest, Self.other, Self.insider].map { ($0, UInt64.max) })
        hostile.clock = VersionVector(everything)
        hostile.revisions[.title] = Self.stamp(.max, Self.honest, seen: everything)
        hostile.revisions[.fieldOrder] = Self.stamp(.max, Self.insider, seen: everything)
        hostile.conflicts[.archived] = [
            ConflictingValue(stamp: Self.stamp(.max - 1, Self.other, seen: everything), value: .archived(true))
        ]
        hostile.retainedValues = [
            ConflictingValue(stamp: Self.stamp(.max, Self.insider, seen: everything), value: .title("Kept"))
        ]
        hostile.discards[.title] = VersionVector(everything)
        hostile.noteLines.append(
            NoteLine(
                id: NoteLine.ID(revision: Revision(version: .max, device: Self.honest), index: .max),
                after: NoteLine.ID(revision: Revision(version: .max, device: Self.other), index: .max),
                text: "planted line"))

        let read = ItemMerge.canonical(hostile, origin: Self.origin(hostile))
        #expect(read.clock.entries.values.allSatisfy { $0 <= 2 })
        #expect(
            read.revisions.values.allSatisfy {
                $0.revision.version <= 2 && $0.seen.entries.values.allSatisfy { $0 <= 2 }
            })
        #expect(read.noteLines.allSatisfy { $0.id.revision.version <= 2 && ($0.after?.revision.version ?? 0) <= 2 })
        #expect(ItemMerge.canonical(read, origin: Self.origin(read)) == read)

        // The honest device merges it, then renames the item and archives it: both supersede the insider's claims.
        let concurrent = Self.edit(base, by: Self.honest, at: 2) { $0.fields[1].value = "changed-meanwhile" }
        let merged = ItemMerge.written(Self.merge(concurrent, hostile), as: Revision(version: 3, device: Self.honest))
        #expect(merged.field(.password)?.value == "changed-meanwhile")
        let edited = Self.edit(merged, by: Self.honest, at: 4) {
            $0.title = "Renamed after"
            $0.archived = false
        }
        let everywhere = Self.merge(edited, hostile)
        #expect(everywhere == edited, "the insider's version adds nothing to one written after seeing it")
        #expect(everywhere.title == "Renamed after" && !everywhere.hasConflicts)
        // And the next edit's lines do not land on the planted line.
        let noted = Self.edit(edited, by: Self.honest, at: 5) { $0.notes += "\nmy recovery phrase" }
        #expect(noted.notes.hasSuffix("my recovery phrase") && noted.notes.contains("planted line"))
    }

    /// Threat: the insider knows the honest device's ID and the vault's version, so it knows the revision the honest
    /// device's *next* edit will carry. It publishes note lines — marked removed, which wins a join — under the line
    /// IDs that revision would use, in a record at or above that version (the engine lets a version jump by 2^20), so
    /// that clamping to the record's version does not touch them. If the person types into the notes before their
    /// device has merged that record, the new lines would take exactly the planted IDs and merge into removed lines:
    /// what they typed gone from every device, with no conflict and no trace (review finding Y21, and Y33 for the
    /// offline case the first fix missed).
    ///
    /// A line ID carries a nonce drawn for the edit, so the insider cannot name a line it has not seen. Here it plants
    /// under nonce zero and a thousand guesses.
    @Test("removed lines planted under the IDs of a device's next edits do not erase what the person types")
    func plantedLineIDs() {
        let base = Self.base(notes: "one")
        var hostile = Self.edit(base, by: Self.insider, at: 3) { $0.archived = true }
        for version in UInt64(2)...4 {
            for index in UInt32(0)..<4 {
                for nonce in [UInt64(0), 1, .max] + (0..<1_000).map({ UInt64($0) &* 0x9E37_79B9_7F4A_7C15 }) {
                    hostile.noteLines.append(
                        NoteLine(
                            id: NoteLine.ID(
                                revision: Revision(version: version, device: Self.honest), index: index, nonce: nonce),
                            after: hostile.noteLines[0].id, text: "", removed: true))
                }
            }
        }
        // The victim typed before seeing the insider's record, at exactly the revision the insider aimed at.
        let offline = Self.edit(base, by: Self.honest, at: 2) {
            $0.notes = "one\nmy recovery phrase\nand a second line"
        }
        #expect(offline.noteLines.contains { $0.id.revision == Revision(version: 2, device: Self.honest) })
        for merged in [Self.merge(offline, hostile), Self.merge(hostile, offline)] {
            #expect(merged.notes == "one\nmy recovery phrase\nand a second line")
        }
        // The same at the insider's own version, and after merging its record: the next edits keep what is typed.
        let level = Self.edit(base, by: Self.honest, at: 3) { $0.notes = "one\nmy recovery phrase" }
        #expect(Self.merge(level, hostile).notes == "one\nmy recovery phrase")
        let seen = ItemMerge.written(Self.merge(offline, hostile), as: Revision(version: 4, device: Self.honest))
        let after = Self.edit(seen, by: Self.honest, at: 5) { $0.notes += "\nand a third" }
        #expect(after.notes.hasSuffix("and a second line\nand a third"))
        #expect(Self.merge(after, hostile).notes == after.notes)
        // What the insider may do, as any writer may: remove a line it has seen, by the ID it now knows.
        var removal = Self.edit(offline, by: Self.insider, at: 6) { $0.notes = "one\nand a second line" }
        removal.notes = NoteText.text(removal.noteLines)
        #expect(Self.merge(offline, removal).notes == "one\nand a second line")
    }

    // MARK: - Structure

    /// Threat: the insider writes note lines that no honest edit could: anchors that form a cycle or point at
    /// nothing, a line anchored on itself, one ID given several times with different texts and anchors, and a chain
    /// thousands deep — to make ordering loop or recurse without end, to make two devices order the same lines
    /// differently, or to have an honest line dropped as a "duplicate".
    @Test(
        "cyclic, dangling and repeated note lines are ordered the same everywhere, and none is dropped",
        .timeLimit(.minutes(2)))
    func noteLineStructure() {
        let base = Self.base()
        func id(_ version: UInt64, _ index: UInt32) -> NoteLine.ID {
            NoteLine.ID(revision: Revision(version: version, device: Self.insider), index: index)
        }
        var lines = base.noteLines
        lines += [
            NoteLine(id: id(2, 0), after: id(2, 1), text: "cycle a"),
            NoteLine(id: id(2, 1), after: id(2, 0), text: "cycle b"),
            NoteLine(id: id(2, 2), after: id(2, 2), text: "anchored on itself"),
            NoteLine(id: id(2, 3), after: id(9, 9), text: "anchored on nothing"),
            NoteLine(id: id(2, 4), after: nil, text: "one ID, first text"),
            NoteLine(id: id(2, 4), after: base.noteLines[0].id, text: "one ID, second text"),
            // An honest line's ID, reused with another text.
            NoteLine(id: base.noteLines[1].id, after: base.noteLines[2].id, text: "not what was written"),
        ]
        var previous = id(2, 4)
        for index in UInt32(10)..<5_010 {
            lines.append(NoteLine(id: id(2, index), after: previous, text: "deep \(index)"))
            previous = id(2, index)
        }
        var hostile = Self.edit(base, by: Self.insider, at: 2) { $0.archived = true }
        hostile.noteLines = lines

        let forwards = NoteText.ordered(lines)
        #expect(NoteText.ordered(lines.reversed()) == forwards && NoteText.ordered(forwards) == forwards)
        #expect(Set(forwards.map(\.id)).count == forwards.count && forwards.count == Set(lines.map(\.id)).count)
        let honest = Self.edit(base, by: Self.honest, at: 2) { $0.notes += "\nfourth" }
        let merged = Self.merge(honest, hostile)
        #expect(merged == Self.merge(hostile, honest))
        #expect(Self.merge(merged, hostile) == merged && Self.merge(merged, honest) == merged)
        let text = NoteText.lines(of: merged.notes)
        for expected in [
            "first", "second", "third", "fourth", "cycle a", "cycle b", "anchored on itself", "anchored on nothing",
            "one ID, first text", "one ID, second text", "not what was written", "deep 5009",
        ] {
            #expect(text.contains(expected), "\(expected) is missing")
        }
        // The item is still editable, and the edit keeps everything else.
        let edited = Self.edit(merged, by: Self.honest, at: 4) {
            $0.notes = $0.notes.replacingOccurrences(of: "fourth", with: "4th")
        }
        #expect(NoteText.lines(of: edited.notes).count == text.count && edited.notes.contains("4th"))
    }

    /// Threat: the insider files values where they do not belong — a title among the conflicts of a group it made up,
    /// one field's contents under another field's group, a removal under an attribute, an arrangement of the fields as
    /// a "conflict", a second spelling of a field's group. Applying a value by its type rather than by the group it is
    /// filed under put the planted title in place of the honest one *under the honest device's stamp*, so the next
    /// merge kept it as that device's own write (review finding Y20).
    @Test("values filed under groups they do not belong to are not read")
    func valuesUnderTheWrongGroup() {
        let base = Self.base()
        let honest = Self.edit(base, by: Self.honest, at: 2) { $0.title = "Honest rename" }
        var hostile = Self.edit(base, by: Self.insider, at: 2) { $0.archived = true }
        let stamp = Self.stamp(2, Self.insider, seen: [Self.honest: 1, Self.insider: 2])
        let planted = Field(id: Self.password, kind: .password, label: "Password", value: "planted-password")
        hostile.conflicts = [
            ItemGroup(rawValue: "zzz"): [ConflictingValue(stamp: stamp, value: .title("Planted"))],
            .tags: [ConflictingValue(stamp: stamp, value: .title("Planted"))],
            .field(Self.username): [ConflictingValue(stamp: stamp, value: .field(planted))],
            .title: [ConflictingValue(stamp: stamp, value: .field(nil))],
            .fieldOrder: [ConflictingValue(stamp: stamp, value: .fieldOrder([]))],
            ItemGroup(rawValue: "field." + Self.password.uuidString.lowercased()): [
                ConflictingValue(stamp: stamp, value: .field(planted))
            ],
        ]
        hostile.revisions[ItemGroup(rawValue: "nonsense")] = stamp
        hostile.retainedValues = [ConflictingValue(stamp: stamp, value: .field(nil))]
        hostile.discards[ItemGroup(rawValue: "zzz")] = VersionVector([Self.honest: 2])

        for merged in [Self.merge(honest, hostile), Self.merge(hostile, honest)] {
            #expect(merged.title == "Honest rename")
            #expect(merged.revisions[.title]?.revision == Revision(version: 2, device: Self.honest))
            #expect(merged.field(.password)?.value == "honest-password" && merged.field(.username)?.value == "pat")
            #expect(merged.archived, "what the insider did write as itself is merged")
            #expect(merged.conflicts.isEmpty && merged.retainedValues.isEmpty && merged.discards.isEmpty)
            #expect(merged.revisions.keys.allSatisfy { $0.isKnown })
            #expect(!Self.fieldValues(merged).contains("planted-password"))
        }
    }

    /// Threat: the insider repeats identifiers — one field ID twice in `fields`, one device twice in a version vector
    /// under two spellings, one stamp on two values, two stamps each claiming to have seen the other — where the
    /// reader keeps "the first" or "the last" in an order that differs from run to run, so two devices (or one device
    /// twice) read different items from the same bytes; or where two values each superseded by the other both vanish.
    @Test("repeated identifiers are read one way, and values that claim to supersede each other are both kept")
    func repeatedIdentifiers() throws {
        let base = Self.base()
        var hostile = Self.edit(base, by: Self.insider, at: 2) { $0.archived = true }
        hostile.fields.append(Field(id: Self.password, kind: .password, label: "Password", value: "second-copy"))
        hostile.fieldOrder = [Self.password, Self.password, Self.username, Self.password]
        // Each claims the other's revision; neither has seen more than the other.
        let mutual: [UUID: UInt64] = [Self.honest: 2, Self.other: 2, Self.insider: 2]
        hostile.revisions[.title] = Self.stamp(2, Self.other, seen: mutual)
        hostile.title = "One"
        hostile.conflicts[.title] = [
            ConflictingValue(stamp: Self.stamp(2, Self.honest, seen: mutual), value: .title("Other")),
            ConflictingValue(stamp: Self.stamp(2, Self.honest, seen: mutual), value: .title("Other")),
            // One stamp, two values.
            ConflictingValue(stamp: Self.stamp(2, Self.other, seen: mutual), value: .title("One again")),
        ]
        let read = ItemMerge.canonical(hostile, origin: Self.origin(hostile))
        #expect(read.fields.map(\.id) == [Self.password, Self.username])
        #expect(read.field(.password)?.value == "honest-password", "the first of a repeated field")
        #expect(read.fieldOrder == [Self.password, Self.username])
        #expect(Set([read.title] + (read.conflicts[.title] ?? []).map { "\($0.value)" }).count == 3)
        #expect(
            Set(ItemMerge.conflicts(of: read)[.title]?.map(\.value) ?? []).union([.title(read.title)]) == [
                .title("One"), .title("Other"), .title("One again"),
            ])
        // Read again from its bytes, and merged with itself, it is the same item every time.
        let bytes = try JSONEncoder().encode(hostile)
        for _ in 0..<8 {
            let again = try JSONDecoder().decode(Item.self, from: bytes)
            #expect(ItemMerge.canonical(again, origin: Self.origin(again)) == read)
        }
        #expect(Self.merge(hostile, hostile) == read && Self.merge(read, hostile) == read)

        // One device under two spellings in a vector: the higher count, whichever comes first.
        let spelled = "{\"\(Self.honest.uuidString)\":3,\"\(Self.honest.uuidString.lowercased())\":7}"
        for _ in 0..<8 {
            #expect(try JSONDecoder().decode(VersionVector.self, from: Data(spelled.utf8)).entries == [Self.honest: 7])
        }
    }

    // MARK: - Size

    /// Threat: the insider fills a record to the payload limit with conflicting values — thousands of values of one
    /// group, none of which supersedes another, then thousands whose vectors are each as long as the limit allows — so
    /// that finding the values nothing supersedes, which compares values pairwise, takes minutes on every device at
    /// every sync. The payload limit (SEC9) is the bound; within it a merge must stay quick (in an optimised build,
    /// about what decoding the payload costs: docs/10-sync-correctness.md §6. This build is not optimised, hence the
    /// generous limit).
    @Test(
        "a record full of conflicting values merges quickly, and loses none of an honest device's",
        .timeLimit(.minutes(3)))
    func enormousMetadata() throws {
        let base = Self.base()
        let honest = Self.edit(base, by: Self.honest, at: 2) { $0.fields[1].value = "changed-meanwhile" }
        func device(_ n: Int) -> UUID {
            UUID(
                uuid: (
                    0xDD, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, UInt8(n >> 16 & 0xFF), UInt8(n >> 8 & 0xFF),
                    UInt8(n & 0xFF)
                ))
        }
        // Thousands of values of one group whose vectors differ in weight and none of which covers another, so that
        // each must be checked against all the heavier ones.
        var wide = Self.edit(base, by: Self.insider, at: 9_000) { $0.archived = true }
        wide.conflicts[.tags] = (0..<3_600).map { n in
            ConflictingValue(
                stamp: Self.stamp(2, device(n), seen: [device(0): UInt64(n + 1), device(1): UInt64(2 * (3_600 - n))]),
                value: .tags(["t\(n)"]))
        }
        // A few hundred values whose vectors name thousands of devices each, every one incomparable with the rest.
        var deep = Self.edit(base, by: Self.insider, at: 9_000) { $0.archived = true }
        deep.conflicts[.title] = (0..<24).map { n in
            var seen: [UUID: UInt64] = [:]
            for other in 0..<900 { seen[device(other)] = other % 24 == n ? 2 : 1 }
            return ConflictingValue(stamp: Self.stamp(2, device(n), seen: seen), value: .title("t\(n)"))
        }
        for hostile in [wide, deep] {
            let size = try ItemCodec.encode(hostile).count
            #expect(size > 700_000, "close to the payload limit (\(size) bytes)")
            let merged = Self.merge(honest, hostile)
            #expect(merged == Self.merge(hostile, honest))
            #expect(Self.merge(merged, hostile) == merged && Self.merge(merged, merged) == merged)
            #expect(merged.field(.password)?.value == "changed-meanwhile")
            #expect(Self.fieldValues(merged).isSuperset(of: ["pat", "changed-meanwhile", "honest-password"]))
            // Still an item a person can edit and resolve.
            let group: ItemGroup = hostile.conflicts[.tags] == nil ? .title : .tags
            let resolved = ItemMerge.resolve(
                merged, group: group, choosing: merged.value(of: group)!, origin: Self.origin(merged),
                revision: Revision(version: 9_001, device: Self.honest))
            #expect(!resolved.hasConflicts)
            #expect(Self.merge(resolved, hostile) == resolved, "resolved for good")
        }
    }

    /// Threat: the insider fills a record to the payload limit with note lines that all carry one ID, or a handful
    /// of IDs, each copy with a different text. Copies of one ID are joined, keeping every text; joining them one at
    /// a time re-split and re-sorted everything joined so far at each step, so one such record cost each honest
    /// device ten to twenty seconds of CPU *every time it read the item* (optimised; minutes in this build), and a
    /// few hundred of them kept sync busy for an hour (review finding Y32). Reading must stay linear in the payload.
    @Test(
        "a record full of note lines under one ID, or a few, is read in linear time and loses no honest line",
        .timeLimit(.minutes(2)))
    func linesUnderOneID() throws {
        let base = Self.base()
        let honest = Self.edit(base, by: Self.honest, at: 2) { $0.notes += "\nfourth" }
        for ids in [1, 5] {
            var hostile = Self.edit(base, by: Self.insider, at: 2) { $0.archived = true }
            hostile.noteLines += (0..<6_000).map { n in
                NoteLine(
                    id: NoteLine.ID(revision: Revision(version: 2, device: Self.insider), index: UInt32(n % ids)),
                    after: n < 50 ? base.noteLines[n % base.noteLines.count].id : nil, text: "t\(n)")
            }
            let size = try ItemCodec.encode(hostile).count
            #expect(size > 700_000, "close to the payload limit (\(size) bytes)")
            let merged = Self.merge(honest, hostile)
            #expect(merged == Self.merge(hostile, honest))
            #expect(Self.merge(merged, hostile) == merged && Self.merge(merged, merged) == merged)
            let lines = Set(NoteText.lines(of: merged.notes))
            #expect(lines.isSuperset(of: ["first", "second", "third", "fourth", "t0", "t5999"]))
            #expect(lines.count == 6_004 && merged.noteLines.count == honest.noteLines.count + ids)
            // Still an item a person can edit.
            let edited = Self.edit(merged, by: Self.honest, at: 4) {
                $0.notes = $0.notes.replacingOccurrences(of: "fourth", with: "4th")
            }
            #expect(NoteText.lines(of: edited.notes).contains("4th"))
        }
    }

    /// Threat: the insider writes stamps that no `GroupStamp.init` produces — a vector that does not contain the
    /// stamp's own revision (a stamp decodes as it was encoded) — on a value it files among the retained ones. A
    /// resolution discards what the person had before them *by revision*; a value whose vector hid its revision was
    /// removed where the person resolved and came back with the next merge, so an explicit discard (F7.7) did not
    /// hold and the resolved version did not contain the one it was made on (review finding Y34).
    @Test("a stamp that omits its own revision is read as containing it: a resolution discards the value for good")
    func stampsThatOmitTheirRevision() throws {
        let base = Self.base()
        let honest = Self.edit(base, by: Self.honest, at: 2) { $0.fields[1].value = "mine" }
        var hostile = Self.edit(base, by: Self.insider, at: 2) { $0.fields[1].value = "theirs" }
        let json = """
            {"stamp":{"revision":{"version":1,"device":"\(Self.other.uuidString)"},"seen":{"\(Self.honest.uuidString)":1}},
             "value":{"field":{"_0":{"id":"\(Self.password.uuidString)","kind":"password","label":"Password","value":"planted","meta":{}}}}}
            """
        let planted = try JSONDecoder().decode(ConflictingValue.self, from: Data(json.utf8))
        #expect(!planted.stamp.seen.contains(planted.stamp.revision), "decoded as written")
        hostile.retainedValues = [planted]
        let merged = ItemMerge.written(Self.merge(honest, hostile), as: Revision(version: 3, device: Self.honest))
        #expect(merged.retainedValues.count == 1 && merged.hasConflicts)
        let group = ItemGroup.field(Self.password)
        let resolved = ItemMerge.resolve(
            merged, group: group, choosing: merged.value(of: group)!, origin: Self.origin(merged),
            revision: Revision(version: 4, device: Self.honest))
        #expect(resolved.retainedValues.isEmpty && !resolved.hasConflicts)
        for other in [merged, hostile, honest] {
            let again = Self.merge(resolved, other)
            #expect(again == resolved, "the discard holds against every copy that still has the value")
        }
    }

    // MARK: - Laws on anything

    /// Threat: the insider writes metadata chosen so that the merge is no longer a join — the result depends on the
    /// order two honest devices happen to receive versions in, and they never agree (each writes its result, the other
    /// merges it into something else, for ever) — or so that merging its record makes an honest value disappear with
    /// no value claiming to have replaced it.
    ///
    /// Random records are built from honest ones by replacing stamps, clocks, conflicts, retained values, discards,
    /// note lines, field lists and orders with arbitrary ones drawn from a small pool (so identifiers collide), at
    /// record versions from 1 to 2^62. Whatever they hold, read as every device reads them, they obey the laws.
    @Test(
        "on arbitrary metadata the merge is still commutative, associative and idempotent, and drops nothing unclaimed")
    func lawsOnHostileMetadata() {
        let seed = TestEnvironment.seed(fallback: 0xBAD_17E3)
        var generator = SeededGenerator(seed: seed)
        for round in 0..<TestEnvironment.iterations(standard: 150, long: 10_000) {
            let honest = Self.honestVersions(using: &generator)
            let items = (0..<3).map { _ in
                Self.hostile(from: honest.randomElement(using: &generator)!, using: &generator)
            }
            let (a, b, c) = (items[0], items[1], items[2])
            let context = "seed \(seed), round \(round)"
            for item in items {
                let read = ItemMerge.canonical(item, origin: Self.origin(item))
                #expect(
                    ItemMerge.canonical(read, origin: Self.origin(read)) == read, "\(context): reading is not stable")
                #expect(Self.merge(item, item) == read, "\(context): not idempotent")
            }
            let ab = Self.merge(a, b)
            #expect(ab == Self.merge(b, a), "\(context): not commutative")
            #expect(
                Self.merge(ab, a) == ab && Self.merge(ab, b) == ab, "\(context): a merge does not contain its inputs")
            let left = Self.merge(ab, c)
            #expect(left == Self.merge(a, Self.merge(b, c)), "\(context): not associative")
            #expect(left == Self.merge(Self.merge(a, c), b), "\(context): not associative")

            // An honest version merged with a hostile one: every honest value is still there, unless a value of the
            // same group in the hostile record claims to have seen more than its writer had.
            let mine = honest.randomElement(using: &generator)!
            let merged = Self.merge(mine, a)
            let hostile = ItemMerge.canonical(a, origin: Self.origin(a))
            for (group, stamp) in mine.revisions where group != .fieldOrder {
                let candidates =
                    [ConflictingValue(stamp: stamp, value: mine.value(of: group)!)] + (mine.conflicts[group] ?? [])
                let theirs =
                    (hostile.revisions[group].map { [$0] } ?? []) + (hostile.conflicts[group] ?? []).map(\.stamp)
                for candidate in candidates where !theirs.contains(where: { $0.supersedes(candidate.stamp) }) {
                    let kept = [merged.value(of: group)!] + (merged.conflicts[group] ?? []).map(\.value)
                    #expect(kept.contains(candidate.value), "\(context): \(group.rawValue) lost an honest value")
                }
            }
            // Updates made on a hostile record contain it, as they contain an honest one: an edit, a resolution, and
            // a deletion that did not cover it, which is the same join whichever side of a merge it is applied to.
            let next = Revision(version: hostile.version + 1, device: Self.honest)
            var draft = hostile
            draft.title = "renamed after"
            draft.notes += "\nadded after"
            draft.version = next.version
            var nonces = SeededGenerator(seed: UInt64(round))
            let edited = ItemMerge.stamped(
                draft, previous: a, previousOrigin: Self.origin(a), revision: next, using: &nonces)
            #expect(Self.merge(edited, a) == edited, "\(context): an edit does not contain its predecessor")
            #expect(edited.title == "renamed after" && edited.conflicts[.title] == nil, "\(context): edit not shown")
            #expect(
                Array(edited.notes.utf8) == Array(draft.notes.utf8),
                "\(context): the notes saved are not the notes typed")
            for (group, values) in ItemMerge.conflicts(of: hostile) {
                let chosen = values.randomElement(using: &generator)!.value
                let resolved = ItemMerge.resolve(
                    hostile, group: group, choosing: chosen, origin: Self.origin(hostile), revision: next)
                #expect(
                    Self.merge(resolved, a) == resolved, "\(context): a resolution does not contain its predecessor")
                #expect(resolved.value(of: group) == chosen, "\(context): a resolution does not show the choice")
                #expect(
                    !resolved.retainedValues.contains { ItemMerge.group(of: $0.value) == group },
                    "\(context): a resolution left retained values")
            }
            let erasure = ItemErasure(
                seen: VersionVector([Self.honest: [0, 1, 2].randomElement(using: &generator)!]),
                row: [1, 2, 9].randomElement(using: &generator)!, device: Self.other,
                date: Date(timeIntervalSince1970: 7))
            func settled(_ item: Item) -> Item? {
                switch ItemMerge.settle(item, origin: Self.origin(item), against: erasure) {
                case .erase: return nil
                case .keep: return ItemMerge.canonical(item, origin: Self.origin(item))
                case .kept(let kept):
                    // Written above the row and the tombstone, as `ItemRecordMerger` writes it.
                    let above = max(item.version, erasure.revision.version) + 1
                    return ItemMerge.written(kept, as: Revision(version: above, device: Self.honest))
                }
            }
            if let keptA = settled(a), let keptB = settled(b), let keptBoth = settled(ab) {
                #expect(Self.merge(keptA, a) == keptA, "\(context): a deletion kept less than it was applied to")
                #expect(settled(keptA) == keptA, "\(context): settling twice is not settling once")
                #expect(
                    ItemMerge.sameState(keptBoth, Self.merge(keptA, keptB)),
                    "\(context): settling does not commute with merging")
            }
            #expect(Set(merged.history).isSuperset(of: mine.history), "\(context): history shortened")
            let removed = Set(hostile.noteLines.filter(\.removed).map(\.id))
            let visible = Set(NoteText.lines(of: merged.notes))
            for line in mine.noteLines where !line.removed && !removed.contains(line.id) {
                #expect(visible.contains(line.text), "\(context): a note line was dropped that nothing removed")
            }
        }
    }

    /// A few honest versions of one item: edits by two devices, merged or not.
    static func honestVersions(using generator: inout SeededGenerator) -> [Item] {
        var model = MergeFixtureModel()
        for _ in 0..<Int.random(in: 1...6, using: &generator) { model.step(using: &generator) }
        return model.versions
    }

    struct MergeFixtureModel {
        var copies: [Item]
        var versions: [Item]
        var next: UInt64 = 2

        init() {
            let base = AdversarialItemMergeTests.base()
            copies = [base, base]
            versions = [base]
        }

        mutating func step(using generator: inout SeededGenerator) {
            typealias T = AdversarialItemMergeTests
            let index = Int.random(in: 0..<2, using: &generator)
            let device = [T.honest, T.other][index]
            let word = "w\(next)"
            switch Int.random(in: 0..<7, using: &generator) {
            case 0: copies[index] = T.edit(copies[index], by: device, at: next) { $0.title = word }
            case 1:
                copies[index] = T.edit(copies[index], by: device, at: next) {
                    if !$0.fields.isEmpty { $0.fields[0].value = word }
                }
            case 2: copies[index] = T.edit(copies[index], by: device, at: next) { $0.notes += "\n" + word }
            case 3:
                copies[index] = T.edit(copies[index], by: device, at: next) {
                    if $0.fields.count > 1 { $0.fields.removeLast() }
                }
            case 4: copies[index] = T.edit(copies[index], by: device, at: next) { $0.fields.reverse() }
            case 5:
                copies[index] = T.edit(copies[index], by: device, at: next) {
                    $0.trashedAt = $0.trashedAt == nil ? Date(timeIntervalSince1970: 1_800_000_500) : nil
                }
            default:
                copies[index] = ItemMerge.written(
                    T.merge(copies[index], copies[1 - index]), as: Revision(version: next, device: device))
            }
            next += 1
            versions.append(copies[index])
        }
    }

    /// `item` with its sync metadata replaced, in part, by arbitrary claims.
    static func hostile(from item: Item, using generator: inout SeededGenerator) -> Item {
        var item = item
        let devices = [honest, other, insider, ItemMerge.zeroDevice]
        let counts: [UInt64] = [0, 1, 2, 3, 5, 8, item.version, item.version + 1, 1 << 62, .max]
        item.version = [1, 3, 9, 1 << 62].randomElement(using: &generator)!
        func revision(_ g: inout SeededGenerator) -> Revision {
            Revision(version: counts.randomElement(using: &g)!, device: devices.randomElement(using: &g)!)
        }
        func vector(_ g: inout SeededGenerator) -> VersionVector {
            var entries: [UUID: UInt64] = [:]
            for device in devices where Bool.random(using: &g) { entries[device] = counts.randomElement(using: &g)! }
            return VersionVector(entries)
        }
        func stamp(_ g: inout SeededGenerator) -> GroupStamp {
            var stamp = GroupStamp(revision: revision(&g), seen: vector(&g))
            // As a stamp decodes: its vector need not contain its own revision (review finding Y34).
            if Int.random(in: 0..<3, using: &g) == 0 { stamp.seen = vector(&g) }
            return stamp
        }
        // Two spellings of one text, equal as `String`s and different in bytes (review finding Y31), among the others.
        let words = ["hostile-0", "hostile-1", "caf\u{E9}", "cafe\u{301}"]
        let fieldIDs = [username, password, UUID(uuidString: "F1000000-0000-4000-8000-000000000003")!]
        func field(_ g: inout SeededGenerator) -> Field {
            Field(
                id: fieldIDs.randomElement(using: &g)!, kind: .text,
                label: ["L", "\u{E9}", "e\u{301}"].randomElement(using: &g)!,
                value: words.randomElement(using: &g)!,
                meta: Int.random(in: 0..<4, using: &g) == 0 ? [words.randomElement(using: &g)!: "m"] : [:])
        }
        func value(_ g: inout SeededGenerator) -> ItemGroupValue {
            switch Int.random(in: 0..<10, using: &g) {
            case 0: return .title(words.randomElement(using: &g)!)
            case 1: return .tags((["a\nb", "a", "b"] + words).randomElement(using: &g).map { [$0] } ?? [])
            case 2:
                var scope = ServiceScope(host: "h\(Int.random(in: 0..<2, using: &g)).example.com")
                if Bool.random(using: &g) { scope.host = words.randomElement(using: &g)! }
                return .scopes([scope])
            case 3: return .archived(Bool.random(using: &g))
            case 4: return .trashedAt(Bool.random(using: &g) ? Date(timeIntervalSince1970: 5) : nil)
            case 5: return .keptAfterDeletion(Bool.random(using: &g))
            case 6: return .excludedFromSuggestions(Bool.random(using: &g))
            case 7: return .fieldOrder(fieldIDs.shuffled(using: &g))
            case 8: return .field(nil)
            default: return .field(field(&g))
            }
        }
        let groups =
            ItemGroup.attributes + fieldIDs.map(ItemGroup.field) + [
                ItemGroup(rawValue: "zzz"), ItemGroup(rawValue: "field." + password.uuidString.lowercased()),
            ]
        func conflict(_ g: inout SeededGenerator) -> ConflictingValue {
            ConflictingValue(stamp: stamp(&g), value: value(&g))
        }
        if Bool.random(using: &generator) { item.clock = vector(&generator) }
        for group in groups {
            switch Int.random(in: 0..<6, using: &generator) {
            case 0: item.revisions[group] = stamp(&generator)
            case 1: item.revisions[group] = nil
            case 2:
                // Values of the right kind for the group as often as not, so that they are read and compete.
                item.conflicts[group] = (0..<Int.random(in: 1...4, using: &generator)).map { _ in
                    var planted = conflict(&generator)
                    if Bool.random(using: &generator), let own = item.value(of: group) {
                        planted.value = Bool.random(using: &generator) ? own : planted.value
                        if case .title = own { planted.value = .title(words.randomElement(using: &generator)!) }
                        if case .field = own {
                            planted.value = .field(
                                Field(
                                    id: group.fieldID ?? username, kind: .text, label: "L",
                                    value: words.randomElement(using: &generator)!))
                        }
                    }
                    return planted
                }
            case 3: item.discards[group] = vector(&generator)
            default: break
            }
        }
        if Bool.random(using: &generator) {
            item.retainedValues = (0..<Int.random(in: 0...4, using: &generator)).map { _ in conflict(&generator) }
        }
        if Bool.random(using: &generator) {
            item.fields += (0..<Int.random(in: 0...2, using: &generator)).map { _ in field(&generator) }
            item.fields.shuffle(using: &generator)
        }
        switch Int.random(in: 0..<3, using: &generator) {
        case 0: item.fieldOrder = nil
        case 1: item.fieldOrder = (fieldIDs + fieldIDs).shuffled(using: &generator)
        default: break
        }
        if Bool.random(using: &generator) {
            let ids = (0..<4).map { _ in
                NoteLine.ID(
                    revision: revision(&generator), index: UInt32.random(in: 0..<2, using: &generator),
                    nonce: UInt64.random(in: 0..<2, using: &generator))
            }
            item.noteLines += (0..<Int.random(in: 1...6, using: &generator)).map { _ in
                NoteLine(
                    id: ids.randomElement(using: &generator)!,
                    after: Bool.random(using: &generator)
                        ? ids.randomElement(using: &generator)! : item.noteLines.randomElement(using: &generator)?.id,
                    text: (["x", "y", "x\ny", ""] + words).randomElement(using: &generator)!,
                    removed: Int.random(in: 0..<4, using: &generator) == 0)
            }
            if Bool.random(using: &generator) { item.noteLines.shuffle(using: &generator) }
            if Int.random(in: 0..<4, using: &generator) == 0 { item.notes = "claimed, not what the lines say" }
        }
        if Int.random(in: 0..<4, using: &generator) == 0 {
            item.history.append(
                ItemHistoryEntry(
                    replacedAt: Date(timeIntervalSince1970: Double(Int.random(in: 0..<3, using: &generator))),
                    version: counts.randomElement(using: &generator)!, fields: [field(&generator)]))
        }
        return item
    }

    // MARK: - Erasure summaries

    /// Threat: the insider publishes a tombstone whose erasure summary is not what an honest deletion writes: bytes
    /// that do not decode; a vector naming `UInt64.max`, so that the version of the copy kept after the deletion —
    /// computed from it — overflows and traps every device holding the item, at every launch (review finding Y24); a
    /// vector that claims more than the row it says it erased could hold. None may crash, and none may erase anything:
    /// a summary that is not plausible has seen nothing, so every version is kept.
    @Test("an erasure summary that overflows, lies or does not decode erases nothing and traps nothing")
    func hostileErasureSummaries() async throws {
        let keys = FakeAccountKeys(seed: 21)
        await keys.addVaultKey(vaultID: Self.vault)
        let keyring = FakeSyncKeyring(deviceID: Self.honest, keys: keys)
        let merger = ItemRecordMerger(sealer: keyring, deviceID: Self.honest)
        let item = Self.edit(Self.base(), by: Self.honest, at: 2) { $0.fields[1].value = "kept-password" }
        let row = try await keyring.sealItem(item)
        let everything = "{\"\(Self.honest.uuidString)\":18446744073709551615}"
        let summaries: [[UInt8]] = [
            [], [0xFF, 0x00], Array("null".utf8), Array("[]".utf8), Array(everything.utf8),
            Array(
                "{\"seen\":\(everything),\"row\":18446744073709551615,\"device\":\"\(Self.insider.uuidString)\"}".utf8),
            Array("{\"seen\":\(everything),\"row\":3,\"device\":\"\(Self.insider.uuidString)\"}".utf8),
            Array("{\"seen\":{},\"row\":-1,\"device\":\"\(Self.insider.uuidString)\"}".utf8),
            Array("{\"seen\":{\"not a device\":1},\"row\":9,\"device\":\"\(Self.insider.uuidString)\"}".utf8),
        ]
        // Each arrives on a tombstone just above the row, as a deletion of it is stamped; the copy kept is written
        // above that tombstone, which the engine names (Y28), whatever the summary says.
        let tombstone = row.version + 1
        for summary in summaries {
            #expect(ItemErasure(summary: summary) == .void)
            #expect(ItemErasures(summary: summary) == ItemErasures([.void]))
            guard case .replace(let kept) = try await merger.resolveErasure(summary, of: row, above: tombstone) else {
                Issue.record("a summary that has seen nothing erased or ignored a version")
                continue
            }
            let opened = try await keyring.openItem(kept)
            #expect(opened.field(.password)?.value == "kept-password" && opened.isTrashed && opened.keptAfterDeletion)
            #expect(!opened.isTrashedByPerson && kept.version == tombstone + 1)
        }
        // A plausible summary from the insider, on the tombstone it names, erases what it claims to have seen — a
        // deletion is a writer's to make — and nothing more: an edit above what it names is kept, above the tombstone.
        let plausible = try ItemErasure(
            seen: VersionVector([Self.honest: 1]), row: 1 << 40, device: Self.insider,
            date: Date(timeIntervalSince1970: 1)
        ).summary()
        guard case .replace(let kept) = try await merger.resolveErasure(plausible, of: row, above: (1 << 40) + 1)
        else {
            Issue.record("an edit the summary does not name was not kept")
            return
        }
        #expect(kept.version == (1 << 40) + 2)
        #expect(try await keyring.openItem(kept).field(.password)?.value == "kept-password")
        // On a tombstone below the row it names, it is not believed at all: it has seen nothing, and the copy is
        // written just above the tombstone.
        guard case .replace(let exact) = try await merger.resolveErasure(plausible, of: row, above: 7) else {
            Issue.record("an edit the summary does not name was not kept")
            return
        }
        #expect(exact.version == 8)
        let opened = try await keyring.openItem(exact)
        #expect(opened.revisions[.trashedAt]?.revision == ItemErasure.void.revision, "the summary was not believed")
    }

    /// Threat: the insider publishes a tombstone at an ordinary version whose summary says the row it erased was at
    /// version 2^40. A version kept after a deletion is written above the row the summary names, so every device
    /// holding an edit the summary does not cover writes its copy at 2^40 + 2: the vault's versions have jumped by more
    /// than the engine lets any *received* version jump (review finding U5 — repeat it and the versions run out).
    ///
    /// The engine now passes the tombstone's stamp to `RecordMerger.resolveErasure`, and `ItemRecordMerger` believes
    /// no summary that names a row above it and writes just above the tombstone (docs/06-adversarial-review.md §H,
    /// Y28, fixed when the sync-core workstream merged).
    @Test("a tombstone whose summary names a far higher row does not raise the vault's versions")
    func tombstoneNamingAHigherRow() async throws {
        let keys = FakeAccountKeys(seed: 22)
        await keys.addVaultKey(vaultID: Self.vault)
        await keys.trust(device: Self.insider)
        await keys.trust(device: Self.honest)
        let transport = InMemorySyncTransport()
        let writer = SyncTestClient(deviceID: Self.insider, vaultID: Self.vault, keys: keys, transport: transport)
        let reader = SyncTestClient(deviceID: Self.honest, vaultID: Self.vault, keys: keys, transport: transport)
        let item = try await writer.save(
            Item(
                id: Self.itemID, vaultID: Self.vault, title: "Bank", scopes: [],
                fields: [Field(id: Self.password, kind: .password, label: "Password", value: "one")]))
        try await writer.sync()
        try await reader.sync()
        try await reader.edit(item.id) { $0.fields[0].value = "typed on the honest device" }

        let key = RecordKey(recordID: item.id, kind: .item)
        let summary = try ItemErasure(
            seen: VersionVector([Self.insider: 1]), row: 1 << 40, device: Self.insider,
            date: Date(timeIntervalSince1970: 1)
        ).summary()
        let payload = SyncPayload(
            kind: .segment, vaultID: Self.vault, author: Self.insider, number: 2, vector: [:],
            entries: [
                .tombstone(key, stamp: RecordStamp(version: 2, device: Self.insider, deleted: true), erasure: summary)
            ])
        let envelope = try await writer.keyring.seal(payload.encoded(), at: payload.location)
        let signature = try await writer.keyring.sign(envelope, at: payload.location)
        try await transport.create(
            payload.location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())

        let report = try await reader.sync()
        #expect(report.rejected.isEmpty)
        let kept = try #require(await reader.store.record(key))
        #expect(try await reader.item(item.id).fields[0].value == "typed on the honest device")
        #expect(kept.version <= 2 + SyncTestClient.configuration.maximumVersionJump)
        #expect(kept.version == 3, "just above the tombstone")
    }

    // MARK: - Size, at the engine

    static func clients(seed: UInt64, _ devices: [UUID]) async -> [SyncTestClient] {
        let keys = FakeAccountKeys(seed: seed)
        await keys.addVaultKey(vaultID: vault)
        for device in devices { await keys.trust(device: device) }
        let transport = InMemorySyncTransport()
        return devices.map { SyncTestClient(deviceID: $0, vaultID: vault, keys: keys, transport: transport) }
    }

    /// Threat: the insider publishes one version of an item whose clock names thousands of made-up devices. A clock is
    /// a claim like any other, and the merge joins it into every honest copy (it cannot truncate: that is not a join).
    /// When a person then deletes the item — or the 30-day purge does it for them — the tombstone's erasure summary
    /// carried that whole clock: over the 64 KiB a reader accepts, so every other device refused the deleting
    /// device's segment with `erasureTooLarge`, at every sync, and that device's stream stopped there for good.
    /// Nothing it wrote afterwards, in any item, reached anyone (review finding Y36).
    ///
    /// A summary that would not fit now says the deleting device had seen nothing: the tombstone is accepted, erases
    /// nothing elsewhere, and the stream carries on.
    @Test("deleting an item whose clock names thousands of devices does not stop the deleting device's stream")
    func enormousClockAndDeletion() async throws {
        let clients = await Self.clients(seed: 23, [Self.insider, Self.honest, Self.other])
        let (writer, deleter, reader) = (clients[0], clients[1], clients[2])
        var junk = Self.base()
        var claimed: [UUID: UInt64] = [:]
        for n in 0..<2_000 {
            claimed[UUID(uuid: (0xDD, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, UInt8(n >> 8), UInt8(n & 0xFF)))] = 1
        }
        junk.clock = VersionVector(claimed)
        let row = try await writer.keyring.sealItem(junk)
        try await writer.sessionStore.commit(StoreChange(upserts: [row]))
        try await writer.sync()
        try await deleter.sync()
        try await reader.sync()

        // What the merger used to hand the engine, and what it hands it now.
        let held = try #require(await deleter.store.record(row.key))
        let whole = try ItemErasure(
            seen: ItemMerge.effectiveClock(junk, origin: Revision(version: 1, device: Self.insider)), row: 1,
            device: Self.honest, date: junk.modifiedAt
        ).summary()
        #expect(whole.count > SyncPayload.maximumErasureLength, "the clock does not fit in a summary")
        let summary = try await ItemRecordMerger(sealer: deleter.keyring, deviceID: Self.honest)
            .erasureSummary(of: held)
        #expect(summary.count <= SyncPayload.maximumErasureLength)
        let erasure = ItemErasure(summary: summary, tombstone: 2)
        #expect(erasure.seen.isEmpty && erasure.row == 1 && erasure.device == Self.honest)

        try await deleter.delete(junk.id)
        try await deleter.sync()
        let later = try await deleter.save(
            Item(vaultID: Self.vault, title: "Written after the deletion", scopes: [], fields: []))
        try await deleter.sync()

        for _ in 0..<2 {
            let report = try await reader.sync()
            #expect(report.rejected.isEmpty && report.waiting.isEmpty)
        }
        #expect(try await reader.item(later.id).title == "Written after the deletion")
        // The deletion claimed to have seen nothing, so it erased nothing here: the item is kept, in the trash, and
        // is not one the purge removes — the direction that loses no data.
        let kept = try await reader.item(junk.id)
        #expect(kept.isTrashed && kept.keptAfterDeletion && !kept.isTrashedByPerson)
        #expect(kept.field(.password)?.value == "honest-password")
        // And every device settles on that.
        try await writer.sync()
        try await deleter.sync()
        for client in clients {
            let report = try await client.sync()
            #expect(report.rejected.isEmpty && report.waiting.isEmpty)
        }
    }

    /// Threat: none is needed — two honest devices each write long notes into one item without seeing the other's
    /// (each version fits the payload limit, SEC9; their join does not) — and an insider (A4) can arrange it at will.
    /// The merger cannot seal the join, so it throws; the engine rejects the whole object that carried the remote
    /// version, and because a stream is merged strictly in sequence, every later segment from that device is never
    /// applied on the device that could not merge: unrelated items stop arriving, silently and for good.
    ///
    /// The merger now says which failure this is (`ItemMergeError.resultNotSealable`), so that the engine can set
    /// that one entry aside — keep the local version, quarantine the remote one (PRD F7.7) — and carry on with the
    /// stream. The engine does not do that yet; recorded as a known issue until it does
    /// (docs/06-adversarial-review.md §H, Y37).
    @Test("two versions whose merge is over the payload limit do not stop the stream that carried one of them")
    func mergeOverThePayloadLimit() async throws {
        let clients = await Self.clients(seed: 24, [Self.honest, Self.other, Self.insider])
        let (first, reader, second) = (clients[0], clients[1], clients[2])
        let item = try await first.save(
            Item(id: Self.itemID, vaultID: Self.vault, title: "Bank", scopes: [], fields: [], notes: "start"))
        for client in clients { try await client.sync() }
        for client in clients { try await client.sync() }
        try await second.edit(item.id) { $0.notes = String(repeating: "c", count: 505_000) }
        try await first.edit(item.id) { $0.notes = String(repeating: "a", count: 30_000) }
        try await second.sync()
        try await reader.sync()
        let local = try #require(await reader.store.record(RecordKey(recordID: item.id, kind: .item)))
        let remote = try #require(await first.store.record(RecordKey(recordID: item.id, kind: .item)))
        try await first.sync()
        let unrelated = try await first.save(
            Item(vaultID: Self.vault, title: "Unrelated, written afterwards", scopes: [], fields: []))
        try await first.sync()

        await #expect(throws: ItemMergeError.resultNotSealable(item.id)) {
            _ = try await ItemRecordMerger(sealer: reader.keyring, deviceID: Self.other)
                .merge(local: local, remote: remote)
        }
        var report = SyncReport()
        for _ in 0..<2 { report = try await reader.sync() }
        let arrived = try await reader.items()[unrelated.id] != nil
        // Neither version is lost meanwhile: each device still holds its own.
        #expect(try await reader.item(item.id).notes.count == 505_000)
        #expect(try await first.item(item.id).notes.count == 30_000)
        withKnownIssue(
            "SyncEngine rejects the object carrying a version it cannot merge, and the author's stream waits there"
        ) {
            #expect(report.rejected.isEmpty && report.waiting.isEmpty)
            #expect(arrived, "an unrelated item written afterwards never arrives")
        }
    }

    /// Threat: the insider, or a sealer that does not check an item against its row, hands the merger two records
    /// that open to different items. `ItemMerge.merge` traps on that by design; a trap reachable from a record on the
    /// transport is a crash loop.
    @Test("records that open to different items are refused with a typed error, not trapped on")
    func mismatchedIdentity() async throws {
        struct LooseSealer: ItemSealer {
            let items: [UInt64: Item]
            func openItem(_ row: StoredRecord) async throws -> Item { items[row.version]! }
            func sealItem(_ item: Item) async throws -> StoredRecord {
                StoredRecord(
                    recordID: item.id, kind: .item, vaultID: item.vaultID, keyID: UUID(), version: item.version,
                    deviceID: AdversarialItemMergeTests.honest, envelope: [])
            }
        }
        let local = Self.base()
        var foreign = Self.edit(local, by: Self.insider, at: 2) { $0.title = "Another item" }
        foreign.id = UUID()
        let sealer = LooseSealer(items: [1: local, 2: foreign])
        let merger = ItemRecordMerger(sealer: sealer, deviceID: Self.honest)
        let (localRow, foreignRow) = (try await sealer.sealItem(local), try await sealer.sealItem(foreign))
        var relabelled = foreignRow
        relabelled.recordID = local.id
        await #expect(throws: ItemMergeError.identityMismatch(local.id)) {
            _ = try await merger.merge(local: localRow, remote: relabelled)
        }
        await #expect(throws: ItemMergeError.identityMismatch(local.id)) {
            _ = try await merger.resolveErasure([], of: relabelled, above: relabelled.version + 1)
        }
    }
}
