import Foundation
import Testing

@testable import WatchwordModel

/// Equality of what an item holds is equality of bytes (docs/10-sync-correctness.md §2, review finding Y31). Swift's
/// `String` compares by Unicode canonical equivalence, under which the two spellings below are equal; a site hashes
/// the bytes of a password, so to a password manager they are two values.
@Suite("Byte-exact equality of item values")
struct ExactEqualityTests {
    /// "café" with U+00E9, and with "e" followed by U+0301.
    static let composed = "caf\u{E9}"
    static let decomposed = "cafe\u{301}"
    static let device = UUID(uuidString: "D0000000-0000-4000-8000-0000000000A0")!
    static let fieldID = UUID(uuidString: "F1000000-0000-4000-8000-000000000001")!

    static func item(_ text: String) -> Item {
        Item(
            id: UUID(uuidString: "17E00000-0000-4000-8000-000000000001")!,
            vaultID: UUID(uuidString: "0A0A0A0A-0000-4000-8000-00000000000A")!, title: "Bank", scopes: [],
            fields: [Field(id: fieldID, kind: .password, label: "Password", value: text)])
    }

    @Test("the fixture is what it claims: equal as Strings, different bytes")
    func fixture() {
        #expect(Self.composed == Self.decomposed)
        #expect(Array(Self.composed.utf8) == [0x63, 0x61, 0x66, 0xC3, 0xA9])
        #expect(Array(Self.decomposed.utf8) == [0x63, 0x61, 0x66, 0x65, 0xCC, 0x81])
    }

    @Test("a field, a scope, a note line and a group value respelt in another normalisation form are other values")
    func leaves() {
        let (a, b) = (Self.composed, Self.decomposed)
        func field(label: String = "L", value: String = "v", meta: [String: String] = [:]) -> Field {
            Field(id: Self.fieldID, kind: .text, label: label, value: value, meta: meta)
        }
        #expect(field(value: a) != field(value: b) && field(value: a) == field(value: a))
        #expect(field(label: a) != field(label: b))
        #expect(field(meta: [a: "x"]) != field(meta: [b: "x"]) && field(meta: ["k": a]) != field(meta: ["k": b]))
        #expect(field(meta: [a: "x", "k": b]) == field(meta: ["k": b, a: "x"]))

        var scopeA = ServiceScope(host: "example.com")
        var scopeB = scopeA
        scopeA.host = a
        scopeB.host = b
        #expect(scopeA != scopeB && scopeA == scopeA)
        scopeB.host = a
        scopeA.excludedHosts = [a]
        scopeB.excludedHosts = [b]
        #expect(scopeA != scopeB)

        let id = NoteLine.ID(revision: Revision(version: 1, device: Self.device), index: 0)
        #expect(NoteLine(id: id, after: nil, text: a) != NoteLine(id: id, after: nil, text: b))

        let pairs: [(ItemGroupValue, ItemGroupValue)] = [
            (.title(a), .title(b)), (.tags([a]), .tags([b])), (.tags([a, "x"]), .tags([b, "x"])),
            (.scopes([scopeA]), .scopes([scopeB])), (.field(field(value: a)), .field(field(value: b))),
        ]
        for (x, y) in pairs {
            #expect(x != y && x == x && y == y)
            // Both are members of a set: the hash agrees, the equality tells them apart.
            #expect(Set([x, y]).count == 2 && Set([x, x]).count == 1)
        }
        let unlike: [ItemGroupValue] = [
            .title(a), .tags([a]), .scopes([]), .archived(true), .trashedAt(nil), .keptAfterDeletion(true),
            .excludedFromSuggestions(true), .fieldOrder([]), .field(nil), .field(field()),
        ]
        for (index, x) in unlike.enumerated() {
            for (other, y) in unlike.enumerated() { #expect((x == y) == (index == other)) }
        }
    }

    @Test("an item, a history entry and a conflicting value differ when any text in them is spelt differently")
    func composites() {
        let (a, b) = (Self.item(Self.composed), Self.item(Self.decomposed))
        #expect(a != b && a == a && Set([a, b]).count == 2)
        var titled = a
        titled.title = Self.decomposed
        var other = a
        other.title = Self.composed
        #expect(titled != other)
        titled = a
        other = a
        titled.notes = Self.composed
        other.notes = Self.decomposed
        #expect(titled != other)
        titled = a
        other = a
        titled.tags = [Self.composed]
        other.tags = [Self.decomposed]
        #expect(titled != other)

        let date = Date(timeIntervalSince1970: 1)
        #expect(
            ItemHistoryEntry(replacedAt: date, version: 1, fields: a.fields)
                != ItemHistoryEntry(replacedAt: date, version: 1, fields: b.fields))
        let stamp = GroupStamp(revision: Revision(version: 1, device: Self.device), seen: VersionVector())
        let values = [
            ConflictingValue(stamp: stamp, value: .title(Self.composed)),
            ConflictingValue(stamp: stamp, value: .title(Self.decomposed)),
        ]
        #expect(values[0] != values[1] && Set(values).count == 2)
    }

    /// `Hashable` requires equal values to hash alike. `==` is finer than the synthesised hash's notion of equality
    /// (bytes, not canonical equivalence), so this holds; two spellings may hash alike and still be told apart.
    @Test("values equal byte for byte hash alike, and two spellings are two keys")
    func hashingAgreesWithEquality() throws {
        for text in [Self.composed, Self.decomposed] {
            var item = Self.item(text)
            item.title = text
            item.notes = text
            item.tags = [text, "x"]
            item.fields[0].meta = [text: text]
            let copy = try JSONDecoder().decode(Item.self, from: JSONEncoder().encode(item))
            #expect(copy == item && copy.hashValue == item.hashValue)
            #expect(copy.fields[0].hashValue == item.fields[0].hashValue)
            let value = ItemGroupValue.tags(item.tags)
            #expect(value == .tags(copy.tags) && value.hashValue == ItemGroupValue.tags(copy.tags).hashValue)
        }
        var byValue: [ItemGroupValue: Int] = [:]
        byValue[.title(Self.composed)] = 1
        byValue[.title(Self.decomposed)] = 2
        #expect(byValue.count == 2 && byValue[.title(Self.composed)] == 1 && byValue[.title(Self.decomposed)] == 2)
    }

    @Test("encoding and decoding an item keeps the bytes of each spelling")
    func roundTrip() throws {
        for text in [Self.composed, Self.decomposed] {
            var item = Self.item(text)
            item.title = text
            item.notes = text
            item.tags = [text]
            let decoded = try JSONDecoder().decode(Item.self, from: JSONEncoder().encode(item))
            #expect(decoded == item)
            #expect(Array(decoded.fields[0].value.utf8) == Array(text.utf8))
            #expect(Array(decoded.title.utf8) == Array(text.utf8) && Array(decoded.notes.utf8) == Array(text.utf8))
        }
    }

    /// `==` is written out for these types, so a stored property added later must be added to it. This fails until
    /// the count here — and `ExactEquality.swift` — are brought up to date.
    @Test("every stored property is compared: the counts `==` was written for still hold")
    func everyPropertyIsCompared() {
        let item = Self.item("x")
        #expect(Mirror(reflecting: item).children.count == 22)
        #expect(Mirror(reflecting: item.fields[0]).children.count == 5)
        #expect(Mirror(reflecting: ServiceScope(host: "example.com")).children.count == 3)
        let id = NoteLine.ID(revision: Revision(version: 1, device: Self.device), index: 0)
        #expect(Mirror(reflecting: NoteLine(id: id, after: nil, text: "")).children.count == 5)
    }
}

@Suite("Sync metadata as stored")
struct SyncMetadataFormatTests {
    static let device = UUID(uuidString: "D0000000-0000-4000-8000-0000000000A0")!

    @Test("a note line written before lines carried a nonce still opens, with nonce zero")
    func lineWithoutNonce() throws {
        let json = """
            {"id":{"revision":{"version":3,"device":"\(Self.device.uuidString)"},"index":2},"text":"old","removed":false}
            """
        let line = try JSONDecoder().decode(NoteLine.self, from: Data(json.utf8))
        #expect(line.id == NoteLine.ID(revision: Revision(version: 3, device: Self.device), index: 2, nonce: 0))
        let nonced = NoteLine.ID(revision: line.id.revision, index: 2, nonce: 7)
        #expect(try JSONDecoder().decode(NoteLine.ID.self, from: JSONEncoder().encode(nonced)) == nonced)
        // The nonce orders lines only where revision and index tie.
        #expect(line.id < nonced && nonced < NoteLine.ID(revision: line.id.revision, index: 3))
    }

    @Test("a stamp read from a record contains its own revision, whatever the record says")
    func stampContainsItsRevision() {
        let revision = Revision(version: 5, device: Self.device)
        var stamp = GroupStamp(revision: revision, seen: VersionVector())
        #expect(stamp.seen.contains(revision))
        stamp.seen = VersionVector()
        #expect(!stamp.seen.contains(revision))
        #expect(stamp.clamped(to: 9).seen.contains(revision))
        let lowered = stamp.clamped(to: 3)
        #expect(lowered.revision.version == 3 && lowered.seen.entries == [Self.device: 3])
    }
}
