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

    static func base() -> Item {
        let item = Item(
            id: UUID(uuidString: "17E00000-0000-4000-8000-000000000001")!, vaultID: vault, title: "Bank",
            scopes: [ServiceScope(host: "firstbank.co.uk")],
            fields: [
                Field(id: fieldID(1), kind: .username, label: "Username", value: "pat"),
                Field(id: fieldID(2), kind: .password, label: "Password", value: "old-password"),
            ],
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
        return ItemMerge.stamped(item, previous: previous, revision: Revision(version: version, device: device))
    }

    static func origin(_ item: Item, _ device: UUID) -> Revision {
        Revision(version: item.version, device: device)
    }

    static func unordered(_ item: Item) -> Item {
        var item = current(item)
        item.fields.sort { $0.id.precedes($1.id) }
        return item
    }

    /// Current values only: what must agree across devices.
    static func current(_ item: Item) -> Item {
        var item = item
        item.version = 0
        item.history = []
        return item
    }
}

@Suite("Field-level item merge")
struct ItemMergeTests {
    typealias F = MergeFixtures

    @Test("a new item has every group stamped; an edit stamps only what changed")
    func stamping() {
        let base = F.base()
        #expect(Set(base.revisions.keys) == Set(ItemGroup.attributes + [.field(F.fieldID(1)), .field(F.fieldID(2))]))
        #expect(base.revisions.values.allSatisfy { $0 == Revision(version: 1, device: F.a) })
        let edited = F.edit(base, by: F.b, at: 2) { $0.title = "First Bank" }
        #expect(edited.revisions[.title] == Revision(version: 2, device: F.b))
        #expect(edited.revisions[.field(F.fieldID(2))] == Revision(version: 1, device: F.a))
        let removed = F.edit(edited, by: F.a, at: 3) { $0.fields.removeAll { $0.id == F.fieldID(1) } }
        #expect(removed.revisions[.field(F.fieldID(1))] == Revision(version: 3, device: F.a), "a removal is recorded")
        #expect(removed.revisions[.fieldOrder] == Revision(version: 3, device: F.a))
        var slowClock = removed
        slowClock.modifiedAt = Date(timeIntervalSince1970: 0)
        let saved = ItemMerge.stamped(slowClock, previous: removed, revision: Revision(version: 4, device: F.c))
        #expect(saved.modifiedAt == removed.modifiedAt, "a device with a slow clock never moves modifiedAt back")
    }

    @Test("edits to different groups on two devices both survive")
    func disjointEdits() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "new-password" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.notes = "Branch: Leeds" }
        let merged = ItemMerge.merge(onA, origin: F.origin(onA, F.a), onB, origin: F.origin(onB, F.b))
        #expect(merged.field(.password)?.value == "new-password")
        #expect(merged.notes == "Branch: Leeds")
    }

    @Test("the same field edited on two devices: the later revision wins and the loser is in the history (F7.4)")
    func conflictingEdits() {
        let base = F.base()
        let onA = F.edit(base, by: F.a, at: 2) { $0.fields[1].value = "password-from-A" }
        let onB = F.edit(base, by: F.b, at: 2) { $0.fields[1].value = "password-from-B" }
        let merged = ItemMerge.merge(onA, origin: F.origin(onA, F.a), onB, origin: F.origin(onB, F.b))
        // Same version: the higher device ID (B) wins.
        #expect(merged.field(.password)?.value == "password-from-B")
        let historic = merged.history.flatMap(\.fields).map(\.value)
        #expect(historic.contains("password-from-A"))
        #expect(historic.contains("old-password"))
        let later = F.edit(onA, by: F.a, at: 3) { $0.fields[1].value = "password-from-A-again" }
        let second = ItemMerge.merge(later, origin: F.origin(later, F.a), onB, origin: F.origin(onB, F.b))
        #expect(second.field(.password)?.value == "password-from-A-again")
    }

    @Test("a removed field stays removed unless it was edited later")
    func removal() {
        let base = F.base()
        let removed = F.edit(base, by: F.a, at: 2) { $0.fields.removeAll { $0.kind == .username } }
        let untouched = F.edit(base, by: F.b, at: 2) { $0.title = "Renamed" }
        let merged = ItemMerge.merge(
            removed, origin: F.origin(removed, F.a), untouched, origin: F.origin(untouched, F.b))
        #expect(merged.field(.username) == nil)
        #expect(merged.title == "Renamed")
        let editedLater = F.edit(base, by: F.b, at: 3) { $0.fields[0].value = "pat2" }
        let revived = ItemMerge.merge(
            removed, origin: F.origin(removed, F.a), editedLater, origin: F.origin(editedLater, F.b))
        #expect(revived.field(.username)?.value == "pat2")
    }

    @Test("a field added on one device survives a reorder on another")
    func addAndReorder() {
        let base = F.base()
        let added = F.edit(base, by: F.a, at: 2) {
            $0.fields.append(Field(id: F.fieldID(3), kind: .totp, label: "TOTP", value: "otpauth://x"))
        }
        let reordered = F.edit(base, by: F.b, at: 3) { $0.fields.reverse() }
        let merged = ItemMerge.merge(added, origin: F.origin(added, F.a), reordered, origin: F.origin(reordered, F.b))
        #expect(merged.fields.map(\.id) == [F.fieldID(2), F.fieldID(1), F.fieldID(3)])
    }

    @Test("items without revisions merge as whole records, later version winning")
    func legacy() {
        var old = F.base()
        old.revisions = [:]
        var newer = old
        newer.title = "Newer"
        newer.notes = "n"
        newer.version = 5
        let merged = ItemMerge.merge(
            old, origin: Revision(version: 1, device: F.c), newer, origin: Revision(version: 5, device: F.a))
        #expect(merged.title == "Newer")
        #expect(merged.revisions[.title] == Revision(version: 5, device: F.a), "revisions are materialised")
    }

    @Test("groups from a newer client are kept")
    func unknownGroups() {
        var base = F.base()
        base.revisions[ItemGroup(rawValue: "icon")] = Revision(version: 9, device: F.c)
        let other = F.edit(F.base(), by: F.b, at: 2) { $0.title = "x" }
        let merged = ItemMerge.merge(base, origin: F.origin(base, F.a), other, origin: F.origin(other, F.b))
        #expect(merged.revisions[ItemGroup(rawValue: "icon")] == Revision(version: 9, device: F.c))
    }

    @Test("revisions survive the item payload codec, and payloads without them still decode")
    func codec() throws {
        let item = F.edit(F.base(), by: F.b, at: 2) { $0.title = "x" }
        let encoder = JSONEncoder()
        let decoded = try JSONDecoder().decode(Item.self, from: encoder.encode(item))
        #expect(decoded == item)
        var object = try JSONSerialization.jsonObject(with: encoder.encode(item)) as! [String: Any]
        object["revisions"] = nil
        let legacy = try JSONDecoder().decode(Item.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(legacy.revisions.isEmpty)
        #expect(legacy.title == "x")
    }

    /// The property convergence rests on: current values are a join, so order, grouping and repetition do not matter.
    @Test(
        "current values are commutative, idempotent, and associative up to field order, under random concurrent edits")
    func joinProperties() {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 0xC0FFEE))
        for _ in 0..<TestEnvironment.iterations(standard: 300, long: 20_000) {
            let devices = [F.a, F.b, F.c]
            var versions: [(Item, Revision)] = []
            for device in devices {
                var item = F.base()
                var version: UInt64 = 1
                for _ in 0..<Int.random(in: 1...4, using: &generator) {
                    version += UInt64.random(in: 1...3, using: &generator)
                    item = F.edit(item, by: device, at: version) { Self.randomEdit(&$0, using: &generator) }
                }
                versions.append((item, Revision(version: version, device: device)))
            }
            let (x, ox) = versions[0]
            let (y, oy) = versions[1]
            let (z, oz) = versions[2]
            let xy = ItemMerge.merge(x, origin: ox, y, origin: oy)
            let yx = ItemMerge.merge(y, origin: oy, x, origin: ox)
            #expect(F.current(xy) == F.current(yx))
            let oxy = Revision(version: max(ox.version, oy.version) + 1, device: F.a)
            let yz = ItemMerge.merge(y, origin: oy, z, origin: oz)
            let oyz = Revision(version: max(oy.version, oz.version) + 1, device: F.b)
            let left = ItemMerge.merge(xy, origin: oxy, z, origin: oz)
            let right = ItemMerge.merge(x, origin: ox, yz, origin: oyz)
            // Associative in everything but field order (see `ItemMerge`): a field revived by a later edit can lose its
            // position in an intermediate merge that did not have it. Devices still agree, one exchange later, through
            // the equal-revision tie-break; the simulation checks that end to end.
            #expect(F.unordered(left) == F.unordered(right))
            #expect(F.current(ItemMerge.merge(x, origin: ox, x, origin: ox)) == F.current(x))
            #expect(F.current(ItemMerge.merge(xy, origin: oxy, x, origin: ox)) == F.current(xy))
        }
    }

    static func randomEdit(_ item: inout Item, using generator: inout SeededGenerator) {
        let word = ["alpha", "beta", "gamma", "delta"].randomElement(using: &generator)!
        switch Int.random(in: 0..<8, using: &generator) {
        case 0: item.title = word
        case 1: item.notes = word
        case 2: item.tags.insert(word)
        case 3: item.archived.toggle()
        case 4:
            if !item.fields.isEmpty {
                item.fields[Int.random(in: 0..<item.fields.count, using: &generator)].value = word
            }
        case 5:
            item.fields.append(
                Field(id: F.fieldID(UInt8.random(in: 3...9, using: &generator)), kind: .text, label: word, value: word))
            var seen: Set<UUID> = []
            item.fields = item.fields.filter { seen.insert($0.id).inserted }
        case 6:
            if !item.fields.isEmpty { item.fields.remove(at: Int.random(in: 0..<item.fields.count, using: &generator)) }
        default: item.fields.shuffle(using: &generator)
        }
    }
}
