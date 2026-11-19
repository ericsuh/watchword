import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordSync

/// `ItemMerge.reattributed`: what a restore carries over from its earlier device ID's unpublished work (review of
/// round 12, M1 and Z191; docs/10-sync-correctness.md §9).
@Suite("Item reattribution")
struct ItemReattributionTests {
    typealias F = MergeFixtures
    /// The earlier ID (`F.a`, which wrote the base at version 1 and published it) and the new one.
    static let earlier = F.a
    static let restored = UUID(uuidString: "4E700000-0000-4000-8000-000000000001")!

    /// The base as published, then edited by the earlier ID at versions 2 and 3, published by nobody: a title, a
    /// password (with its history entry) and a note line.
    static func unpublished() -> (published: Item, edited: Item) {
        let published = F.base(notes: "First line")
        let titled = F.edit(published, by: earlier, at: 2) { $0.title = "Bank, renamed" }
        let edited = F.edit(titled, by: earlier, at: 3) {
            $0.fields[1].value = "new-password"
            $0.notes = "First line\nSecond line"
        }
        return (published, edited)
    }

    @Test("the unpublished work is the new ID's, and the published work stays the earlier ID's")
    func renamesOnlyTheUnpublished() {
        let (_, edited) = Self.unpublished()
        let carried = ItemMerge.reattributed(
            edited, origin: F.origin(edited, Self.earlier), from: Self.earlier, above: 1, to: Self.restored)
        let values = ItemMerge.attributedValues(carried, origin: F.origin(carried, Self.restored))
        let unpublished = values.filter { $0.revision.device == Self.earlier && $0.revision.version > 1 }
        #expect(unpublished.isEmpty, "a value still names the earlier ID's unpublished work")
        #expect(values.contains { $0.revision.device == Self.earlier }, "the published work was renamed too")
        #expect(carried.revisions[.title]?.revision == Revision(version: 2, device: Self.restored))
        let clock = ItemMerge.effectiveClock(carried, origin: F.origin(carried, Self.restored))
        #expect(clock.entries[Self.earlier] == 1)
        #expect(clock.entries[Self.restored] == 3)
        #expect(carried.title == edited.title)
        #expect(carried.fields == edited.fields)
        #expect(carried.notes == edited.notes)
        #expect(Set(carried.history.map(ItemState.content(of:))) == Set(edited.history.map(ItemState.content(of:))))
    }

    @Test("merged with the version that was published, the carried version supersedes it, as the edit did")
    func supersedesThePublishedVersion() {
        let (published, edited) = Self.unpublished()
        let carried = ItemMerge.reattributed(
            edited, origin: F.origin(edited, Self.earlier), from: Self.earlier, above: 1, to: Self.restored)
        let merged = F.merge((published, Self.earlier), (carried, Self.restored))
        #expect(!merged.hasConflicts)
        #expect(merged.title == "Bank, renamed")
        #expect(merged.notes == edited.notes)
        #expect(merged.retainedValues.isEmpty)
        // And another device's edit made on the published version is concurrent with it, as before.
        let elsewhere = F.edit(published, by: F.b, at: 2) { $0.title = "Bank, elsewhere" }
        let both = F.merge((elsewhere, F.b), (carried, Self.restored))
        #expect(F.conflictValues(both, .title).count == 1)
    }

    @Test("with nothing published, everything the earlier ID wrote is the new ID's")
    func nothingPublished() {
        let (_, edited) = Self.unpublished()
        let carried = ItemMerge.reattributed(
            edited, origin: F.origin(edited, Self.earlier), from: Self.earlier, above: 0, to: Self.restored)
        let values = ItemMerge.attributedValues(carried, origin: F.origin(carried, Self.restored))
        #expect(!values.contains { $0.revision.device == Self.earlier })
        let clock = ItemMerge.effectiveClock(carried, origin: F.origin(carried, Self.restored))
        #expect(clock.entries[Self.earlier] == nil)
    }

    @Test("an item with nothing above the published version is unchanged")
    func nothingToCarry() {
        let (published, _) = Self.unpublished()
        let origin = F.origin(published, Self.earlier)
        let carried = ItemMerge.reattributed(published, origin: origin, from: Self.earlier, above: 1, to: Self.restored)
        #expect(carried == ItemMerge.canonical(published, origin: origin))
    }
}
