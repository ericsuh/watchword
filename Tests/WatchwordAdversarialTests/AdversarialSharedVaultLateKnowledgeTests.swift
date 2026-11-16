import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Review findings S45 and S46 (docs/06-adversarial-review.md §I, fourth round): what a late write *claims to have
/// seen*, carried on by a device that merged it before it was shown the removal. In the suite "shared vaults through
/// the session".
extension AdversarialSharedVaultTests {
    /// Every title a copy holds: the one shown and the concurrent ones beside it.
    static func titles(_ item: Item) -> Set<String> {
        var titles: Set<String> = [item.title]
        for value in item.conflicts[.title] ?? [] {
            if case .title(let title) = value.value { titles.insert(title) }
        }
        return titles
    }

    /// Threat: review finding S46. A former member (A5) with a modified client, behind a store (A1) that withholds
    /// the record removing them from them and from the remaining member's device, writes a late version of the bank
    /// item that changes no value at all: it copies what it holds and claims, in its clock, to have seen edits of the
    /// owner's device up to a version the owner has not reached. Nothing in it is the former member's own, so no
    /// value of it is held aside anywhere. The remaining member's device merges it before it knows and renames the
    /// item; that edit's stamp carries the claim. The owner, who has not seen the rename, renames the item too. The
    /// two renames are concurrent, but the member's stamp says it had seen the owner's, so every device dropped the
    /// owner's title for good (titles have no history). A claim about a device's edits counts only once a segment of
    /// that device's stream that counts has published them; until then the version that makes it waits.
    @Test("a removed member's claim to have seen a current member's future edits supersedes none of them")
    func lateClaimOfFutureEdits() async throws {
        let household = SharedVaultHousehold()
        let setup = try await Self.householdWithARemovalWithheld(household, seed: 2_300)
        let (bank, owner, removed, member) = (setup.bank, setup.owner, setup.removed, setup.member)
        let ownerDevice = try #require(await owner.session.deviceIDForTest())

        var late = try await removed.session.item(id: bank.id)
        late.version += 10
        late.clock.record(Revision(version: late.version - 1, device: ownerDevice))
        try await removed.session.overwriteAsAModifiedClient(late)
        try await removed.session.sync()
        try await member.session.sync()

        var renamed = try await member.session.item(id: bank.id)
        renamed.title = "Member's title"
        try await member.session.save(renamed)
        try await member.session.sync()
        var ownerEdit = try await owner.session.item(id: bank.id)
        ownerEdit.title = "Owner's title"
        try await owner.session.save(ownerEdit)
        try await owner.session.sync()

        await setup.memberView.reveal()
        try await Self.syncAll([member, owner, member, owner])
        let ownerCopy = try await owner.session.item(id: bank.id)
        let memberCopy = try await member.session.item(id: bank.id)
        for copy in [ownerCopy, memberCopy] {
            #expect(Self.titles(copy).isSuperset(of: ["Owner's title", "Member's title"]))
        }
        #expect(ItemMerge.sameState(ownerCopy, memberCopy))
    }

    /// Threat: review finding S45. A former member (A5) whose client still writes, behind a store (A1) that withholds
    /// the record removing them from them and from the remaining member's device. Just before the removal the owner
    /// renames the bank item, and the former member's client merges the rename; afterwards it writes a late title over
    /// it. The remaining member's device merges both in one sync, so the person is shown only the late title, and
    /// trashes and deletes the item. The tombstone's erasure summary is that device's clock, which holds the owner's
    /// rename; the owner's device, which holds the late write aside and shows its own title, applied the tombstone
    /// and erased the item with the rename, though the person who deleted had only ever been shown the late title. A
    /// deletion built on a late write is held aside like a version built on one: the item stays, with the owner's
    /// title, on every device.
    @Test("a deletion made on a copy holding a late write erases nothing the deleter saw only through it")
    func deletionOnTopOfALateWrite() async throws {
        let household = SharedVaultHousehold()
        let setup = try await Self.householdWithARemovalWithheld(household, seed: 2_400) { bank, owner, removed, _ in
            var ownerEdit = try await owner.session.item(id: bank.id)
            ownerEdit.title = "Owner's title"
            try await owner.session.save(ownerEdit)
            try await owner.session.sync()
            try await removed.session.sync()
        }
        let (bank, owner, removed, member) = (setup.bank, setup.owner, setup.removed, setup.member)

        var late = try await removed.session.item(id: bank.id)
        late.title = "Late title"
        try await removed.session.save(late)
        try await removed.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).title == "Late title")
        try await member.session.trash(id: bank.id)
        try await member.session.deletePermanently(id: bank.id)
        try await member.session.sync()
        try await owner.session.sync()

        await setup.memberView.reveal()
        try await Self.syncAll([member, owner, member, owner])
        let ownerCopy = try await owner.session.item(id: bank.id)
        let memberCopy = try await member.session.item(id: bank.id)
        #expect(ownerCopy.title == "Owner's title")
        #expect(memberCopy.title == "Owner's title")
        #expect(ItemMerge.sameState(ownerCopy, memberCopy))
        // The deletion is kept for the person, not applied.
        #expect(try await owner.session.quarantinedVersions().contains { $0.recordID == bank.id && $0.isDeletion })
    }
}
