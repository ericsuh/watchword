import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Review findings S32 and S43 (docs/06-adversarial-review.md §I): the three parts of an item that named no writer —
/// a note line's removal, the discards of a resolution and the history — attacked by a former member whose late
/// version a remaining member's device merges before it is shown the removal. In the suite "shared vaults through the
/// session".
extension AdversarialSharedVaultTests {
    /// The household of `householdBeforeARemoval`, the bank item's notes written by the owner first, everything
    /// synced, then the record removing the former member signed by the owner and withheld by the store (A1) from the
    /// former member's device and the remaining member's.
    static func householdWithARemovalWithheld(
        _ household: SharedVaultHousehold, seed: UInt64, notes: String? = nil,
        beforeRemoval: (Item, SharingAccount, SharingAccount, SharingAccount) async throws -> Void = { _, _, _, _ in }
    ) async throws -> (
        vaultID: UUID, bank: Item, owner: SharingAccount, removed: SharingAccount, member: SharingAccount,
        memberView: WithholdingTransport, inCut: Revision
    ) {
        let setup = try await householdBeforeARemoval(household, seed: seed) { removed, _ in removed }
        let (vaultID, owner, removed, member) = (setup.vaultID, setup.owner, setup.removed, setup.member)
        if let notes {
            var item = try await owner.session.item(id: setup.bank.id)
            item.notes = notes
            try await owner.session.save(item)
        }
        try await syncAll([owner, removed, member])
        try await beforeRemoval(setup.bank, owner, removed, member)
        await setup.removedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await setup.memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        #expect(try await owner.session.removeMember(removed.accountID, from: vaultID) == .complete)
        return (vaultID, setup.bank, owner, removed, member, setup.memberView, setup.inCut)
    }

    /// The remaining member writes on top of what they merged, the owner syncs, then the store shows the member's
    /// device the removal and every device syncs until settled.
    static func writeOnTopThenReveal(
        _ bank: Item, owner: SharingAccount, member: SharingAccount, memberView: WithholdingTransport
    ) async throws {
        var onTop = try await member.session.item(id: bank.id)
        onTop.title = "Written on top"
        try await member.session.save(onTop)
        try await member.session.sync()
        try await owner.session.sync()
        await memberView.reveal()
        try await syncAll([member, owner, member, owner])
    }

    /// Threat: review finding S32. A former member (A5) whose client still writes, with a store (A1) that withholds
    /// the record removing them from them and from the remaining member's device. Their late edit of the bank item's
    /// notes removes a line the owner wrote; the remaining member's device merges it before it knows, writes on top,
    /// and publishes. A line's removal used to name no writer, so the member's version carried it as nobody's in
    /// particular and it counted everywhere: the owner's line was gone for good. Now the removal is stamped with the
    /// late revision, every version carrying it is held aside, and the device that merged it takes it out again: the
    /// line is back on every device, and both hold the same item.
    @Test("a removed member's late removal of a note line counts on no device")
    func lateNoteLineRemoval() async throws {
        let household = SharedVaultHousehold()
        let setup = try await Self.householdWithARemovalWithheld(
            household, seed: 1_700, notes: "Branch: Main Street\nAccount manager: Ada")
        let (bank, owner, removed, member) = (setup.bank, setup.owner, setup.removed, setup.member)

        var late = try await removed.session.item(id: bank.id)
        late.notes = "Branch: Main Street"
        try await removed.session.save(late)
        try await removed.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).notes == "Branch: Main Street")

        try await Self.writeOnTopThenReveal(bank, owner: owner, member: member, memberView: setup.memberView)
        let ownerCopy = try await owner.session.item(id: bank.id)
        let memberCopy = try await member.session.item(id: bank.id)
        #expect(ownerCopy.notes == "Branch: Main Street\nAccount manager: Ada")
        #expect(memberCopy.notes == "Branch: Main Street\nAccount manager: Ada")
        #expect(ItemMerge.sameState(ownerCopy, memberCopy))
    }

    /// Threat: review finding S43, discards. A conflict on the bank item's title left a value retained (an edit
    /// superseded it; nobody chose to discard it). A former member (A5) with a modified client, behind a store (A1)
    /// that withholds their removal from them and from the remaining member's device, writes a late version whose
    /// resolution discards every retained value of the title, the discard back-dated to their own in-cut revision.
    /// The remaining member's device merges it, losing the retained value, and writes on top. The discard is judged
    /// like any value: its bytes were first carried by the late segment, so it counts on no device, and the retained
    /// value is back everywhere.
    @Test("a removed member's late discard of retained values counts on no device")
    func lateDiscardOfRetainedValues() async throws {
        let household = SharedVaultHousehold()
        let setup = try await Self.householdWithARemovalWithheld(household, seed: 1_800) {
            bank, owner, removed, member in
            // Concurrent titles from the two members, then the owner's edit over the conflict: one retained value.
            for (account, title) in [(removed, "Removed member's title"), (member, "Member's title")] {
                var item = try await account.session.item(id: bank.id)
                item.title = title
                try await account.session.save(item)
            }
            try await Self.syncAll([removed, member, owner])
            var item = try await owner.session.item(id: bank.id)
            item.title = "Owner's title"
            try await owner.session.save(item)
            try await Self.syncAll([owner, removed, member])
        }
        let (bank, owner, removed, member) = (setup.bank, setup.owner, setup.removed, setup.member)
        let retained = try await member.session.item(id: bank.id).retainedValues
        try #require(!retained.isEmpty)

        var late = try await removed.session.item(id: bank.id)
        late.version += 1
        late.discards[.title] = [ItemDiscard(revision: setup.inCut, seen: late.clock)]
        late.retainedValues = []
        try await removed.session.overwriteAsAModifiedClient(late)
        try await removed.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).retainedValues.isEmpty)

        try await Self.writeOnTopThenReveal(bank, owner: owner, member: member, memberView: setup.memberView)
        let ownerCopy = try await owner.session.item(id: bank.id)
        let memberCopy = try await member.session.item(id: bank.id)
        #expect(ownerCopy.retainedValues == retained)
        #expect(memberCopy.retainedValues == retained)
        #expect(ItemMerge.sameState(ownerCopy, memberCopy))
    }

    /// Threat: review finding S43, history. A former member (A5) with a modified client, behind a store (A1) that
    /// withholds their removal, plants an entry in the bank item's history — an "earlier password" the person never
    /// had, for them to restore or reuse — in a late version that changes nothing else, the entry written with no
    /// writer at all, as a record from before history named one. The remaining member's device merges it and writes
    /// on top. An entry without a writer is the work of the version that carries it, here the late one, so it counts
    /// on no device; the planted entry is in no device's history, and the owner's real history is intact.
    @Test("a removed member's late history entry counts on no device")
    func lateHistoryEntry() async throws {
        let household = SharedVaultHousehold()
        let setup = try await Self.householdWithARemovalWithheld(household, seed: 1_900) { bank, owner, _, _ in
            let item = try await owner.session.item(id: bank.id)
            try await owner.session.save(Self.setting(.password, to: "bank-password-2", in: item))
        }
        let (bank, owner, removed, member) = (setup.bank, setup.owner, setup.removed, setup.member)
        let history = try await owner.session.item(id: bank.id).history
        try #require(history.count == 1)

        var late = try await removed.session.item(id: bank.id)
        late.version += 1
        let planted = Field(kind: .password, label: "Password", value: "planted-password")
        late.history.insert(ItemHistoryEntry(replacedAt: late.modifiedAt, version: 1, fields: [planted]), at: 0)
        try await removed.session.overwriteAsAModifiedClient(late)
        try await removed.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).history.count == 2)

        try await Self.writeOnTopThenReveal(bank, owner: owner, member: member, memberView: setup.memberView)
        let ownerCopy = try await owner.session.item(id: bank.id)
        let memberCopy = try await member.session.item(id: bank.id)
        for copy in [ownerCopy, memberCopy] {
            #expect(copy.history.map(\.fields) == history.map(\.fields))
            #expect(!copy.history.flatMap(\.fields).contains { $0.value == "planted-password" })
        }
        #expect(ItemMerge.sameState(ownerCopy, memberCopy))
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: review finding S32 again, from a modified client. The former member (A5), behind a store (A1) that
    /// withholds their removal from them and the remaining member's device, marks a note line removed in a late
    /// version that changes nothing else — no clock entry, no stamp, the removal naming no writer, as in a record from
    /// before removals named one. A removal that names nobody is the work of the row that carries it, here the late
    /// one, so the version the unaware member writes on top of it counts on no device.
    @Test("a removed member's late removal of a note line, naming no writer, counts on no device")
    func lateUnstampedNoteLineRemoval() async throws {
        let household = SharedVaultHousehold()
        let setup = try await Self.householdWithARemovalWithheld(
            household, seed: 2_100, notes: "Branch: Main Street\nAccount manager: Ada")
        let (bank, owner, removed, member) = (setup.bank, setup.owner, setup.removed, setup.member)

        var late = try await removed.session.item(id: bank.id)
        late.version += 1
        let line = try #require(late.noteLines.firstIndex { $0.text == "Account manager: Ada" })
        late.noteLines[line].removed = true
        late.noteLines[line].text = ""
        late.notes = "Branch: Main Street"
        try await removed.session.overwriteAsAModifiedClient(late)
        try await removed.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).notes == "Branch: Main Street")

        try await Self.writeOnTopThenReveal(bank, owner: owner, member: member, memberView: setup.memberView)
        let ownerCopy = try await owner.session.item(id: bank.id)
        let memberCopy = try await member.session.item(id: bank.id)
        #expect(ownerCopy.notes == "Branch: Main Street\nAccount manager: Ada")
        #expect(ItemMerge.sameState(ownerCopy, memberCopy))
    }

    /// Threat: review finding S44. A member demoted to read-only (A4 until then) whose client has not been shown the
    /// record, with a store (A1) that withholds it from them and from another member's device, and that also holds
    /// back the owner's stream from that device for a while. The owner renames the bank item; the demoted member's
    /// client merges the rename and writes a late title over it, its stamp saying it had seen the owner's. The other
    /// member's device merges only the late title, and the person renames the item again. That edit was made on a
    /// copy that held the late write, so its stamp claims to have seen the owner's rename too, and would supersede it
    /// everywhere: titles have no history, and the owner's would be gone, though the late write counts nowhere. A
    /// version whose clock holds an edit that does not count is built on it, and is held aside like the edit.
    @Test("a demoted member's late edit lends its knowledge to no edit made on top of it")
    func lateKnowledgeOfADemotedMember() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 2_200)
        let (demoted, demotedView) = try await household.withheldAccount(seed: 2_217)
        let (member, memberView) = try await household.withheldAccount(seed: 2_234)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(demoted, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, demoted, member])
        await demotedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        try await owner.session.changeRole(of: demoted.accountID, in: vaultID, to: .readOnly)

        let ownerDevice = try #require(await owner.session.deviceIDForTest())
        await memberView.withholdNew(under: SyncObjectLocation.vaultPrefix(vaultID) + "log/\(ownerDevice.uuidString)/")
        var renamed = try await owner.session.item(id: bank.id)
        renamed.title = "Owner's title"
        try await owner.session.save(renamed)
        try await owner.session.sync()
        try await demoted.session.sync()
        var late = try await demoted.session.item(id: bank.id)
        late.title = "Late title"
        try await demoted.session.save(late)
        try await demoted.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).title == "Late title")
        var onTop = try await member.session.item(id: bank.id)
        onTop.title = "Member's title"
        try await member.session.save(onTop)
        try await member.session.sync()

        try await owner.session.sync()
        await memberView.reveal()
        try await Self.syncAll([member, owner, member, owner])
        let ownerCopy = try await owner.session.item(id: bank.id)
        let memberCopy = try await member.session.item(id: bank.id)
        #expect(ownerCopy.title == "Owner's title")
        #expect(memberCopy.title == "Owner's title")
        #expect(ItemMerge.sameState(ownerCopy, memberCopy))
        // Held aside for the person, not destroyed.
        #expect(try await member.session.quarantinedVersions().contains { $0.recordID == bank.id })
    }
}
