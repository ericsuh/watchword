import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of round 10 (docs/06-adversarial-review.md Z179 onward): claims, in a version's clock or a deletion's
// erasure summary, about a device ID of this account's registry that does not commit. In the suite "shared vaults
// through the session".
extension AdversarialSharedVaultTests {
    /// Threat: a current member with write access (A4) and a modified client, in a vault shared with an account one of
    /// whose devices has an ID that does not commit (a device an older build let accept the invitation, Z162). The
    /// member publishes a version of an item that claims, in its clock, an edit of that device's ID; merged there, it
    /// leaves a row of that device's whose clock names the device. The gate counted such a row as unpublished work by
    /// its clock (`holdsUnpublishedEdit`), so the claim held back every deletion the device made, Personal included,
    /// for as long as the row stood. It decides by values now (`holdsValue`), as Z173's predicate does. The judge
    /// refuses the claim since Z179, so the row is planted here as that merge left it.
    @Test("a member's clock claim naming this device's non-committing ID holds back none of its deletions")
    func clockClaimNamingThisDevice() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite], seed: 17_910)
        let (victim, attacker) = (members[0], members[1])
        let legacy = try await Self.legacyDevice(of: victim, in: household, modified: true)
        try await legacy.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        await legacy.session.playModifiedClient(false)
        let legacyID = try await Self.deviceID(of: legacy)
        let bank = try await attacker.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([attacker, owner])
        _ = try await legacy.session.syncAll()
        _ = try await legacy.session.syncAll()
        let personal = try #require(try await legacy.vault.store.loadAccount()?.personalVaultID)
        let doomed = try await legacy.session.save(Self.bank(in: personal))
        _ = try await legacy.session.syncAll()
        try await Self.syncAll([victim])
        #expect((try? await victim.session.item(id: doomed.id)) != nil)

        var claimed = try await legacy.session.item(id: bank.id)
        claimed.version += 1
        claimed.clock.record(Revision(version: 3, device: legacyID))
        try await legacy.session.overwriteAsAModifiedClient(claimed)
        let row = try #require(try await legacy.vault.store.record(RecordKey(recordID: bank.id, kind: .item)))
        #expect(row.deviceID == legacyID)

        try await legacy.session.trash(id: doomed.id)
        try await legacy.session.deletePermanently(id: doomed.id)
        let report = try await legacy.session.syncAll()
        #expect(!report.deletionsHeldBack.contains(vaultID), "the clock claim held the deletion back")
        try await Self.syncAll([victim])
        #expect((try? await victim.session.item(id: doomed.id)) == nil, "the deletion never went out")
    }

    /// Threat: a current member with write access (A4) and a modified client, here the vault's owner, reading the
    /// segments of a device ID of the victim's account that does not commit (Z170's restored move: the copy is on the
    /// restored device alone, the original's deletion parked). No account counts that ID, so the judge passed over every
    /// claim about it (`knowledgeCounts` and `judgeAdmitsErasure` stepped past an ID nobody lists before asking whether
    /// it was this device's own). The member took the copy as that ID's segment carried it and deleted it: the
    /// deletion's erasure summary said it had seen the copy's values, was admitted, erased them on the restored device,
    /// and with no value of that ID left the parked deletion was released and the original deleted everywhere, while
    /// the copy existed nowhere (F7.6). A claim about an ID `idsNobodyReceives` names, whose values this device's row
    /// holds, is refused unless carried, as one about this device's own edits is (Z136): the deletion is held aside,
    /// the copy stays, and the original's deletion stays parked.
    @Test("a member's deletion claiming a non-committing ID's copy neither erases it nor releases a parked deletion")
    func erasureClaimOverAnUnreceivedCopy() async throws {
        let restored = try await Self.restoredMove(seed: 17_920)
        let (vaultID, owner, member, device) = (restored.vaultID, restored.owner, restored.member, restored.device)
        let second = try await device.session.syncAll()
        #expect(second.deletionsHeldBack.contains(vaultID))

        // The copy as the old ID's segment carried it, decrypted with the vault key the member holds.
        let copy = try await device.session.item(id: restored.copy.id)
        #expect(copy.revisions.values.contains { $0.revision.device == restored.oldID })
        try await owner.session.plantAsAModifiedClient(copy)
        try await owner.session.trash(id: copy.id)
        try await owner.session.deletePermanently(id: copy.id)
        try await owner.session.sync()

        let third = try await device.session.syncAll()
        #expect((try? await device.session.item(id: copy.id)) != nil, "the member's deletion erased the copy")
        #expect(third.deletionsHeldBack.contains(vaultID), "the parked deletion was released")
        try await device.session.sync()
        try await Self.syncAll([member])
        #expect((try? await member.session.item(id: restored.original.id)) != nil, "the original was erased")
    }

    /// Threat: as `erasureClaimOverAnUnreceivedCopy`, a writing member (A4) with the copy, who this time writes a version
    /// over every group of it, each stamp claiming to have seen the old ID's values. Admitted, the merge replaced them,
    /// and the restored device's row held no value of that ID any more. The version's clock names the ID, so it is held
    /// aside now, and the copy's own values stay.
    @Test("a member's version superseding a non-committing ID's copy is held aside, and the copy's values stay")
    func supersedingClaimOverAnUnreceivedCopy() async throws {
        let restored = try await Self.restoredMove(seed: 17_930)
        let (vaultID, owner, device) = (restored.vaultID, restored.owner, restored.device)
        _ = try await device.session.syncAll()
        let copy = try await device.session.item(id: restored.copy.id)
        try await owner.session.plantAsAModifiedClient(copy)
        let ownerID = try await Self.deviceID(of: owner)
        var over = try await owner.session.item(id: copy.id)
        var seen = over.clock
        seen.record(Revision(version: over.version, device: restored.oldID))
        let revision = Revision(version: over.version + 5, device: ownerID)
        for group in over.revisions.keys { over.revisions[group] = GroupStamp(revision: revision, seen: seen) }
        over.title = "Taken over"
        over.version += 5
        over.clock = seen
        over.clock.record(revision)
        try await owner.session.overwriteAsAModifiedClient(over)
        try await owner.session.sync()

        let report = try await device.session.syncAll()
        let kept = try await device.session.item(id: copy.id)
        #expect(kept.title == copy.title, "the member's version replaced the copy's values")
        #expect(report.deletionsHeldBack.contains(vaultID), "the parked deletion was released")
    }
}

extension VaultSession {
    /// Seals `item` into the store as a new row, the way a modified client that read it from another device's segment
    /// would keep it: no judge, no `ItemMerge.stamped`.
    func plantAsAModifiedClient(_ item: Item) async throws {
        guard let account = try await loadAccount(), let keys,
            let key = currentVaultKey(item.vaultID, keys: keys, account: account)
        else { throw VaultError.noAccount }
        let sealed = try sealItem(item, vaultKey: key, account: account)
        try await store.commit(StoreChange(upserts: [sealed], expectations: [sealed.key: .absent]))
    }
}
