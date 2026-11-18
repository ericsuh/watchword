import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of round 9 (docs/06-adversarial-review.md Z173, Z177): what decides that a shared vault holds a copy
// nobody received, and what registration does when the deletions it parks cannot be read. In the suite "shared vaults
// through the session".
extension AdversarialSharedVaultTests {
    /// Threat: a current member with write access (A4) and a modified client, in a vault shared with an account whose
    /// registry lists a device ID that does not commit (a device an older build approved, which takes no part, Z162).
    /// The member publishes a version of an item that changes nothing and claims, in its clock, to have seen an edit of
    /// that ID. No account counts the ID, so no judge asks about the claim and the version is merged. Z170's predicate
    /// read the clock, so the claim made the row look like a copy nobody received: every deletion of the victim's
    /// account, in every vault, was held back for as long as the row stood. It now reads values (each stamped by its
    /// writer, history entries included), and a value stamped with that ID from another account's stream is held aside
    /// by the judge, so only the account's own writes count: the deletion goes out.
    @Test("a writing member's clock claim naming another account's non-committing ID holds back none of its deletions")
    func clockClaimHoldsNothingBack() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite], seed: 17_300)
        let (victim, attacker) = (members[0], members[1])
        let legacy = try await Self.legacyDevice(of: victim, in: household, modified: false)
        let legacyID = try #require(await legacy.session.deviceIDForTest())
        let bank = try await victim.session.save(Self.bank(in: vaultID))
        let doomed = try await victim.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([victim, attacker, owner])
        #expect((try? await owner.session.item(id: doomed.id)) != nil)

        var claim = try await attacker.session.item(id: bank.id)
        claim.version += 10
        claim.clock.record(Revision(version: 1, device: legacyID))
        try await attacker.session.overwriteAsAModifiedClient(claim)
        try await attacker.session.sync()
        _ = try await victim.session.syncAll()
        let merged = try await victim.session.item(id: bank.id)
        #expect((merged.clock.entries[legacyID] ?? 0) > 0, "the claim did not reach the victim's copy")

        try await victim.session.trash(id: doomed.id)
        try await victim.session.deletePermanently(id: doomed.id)
        let report = try await victim.session.syncAll()
        #expect(report.copiesNobodyReceived.isEmpty, "the claim was taken for a copy nobody received")
        #expect(!report.deletionsHeldBack.contains(vaultID), "the deletion was held back")
        try await Self.syncAll([owner])
        #expect((try? await owner.session.item(id: doomed.id)) == nil, "the deletion never went out")

        // A value relabelled as that ID's: the judge holds it aside (no counted stream carried it), so it is no
        // copy of the victim's account either.
        let stamped = try #require(merged.revisions.values.first?.revision)
        let relabelled = try await attacker.session.item(id: bank.id)
            .relabelled(stamped, as: Revision(version: 2, device: legacyID))
        #expect(relabelled.revisions.values.contains { $0.revision.device == legacyID })
        try await attacker.session.overwriteAsAModifiedClient(relabelled)
        try await attacker.session.sync()
        _ = try await victim.session.syncAll()
        let second = try await victim.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([victim, owner])
        try await victim.session.trash(id: second.id)
        try await victim.session.deletePermanently(id: second.id)
        let after = try await victim.session.syncAll()
        #expect(after.copiesNobodyReceived.isEmpty, "a relabelled value was taken for a copy nobody received")
        try await Self.syncAll([owner])
        #expect((try? await owner.session.item(id: second.id)) == nil, "the second deletion never went out")
    }

    /// Threat: none needed but a sync state file that fails one read (a busy or damaged database); the review of round 9
    /// (I6, F7.6). The installation of `twiceRestoredNonCommittingMove` is restored a second time, and reading the
    /// deletions its second ID had parked fails while the third registers. Registration read them with `try?`, so it
    /// went on with none: the third ID never parked them again, they stayed parked for an ID nobody releases, and
    /// moving the copy out never let the original's deletion go. Registration now fails closed: it is not made, and the
    /// next unlock makes it with the deletions parked again, which go out once the copy is moved out.
    @Test("parked deletions that cannot be read when a restore registers are not stranded")
    func parkedDeletionsUnreadableAtRegistration() async throws {
        let state = InterceptingStateStore()
        let restored = try await Self.restoredMove(seed: 17_700, syncState: state)
        let (vaultID, owner, member, device) = (restored.vaultID, restored.owner, restored.member, restored.device)
        let second = try await device.session.syncAll()
        #expect(second.deletionsHeldBack.contains(vaultID))
        let secondID = try await Self.deviceID(of: device)

        await state.failSecondPendingDeletionRead()
        try await Self.restoreOntoOtherHardware(device, account: member.accountID)
        #expect(try await Self.deviceID(of: device) == secondID, "registered without the parked deletions")
        await device.session.lock()
        try await device.session.unlock(password: TestVault.password)
        #expect(try await Self.deviceID(of: device) != secondID, "the next unlock did not register")
        let third = try await device.session.syncAll()
        #expect(third.deletionsHeldBack.contains(vaultID))

        let again: Item
        do {
            again = try await device.session.move(itemID: restored.copy.id, to: restored.personal)
        } catch VaultError.transferNeedsConfirmation(let concern) {
            again = try await device.session.move(itemID: restored.copy.id, to: restored.personal, confirming: concern)
        }
        let fourth = try await device.session.syncAll()
        #expect(fourth.deletionsHeldBack.isEmpty)
        try await device.session.sync()
        try await Self.syncAll([member, owner])
        #expect((try? await member.session.item(id: again.id)) != nil, "the new copy did not arrive")
        #expect((try? await member.session.item(id: restored.original.id)) == nil, "the parked deletion was stranded")
    }
}
