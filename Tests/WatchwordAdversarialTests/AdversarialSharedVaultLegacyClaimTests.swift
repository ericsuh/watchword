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
}
