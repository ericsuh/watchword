import Foundation
import Testing
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// The review of round 11 (docs/06-adversarial-review.md Z185; M1): a restore's move of its old device ID's deletions
// when one of them is in a shared vault this device holds closed. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: none needed but a shared vault this device holds closed (no verified ledger, Z41: here the owner's pin
    /// lost with the restore; a disputed owner, Z59, or a key this device does not hold does the same), in a store
    /// restored onto other hardware that holds a deletion made there and never published. The move of the old ID's
    /// deletions signs each as the new ID's, which needs a current key for its vault: that one threw, every attempt,
    /// so the move's record was never cleared and the device published nothing in any vault, Personal included, for as
    /// long as the vault stayed closed, and said nothing. The deletion is parked now: the move completes, the Personal
    /// vault's deletion goes out, and the shared vault's goes out once the vault opens here again. Nothing is lost.
    @Test("a restore's deletion in a shared vault held closed is parked, and the device still publishes elsewhere")
    func restoreWithASharedVaultHeldClosed() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 18_550)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let shared = try await member.session.save(Self.bank(in: vaultID))
        let mine = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        #expect((try? await owner.session.item(id: shared.id)) != nil)
        #expect((try? await other.session.item(id: mine.id)) != nil)

        // Both deleted, neither deletion published (each trash was: a restore's unpublished edits in a shared vault
        // are held aside on members' devices, Z191); then the store restored onto other hardware without the owner's
        // pin.
        for item in [shared, mine] { try await member.session.trash(id: item.id) }
        try await Self.syncAll([member, owner, other])
        for item in [shared, mine] { try await member.session.deletePermanently(id: item.id) }
        await member.session.lock()
        await member.contacts.removePin(for: owner.accountID)
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let restored = member.vault.relaunched(seed: 18_551)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        let account = try #require(try await member.vault.store.loadAccount())
        #expect(account.migration == nil, "the move was left incomplete")
        #expect(try await restored.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)

        let report = try await restored.session.syncAll()
        #expect(!report.deviceMigrationIncomplete)
        try await other.session.sync()
        #expect((try? await other.session.item(id: mine.id)) == nil, "the Personal vault's deletion never went out")
        try await owner.session.sync()
        #expect((try? await owner.session.item(id: shared.id)) != nil, "deleted while its vault was held closed")

        // The vault opens here again (the remedy for a lost pin, Z41): the parked deletion goes out.
        try await restored.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        _ = try await restored.session.syncAll()
        _ = try await restored.session.syncAll()
        try await owner.session.sync()
        #expect((try? await owner.session.item(id: shared.id)) == nil, "the shared vault's deletion was lost")
    }
}
