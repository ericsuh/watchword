import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z43 (docs/06-adversarial-review.md): an addition and the removal that undid it lose a fork together.
extension AdversarialSharedVaultTests {
    /// Threat: a former member (A5) with the store's help (A1 withholds one membership object from an
    /// administrator's device), or plain lag on a file transport. The administrator's device has not been shown an
    /// owner-signed record. On its stale head it invites X, who is granted the vault's key, and later removes X,
    /// rotating the key. The store then shows the owner's record: the owner's path wins, and the addition, the
    /// removal and the rotation all lose. What that branch last meant was that X is **not** a member. So the
    /// addition is not replayed (it was: the device signed X in again and wrapped the current key to them, with no
    /// person involved); the key X was granted, which is current again, is reported as held by someone outside the
    /// vault until an administrator's device rotates it; and nothing is sealed again towards that key meanwhile.
    @Test("an addition undone on a branch that lost is not replayed, and the key it handed out is rotated")
    func additionAndRemovalLoseAForkTogether() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 940)
        let (administrator, view) = try await household.withheldAccount(seed: 941)
        let witness = try await household.account(seed: 942)
        let outsider = try await household.account(seed: 943)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(administrator, to: vaultID, as: .administrator, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, administrator])
        let firstKey = try await owner.session.sharedVaultStatus(vaultID).membership.vaultKeyID

        // The owner adds a member, and the store does not show the administrator's device that record.
        let membership = SharingObjectLocation.membershipPrefix(vaultID)
        let shown = Set(await household.transport.list(prefix: membership))
        try await owner.invite(witness, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, witness])
        await view.withhold(Set(await household.transport.list(prefix: membership)).subtracting(shown))

        // On its stale head the administrator invites the outsider, then removes them.
        try await administrator.session.verifyContact(
            outsider.accountID, evidence: .safetyNumber(outsider.safetyNumber))
        _ = try await administrator.session.invite(outsider.accountID, to: vaultID, as: .readWrite)
        try await administrator.session.sync()
        let grantsToOutsider = SharingObjectLocation.vaultPrefix(vaultID) + "grant/"
        func grants() async -> [String] {
            await household.transport.list(prefix: grantsToOutsider).filter {
                $0.contains("/\(outsider.accountID.uuidString)/")
            }
        }
        #expect(await grants().count == 1, "the outsider was granted the vault's key")
        try await administrator.session.removeMember(outsider.accountID, from: vaultID)
        let branchKey = try await administrator.session.sharedVaultStatus(vaultID).membership.vaultKeyID
        #expect(branchKey != firstKey)
        // Something written under the branch's key, which a re-seal towards the first key would hand the outsider.
        _ = try await administrator.session.save(
            Self.setting(.password, to: "after-the-removal", in: try await administrator.session.item(id: bank.id)))
        try await administrator.session.sync()

        // The store shows the administrator everything. A member who can do nothing about it sees it first.
        await view.reveal()
        try await witness.session.sync()
        let seen = try await witness.session.sharedVaultStatus(vaultID)
        #expect(seen.membership.member(outsider.accountID) == nil)
        #expect(seen.membership.vaultKeyID == firstKey, "the owner's path won: the first key is current again")
        #expect(
            seen.pendingRotation.contains(.keyHeldOutsideTheVault(outsider.accountID)),
            "nothing says that someone outside the vault holds its key: \(seen.pendingRotation)")

        try await administrator.session.sync()
        #expect(
            try await administrator.session.sharedVaultStatus(vaultID).membership.member(outsider.accountID) == nil,
            "the addition was replayed")
        #expect(await grants().count == 1, "the current key was wrapped to the outsider again")
        #expect(
            try await administrator.vault.store.record(RecordKey(recordID: bank.id, kind: .item))?.keyID != firstKey,
            "sealed again under the key the outsider holds")

        try await Self.syncAll([administrator, owner, witness], rounds: 3)
        for account in [owner, administrator, witness] {
            let status = try await account.session.sharedVaultStatus(vaultID)
            #expect(status.membership.member(outsider.accountID) == nil)
            #expect(status.membership.vaultKeyID != firstKey, "the key the outsider was granted is still current")
            #expect(status.pendingRotation.isEmpty, "\(status.pendingRotation)")
            #expect(status.membership.members.count == 3)
        }
        #expect(await grants().count == 1)
        // What the administrator wrote under the losing branch's key reaches the others sealed again: its stream
        // does not wait for good at a segment sealed under a key the accepted chain never names.
        #expect(try await owner.session.syncAll().vaults[vaultID]?.waiting.isEmpty == true)
        #expect(try await owner.session.item(id: bank.id).field(.password)?.value == "after-the-removal")
        #expect(try await witness.session.item(id: bank.id).field(.password)?.value == "after-the-removal")
        #expect(try await owner.session.sharedVaultStatus(vaultID).heldAside == 0)

        // Later the administrator is made read-only. The cut the owner's device signs must reach past the segments
        // it could not open: it recorded them by digest and signer (Z51), so its chain over the administrator's
        // stream has no gap, and what that device wrote afterwards is inside the cut and still counts everywhere.
        // Recorded only where they opened, the cut ended before the episode and all of it was held aside (Z52).
        var later = Self.bank(in: vaultID)
        later.title = "Written after the fork was settled"
        later = try await administrator.session.save(later)
        try await Self.syncAll([administrator, owner, witness])
        try await owner.session.changeRole(of: administrator.accountID, in: vaultID, to: .readOnly)
        try await Self.syncAll([owner, witness, administrator], rounds: 3)
        for account in [owner, witness] {
            #expect(try await account.session.item(id: later.id).title == later.title)
            #expect(try await account.session.item(id: bank.id).field(.password)?.value == "after-the-removal")
            #expect(try await account.session.sharedVaultStatus(vaultID).heldAside == 0, "held aside by the cut")
        }
    }
}
