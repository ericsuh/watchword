import Foundation
import Testing
import WatchwordAutoFill
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z45 (docs/06-adversarial-review.md): what the screens said of leaving, and what the code did.
extension AdversarialSharedVaultTests {
    /// Threat: no adversary; a security statement made to the person. The leave dialog said the vault's items "go
    /// from your devices" once the key was replaced. Nothing removed them: after the rotation the vault dropped out of
    /// the list while its items stayed in every list and in what AutoFill is given, so a device handed on, or simply
    /// trusted, went on filling the credentials of a vault its owner had left, with no vault shown to say where they
    /// came from. Now: until the rotation the member is a member; after it the items are not offered to AutoFill, the
    /// vault is listed as one this account is no longer in, and the items go when the person removes them, which
    /// publishes nothing and touches nobody else's copy.
    @Test(
        "a vault this account left is not offered to AutoFill, is shown for what it is, and goes when the person removes it"
    )
    func leftVaultStaysUntilRemoved() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 980)
        let (owner, member) = (home.owner, home.members[0])
        let vaultID = home.vaultID
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member])
        #expect(try await member.session.credentialItems().contains { $0.id == bank.id })
        await #expect(throws: SharedVaultError.stillAMember(vaultID)) {
            try await member.session.removeLocalCopies(ofSharedVault: vaultID)
        }

        // Leaving is a request. Until an administrator's device carries it out the member is a member, on the share.
        try await member.session.leaveSharedVault(vaultID)
        #expect(try await member.session.sharedVaultStatus(vaultID).role == .readWrite)
        #expect(await member.shareAccess.revoked.isEmpty, "a leaving member's device takes nobody off the share")
        #expect(try await member.session.credentialItems().contains { $0.id == bank.id })

        try await Self.syncAll([owner, member], rounds: 3)
        #expect(await owner.shareAccess.revoked.contains { $0.account == member.accountID && $0.vault == vaultID })
        #expect(try await member.session.sharedVaultStatus(vaultID).role == nil)

        // Nothing removed the copies: they are on the device, readable, in a vault that is still listed.
        #expect(try await member.session.item(id: bank.id).title == bank.title)
        #expect(
            try await member.session.vaults().contains { $0.id == vaultID }, "its items would be listed under no vault")
        // They are not offered to a page, and nothing can be written there.
        #expect(try await !member.session.credentialItems().contains { $0.id == bank.id })
        await #expect(throws: SharedVaultError.writeRefused(.notAMember)) {
            try await member.session.setArchived(true, id: bank.id)
        }

        // The person removes them. Not a deletion: the owner's copy is untouched, and no sync brings them back.
        let before = Set(await household.transport.list(prefix: "vault/\(vaultID.uuidString)/"))
        #expect(try await member.session.removeLocalCopies(ofSharedVault: vaultID) == 1)
        #expect(try await member.session.items(in: vaultID).items.isEmpty)
        #expect(try await !member.session.vaults().contains { $0.id == vaultID })
        try await Self.syncAll([member, owner])
        #expect(Set(await household.transport.list(prefix: "vault/\(vaultID.uuidString)/")).isSuperset(of: before))
        #expect(try await owner.session.item(id: bank.id).title == bank.title)
        #expect(try await member.session.items(in: vaultID).items.isEmpty)
        #expect(try await member.vault.sync?.state.pendingDeletions(vaultID: vaultID).isEmpty == true)
    }

    /// Threat: the same statement, for a device that cannot tell whether its account is still a member: a shared
    /// vault with no ledger here (its sharing state was lost after it left, say). Its items are not offered either.
    @Test("a shared vault with no ledger on this device is not offered to AutoFill")
    func unavailableVaultIsNotOffered() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 990)
        let member = home.members[0]
        let bank = try await home.owner.session.save(Self.bank(in: home.vaultID))
        try await Self.syncAll([home.owner, member])
        #expect(try await member.session.credentialItems().contains { $0.id == bank.id })

        await member.session.lock()
        await member.state.tamper(.ledger, vaultID: home.vaultID, value: nil)
        let relaunched = member.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(try await relaunched.session.item(id: bank.id).title == bank.title)
        #expect(try await !relaunched.session.credentialItems().contains { $0.id == bank.id })
    }

    /// Threat: none needed; a member removed while their device held work it had not synced (review finding Z57).
    /// What `removeLocalCopies` takes off the device is described as copies, "the vault's members keep theirs", and
    /// that is not true of an item written here that reached nobody: it is the only one. Removing it is a discard
    /// only the person can make (F7.6), and a removal that later loses a fork would have given the membership back
    /// and let it be published. So the removal is refused until the caller says how many such changes the person
    /// was told of, and the session reports the number.
    @Test("removing a left vault's items from a device does not discard its own unsynced work without being told to")
    func removingCopiesKeepsUnsharedWork() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 985)
        let (owner, member) = (home.owner, home.members[0])
        let vaultID = home.vaultID
        _ = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member])
        var own = Self.bank(in: vaultID)
        own.title = "Written here, synced nowhere"
        let unsynced = try await member.session.save(own)
        try await owner.session.removeMember(member.accountID, from: vaultID)
        try await Self.syncAll([owner, member], rounds: 3)
        #expect(try await member.session.sharedVaultStatus(vaultID).role == nil)
        #expect(try await !owner.session.items(in: vaultID).items.contains { $0.id == unsynced.id })

        let unshared = try await member.session.unsharedWork(inSharedVault: vaultID)
        #expect(unshared == 1)
        await #expect(throws: SharedVaultError.unsharedWork(vaultID, unshared)) {
            try await member.session.removeLocalCopies(ofSharedVault: vaultID)
        }
        let syncState = try #require(member.vault.sync?.state)
        let here = try await member.session.items(in: vaultID).items.contains { $0.id == unsynced.id }
        let aside = try await syncState.quarantined(vaultID: vaultID).contains { $0.recordID == unsynced.id }
        #expect(here || aside, "the only copy of the item went with a refusal")

        // Told of it, the person may discard it with the rest.
        try await member.session.removeLocalCopies(ofSharedVault: vaultID, discardingUnshared: unshared)
        #expect(try await member.session.items(in: vaultID).items.isEmpty)
        #expect(try await syncState.quarantined(vaultID: vaultID).isEmpty)
    }
}
