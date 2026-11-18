import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

/// A shared vault whose saved ledger does not restore on a member's device (docs/06-adversarial-review.md, V19). In
/// the suite "shared vaults through the session"; the adversaries are those of §2.
extension AdversarialSharedVaultTests {
    /// A member's device whose sharing state still lists `vaultID`, relaunched over `contacts`, unlocked.
    static func relaunch(_ member: SharingAccount, directory: InMemoryKeyBundleDirectory) async throws -> TestVault {
        let relaunched = member.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(
                state: member.state, contacts: member.contacts, directory: directory,
                shareAccess: member.shareAccess))
        try await relaunched.session.unlock(password: TestVault.password)
        return relaunched
    }

    /// Threat: A8 (write access to the device's files while the app is closed) deletes the owner's pin, so the saved
    /// ledger of a shared vault no longer restores at the next launch (S13 accepts the deletion on the premise that it
    /// puts the owner back in front of the person). The vault has no "shared" flag of its own, so it used to fall back
    /// to being one of the account's own: synced with no judge and with snapshots and collection on, written and
    /// renamed by a member who may not, sealed under the smallest key ID held (perhaps one from before a rotation), and
    /// offered for sharing, which minted a new genesis over the saved owner. The vault is now shared and unavailable:
    /// nothing is written, renamed, published, verified, shared again or accepted into it, and it comes back once the
    /// owner is checked again.
    @Test("a shared vault whose ledger does not restore is unavailable, never one of the member's own vaults")
    func unrestoredSharedVaultIsUnavailable() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readOnly], seed: 1_270)
        let member = members[0]
        await member.contacts.removePin(for: owner.accountID)
        let ownerRow = await member.state.value(.owner, vaultID: vaultID)
        let ledgerRow = await member.state.value(.ledger, vaultID: vaultID)
        let device = try await Self.relaunch(member, directory: household.directory)
        let session = device.session

        #expect(try await session.sharedVaultIDs().contains(vaultID) == false)
        #expect(try await session.sharedVaultsAwaitingOwnerCheck() == [vaultID])
        // A read-only member's device writes nothing, renames nothing and shares nothing again.
        await #expect(throws: SharedVaultError.sharedVaultUnavailable(vaultID)) {
            _ = try await session.save(Self.bank(in: vaultID))
        }
        await #expect(throws: SharedVaultError.sharedVaultUnavailable(vaultID)) {
            _ = try await session.renameVault(id: vaultID, to: "Ours now")
        }
        await #expect(throws: SharedVaultError.sharedVaultUnavailable(vaultID)) {
            try await session.shareVault(vaultID)
        }
        await #expect(throws: SharedVaultError.sharedVaultUnavailable(vaultID)) {
            try await session.acceptInvitation(Invitation(vaultID: vaultID, ownerAccountID: owner.accountID))
        }
        #expect(await member.state.value(.owner, vaultID: vaultID) == ownerRow, "the saved owner is untouched")
        #expect(await member.state.value(.ledger, vaultID: vaultID) == ledgerRow, "the saved ledger is untouched")

        // The owner writes; the member's sync publishes nothing in the vault, snapshots and collects nothing, and
        // takes in nothing it cannot judge.
        let written = try await owner.session.save(Self.bank(in: vaultID))
        try await owner.session.sync()
        let before = Set(await household.transport.list(prefix: SyncObjectLocation.vaultPrefix(vaultID)))
        try await session.sync()
        try await session.sync()
        let after = Set(await household.transport.list(prefix: SyncObjectLocation.vaultPrefix(vaultID)))
        #expect(after == before, "nothing was published, snapshotted or collected in the vault")
        await #expect(throws: VaultError.itemNotFound(written.id), "nothing was taken in unjudged") {
            _ = try await session.item(id: written.id)
        }

        // Checked again, the owner's pin restores the vault, as shared and read-only.
        try await session.verifyContact(owner.accountID, evidence: .safetyNumber(owner.safetyNumber))
        #expect(try await session.sharedVaultIDs().contains(vaultID))
        #expect(try await session.sharedVaultsAwaitingOwnerCheck().isEmpty)
        #expect(try await session.sharedVaultStatus(vaultID).role == .readOnly)
    }
}
