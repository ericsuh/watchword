import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordSharing
import WatchwordTestSupport

extension AdversarialSharedVaultTests {
    /// Threat: review finding D17 and SEC3 across a relaunch. The key directory (A1) served a member's device forged
    /// keys for another member's account, and the person pinned them; the chain lists that member's real keys. When the
    /// app starts again, the comparison of the chain with the pins must be made again before anything is shown: a
    /// device that restored the ledger and nothing else showed every member as verified, the substituted one included.
    @Test(
        "after a relaunch a member whose keys differ from the pin is still reported, and no member is called verified unchecked"
    )
    func keyCheckSurvivesRelaunch() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 611)
        let viewer = try await household.account(seed: 612)
        let target = try await household.account(seed: 613)
        let forged = try Keyset.generate(accountID: target.accountID).publicKeyBundle()
        await household.directory.tamper(target.accountID, contents: KeyBundleCodec.encode(forged))
        try await viewer.session.verifyContact(
            target.accountID, evidence: .safetyNumber(forged.fingerprint.safetyNumber))
        await household.directory.publish(target.bundle)

        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(viewer, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(target, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, viewer, target])
        let before = try await viewer.session.sharedVaultStatus(vaultID)
        #expect(before.substitutedMembers == [target.accountID])
        #expect(before.verifiedMembers == [owner.accountID])

        let relaunched = viewer.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: viewer.state, contacts: viewer.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        let after = try await relaunched.session.sharedVaultStatus(vaultID)
        #expect(after.substitutedMembers == [target.accountID], "the warning was lost with the relaunch")
        #expect(after.verifiedMembers == [owner.accountID])
        #expect(after.unverifiedMembers.isEmpty)

        // Locked, the comparison cannot be made: nothing is called verified, and the warning is kept.
        await relaunched.session.lock()
        let locked = try await relaunched.session.sharedVaultStatus(vaultID)
        #expect(locked.verifiedMembers == nil || locked.verifiedMembers == [owner.accountID])
    }
}
