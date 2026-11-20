import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The independent review of V31 to V37 (docs/06-adversarial-review.md V39), finding M1: with only part of the
// security-audit branch's design ported, a device led into another chain spread a marker naming the wrong owner across
// the account, and a later device followed whichever marker its directory fetch took first. These tests hold M1's
// exact scenario on the merged code, where Z48 and Z59 close it.
extension AdversarialSharedVaultTests {
    /// Threat: the store (A1) withholds the account's directory objects for a vault from a member's new laptop, and a
    /// contact the person has reason to verify (A5) signs a rival chain for the same vault ID and invites the member
    /// naming themself. The laptop joins it and publishes a marker naming A5. A third device of the member, enrolled
    /// once both markers are on the transport, took the first marker its directory fetch read (by author name, so
    /// about half the time A5's), offered A5's chain as the vault's to set up again, and followed it. Whichever marker
    /// the fetch takes first, the third device must hold the vault closed as disputed, name no owner, accept neither
    /// chain's invitation, and seal nothing; and the phone, which holds the real chain, must hold it closed too.
    @Test(
        "a device enrolled after a rival marker reached the account follows neither owner",
        arguments: [UInt64(5960), 5970, 5980])
    func laterDeviceFollowsNeitherMarker(seed: UInt64) async throws {
        let setting = try await ImpostorChain.make(seed: seed)
        let (member, laptop, vaultID) = (setting.member, setting.laptop, setting.vaultID)
        await setting.view.reveal()
        try await laptop.session.sync()
        try await member.session.sync()
        let markers = await setting.household.transport.list(prefix: setting.directoryPrefix + "shared/")
        #expect(markers.count >= 2, "both markers are on the transport: the test proves nothing otherwise")

        let desktop = try await setting.household.secondDevice(of: member)
        try await desktop.session.sync()
        try await desktop.session.sync()
        let info = try #require(try await desktop.session.vaults().first { $0.id == vaultID })
        #expect(info.isSharedUnavailable && info.isOwnerDisputed)
        #expect(try await desktop.session.sharedVaultInvitation(vaultID) == nil, "an owner was named")
        await #expect(throws: (any Error).self) {
            try await desktop.session.setUpSharedVaultAgain(vaultID)
        }
        let rival = Invitation(vaultID: vaultID, ownerAccountID: setting.impostor.accountID)
        await #expect(throws: (any Error).self) {
            try await desktop.session.acceptInvitation(
                rival, ownerEvidence: .safetyNumber(try setting.impostor.publicKeyBundle().fingerprint.safetyNumber))
        }
        #expect(try await desktop.session.sharedVaultIDs().isEmpty, "the desktop joined a chain")
        await #expect(throws: (any Error).self) {
            try await desktop.session.save(Self.bank(in: vaultID))
        }
        // Nothing of the desktop's reaches the vault's log.
        let device = try await Self.deviceID(of: desktop)
        #expect(
            await setting.household.transport.list(prefix: "vault/\(vaultID.uuidString)/log/\(device.uuidString)/")
                .isEmpty)
        // The phone, which holds the real chain, sees the dispute as well.
        #expect(try await member.session.sharedVaultStatus(vaultID).ownerDisputed)
        // And the laptop's copy of the real key, if the directory brought it, is not used under the rival chain.
        #expect(await laptop.session.keys?.vaultKeys[setting.realKey] == nil, "the real key is resident on the laptop")
    }
}
