import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

/// "Shared" as a fact the sharing state cannot take away (docs/06-adversarial-review.md, V31; the design of the
/// security-audit branch's Z41). In the suite "shared vaults through the session"; the adversaries are those of §2.
extension AdversarialSharedVaultTests {
    /// Every row of `vaultID`'s sharing state removed, as someone with the device's files can (A8).
    static func eraseSharingState(_ state: InMemorySharingStateStore, vaultID: UUID) async {
        for key in SharingStateKey.allCases { await state.tamper(key, vaultID: vaultID, value: nil) }
    }

    /// Threat: A8 (write access to the device's files while the app is closed) deletes a shared vault's `.ledger` and
    /// `.owner` rows on a read-write member's device, after a rotation that left it holding the key from before
    /// (which the removed member, A5, also holds). V19 only covered a ledger that was listed and did not restore;
    /// with the rows gone the sharing state listed nothing, and the vault became one of the account's own: written
    /// and published with no judge, sealed under the smallest key ID held (perhaps the old one), snapshotted and
    /// collected, and offered for sharing, which signed a second genesis for it. The account's marker and the key that
    /// arrived by grant keep it shared and unavailable: nothing is written, renamed, deleted, published or shared
    /// again, and nothing is sealed under any key; accepting its invitation on this device sets it up again, under the
    /// key its chain names.
    @Test("a shared vault whose ledger and owner rows are deleted stays shared and closed, never an own vault")
    func deletedLedgerRowsKeepTheVaultShared() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite], seed: 1_400)
        let (member, leaving) = (members[0], members[1])
        #expect(try await owner.session.removeMember(leaving.accountID, from: vaultID) == .complete)
        try await Self.syncAll([owner, member, owner])
        let current = try await member.session.sharedVaultStatus(vaultID).membership.vaultKeyID
        await Self.eraseSharingState(member.state, vaultID: vaultID)
        #expect(await member.state.sharedVaultIDs().isEmpty)
        let device = try await Self.relaunch(member, directory: household.directory)
        let session = device.session

        #expect(try await session.sharedVaultIDs().contains(vaultID) == false)
        #expect(try await session.sharedVaultsAwaitingOwnerCheck() == [vaultID])
        let listed = try #require(try await session.vaults().first { $0.id == vaultID })
        #expect(listed.isSharedUnavailable, "listed as shared and closed, not as one of the account's own")
        let membership = Set(await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))
        let log = Set(await household.transport.list(prefix: SyncObjectLocation.vaultPrefix(vaultID)))

        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            _ = try await session.save(Self.bank(in: vaultID))
        }
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            _ = try await session.renameVault(id: vaultID, to: "Ours now")
        }
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await session.deleteVault(id: vaultID, confirmingItemCount: 0)
        }
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await session.shareVault(vaultID)
        }
        let personal = try await session.save(Self.bank(in: try #require(try await session.vaults().first?.id)))
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            _ = try await session.move(itemID: personal.id, to: vaultID)
        }
        try await session.sync()
        try await session.sync()
        let membershipAfter = Set(
            await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))
        #expect(membershipAfter == membership, "no second genesis, nor any record")
        let logAfter = Set(await household.transport.list(prefix: SyncObjectLocation.vaultPrefix(vaultID)))
        #expect(logAfter == log, "nothing published, snapshotted or collected in the vault")
        #expect(await member.state.sharedVaultIDs().isEmpty, "no sharing state written for a chain of its own")

        // The way out: the vault's invitation, from the account's marker, accepted on this device (the owner is still
        // pinned). Shared again, read-write, and sealed under the key the chain names.
        let invitation = try #require(try await session.sharedVaultInvitation(vaultID))
        #expect(invitation.ownerAccountID == owner.accountID)
        try await session.acceptInvitation(invitation)
        #expect(try await session.sharedVaultsAwaitingOwnerCheck().isEmpty)
        #expect(try await session.sharedVaultStatus(vaultID).role == .readWrite)
        let saved = try await session.save(Self.bank(in: vaultID))
        let row = try #require(await session.storedRowForTest(RecordKey(recordID: saved.id, kind: .item)))
        #expect(row.keyID == current, "sealed under the chain's current key")
    }

    /// Threat: A8 deletes the sharing state of a vault on its owner's own device. The owner made the vault's key, so no
    /// key of it arrived by grant; only the account's marker says it is shared. It stays shared and closed (no second
    /// genesis, no write), and the owner sets it up again by accepting an invitation naming themself, with the key
    /// the account's directory holds for it.
    @Test("an owner's shared vault whose sharing state is deleted stays shared and is set up again from the marker")
    func ownersDeletedSharingState() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, _) = try await household.household(roles: [.readOnly], seed: 1_430)
        await Self.eraseSharingState(owner.state, vaultID: vaultID)
        let device = try await Self.relaunch(owner, directory: household.directory)
        let session = device.session
        let membership = Set(await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))

        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await session.shareVault(vaultID)
        }
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            _ = try await session.save(Self.bank(in: vaultID))
        }
        let membershipAfter = Set(
            await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))
        #expect(membershipAfter == membership, "no second genesis")

        let invitation = try #require(try await session.sharedVaultInvitation(vaultID))
        #expect(invitation.ownerAccountID == owner.accountID)
        try await session.acceptInvitation(invitation)
        #expect(try await session.sharedVaultStatus(vaultID).role == .owner)
        _ = try await session.save(Self.bank(in: vaultID))
    }

    /// Threat: a second device of a member (or of the owner) holds a shared vault's key from the account's directory
    /// and no ledger: it never had one. It used to run the vault as one of the account's own. The key's wrap says it
    /// arrived by grant and the account's marker names the owner, so the new device holds the vault closed until it
    /// accepts the vault's invitation itself.
    @Test("a member's new device holds a shared vault closed until it accepts the vault's invitation")
    func newDeviceHoldsTheVaultClosed() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 1_460)
        let member = members[0]
        let second = try await member.vault.enrolledDevice(deviceID: UUID(), over: household.transport)
        let state = InMemorySharingStateStore()
        await second.session.configureSharing(
            SharingSettings(state: state, contacts: member.contacts, directory: household.directory))
        try await second.session.unlock(password: TestVault.password)
        try await second.session.sync()

        #expect(try await second.session.sharedVaultsAwaitingOwnerCheck() == [vaultID])
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            _ = try await second.session.save(Self.bank(in: vaultID))
        }
        let invitation = try #require(try await second.session.sharedVaultInvitation(vaultID))
        #expect(invitation.ownerAccountID == owner.accountID)
        try await second.session.acceptInvitation(invitation)
        _ = try await second.session.save(Self.bank(in: vaultID))
    }
}
