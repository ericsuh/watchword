import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// Review finding Z50 (docs/06-adversarial-review.md): "the marker first" could close an owner's own vault for good.
extension AdversarialSharedVaultTests {
    /// Threat: none; a lock, or the system ending the process, in the middle of sharing. The marker is written
    /// before the chain, so that every device of the account learns the vault is shared whether or not it ever sees
    /// the chain. Interrupted between the two, the device was left with a marker naming its own account as owner, no
    /// ledger and no genesis record anywhere: the vault closed for every write, nothing of it offered to AutoFill,
    /// `shareVault` refused as a second share and the invitation the marker offers failing for want of a genesis. A
    /// vault whose only mark is this account's own marker naming this account, none of whose keys came by grant, is
    /// this account's to finish sharing: `shareVault` goes on from where it stopped.
    @Test("a share cut short after the marker is finished by sharing again, and the vault is never closed for good")
    func shareInterruptedAfterTheMarker() async throws {
        let base = InMemorySyncTransport()
        let directory = InMemoryKeyBundleDirectory()
        let tripwire = LockingTransport(base: base)
        let owner = try await SharingAccount.make(over: tripwire, directory: directory, seed: 5010)
        let vaultID = try await owner.session.createVault(name: "Household").id
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await owner.session.sync()

        // The lock lands while the marker is being published: the chain is never saved and never published.
        await tripwire.lock(
            owner.session,
            onCreateUnder: AccountObjectLocation.vaultsPrefix(owner.accountID) + "\(vaultID.uuidString)/shared/")
        await #expect(throws: (any Error).self) { try await owner.session.shareVault(vaultID) }
        #expect(try await owner.session.state() == .locked)
        #expect(await base.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)).isEmpty)

        // The process is gone; the app starts again.
        let relaunched = owner.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: owner.state, contacts: owner.contacts, directory: directory))
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(try await relaunched.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)

        try await relaunched.session.shareVault(vaultID)
        #expect(try await relaunched.session.sharedVaultStatus(vaultID).role == .owner)
        #expect(try await relaunched.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == false)
        try await relaunched.session.setArchived(true, id: bank.id)
        #expect(await base.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)).count == 1)

        // And it is a shared vault like any other: someone can be invited and reads it.
        let member = try await SharingAccount.make(over: base, directory: directory, seed: 5011)
        try await relaunched.session.verifyContact(member.accountID, evidence: .safetyNumber(member.safetyNumber))
        let invitation = try await relaunched.session.invite(member.accountID, to: vaultID, as: .readWrite)
        try await member.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await relaunched.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).archived)
    }

    /// Threat: none; the transport fails for the one call that publishes the genesis record. The vault was shared on
    /// this device and nobody else could ever join it: nothing published the record again, so an invitee and the
    /// owner's other devices found no chain. The owner's device puts its genesis record back at each sync while the
    /// store does not list it.
    @Test("a genesis record the store does not hold is published again by the owner's next sync")
    func genesisPublishedAgain() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 5020)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let prefix = SharingObjectLocation.membershipPrefix(vaultID)
        let genesis = try #require(await household.transport.list(prefix: prefix).first)
        let bytes = try #require(await household.transport.fetch(genesis, maximumLength: 1 << 16))
        await household.transport.tamper(genesis, contents: nil)

        try await owner.session.sync()
        #expect(try await household.transport.fetch(genesis, maximumLength: 1 << 16) == bytes)
        let member = try await household.account(seed: 5021)
        try await owner.invite(member, to: vaultID, as: .readOnly, owner: owner)
        #expect(try await member.session.sharedVaultStatus(vaultID).role == .readOnly)
    }

    /// Threat: someone with the device's files (A8) plants rows in the sharing state naming a vault that is the
    /// account's own and was never shared. Nothing in that file is trust: an owner row is not signed, and a ledger
    /// that does not restore is nothing. Such rows must not close a private vault (they did: any vault the sharing
    /// state named without a ledger that loaded was held closed, with no way out).
    @Test("rows planted in the sharing state do not close a vault that was never shared")
    func plantedSharingStateRow() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 5030)
        let vaultID = try await owner.session.createVault(name: "Mine").id
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        await owner.session.lock()
        await owner.state.tamper(.owner, vaultID: vaultID, value: Array(repeating: 0x41, count: 16))
        await owner.state.tamper(.ledger, vaultID: vaultID, value: Array(repeating: 0x42, count: 300))

        let relaunched = owner.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: owner.state, contacts: owner.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(try await relaunched.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == false)
        try await relaunched.session.setArchived(true, id: bank.id)
        #expect(try await relaunched.session.credentialItems().contains { $0.id == bank.id })
        try await relaunched.session.sync()
        #expect(await household.transport.list(prefix: SharingObjectLocation.vaultPrefix(vaultID)).isEmpty)
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: none. The same rule that finishes a share cut short lets the owner's other device take up a vault
    /// the account shared elsewhere, while it has not rotated: its own marker names this account and every key it
    /// holds is the account's own, so the genesis record it would sign is the one that exists. It then holds the
    /// chain's first record and takes the rest from the store. Once a key of the vault has come by grant (a
    /// rotation), that is no longer so, and `shareVault` is refused there as on a member's device (Z41).
    @Test("the owner's other device takes up a vault its account shared by sharing it, until the vault has rotated")
    func ownerOtherDeviceSharesAgain() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite, .readWrite], seed: 5040)
        let (owner, member, other) = (home.owner, home.members[0], home.members[1])
        let vaultID = home.vaultID
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member])
        let second = try await household.secondDevice(of: owner)
        #expect(try await second.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)
        let records = Set(await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))

        try await second.session.shareVault(vaultID)
        try await second.session.sync()
        let status = try await second.session.sharedVaultStatus(vaultID)
        #expect(status.role == .owner && status.membership.members.count == 3)
        #expect(status.membership.hash == (try await owner.session.sharedVaultStatus(vaultID).membership.hash))
        try await second.session.setArchived(true, id: bank.id)
        try await Self.syncAll([second, owner, member])
        #expect(try await member.session.item(id: bank.id).archived)
        #expect(try await member.session.sharedVaultStatus(vaultID).heldAside == 0)
        // On Linux a signature is a function of its message, so the record signed again is the same object.
        #if !canImport(Darwin)
            #expect(
                Set(await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID))) == records)
        #endif

        // After a rotation the new key reaches a third device of the owner's by grant: no second genesis there.
        try await owner.session.removeMember(other.accountID, from: vaultID)
        try await owner.session.sync()
        let third = try await household.secondDevice(of: owner)
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await third.session.shareVault(vaultID)
        }
    }
}
