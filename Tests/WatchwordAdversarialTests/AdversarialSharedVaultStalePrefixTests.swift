import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The independent review of V31 to V37, finding L1 (docs/06-adversarial-review.md V41): setting a shared vault up again
// joins from the transport with no saved ledger to continue, so a store that serves an older prefix of the chain can
// roll the device back to a head whose current key a member removed since still holds.
extension AdversarialSharedVaultTests {
    /// `account`'s device, relaunched over `view` with its sharing state and contacts.
    static func relaunch(_ account: SharingAccount, over view: any SyncTransport, directory: InMemoryKeyBundleDirectory)
        async throws -> TestVault
    {
        var sync = try #require(account.vault.sync)
        sync.transport = view
        let device = TestVault(
            store: account.vault.store, keychain: account.vault.keychain, biometrics: account.vault.biometrics,
            clock: account.vault.clock, sync: sync, seed: 11, deviceKeys: account.vault.deviceKeys)
        await device.session.configureSharing(
            SharingSettings(
                state: account.state, contacts: account.contacts, directory: directory,
                shareAccess: account.shareAccess))
        try await device.session.unlock(password: TestVault.password)
        return device
    }

    /// Threat: A8 (the device's files) deletes a member's saved ledger after the owner removed another member (A5)
    /// and rotated the key, and the store (A1) then serves the member's device the chain only up to before the
    /// removal. Setting the vault up again joined that prefix, whose current key is the one A5 kept: what the member
    /// wrote next was sealed under it, and A5's writes counted. The device holds the newer key, which reached the
    /// account by a grant of the record the prefix lacks; a chain that names none of the granted keys held is not
    /// joined. With the whole chain served, it is set up again under the current key.
    @Test("a chain that never names a key the account was granted is not joined")
    func stalePrefixIsNotJoined() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite], seed: 1_510)
        let (member, removed) = (members[0], members[1])
        let before = Set(await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))
        let oldKey = try await member.session.sharedVaultStatus(vaultID).membership.vaultKeyID
        #expect(try await owner.session.removeMember(removed.accountID, from: vaultID) == .complete)
        try await Self.syncAll([owner, member])
        let newKey = try await member.session.sharedVaultStatus(vaultID).membership.vaultKeyID
        try #require(newKey != oldKey, "the vault did not rotate: the test proves nothing")

        await Self.eraseSharingState(member.state, vaultID: vaultID)
        let view = WithholdingTransport(base: household.transport)
        let after = Set(await household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)))
        await view.withhold(after.subtracting(before))
        let device = try await Self.relaunch(member, over: view, directory: household.directory)
        let session = device.session
        try await session.sync()
        await #expect(throws: SharedVaultError.chainBehindHeldKeys(vaultID)) {
            try await session.setUpSharedVaultAgain(vaultID)
        }
        #expect(try await session.sharedVaultIDs().isEmpty, "the device joined the older prefix")

        await view.reveal()
        try await session.setUpSharedVaultAgain(vaultID)
        #expect(try await session.sharedVaultStatus(vaultID).membership.vaultKeyID == newKey)
        let saved = try await session.save(Self.bank(in: vaultID))
        let row = try #require(await session.storedRowForTest(RecordKey(recordID: saved.id, kind: .item)))
        #expect(row.keyID == newKey, "sealed under a key the removed member holds")
    }
}
