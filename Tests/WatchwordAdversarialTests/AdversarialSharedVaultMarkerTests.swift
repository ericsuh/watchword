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

extension AdversarialSharedVaultTests {
    /// Threat: A8 plants `.owner` and `.ledger` rows in the sharing state for one of the account's own vaults and for
    /// its Personal vault (review of the follow-up audit's fixes, L1). With V19's rule a listed ledger that did not
    /// restore closed the vault for good, the Personal vault included: no write, no sync of its objects, and no way
    /// back. Rows of the sharing state mark nothing (the security-audit branch's Z50): both vaults stay the account's
    /// own, writable and shareable, and nothing is reported unavailable.
    @Test("rows planted in the sharing state close no vault, the Personal one included")
    func plantedRowsCloseNothing() async throws {
        let household = SharedVaultHousehold()
        let account = try await household.account(seed: 1_490)
        let own = try await account.session.createVault(name: "Mine").id
        let personal = try #require(try await account.session.vaults().first { $0.isPersonal }?.id)
        for vaultID in [own, personal] {
            await account.state.tamper(.owner, vaultID: vaultID, value: Array(repeating: 0x41, count: 16))
            await account.state.tamper(.ledger, vaultID: vaultID, value: Array(repeating: 0x57, count: 96))
        }
        let device = try await Self.relaunch(account, directory: household.directory)
        let session = device.session

        #expect(try await session.unavailableSharedVaults().isEmpty)
        for vaultID in [own, personal] {
            _ = try await session.save(Self.bank(in: vaultID))
        }
        try await session.sync()
        try await session.shareVault(own)
        #expect(try await session.sharedVaultIDs() == [own])
    }

    /// Threat: A8 damages a shared vault's saved ledger on a member's device while the owner's pin stays. Nothing on
    /// the device verifies the ledger, so checking the owner again (all V19's wording offered) could not restore it,
    /// and the vault stayed closed for good. The session tells this apart from a missing pin (V33), and the person's
    /// way back, setting the vault up again on this device from the account's marker, verifies the chain against the
    /// owner's pin and keeps every item.
    @Test("a shared vault whose ledger does not verify is set up again, and keeps every item")
    func damagedLedgerIsSetUpAgain() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 1_500)
        let member = members[0]
        let saved = try await member.session.save(Self.bank(in: vaultID))
        try await member.session.sync()
        await member.state.tamper(.ledger, vaultID: vaultID, value: Array(repeating: 0x57, count: 96))
        let device = try await Self.relaunch(member, directory: household.directory)
        let session = device.session

        let reason = try await session.unavailableSharedVaults()[vaultID]
        #expect(reason == .notSetUp(owner: owner.accountID))
        #expect(try await session.item(id: saved.id).title == saved.title, "readable while closed")
        try await session.setUpSharedVaultAgain(vaultID)
        #expect(try await session.unavailableSharedVaults().isEmpty)
        #expect(try await session.sharedVaultStatus(vaultID).role == .readWrite)
        #expect(try await session.item(id: saved.id).title == saved.title, "nothing was lost")
        try await session.sync()
        #expect(try await session.item(id: saved.id).title == saved.title, "nor taken out by the restored ledger")
    }

    /// Threat: as V28 (A8 damages a shared vault's ledger, A1 serves impostor keys, an attacker runs a session under
    /// an account), but for an account that owns no vault this device cannot read. V28's guard refused every pin
    /// replacement while any listed ledger did not restore, so one planted or damaged row blocked the person's
    /// "use their new keys" for every contact. Only the pin of an unavailable vault's owner is refused now; the
    /// owner's is (`noPinReplacedWhileAVaultIsUnrestored`), another contact's is not.
    @Test("an unavailable shared vault blocks replacing its owner's pin and no other")
    func pinReplacementScopedToTheOwner() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, _, members) = try await household.household(roles: [.readWrite], seed: 1_530)
        let member = members[0]
        let contact = try await household.account(seed: 1_590)
        try await member.session.verifyContact(contact.accountID, evidence: .safetyNumber(contact.safetyNumber))
        await member.state.tamper(.ledger, vaultID: vaultID, value: Array(repeating: 0x57, count: 64))
        let device = try await Self.relaunch(member, directory: household.directory, board: household.board)
        #expect(try await device.session.sharedVaultsAwaitingOwnerCheck() == [vaultID])

        let replacement = try SharingParty(accountID: contact.accountID, seed: 1_549)
        await household.directory.publish(replacement.bundle)
        var generator = SeededGenerator(seed: 1_550)
        var starter = SharingCodeStarter.draw(as: replacement.bundle, using: &generator, at: Date())
        try await starter.publish(on: household.board, at: Date())
        _ = try await device.session.joinSharingCodeSession(number: starter.number.digits)
        try await starter.poll(board: household.board, directory: household.directory, at: Date())
        let shown = try await device.session.refreshSharingCodeSession()
        _ = try starter.enterJoinerCode(try #require(shown.ownCode), at: Date())
        let typed = try await device.session.enterSharingCode(try #require(starter.code))
        #expect(typed.keysDifferFromPin && !typed.pinned)

        try await device.session.replacePinFromSharingCode()
        let pins = VerifiedContacts(store: member.contacts, account: member.bundle)
        let pin = try #require(try await pins.pinned(contact.accountID))
        #expect(pin.bundle.hasSameKeys(as: replacement.bundle), "the person's choice was honoured")
    }
}
