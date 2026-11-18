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

// Review of Z41's fix (docs/06-adversarial-review.md, "claims with no test"): a vault held closed for want of a ledger
// was shown to refuse five calls. These are the others.
extension AdversarialSharedVaultTests {
    static let importFile = Array(
        """
        Title,URL,Username,Password,Notes,OTPAuth
        Bank,https://bank.example/,wendy,bank-pw,,
        """.utf8)

    /// Threat: someone with the device's files (A8) who deletes the saved ledger from a member's device, or a
    /// restore that loses it; a former member (A5) who reads the store profits. The device holds the vault's keys and
    /// items and no ledger, so it cannot tell which key is current or whether its account may write. Anything it
    /// sealed could be under the key a removed member kept; anything it deleted would be a tombstone nobody judged.
    /// Every path of the session that writes, deletes or seals in a vault must refuse there: trashing and restoring,
    /// deleting for good, the purge, a move out or in, a copy in, a login saved or updated from a page, a conflict
    /// resolved, an import. And nothing may have changed, been queued or been published.
    @Test("no write path of a session reaches a shared vault held closed for want of a ledger")
    func everyWritePathWithoutLedger() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 815)
        let (owner, member) = (home.owner, home.members[0])
        let vaultID = home.vaultID
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        let trashed = try await owner.session.save(Self.bank(in: vaultID))
        try await owner.session.trash(id: trashed.id)
        try await Self.syncAll([owner, member])
        let personal = try #require(await member.session.personalVaultID)
        let own = try await member.session.save(Self.bank(in: personal))
        try await member.session.sync()

        await member.session.lock()
        await member.state.tamper(.ledger, vaultID: vaultID, value: nil)
        let device = member.vault.relaunched()
        await device.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await device.session.unlock(password: TestVault.password)
        let session = device.session
        #expect(try await session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)
        let rows = try await device.store.records(in: vaultID, kind: .item)
        #expect(rows.count == 2, "the device holds nothing of the vault: the test proves nothing")
        let held = try await session.item(id: bank.id)
        let published = Set(await household.transport.list(prefix: "vault/\(vaultID.uuidString)/"))

        let refused = SharedVaultError.ledgerUnavailable(vaultID)
        await #expect(throws: refused) { try await session.trash(id: bank.id) }
        await #expect(throws: refused) { try await session.restore(id: trashed.id) }
        await #expect(throws: refused) { try await session.deletePermanently(id: trashed.id) }
        await #expect(throws: refused) { try await session.move(itemID: bank.id, to: personal) }
        await #expect(throws: refused) { try await session.move(itemID: own.id, to: vaultID) }
        await #expect(throws: refused) { try await session.copy(itemID: own.id, to: vaultID) }
        // The AutoFill port reports a refusal by its type alone.
        let refusedToAutoFill = CredentialVaultError.failed("SharedVaultError")
        await #expect(throws: refusedToAutoFill) {
            try await session.saveCredentialItem(Self.bank(in: vaultID), replacingVersion: nil)
        }
        await #expect(throws: refusedToAutoFill) {
            var changed = held
            changed.title = "Updated from a page"
            return try await session.saveCredentialItem(changed, replacingVersion: held.version)
        }
        await #expect(throws: refused) {
            try await session.resolveConflict(itemID: bank.id, group: .title, choosing: .title(held.title))
        }
        await #expect(throws: refused) {
            try await session.previewImport(Self.importFile, format: .passwordCSV, into: vaultID)
        }
        // Nor are its items taken off the device as a left vault's are: whether the account left cannot be told.
        await #expect(throws: refused) { try await session.removeLocalCopies(ofSharedVault: vaultID) }
        // The purge skips the vault; thirty-one days on, the trashed item is due.
        await device.clock.advance(by: 31 * 24 * 60 * 60)
        try await session.purgeExpiredTrash()

        #expect(try await device.store.records(in: vaultID, kind: .item) == rows, "a row of the vault changed")
        #expect(try await session.items(in: personal).items.map(\.id) == [own.id], "a move or copy left something")
        let syncState = try #require(device.sync?.state)
        #expect(try await syncState.pendingDeletions(vaultID: vaultID).isEmpty)
        #expect(try await syncState.pendingDeletions(vaultID: personal).isEmpty)
        try await session.sync()
        #expect(Set(await household.transport.list(prefix: "vault/\(vaultID.uuidString)/")) == published)
    }

    /// Threat: none needed for the state; a former member (A5) profits if it fails. The owner's first device shares a
    /// vault and writes the account's marker; it is then lost and revoked from the second device, which holds the
    /// marker and no ledger. A marker is the account's statement, vouched for by a device registered when it was
    /// taken: if revoking that device unmarked the vault, revoking a device would reopen, as private vaults, the
    /// vaults it had marked. And a device enrolled afterwards must know the vault is shared from its first moment,
    /// before any sync of its own: enrolment brings the markers with the vault's keys.
    @Test("a vault stays marked when the device that marked it is revoked, and a device enrolled later knows at once")
    func markerOutlivesItsDevice() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 860)
        let vaultID = try await owner.session.createVault(name: "Household").id
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await owner.session.sync()
        let second = try await household.secondDevice(of: owner)
        try await owner.session.shareVault(vaultID)
        try await owner.session.sync()
        try await second.session.sync()
        #expect(try await second.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)

        let first = try #require(try await owner.vault.store.loadAccount()).deviceID
        try await second.session.revokeDevice(first, password: .keepPassword(current: TestVault.password))
        try await second.session.sync()
        await second.session.lock()
        let relaunched = second.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: second.state, contacts: second.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        try await relaunched.session.sync()
        #expect(
            try await relaunched.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true,
            "revoking the device that wrote the marker reopened the vault as a private one")
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await relaunched.session.setArchived(true, id: bank.id)
        }

        // A third device, enrolled from the transport: asked before it has synced at all.
        let third = try await relaunched.enrolledDevice(deviceID: UUID(), over: household.transport)
        await third.session.configureSharing(
            SharingSettings(
                state: InMemorySharingStateStore(), contacts: InMemoryVerifiedContactStore(),
                directory: household.directory))
        try await third.session.unlock(password: TestVault.password)
        #expect(
            try await third.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true,
            "a new device ran a shared vault as its account's own until its first sync")
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await third.session.save(Self.bank(in: vaultID))
        }
    }
}
