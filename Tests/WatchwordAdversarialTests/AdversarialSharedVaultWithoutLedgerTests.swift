import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z41 (docs/06-adversarial-review.md): "is this vault shared?" was answered only by the ledger a device
// had loaded. A device of a member's or the owner's account that never held the ledger, or one whose saved ledger no
// longer loads, ran the vault as the account's own: no role, the lowest key ID as the current key, no judge, the log
// collected, and "delete vault" open to it.
extension AdversarialSharedVaultTests {
    /// The key ID each of the vault's item rows on `account`'s device is sealed under.
    static func itemKeyIDs(_ account: SharingAccount, in vaultID: UUID) async throws -> Set<UUID> {
        Set(try await account.vault.store.records(in: vaultID, kind: .item).map(\.keyID))
    }

    /// Threat: no adversary is needed for the state, and a former member (A5) who still reads the store profits. A
    /// member's second device receives the vault's keys through the account's own vault directory and holds no
    /// ledger. It must not write, publish, maintain or delete there until it holds a verified ledger; it must be able
    /// to get one by accepting the invitation itself; and then it seals under the key the chain names, not the lowest
    /// key ID it holds (after a rotation, about half the time the key the removed member kept).
    @Test("a member's other device holds a shared vault closed until it accepts the invitation itself")
    func memberSecondDeviceWithoutLedger() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite, .readWrite], seed: 810)
        let (owner, member, former) = (home.owner, home.members[0], home.members[1])
        let vaultID = home.vaultID
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member, former])

        // The owner removes the third member: the key rotates. The member's first device adopts the new key and
        // vouches for it in the account's vault directory, where the second device finds both.
        try await owner.session.removeMember(former.accountID, from: vaultID)
        try await Self.syncAll([owner, member])
        let second = try await household.secondDevice(of: member)
        try await second.session.sync()
        let currentKey = try await owner.session.sharedVaultStatus(vaultID).membership.vaultKeyID

        // Shown, and shown as shared and not available here; never as one of the account's own.
        let listed = try #require(try await second.session.vaults().first { $0.id == vaultID })
        #expect(listed.isSharedUnavailable)

        // No write, no rename, no deletion of an item or of the vault, no second chain.
        var draft = Self.bank(in: vaultID)
        draft.title = "Written without a ledger"
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) { try await second.session.save(draft) }
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await second.session.renameVault(id: vaultID, to: "Mine")
        }
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await second.session.shareVault(vaultID)
        }
        let count = try await second.session.itemCount(in: vaultID)
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await second.session.deleteVault(id: vaultID, confirmingItemCount: count)
        }
        // Nothing of this device's reaches the vault's log: no segment, no snapshot, nothing collected.
        let before = Set(await household.transport.list(prefix: "vault/\(vaultID.uuidString)/"))
        let report = try await second.session.syncAll()
        #expect(report.vaults[vaultID]?.segmentsWritten == 0 && report.vaults[vaultID]?.snapshotsWritten == 0)
        #expect(Set(await household.transport.list(prefix: "vault/\(vaultID.uuidString)/")) == before)
        #expect(try await owner.session.items(in: vaultID).items.count == 1)

        // The remedy S35 names: this device accepts the invitation itself, comparing the owner's number.
        try await second.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await second.session.sync()
        #expect(try await second.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == false)
        let saved = try await second.session.save(draft)
        #expect(
            try await second.vault.store.record(RecordKey(recordID: saved.id, kind: .item))?.keyID == currentKey,
            "sealed under a key the chain does not name as current")
        try await Self.syncAll([second, owner, member])
        #expect(try await owner.session.item(id: saved.id).title == "Written without a ledger")
        #expect(try await owner.session.sharedVaultStatus(vaultID).heldAside == 0)
        // And it reads what the others wrote, which it refused while it held no ledger.
        #expect(try await second.session.item(id: bank.id).title == bank.title)
    }

    /// Threat: someone with the device's files (A8) deletes the saved ledger, or the owner's pin, from the sharing
    /// state of a read-only member's only device; or the file is lost in a restore. "A planted file can delete trust
    /// and never add it" must mean the vault closes, not that the role check, the chain's key and the judge go with
    /// the ledger.
    @Test(
        "a shared vault whose saved ledger or owner's pin is gone is held closed, not run as a private vault",
        arguments: ["ledger", "owner", "pin"])
    func deletedSharingState(_ deleted: String) async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readOnly], seed: 830)
        let (owner, reader) = (home.owner, home.members[0])
        let vaultID = home.vaultID
        _ = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, reader])
        await #expect(throws: SharedVaultError.writeRefused(.readOnly)) {
            try await reader.session.save(Self.bank(in: vaultID))
        }

        await reader.session.lock()
        switch deleted {
        case "ledger": await reader.state.tamper(.ledger, vaultID: vaultID, value: nil)
        case "owner": await reader.state.tamper(.owner, vaultID: vaultID, value: nil)
        default: await reader.contacts.removePin(for: owner.accountID)
        }
        let relaunched = reader.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: reader.state, contacts: reader.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)

        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await relaunched.session.save(Self.bank(in: vaultID))
        }
        #expect(try await relaunched.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)
        let before = Set(await household.transport.list(prefix: "vault/\(vaultID.uuidString)/"))
        try await relaunched.session.sync()
        #expect(Set(await household.transport.list(prefix: "vault/\(vaultID.uuidString)/")) == before)
        let count = try await relaunched.session.itemCount(in: vaultID)
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await relaunched.session.deleteVault(id: vaultID, confirmingItemCount: count)
        }
    }

    /// Threat: none needed. The owner shares a vault from one device; the account's other device holds the vault's
    /// key already and no ledger. It must learn that the vault is shared from something the account signed (the
    /// marker beside the vault's directory entry), hold the vault closed, offer no second "Share", and be able to
    /// join the chain as the owner's device.
    @Test("the owner's other device learns a vault was shared, holds it closed, and joins its own chain")
    func ownerSecondDeviceWithoutLedger() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 850)
        let vaultID = try await owner.session.createVault(name: "Household").id
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await owner.session.sync()
        let second = try await household.secondDevice(of: owner)
        #expect(try await second.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == false)

        let member = try await household.account(seed: 851)
        try await owner.session.shareVault(vaultID)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, member, second])

        #expect(try await second.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await second.session.shareVault(vaultID)
        }
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await second.session.setArchived(true, id: bank.id)
        }
        let count = try await second.session.itemCount(in: vaultID)
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await second.session.deleteVault(id: vaultID, confirmingItemCount: count)
        }

        // Its own account is the owner: no fingerprint to compare, and the key is the one the account's directory
        // gave it.
        let invitation = try #require(try await second.session.sharedVaultInvitation(vaultID))
        #expect(invitation.ownerAccountID == owner.accountID)
        try await second.session.acceptInvitation(invitation)
        try await second.session.sync()
        #expect(try await second.session.sharedVaultStatus(vaultID).role == .owner)
        try await second.session.setArchived(true, id: bank.id)
        try await Self.syncAll([second, owner, member])
        #expect(try await member.session.item(id: bank.id).archived)
        #expect(try await member.session.sharedVaultStatus(vaultID).heldAside == 0)
    }

    /// Threat: an invitation to a vault this account's other device shared or joined must still be refused when it
    /// names another owner (S6): the marker gives the owner the account vouched for.
    @Test("a second device refuses an invitation naming another owner for a vault its account already holds")
    func secondDeviceRefusesAnotherOwner() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 870)
        let second = try await household.secondDevice(of: home.members[0])
        let stranger = try await household.account(seed: 871)
        await #expect(throws: SharingError.vaultOwnerConflict(vaultID: home.vaultID)) {
            try await second.session.acceptInvitation(
                Invitation(vaultID: home.vaultID, ownerAccountID: stranger.accountID),
                ownerEvidence: .safetyNumber(stranger.safetyNumber))
        }
    }

    /// Threat: the store (A1) serves a member's other device the vault's keys from the account's vault directory and
    /// withholds the marker beside them. The key itself says where it came from: its wrap under the account's keyset
    /// is of the class a grant gives, which the store cannot change, so the vault is held closed all the same.
    @Test("a store that withholds the marker and serves the key does not open a member's shared vault")
    func markerWithheld() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 880)
        let member = try await household.account(seed: 881)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let view = WithholdingTransport(base: household.transport)
        await view.withholdNew(
            under: AccountObjectLocation.vaultsPrefix(member.accountID) + "\(vaultID.uuidString)/shared/")
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, member])
        #expect(
            await household.transport.list(
                prefix: AccountObjectLocation.vaultsPrefix(member.accountID) + "\(vaultID.uuidString)/shared/"
            ).count == 1, "the member's device publishes its marker")

        let second = try await member.enrolledDevice(over: view, directory: household.directory)
        try await second.session.sync()
        #expect(try await second.session.sharedVaultInvitation(vaultID) == nil, "the marker reached it after all")
        #expect(try await second.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await second.session.save(Self.bank(in: vaultID))
        }
    }

    /// Threat: someone with the device's files (A8) on the owner's other device, whose key for the vault is the
    /// account's own and says nothing: they delete the marker's row, or plant one for a vault that is not shared.
    /// A planted row carries no signature of the account's and marks nothing. A deleted one is fetched again by the
    /// next sync, before any vault's log is touched, so nothing the device wrote in between is published.
    @Test(
        "a marker row deleted from the file is restored by the next sync before anything is published; a planted one marks nothing"
    )
    func markerRowEdited() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 890)
        let shared = try await owner.session.createVault(name: "Household").id
        let own = try await owner.session.createVault(name: "Mine").id
        try await owner.session.shareVault(shared)
        try await owner.session.sync()
        let second = try await household.secondDevice(of: owner)
        #expect(try await second.session.vaults().first { $0.id == shared }?.isSharedUnavailable == true)

        // The files: the shared vault's marker gone, and a marker planted for the vault that is the account's own.
        await second.session.lock()
        let rows = try await second.vault.store.records(in: owner.accountID, kind: .vaultDirectory)
        let marker = try #require(rows.first { $0.envelope.first == 0x03 })
        try await second.vault.store.commit(StoreChange(deletions: [marker.key]))
        var planted = marker
        planted.recordID = UUID()
        planted.envelope = [0x03] + Array(repeating: 0x41, count: marker.envelope.count - 1)
        try await second.vault.store.commit(StoreChange(upserts: [planted]))

        let relaunched = second.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: second.state, contacts: second.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(try await relaunched.session.vaults().first { $0.id == own }?.isSharedUnavailable == false)
        _ = try await relaunched.session.save(Self.bank(in: own))

        // Written while the marker was gone: this device's own, in a vault it took for private. The sync that
        // follows restores the marker first, and publishes none of it.
        let written = try await relaunched.session.save(Self.bank(in: shared))
        let before = Set(await household.transport.list(prefix: "vault/\(shared.uuidString)/"))
        try await relaunched.session.sync()
        #expect(Set(await household.transport.list(prefix: "vault/\(shared.uuidString)/")) == before)
        #expect(try await relaunched.session.vaults().first { $0.id == shared }?.isSharedUnavailable == true)
        await #expect(throws: SharedVaultError.ledgerUnavailable(shared)) {
            try await relaunched.session.setArchived(true, id: written.id)
        }
    }

    /// Threat: none; a store error. The sharing state cannot be read when the vault is first used after unlock. That
    /// is not an answer to "is this vault shared?": the vault is held closed, and opens when the state reads again.
    @Test("a sharing state that cannot be read at unlock closes shared vaults until it can")
    func unreadableSharingState() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readOnly], seed: 900)
        let reader = home.members[0]
        await reader.session.lock()
        let flaky = FlakySharingState(base: reader.state)
        let relaunched = reader.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: flaky, contacts: reader.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)

        await flaky.fail(true)
        await #expect(throws: SharedVaultError.ledgerUnavailable(home.vaultID)) {
            try await relaunched.session.save(Self.bank(in: home.vaultID))
        }
        await flaky.fail(false)
        // The ledger loads now, and says what it always said: this account reads and does not write.
        await #expect(throws: SharedVaultError.writeRefused(.readOnly)) {
            try await relaunched.session.save(Self.bank(in: home.vaultID))
        }
        #expect(try await relaunched.session.sharedVaultStatus(home.vaultID).role == .readOnly)
    }
}

/// A sharing state store whose reads can be made to fail, as a database that is busy or damaged does.
actor FlakySharingState: SharingStateStore {
    struct Unavailable: Error {}
    let base: InMemorySharingStateStore
    private var failing = false

    init(base: InMemorySharingStateStore) {
        self.base = base
    }

    func fail(_ failing: Bool) {
        self.failing = failing
    }

    func sharedVaultIDs() async throws -> [UUID] {
        if failing { throw Unavailable() }
        return await base.sharedVaultIDs()
    }

    func value(_ key: SharingStateKey, vaultID: UUID) async throws -> [UInt8]? {
        if failing { throw Unavailable() }
        return await base.value(key, vaultID: vaultID)
    }

    func setValue(_ value: [UInt8]?, for key: SharingStateKey, vaultID: UUID) async throws {
        if failing { throw Unavailable() }
        await base.setValue(value, for: key, vaultID: vaultID)
    }
}
