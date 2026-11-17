import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// Review finding Z48 (docs/06-adversarial-review.md): the way out of "shared, with no ledger here" reopened S6.
extension AdversarialSharedVaultTests {
    /// A chain for `vaultID` signed by `impostor` as its owner, naming a key of the impostor's choosing under
    /// `keyID`, with `member` added under their real keys; filed on the transport. With `granting`, also a grant of
    /// that key to the member.
    static func plantChain(
        for vaultID: UUID, ownedBy impostor: Keyset, keyID: UUID? = nil, adding member: SharingAccount,
        granting: Bool, on transport: InMemorySyncTransport
    ) async throws {
        var generator = SeededGenerator(seed: 4801)
        var vaultKey = VaultKey.generate(vaultID: vaultID, using: &generator)
        if let keyID {
            vaultKey = VaultKey(vaultID: vaultID, key: try EncryptionKey(keyID: keyID, material: vaultKey.key.material))
        }
        let genesis = try MembershipLedger.create(vaultKey: vaultKey, owner: impostor)
        let contacts = VerifiedContacts(
            store: InMemoryVerifiedContactStore(), account: try impostor.publicKeyBundle())
        let victim = try await contacts.verify(
            member.bundle, evidence: .safetyNumber(member.safetyNumber), signedBy: impostor, at: Date())
        let addition = try genesis.proposeAddition(of: victim, as: .readWrite, signedBy: impostor)
        for object in [SharingObject(genesis.chain[0].record), SharingObject(addition)] {
            await transport.tamper(object.name, contents: object.contents)
        }
        guard granting else { return }
        let grant = try KeyGrantCodec.encode(VaultKeyGrant.seal(vaultKey, to: member.bundle, from: impostor))
        await transport.tamper(
            SharingObjectLocation.grantPrefix(vaultID: vaultID, keyID: vaultKey.key.keyID, recipient: member.accountID)
                + SharingObjectLocation.digest(of: grant).map { String(format: "%02x", $0) }.joined(),
            contents: grant)
    }

    /// Threat: the store (A1) with someone the victim has reason to verify (a former member, A5). A member's other
    /// device holds the vault's keys, which arrived by grant, and the store withholds the account's marker from it,
    /// so the device cannot name the vault's owner. The other party signs a chain of their own for the same vault ID,
    /// with the victim added under their real keys and a grant of a key of the other party's making, and sends an
    /// invitation naming themselves as owner; the person compares their safety number honestly. Accepted, the device
    /// would run the vault under that chain, seal everything it holds and writes under their key, and sign a marker
    /// naming them for the account's other devices: what S6 exists to prevent. A vault whose keys came by grant has
    /// an owner; a device that cannot name them accepts no invitation for it. Withholding the marker is then denial
    /// of service and nothing more.
    @Test("a second device that cannot name a shared vault's owner accepts no invitation for it, whoever it names")
    func invitationForAVaultWhoseOwnerIsUnknown() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 4810)
        let member = try await household.account(seed: 4811)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let view = WithholdingTransport(base: household.transport)
        let markers = AccountObjectLocation.vaultsPrefix(member.accountID) + "\(vaultID.uuidString)/shared/"
        await view.withholdNew(under: markers)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        _ = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member])
        let second = try await member.enrolledDevice(over: view, directory: household.directory)
        try await second.session.sync()
        #expect(try await second.session.sharedVaultInvitation(vaultID) == nil, "the marker reached it after all")

        let impostor = Self.forgedKeyset(for: UUID(), seed: 4812)
        await household.directory.publish(try impostor.publicKeyBundle())
        try await Self.plantChain(
            for: vaultID, ownedBy: impostor, adding: member, granting: true, on: household.transport)
        let invitation = Invitation(vaultID: vaultID, ownerAccountID: impostor.accountID)
        let evidence = VerificationEvidence.safetyNumber(try impostor.publicKeyBundle().fingerprint.safetyNumber)

        await #expect(throws: SharedVaultError.ownerUnknown(vaultID)) {
            try await second.session.acceptInvitation(invitation, ownerEvidence: evidence)
        }
        #expect(try await second.session.sharedVaultIDs().isEmpty, "the vault is run under the other party's chain")
        #expect(try await second.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)
        #expect(await household.transport.list(prefix: markers).count == 1, "a marker naming them was published")
        // The real owner's invitation is refused too: this device cannot tell which is right. It waits for the marker.
        await #expect(throws: SharedVaultError.ownerUnknown(vaultID)) {
            try await second.session.acceptInvitation(
                Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
                ownerEvidence: .safetyNumber(owner.safetyNumber))
        }
        await view.reveal()
        try await second.session.sync()
        try await second.session.acceptInvitation(
            try #require(try await second.session.sharedVaultInvitation(vaultID)),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        #expect(try await second.session.sharedVaultStatus(vaultID).membership.owner.accountID == owner.accountID)
    }

    /// Threat: the same two, against the fallback that lets the owner's own other device join with the key its
    /// account's directory gave it when no grant was ever made. It is for an invitation whose owner is this account
    /// and for nothing else: a chain signed by anyone else that names a key ID this device holds (key IDs are public)
    /// and carries no grant must not be joined on the strength of the held key.
    @Test("a held key stands in for a missing grant only for a vault this account owns")
    func heldKeyOnlyForOnesOwnVault() async throws {
        let base = try await SharingHousehold.make()
        let directory = InMemoryKeyBundleDirectory()
        await directory.publish(base.owner.bundle)
        let guest = base.outsider
        var chain = base
        try await chain.add(guest, as: .readWrite, by: base.owner)
        let records = chain.ledger.chain.map(\.encoded)
        let held = [VaultKey(vaultID: base.vaultID, key: base.vaultKey.key, arrivedByGrant: true)]
        let contacts = VerifiedContacts(store: InMemoryVerifiedContactStore(), account: guest.bundle)
        var incoming = try await IncomingInvitation.begin(
            Invitation(vaultID: base.vaultID, ownerAccountID: base.owner.accountID), knownOwner: nil,
            directory: directory, contacts: contacts)
        try await incoming.confirm(
            .safetyNumber(base.owner.bundle.fingerprint.safetyNumber), contacts: contacts, signedBy: guest.keyset,
            at: base.now)
        #expect(throws: SharingError.grantNotFound) {
            _ = try incoming.accept(
                membership: records, grants: [], as: guest.keyset, continuing: nil, holding: held)
        }

        // The owner's own other device: no grant of the first key exists, and the key its directory gave it is the key.
        let own = VerifiedContacts(store: InMemoryVerifiedContactStore(), account: base.owner.bundle)
        var mine = try await IncomingInvitation.begin(
            Invitation(vaultID: base.vaultID, ownerAccountID: base.owner.accountID),
            knownOwner: base.owner.accountID, directory: directory, contacts: own)
        let joined = try mine.accept(
            membership: records, grants: [], as: base.owner.keyset, continuing: nil,
            holding: [VaultKey(vaultID: base.vaultID, key: base.vaultKey.key)])
        #expect(joined.vaultKey.hasSameMaterial(as: base.vaultKey))
    }

    /// Threat: an account whose devices disagree about whose a vault is: one of them signed a marker naming another
    /// owner (it was led into another chain before this fix, or it is a revoked device that kept the account key).
    /// Each device vouches for the marker it holds under its own name, so the directory can hold both. A device with
    /// no ledger for the vault must not take whichever name sorts first: it is offered no invitation and accepts
    /// none, now and after a restart. A device that holds the vault's verified ledger goes on by it.
    @Test("two markers of one account naming different owners close the vault on a device that has no ledger for it")
    func markersThatDisagree() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 4830)
        let (owner, member) = (home.owner, home.members[0])
        let vaultID = home.vaultID
        // A device of the member's account that was never shown a marker, and so vouches for none.
        let view = WithholdingTransport(base: household.transport)
        let markers = AccountObjectLocation.vaultsPrefix(member.accountID) + "\(vaultID.uuidString)/shared/"
        await view.withhold(Set(await household.transport.list(prefix: markers)))
        let rogue = try await member.enrolledDevice(over: view, directory: household.directory)
        let rogueAccount = try #require(try await rogue.vault.store.loadAccount())
        let other = UUID()
        let location = AccountObjectLocation.vaultShared(
            accountID: member.accountID, vaultID: vaultID, author: rogueAccount.deviceID)
        let body = VaultSession.sharedMarkerBody(vaultID: vaultID, owner: other)
        let signature = try await rogue.session.dualSignature(
            VaultSession.directoryMessage(name: location.name, body: body), domain: .vaultDirectory,
            keys: try #require(await rogue.session.keys), account: rogueAccount)

        // An honest second device, told by the first device's marker whose the vault is.
        let second = try await household.secondDevice(of: member)
        #expect(try await second.session.sharedVaultInvitation(vaultID)?.ownerAccountID == owner.accountID)

        await household.transport.tamper(
            location.name, contents: SignedObject(signature: signature, envelope: body).serialized())
        try await second.session.sync()
        #expect(try await second.session.sharedVaultInvitation(vaultID) == nil, "an owner was still offered")
        await #expect(throws: SharingError.vaultOwnerConflict(vaultID: vaultID)) {
            try await second.session.acceptInvitation(
                Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
                ownerEvidence: .safetyNumber(owner.safetyNumber))
        }
        #expect(try await second.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == true)

        // Kept across a restart, with the transport no longer showing the second marker.
        await household.transport.tamper(location.name, contents: nil)
        await second.session.lock()
        let relaunched = second.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: second.state, contacts: second.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(try await relaunched.session.sharedVaultInvitation(vaultID) == nil)

        // The member's first device holds the ledger it verified, and goes on by it.
        try await member.session.sync()
        _ = try await member.session.save(Self.bank(in: vaultID))
        #expect(try await member.session.sharedVaultStatus(vaultID).membership.owner.accountID == owner.accountID)
    }
}
