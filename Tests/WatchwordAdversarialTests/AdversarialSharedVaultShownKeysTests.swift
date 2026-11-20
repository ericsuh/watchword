import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordPresentation
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

// Review finding Z40 (docs/06-adversarial-review.md): the key directory is asked more than once on the way from "here
// is their safety number" to a pin, and whoever serves it (A1; with a file-based directory any writer of the shared
// folder, so A4 too) may answer differently each time. What is pinned must be what was shown.
extension AdversarialSharedVaultTests {
    /// A second key bundle for `accountID`, self-signed: all the directory's parser asks of one.
    static func forgedKeyset(for accountID: UUID, seed: UInt64) -> Keyset {
        var generator = SeededGenerator(seed: seed)
        return Keyset.generate(accountID: accountID, using: &generator)
    }

    /// Threat: A1 serving the key directory. The inviting person is shown the invitee's real safety number, compares
    /// it with the invitee and says so; the directory then answers the session's next lookup with a bundle of its own
    /// for the same account. The pin must be of the keys compared or of nothing: a pin of the second answer has the
    /// next invitation wrap the vault key to the store. Checked for every kind of evidence, each of which names the
    /// keys it is about.
    @Test("evidence pins the bundle whose number was shown, or nothing, whatever the directory answers next")
    func directoryChangesBeforeThePin() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 701)
        let invitee = try await household.account(seed: 702)
        let contacts = VerifiedContacts(store: owner.contacts, account: owner.bundle)
        let forged = try Self.forgedKeyset(for: invitee.accountID, seed: 7021).publicKeyBundle()

        let shown = try await owner.session.contactCandidate(invitee.accountID)
        #expect(shown.fingerprint == invitee.bundle.fingerprint)
        // No comparison by eye: ADR 0010 removed it (G3), so every kind of evidence left is one the device checks.
        let evidence: [VerificationEvidence] = [
            .safetyNumber(shown.fingerprint.safetyNumber),
            .scannedCode(FingerprintCode(bundle: invitee.bundle).payload),
        ]
        await household.directory.tamper(invitee.accountID, contents: KeyBundleCodec.encode(forged))
        for evidence in evidence {
            await #expect(throws: SharingError.fingerprintMismatch, "\(evidence)") {
                try await owner.session.verifyContact(invitee.accountID, evidence: evidence)
            }
            #expect(try await contacts.pinned(invitee.accountID) == nil, "the directory's second answer was pinned")
        }

        // The honest directory again: the same evidence pins the keys that were compared.
        await household.directory.publish(invitee.bundle)
        let pinned = try await owner.session.verifyContact(
            invitee.accountID, evidence: .safetyNumber(shown.fingerprint.safetyNumber))
        #expect(pinned.bundle.hasSameKeys(as: invitee.bundle) && pinned.method == .safetyNumber)
    }

    /// Threat: A1 again, at the next lookup. The contact is pinned; the directory answers `invite`'s own lookup with
    /// another bundle. Nothing may be wrapped to it: the invitation stops (`keySubstituted`), no grant and no record
    /// naming the invitee reach the transport.
    @Test("an invitation never wraps the vault key to a bundle the directory swapped in after the pin")
    func directoryChangesBeforeTheInvitation() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 711)
        let invitee = try await household.account(seed: 712)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let shown = try await owner.session.contactCandidate(invitee.accountID)
        try await owner.session.verifyContact(
            invitee.accountID, evidence: .safetyNumber(shown.fingerprint.safetyNumber))

        let forged = try Self.forgedKeyset(for: invitee.accountID, seed: 7121).publicKeyBundle()
        await household.directory.tamper(invitee.accountID, contents: KeyBundleCodec.encode(forged))
        await #expect(throws: SharingError.keySubstituted(accountID: invitee.accountID)) {
            try await owner.session.invite(invitee.accountID, to: vaultID, as: .readWrite)
        }
        #expect(await household.transport.list(prefix: SharingObjectLocation.vaultPrefix(vaultID) + "grant/").isEmpty)
        #expect(try await owner.session.sharedVaultStatus(vaultID).membership.members.count == 1)
    }

    /// Threat: A1 serving both the key directory and the vault's objects, on the accepting side. The invitee is shown
    /// the real owner's safety number and confirms it; `acceptInvitation` then looks the owner up again and is given
    /// a bundle of the store's, with a chain that bundle signed listing the invitee's real keys and a grant of a key
    /// the store knows. Anchored on the second answer, everything the invitee saved in that vault would be the
    /// store's to read. The owner pinned must be the one shown, or nobody, and no vault may be held.
    @Test("accepting anchors the chain on the owner whose number was shown, or accepts nothing")
    func directoryChangesBeforeAccepting() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 721)
        let invitee = try await household.account(seed: 722)
        let contacts = VerifiedContacts(store: invitee.contacts, account: invitee.bundle)

        // The store's own "owner": the real owner's account ID with keys of its own, a vault it made up, the invitee
        // added under their real keys, and the vault key wrapped to them.
        let impostor = Self.forgedKeyset(for: owner.accountID, seed: 7211)
        var generator = SeededGenerator(seed: 7212)
        let vaultID = UUID()
        let vaultKey = VaultKey.generate(vaultID: vaultID, using: &generator)
        let genesis = try MembershipLedger.create(vaultKey: vaultKey, owner: impostor)
        let impostorContacts = VerifiedContacts(
            store: InMemoryVerifiedContactStore(), account: try impostor.publicKeyBundle())
        let victim = try await impostorContacts.verify(
            invitee.bundle, evidence: .safetyNumber(invitee.safetyNumber), signedBy: impostor, at: Date())
        let addition = try genesis.proposeAddition(of: victim, as: .readWrite, signedBy: impostor)
        for object in [SharingObject(genesis.chain[0].record), SharingObject(addition)] {
            await household.transport.tamper(object.name, contents: object.contents)
        }
        let grant = try KeyGrantCodec.encode(VaultKeyGrant.seal(vaultKey, to: invitee.bundle, from: impostor))
        await household.transport.tamper(
            SharingObjectLocation.grantPrefix(vaultID: vaultID, keyID: vaultKey.key.keyID, recipient: invitee.accountID)
                + SharingObjectLocation.digest(of: grant).map { String(format: "%02x", $0) }.joined(),
            contents: grant)
        let invitation = Invitation(vaultID: vaultID, ownerAccountID: owner.accountID)

        let shown = try await invitee.session.contactCandidate(owner.accountID)
        #expect(shown.fingerprint == owner.bundle.fingerprint)
        await household.directory.tamper(
            owner.accountID, contents: KeyBundleCodec.encode(try impostor.publicKeyBundle()))
        for evidence in [VerificationEvidence.safetyNumber(shown.fingerprint.safetyNumber)] {
            await #expect(throws: SharingError.fingerprintMismatch, "\(evidence)") {
                try await invitee.session.acceptInvitation(invitation, ownerEvidence: evidence)
            }
            #expect(try await contacts.pinned(owner.accountID) == nil, "the store's bundle was pinned as the owner")
            #expect(try await invitee.session.sharedVaultIDs().isEmpty)
            #expect(try await invitee.session.vaults().allSatisfy { $0.id != vaultID })
        }
    }

    /// Threat: the same, through the screens the person uses (`InvitationModel`, `AcceptInvitationModel`). The toggle
    /// "I compared the two numbers" the finding names is gone (ADR 0010, G3), and the full-code step shows none of the
    /// directory's digits (V17): the person types the sixty digits from the other device, so a directory that changes
    /// its answer after the lookup pins nothing.
    @Test("the screens' full-code fallback pins the keys the other device showed, or nothing")
    @MainActor
    func directoryChangesUnderTheScreens() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 731)
        let invitee = try await household.account(seed: 732)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)

        let inviting = InvitationModel(vaultID: vaultID, context: ScreenContext(session: owner.session))
        inviting.accountText = invitee.accountID.uuidString
        await inviting.lookUp()
        guard case .compareFingerprint(let contact) = inviting.step else {
            Issue.record("expected the fingerprint step, got \(inviting.step)")
            return
        }
        #expect(contact.accountID == invitee.accountID)
        let forged = try Self.forgedKeyset(for: invitee.accountID, seed: 7321).publicKeyBundle()
        await household.directory.tamper(invitee.accountID, contents: KeyBundleCodec.encode(forged))
        inviting.confirmation.typedSafetyNumber = invitee.safetyNumber
        await inviting.confirmFingerprint()
        #expect(inviting.errorMessage != nil)
        #expect(inviting.step == .compareFingerprint(contact), "the step moved on after a refused pin")
        let ownersPins = VerifiedContacts(store: owner.contacts, account: owner.bundle)
        #expect(try await ownersPins.pinned(invitee.accountID) == nil)

        // The accepting screen, with a directory that swaps the owner after showing the real one.
        await household.directory.publish(invitee.bundle)
        try await owner.session.verifyContact(invitee.accountID, evidence: .safetyNumber(invitee.safetyNumber))
        let invitation = try await owner.session.invite(invitee.accountID, to: vaultID, as: .readWrite)
        let accepting = AcceptInvitationModel(context: ScreenContext(session: invitee.session))
        accepting.codeText = SharingCodes.text(for: invitation)
        await accepting.read()
        guard case .compareOwner(let shownOwner) = accepting.step else {
            Issue.record("expected the owner's fingerprint, got \(accepting.step)")
            return
        }
        #expect(shownOwner.accountID == owner.accountID)
        let impostor = try Self.forgedKeyset(for: owner.accountID, seed: 7322).publicKeyBundle()
        await household.directory.tamper(owner.accountID, contents: KeyBundleCodec.encode(impostor))
        accepting.confirmation.typedSafetyNumber = owner.safetyNumber
        await accepting.accept()
        #expect(accepting.errorMessage != nil)
        #expect(accepting.step == .compareOwner(shownOwner))
        let inviteesPins = VerifiedContacts(store: invitee.contacts, account: invitee.bundle)
        #expect(try await inviteesPins.pinned(owner.accountID) == nil)
        #expect(try await invitee.session.sharedVaultIDs().isEmpty)
    }
}
