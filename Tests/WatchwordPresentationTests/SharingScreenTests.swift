import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordPresentation
import WatchwordSharing
import WatchwordTestSupport

@Suite("Screen models: sharing")
@MainActor
struct SharingScreenTests {
    @Test("an owner shares a vault and invites a verified contact, who accepts after comparing the owner's number")
    func inviteAndAccept() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 501)
        let invitee = try await household.account(seed: 502)
        let vaultID = try await owner.session.createVault(name: "Household").id

        let shared = SharedVaultModel(vaultID: vaultID, context: ContextProbe().context(owner.session))
        await shared.load()
        #expect(shared.sharingAvailable && !shared.isShared)
        await shared.share()
        #expect(shared.isShared)
        #expect(shared.members.map(\.trust) == [.you])
        #expect(shared.ownRole == .owner && shared.mayInvite && !shared.mayLeave)
        #expect(shared.fingerprint?.safetyNumber == owner.safetyNumber)

        // The owner names the invitee, compares their safety number and invites them.
        let invitation = InvitationModel(vaultID: vaultID, context: ContextProbe().context(owner.session))
        invitation.accountText = invitee.accountID.uuidString
        await invitation.lookUp()
        guard case .compareFingerprint(let contact) = invitation.step else {
            Issue.record("expected the fingerprint step, got \(invitation.step)")
            return
        }
        #expect(contact.safetyNumber == invitee.safetyNumber && !contact.isVerified)
        await invitation.confirmFingerprint()
        #expect(invitation.errorMessage != nil, "no evidence, no verification")
        invitation.confirmation.typedSafetyNumber = "00000 " + invitee.safetyNumber.dropFirst(6)
        await invitation.confirmFingerprint()
        #expect(invitation.errorMessage?.contains("does not match") == true)
        invitation.confirmation.typedSafetyNumber = invitee.safetyNumber
        await invitation.confirmFingerprint()
        guard case .chooseRole = invitation.step else {
            Issue.record("expected the role step, got \(invitation.step)")
            return
        }
        invitation.role = .readWrite
        await invitation.invite()
        guard case .issued(let code) = invitation.step else {
            Issue.record("expected an invitation, got \(invitation.step) \(invitation.errorMessage ?? "")")
            return
        }

        // The invitee reads the code, compares the owner's number by eye and joins.
        let accept = AcceptInvitationModel(context: ContextProbe().context(invitee.session))
        accept.codeText = code
        await accept.read()
        guard case .compareOwner(let ownerContact) = accept.step else {
            Issue.record("expected the owner's fingerprint, got \(accept.step)")
            return
        }
        #expect(ownerContact.accountID == owner.accountID)
        await accept.accept()
        #expect(accept.errorMessage != nil, "no evidence, no joining")
        accept.confirmation.comparedByEye = true
        await accept.accept()
        #expect(accept.step == .joined(vaultID: vaultID), "\(accept.errorMessage ?? "")")

        try await owner.session.sync()
        await shared.load()
        #expect(shared.members.count == 2)
        let member = try #require(shared.members.first { $0.trust != .you })
        #expect(member.role == .readWrite && member.trust == .verified)
        #expect(shared.roles(assignableTo: member) == [.administrator, .readOnly])
        #expect(shared.mayRemove(member))

        let joined = VaultsModel(context: ContextProbe().context(invitee.session))
        await joined.load()
        let row = try #require(joined.row(vaultID))
        #expect(row.name == "Household" && row.sharing?.role == .readWrite && !row.isReadOnly)
    }

    @Test("a member made read-only sees the vault as read-only, and the key is rotated after the demotion (S42)")
    func demotion() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 520)
        let owner = SharedVaultModel(vaultID: home.vaultID, context: ContextProbe().context(home.owner.session))
        await owner.load()
        let member = try #require(owner.members.first { $0.trust != .you })
        let keyBefore = try await home.owner.session.sharedVaultStatus(home.vaultID).membership.vaultKeyID
        await owner.changeRole(of: member, to: .readOnly)
        #expect(owner.errorMessage == nil, "\(owner.errorMessage ?? "")")
        #expect(owner.members.first { $0.id == member.id }?.role == .readOnly)
        let keyAfter = try await home.owner.session.sharedVaultStatus(home.vaultID).membership.vaultKeyID
        #expect(keyAfter != keyBefore)

        try await home.members[0].session.sync()
        let view = SharedVaultModel(vaultID: home.vaultID, context: ContextProbe().context(home.members[0].session))
        await view.load()
        #expect(view.isReadOnly && !view.mayInvite && view.mayLeave)
        #expect(view.sharing?.readOnlyReason == ErrorWording.readOnly(.readOnly))
        #expect(view.roles(assignableTo: try #require(view.members.first { $0.role == .owner })).isEmpty)
    }

    @Test("a member asks to leave; the owner sees the request as pending rotation until it is carried out")
    func leave() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 540)
        let member = SharedVaultModel(vaultID: home.vaultID, context: ContextProbe().context(home.members[0].session))
        await member.load()
        await member.leave()
        #expect(member.errorMessage == nil, "\(member.errorMessage ?? "")")
        #expect(member.notice?.contains("asked to leave") == true)

        let owner = SharedVaultModel(vaultID: home.vaultID, context: ContextProbe().context(home.owner.session))
        await owner.load()
        #expect(owner.pending.contains { $0.contains("asked to leave") })
    }

    @Test("an invitation code that is not one is refused before anything is looked up")
    func badCode() async throws {
        let household = SharedVaultHousehold()
        let invitee = try await household.account(seed: 560)
        let accept = AcceptInvitationModel(context: ContextProbe().context(invitee.session))
        accept.codeText = "WWIV please let me in"
        await accept.read()
        #expect(accept.step == .enterCode)
        #expect(accept.errorMessage?.contains("not a Watchword invitation") == true)
    }

    @Test("the Personal vault cannot be shared, and the refusal is worded")
    func personalVault() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 580)
        let personal = try #require(await owner.session.personalVaultID)
        let model = SharedVaultModel(vaultID: personal, context: ContextProbe().context(owner.session))
        await model.share()
        #expect(model.errorMessage?.contains("never shared") == true)
    }
}

@Suite("Screen models: member trust")
struct MemberTrustTests {
    static let me = UUID()
    static let owner = UUID()
    static let other = UUID()
    static let members: [(accountID: UUID, role: MemberRole)] = [
        (owner, .owner), (me, .readWrite), (other, .readWrite),
    ]

    @Test("a member is shown as verified only when the comparison on the current head says so (D17)")
    func verifiedOnlyFromTheCheck() {
        let rows = SharedVaultModel.rows(
            members: Self.members, substituted: [], unverified: [], verified: nil, me: Self.me)
        #expect(rows.first { $0.id == Self.me }?.trust == .you)
        #expect(rows.filter { $0.id != Self.me }.allSatisfy { $0.trust == .notChecked })
        #expect(rows.first { $0.id == Self.other }?.trustText == "Not checked yet")
    }

    @Test("a member in none of the check's lists is not verified either")
    func unlistedIsNotVerified() {
        let rows = SharedVaultModel.rows(
            members: Self.members, substituted: [Self.other], unverified: [], verified: [], me: Self.me)
        #expect(rows.first { $0.id == Self.other }?.trust == .keysChanged)
        #expect(rows.first { $0.id == Self.owner }?.trust == .notChecked)
    }

    @Test("verified, unverified and changed keys come from the check's lists")
    func fromTheLists() {
        let rows = SharedVaultModel.rows(
            members: Self.members, substituted: [], unverified: [Self.other], verified: [Self.owner], me: Self.me)
        #expect(rows.first { $0.id == Self.owner }?.trust == .verified)
        #expect(rows.first { $0.id == Self.other }?.trust == .unverified)
    }
}

extension SharingScreenTests {
    /// The member list after a relaunch: the substituted member's warning survives and the owner, compared, is
    /// verified (review finding D17, SEC3).
    @Test("after a relaunch the member list still warns of changed keys")
    func memberListAfterRelaunch() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 621)
        let viewer = try await household.account(seed: 622)
        let target = try await household.account(seed: 623)
        let forged = try Keyset.generate(accountID: target.accountID).publicKeyBundle()
        await household.directory.tamper(target.accountID, contents: KeyBundleCodec.encode(forged))
        try await viewer.session.verifyContact(
            target.accountID, evidence: .safetyNumber(forged.fingerprint.safetyNumber))
        await household.directory.publish(target.bundle)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(viewer, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(target, to: vaultID, as: .readWrite, owner: owner)
        for account in [owner, viewer, target, owner, viewer] { try await account.session.sync() }

        let relaunched = viewer.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: viewer.state, contacts: viewer.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        let model = SharedVaultModel(vaultID: vaultID, context: ContextProbe().context(relaunched.session))
        await model.load()
        #expect(model.members.first { $0.id == target.accountID }?.trust == .keysChanged)
        #expect(model.members.first { $0.id == owner.accountID }?.trust == .verified)
    }
}

extension SharingScreenTests {
    /// A fingerprint code pasted from a message names an account; it is no comparison. Whoever can message the person
    /// can send a code for an account of their own, so the safety number must still be typed or the comparison
    /// confirmed, and a pin records how it was made, never as a scanned code.
    @Test("a pasted fingerprint code identifies the account but verifies nothing")
    func pastedCodeIsNotEvidence() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 631)
        let stranger = try await household.account(seed: 632)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let invitation = InvitationModel(vaultID: vaultID, context: ContextProbe().context(owner.session))
        invitation.accountText = OwnFingerprint(stranger.bundle).code
        await invitation.lookUp()
        guard case .compareFingerprint(let contact) = invitation.step else {
            Issue.record("a pasted code skipped the comparison: \(invitation.step)")
            return
        }
        #expect(contact.accountID == stranger.accountID && invitation.usesFingerprintCode)
        await invitation.confirmFingerprint()
        #expect(invitation.errorMessage != nil, "the code alone was taken as a comparison")
        let pins = VerifiedContacts(store: owner.contacts, account: owner.bundle)
        #expect(try await pins.pinned(stranger.accountID) == nil)

        invitation.confirmation.comparedByEye = true
        await invitation.confirmFingerprint()
        #expect(try await pins.pinned(stranger.accountID)?.method == .comparedByEye)
        guard case .chooseRole(let chosen) = invitation.step else {
            Issue.record("expected the role step, got \(invitation.step)")
            return
        }
        #expect(chosen.accountID == stranger.accountID)
        #expect(invitation.inviteeName.contains(shortIdentifier(stranger.accountID)))
        #expect(invitation.verificationText == "You confirmed that the two safety numbers match.")
    }
}

extension SharingScreenTests {
    /// A member who may write renames the shared vault "Personal" (A4, an editing member): every list must still tell
    /// it from the account's own Personal vault, by ownership and role rather than by name.
    @Test("a shared vault renamed Personal is labelled apart from the real Personal vault")
    func sharedVaultNamedPersonal() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 641)
        let member = home.members[0]
        _ = try await member.session.renameVault(id: home.vaultID, to: "Personal")
        try await member.session.sync()
        try await home.owner.session.sync()
        let model = VaultsModel(context: ContextProbe().context(member.session))
        await model.load()
        let named = model.rows.filter { $0.name == "Personal" }
        #expect(named.count == 2)
        let real = try #require(named.first { $0.isPersonal })
        let shared = try #require(named.first { !$0.isPersonal })
        #expect(real.label != shared.label)
        #expect(real.badge == "Your own vault")
        #expect(shared.badge == "Shared with you · Can edit")
        #expect(shared.label == "Personal (Shared with you · Can edit)")

        let owners = VaultsModel(context: ContextProbe().context(home.owner.session))
        await owners.load()
        #expect(owners.row(home.vaultID)?.badge == "Shared by you")
    }
}

extension SharingScreenTests {
    /// An invitation from an owner verified before (for another vault, say) is still a question for the person: it
    /// is offered for confirmation, and nothing is joined until they say yes.
    @Test("an invitation from a verified owner asks before joining")
    func confirmBeforeJoining() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 651)
        let invitee = try await household.account(seed: 652)
        try await invitee.session.verifyContact(owner.accountID, evidence: .safetyNumber(owner.safetyNumber))
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.session.verifyContact(invitee.accountID, evidence: .safetyNumber(invitee.safetyNumber))
        let invitation = try await owner.session.invite(invitee.accountID, to: vaultID, as: .readWrite)

        let accept = AcceptInvitationModel(context: ContextProbe().context(invitee.session))
        accept.codeText = SharingCodes.text(for: invitation)
        await accept.read()
        guard case .confirmJoin(let shown) = accept.step else {
            Issue.record("joined without asking: \(accept.step)")
            return
        }
        #expect(shown.accountID == owner.accountID)
        #expect(try await !invitee.session.vaults().contains { $0.id == vaultID })
        await accept.confirmJoin()
        #expect(accept.step == .joined(vaultID: vaultID), "\(accept.errorMessage ?? "")")
    }
}

extension SharingScreenTests {
    /// A shared vault on a device that holds no ledger for it (the account's other device joined it) is another
    /// account's too, whatever this device knows: it is labelled as shared and not set up, never "Only you", offers no
    /// "Share", and gives the invitation to accept here, with which the ordinary accept screen sets it up (review
    /// finding Z41).
    @Test("a shared vault not set up on this device says so, offers no Share, and is set up by accepting here")
    func notSetUpOnThisDevice() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 560)
        let second = try await household.secondDevice(of: home.members[0])

        let vaults = VaultsModel(context: ContextProbe().context(second.session))
        await vaults.load()
        let row = try #require(vaults.row(home.vaultID))
        #expect(row.badge == VaultRow.notSetUpBadge && row.isShared && row.isReadOnly)
        #expect(row.readOnlyReason == VaultRow.notSetUpReason && row.detail != "Only you")

        let shared = SharedVaultModel(vaultID: home.vaultID, context: ContextProbe().context(second.session))
        await shared.load()
        #expect(shared.needsSetUp && !shared.isShared)
        await shared.share()
        #expect(shared.errorMessage?.contains("not set up on this device") == true)
        let code = try #require(shared.setUpCode)

        let accept = AcceptInvitationModel(context: ContextProbe().context(second.session))
        accept.codeText = code
        await accept.read()
        guard case .compareOwner(let owner) = accept.step else {
            Issue.record("expected the owner's fingerprint, got \(accept.step)")
            return
        }
        #expect(owner.accountID == home.owner.accountID)
        accept.confirmation.typedSafetyNumber = home.owner.safetyNumber
        await accept.accept()
        #expect(accept.step == .joined(vaultID: home.vaultID), "\(accept.errorMessage ?? "")")
        await vaults.load()
        #expect(vaults.row(home.vaultID)?.badge == "Shared with you · Can edit")
        await shared.load()
        #expect(shared.isShared && !shared.needsSetUp && shared.members.count == 2)
    }
}
