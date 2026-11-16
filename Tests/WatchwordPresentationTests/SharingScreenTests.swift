import Foundation
import Testing
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
