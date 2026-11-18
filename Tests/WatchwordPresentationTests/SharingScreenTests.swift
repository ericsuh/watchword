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
    @Test("by the full vault sharing code: an owner invites a checked contact, who accepts after typing the owner's")
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

        // The owner names the invitee, types their full code and invites them.
        let invitation = InvitationModel(vaultID: vaultID, context: ContextProbe().context(owner.session))
        #expect(invitation.step == .start)
        await invitation.useFullCode()
        invitation.accountText = invitee.accountID.uuidString
        await invitation.lookUp()
        guard case .compareFingerprint(let comparison) = invitation.step else {
            Issue.record("expected the fingerprint step, got \(invitation.step)")
            return
        }
        #expect(comparison.accountID == invitee.accountID && comparison.own == OwnFingerprint(owner.bundle))
        await invitation.confirmFingerprint()
        #expect(invitation.errorMessage != nil, "no evidence, no verification")
        // The person reads the invitee's own screen (Settings, Vaults, Your Full Vault Sharing Code).
        let inviteeScreen = OwnFingerprint(invitee.bundle).safetyNumber
        invitation.confirmation.typedSafetyNumber = "00000 " + inviteeScreen.dropFirst(6)
        await invitation.confirmFingerprint()
        #expect(invitation.errorMessage?.contains("does not match") == true)
        invitation.confirmation.typedSafetyNumber = inviteeScreen
        await invitation.confirmFingerprint()
        guard case .chooseRole = invitation.step else {
            Issue.record("expected the role step, got \(invitation.step)")
            return
        }
        invitation.role = .readWrite
        await invitation.invite()
        guard case .issued(let code, nil) = invitation.step else {
            Issue.record("expected an invitation, got \(invitation.step) \(invitation.errorMessage ?? "")")
            return
        }

        // The invitee pastes the invitation, types the owner's full code and joins.
        let accept = AcceptInvitationModel(context: ContextProbe().context(invitee.session))
        await accept.useFullCode()
        accept.codeText = try #require(code)
        await accept.read()
        guard case .compareOwner(let ownerComparison) = accept.step else {
            Issue.record("expected the owner's fingerprint, got \(accept.step)")
            return
        }
        #expect(ownerComparison.accountID == owner.accountID && ownerComparison.own == OwnFingerprint(invitee.bundle))
        await accept.accept()
        #expect(accept.errorMessage != nil, "no evidence, no joining")
        accept.confirmation.typedSafetyNumber = OwnFingerprint(owner.bundle).safetyNumber
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

    /// ADR 0010 through the screens: the inviter shows the vault sharing code, the invitee types it, each types the
    /// other's six digits (one wrong first), the invitation arrives inside the session and the invitee joins after
    /// saying yes. Nothing is pasted.
    @Test("an invitation by vault sharing code: eight digits one way, six each way back, and the invitation arrives")
    func inviteBySharingCode() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 571)
        let invitee = try await household.account(seed: 572)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)

        let invitation = InvitationModel(vaultID: vaultID, context: ContextProbe().context(owner.session))
        await invitation.startSession()
        guard case .showCode(let number, let payload) = invitation.step else {
            Issue.record("expected the vault sharing code, got \(invitation.step) \(invitation.errorMessage ?? "")")
            return
        }
        #expect(number.count == 9 && payload.hasPrefix("WWSC1-") && invitation.isWaiting)
        await invitation.refresh()
        #expect(invitation.isWaiting, "nobody answered yet")

        let accept = AcceptInvitationModel(context: ContextProbe().context(invitee.session))
        accept.numberText = number
        await accept.joinWithNumber()
        #expect(accept.step == .waiting, "\(accept.errorMessage ?? "")")
        await invitation.refresh()
        #expect(invitation.step == .typeTheirCode(attemptsLeft: 3))
        await accept.refresh()
        guard case .showCodeAndType(let inviteeCode, _, _) = accept.step else {
            Issue.record("expected the invitee's code, got \(accept.step)")
            return
        }

        // One slip of the finger, then the right code.
        let wrong = inviteeCode.first == "0" ? "1" + inviteeCode.dropFirst() : "0" + inviteeCode.dropFirst()
        invitation.typedCode = String(wrong)
        await invitation.confirmTheirCode()
        #expect(invitation.step == .typeTheirCode(attemptsLeft: 2))
        #expect(invitation.errorMessage?.contains("2 tries left") == true)
        invitation.typedCode = inviteeCode
        await invitation.confirmTheirCode()
        guard case .chooseRole(let ownerCode?, let contact) = invitation.step else {
            Issue.record("expected the role step with the owner's code, got \(invitation.step)")
            return
        }
        #expect(contact.accountID == invitee.accountID && contact.isVerified)
        #expect(invitation.verificationText == "Their confirmation code matched.")

        // Send before the invitee has typed this device's code (V26): the code stays on the screen, since their
        // device opens the invitation only once it has checked it.
        invitation.role = .readOnly
        await invitation.invite()
        #expect(invitation.step == .issued(code: nil, confirmation: ownerCode), "\(invitation.errorMessage ?? "")")
        await accept.refresh()
        #expect(accept.errorMessage == nil && !accept.isWaiting, "nothing to look for before the code is typed")

        accept.typedCode = ownerCode
        await accept.confirmTheirCode()
        guard case .awaitingInvitation = accept.step else {
            Issue.record("expected to wait for the invitation, got \(accept.step) \(accept.errorMessage ?? "")")
            return
        }
        await accept.refresh()
        guard case .confirmJoin(let shown) = accept.step else {
            Issue.record("expected to be asked, got \(accept.step) \(accept.errorMessage ?? "")")
            return
        }
        #expect(shown.accountID == owner.accountID)
        // A timer that fires once more after the step moved on changes nothing: before, it asked the session again
        // and took the screen back to waiting, so the Join button came and went (the first Mac run's UI tests).
        #expect(!accept.isWaiting && !invitation.isWaiting)
        await accept.refresh()
        #expect(accept.step == .confirmJoin(shown) && accept.errorMessage == nil)
        await invitee.session.endSharingCodeSession()
        await accept.refresh()
        #expect(accept.step == .confirmJoin(shown) && accept.errorMessage == nil, "\(accept.errorMessage ?? "")")
        await accept.confirmJoin()
        #expect(accept.step == .joined(vaultID: vaultID), "\(accept.errorMessage ?? "")")
        #expect(try await invitee.session.sharedVaultStatus(vaultID).role == .readOnly)
        let pins = VerifiedContacts(store: owner.contacts, account: owner.bundle)
        #expect(try await pins.pinned(invitee.accountID)?.method == .sharingCode)
    }

    /// The screen of a member trusted through the chain only: a session with them makes them verified on this
    /// device, and one another account answers is ended before anything is pinned.
    @Test("checking a member by vault sharing code makes them verified, and only they may answer")
    func memberVerification() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.administrator, .readWrite], seed: 581)
        let (administrator, member) = (home.members[0], home.members[1])
        try await administrator.session.sync()
        let before = try await administrator.session.sharedVaultStatus(home.vaultID)
        #expect(before.unverifiedMembers.contains(member.accountID))

        let stranger = try await household.account(seed: 589)
        let wrongPerson = MemberVerificationModel(
            vaultID: home.vaultID, memberID: member.accountID, context: ContextProbe().context(administrator.session))
        await wrongPerson.startSession()
        guard case .showCode(let number, _) = wrongPerson.step else {
            Issue.record("expected the code, got \(wrongPerson.step)")
            return
        }
        _ = try await stranger.session.joinSharingCodeSession(number: number)
        await wrongPerson.refresh()
        guard case .failed(let message) = wrongPerson.step else {
            Issue.record("another account's answer went on: \(wrongPerson.step)")
            return
        }
        #expect(message.contains("Another account"))
        let pins = VerifiedContacts(store: administrator.contacts, account: administrator.bundle)
        #expect(try await pins.pinned(stranger.accountID) == nil)

        let check = MemberVerificationModel(
            vaultID: home.vaultID, memberID: member.accountID, context: ContextProbe().context(administrator.session))
        await check.startSession()
        guard case .showCode(let second, _) = check.step else {
            Issue.record("expected the code, got \(check.step)")
            return
        }
        _ = try await member.session.joinSharingCodeSession(number: second)
        await check.refresh()
        let shown = try await member.session.refreshSharingCodeSession()
        check.typedCode = try #require(shown.ownCode)
        await check.confirmTheirCode()
        guard case .verified(let code?) = check.step else {
            Issue.record("expected verified, got \(check.step) \(check.errorMessage ?? "")")
            return
        }
        _ = try await member.session.enterSharingCode(code)
        let after = try await administrator.session.sharedVaultStatus(home.vaultID)
        #expect(after.verifiedMembers?.contains(member.accountID) == true)
        #expect(!after.unverifiedMembers.contains(member.accountID))
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
        await accept.useFullCode()
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
    /// can send a code for an account of their own, so the full code must still be typed, and a pin records how it was
    /// made, never as a scanned code.
    @Test("a pasted fingerprint code identifies the account but verifies nothing")
    func pastedCodeIsNotEvidence() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 631)
        let stranger = try await household.account(seed: 632)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let invitation = InvitationModel(vaultID: vaultID, context: ContextProbe().context(owner.session))
        await invitation.useFullCode()
        invitation.accountText = OwnFingerprint(stranger.bundle).code
        await invitation.lookUp()
        guard case .compareFingerprint(let comparison) = invitation.step else {
            Issue.record("a pasted code skipped the comparison: \(invitation.step)")
            return
        }
        #expect(comparison.accountID == stranger.accountID && invitation.usesFingerprintCode)
        await invitation.confirmFingerprint()
        #expect(invitation.errorMessage != nil, "the code alone was taken as a comparison")
        let pins = VerifiedContacts(store: owner.contacts, account: owner.bundle)
        #expect(try await pins.pinned(stranger.accountID) == nil)

        invitation.confirmation.typedSafetyNumber = stranger.safetyNumber
        await invitation.confirmFingerprint()
        #expect(try await pins.pinned(stranger.accountID)?.method == .safetyNumber)
        guard case .chooseRole(_, let chosen) = invitation.step else {
            Issue.record("expected the role step, got \(invitation.step)")
            return
        }
        #expect(chosen.accountID == stranger.accountID)
        #expect(invitation.inviteeName.contains(shortIdentifier(stranger.accountID)))
        #expect(invitation.verificationText == "You typed their full vault sharing code, and it matched.")
    }
}

extension SharingScreenTests {
    /// An administrator renames the shared vault "Personal" (A4 with the role; nobody else may name it): every list
    /// must still tell it from the account's own Personal vault, by ownership and role rather than by name.
    @Test("a shared vault renamed Personal is labelled apart from the real Personal vault")
    func sharedVaultNamedPersonal() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.administrator], seed: 641)
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
        #expect(shared.badge == "Shared with you · Administrator")
        #expect(shared.label == "Personal (Shared with you · Administrator)")

        let owners = VaultsModel(context: ContextProbe().context(home.owner.session))
        await owners.load()
        #expect(owners.row(home.vaultID)?.badge == "Shared by you")
    }
}

extension SharingScreenTests {
    /// Only a shared vault's owner or an administrator may rename it (docs/02-architecture.md §8.7): the vault list
    /// says who may, from the session's answer, and words the session's refusal for everyone else.
    @Test("the vault list says who may rename a shared vault, and words the refusal for a member")
    func whoMayRename() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.administrator, .readWrite, .readOnly], seed: 661)
        let (administrator, writer, reader) = (home.members[0], home.members[1], home.members[2])

        let owners = VaultsModel(context: ContextProbe().context(home.owner.session))
        await owners.load()
        #expect(owners.row(home.vaultID)?.mayRename == true)
        #expect(owners.row(home.vaultID)?.renameRefusal == nil)
        let administrators = VaultsModel(context: ContextProbe().context(administrator.session))
        await administrators.load()
        #expect(administrators.row(home.vaultID)?.mayRename == true)

        // A member who may edit items: told why not, and the session refuses if asked anyway.
        let own = try await writer.session.createVault(name: "Garden").id
        let writers = VaultsModel(context: ContextProbe().context(writer.session))
        await writers.load()
        let shared = try #require(writers.row(home.vaultID))
        #expect(!shared.mayRename && !shared.isReadOnly)
        #expect(shared.renameRefusal == ErrorWording.renameRefused)
        #expect(shared.renameRefusal == "Only this vault's owner or an administrator can rename it.")
        #expect(await !writers.rename(home.vaultID, to: "Personal"))
        #expect(writers.errorMessage == ErrorWording.renameRefused)
        #expect(writers.row(home.vaultID)?.name == "Household")
        // Their own vaults are theirs to name.
        #expect(writers.rows.first { $0.isPersonal }?.mayRename == true)
        #expect(writers.row(own)?.mayRename == true)
        #expect(await writers.rename(own, to: "Allotment"))
        #expect(writers.errorMessage == nil)

        // A read-only member is told the vault is read-only, which is the wider reason.
        let readers = VaultsModel(context: ContextProbe().context(reader.session))
        await readers.load()
        #expect(readers.row(home.vaultID)?.mayRename == false)
        #expect(readers.row(home.vaultID)?.renameRefusal == ErrorWording.readOnly(.readOnly))

        // The one screen of a vault reads the same answer.
        let detail = SharedVaultModel(vaultID: home.vaultID, context: ContextProbe().context(writer.session))
        await detail.load()
        #expect(detail.sharing?.renameRefusal == ErrorWording.renameRefused)

        // Promoted, the member may.
        try await home.owner.session.changeRole(of: writer.accountID, in: home.vaultID, to: .administrator)
        try await writer.session.sync()
        await writers.load()
        #expect(writers.row(home.vaultID)?.mayRename == true)
        #expect(await writers.rename(home.vaultID, to: "Home"))
        #expect(writers.row(home.vaultID)?.name == "Home")
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
        await accept.useFullCode()
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
    /// The full-code fallback (docs/06-adversarial-review.md, V17): A1 runs the key directory and publishes its own
    /// keys under the invitee's account. A step that showed the directory's sixty digits above the field the person
    /// types into would pass whoever copies the screen, and pin A1's keys as a typed full code. The steps carry this
    /// device's own code and none of the directory's digits for the other account, and typing what the screen shows
    /// fails the check.
    @Test("the full-code fallback shows this device's own code and none of the other account's digits")
    func fallbackShowsOnlyOwnDigits() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 671)
        let invitee = try await household.account(seed: 672)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let impostor = try SharingParty(accountID: invitee.accountID, seed: 679)
        await household.directory.publish(impostor.bundle)

        let invitation = InvitationModel(vaultID: vaultID, context: ContextProbe().context(owner.session))
        await invitation.useFullCode()
        invitation.accountText = invitee.accountID.uuidString
        await invitation.lookUp()
        guard case .compareFingerprint(let comparison) = invitation.step else {
            Issue.record("expected the fingerprint step, got \(invitation.step)")
            return
        }
        let shown = String(describing: invitation.step)
        let directoryGroups: [String] = SharingCodes.groups(of: impostor.bundle.fingerprint.safetyNumber)
        for group in directoryGroups {
            #expect(!shown.contains(group), "the directory's digits are on the screen")
        }
        #expect(comparison.own.safetyNumber == owner.safetyNumber)

        // Copying everything the screen shows does not pass, and pins nobody.
        invitation.confirmation.typedSafetyNumber = comparison.own.safetyNumber
        await invitation.confirmFingerprint()
        #expect(invitation.errorMessage?.contains("does not match") == true)
        let pins = VerifiedContacts(store: owner.contacts, account: owner.bundle)
        #expect(try await pins.pinned(invitee.accountID) == nil)

        // The invitee's side: an invitation from an owner whose keys the directory replaced.
        await household.directory.publish(invitee.bundle)
        let ownerImpostor = try SharingParty(accountID: owner.accountID, seed: 678)
        await household.directory.publish(ownerImpostor.bundle)
        let accept = AcceptInvitationModel(context: ContextProbe().context(invitee.session))
        await accept.useFullCode()
        accept.codeText = SharingCodes.text(for: Invitation(vaultID: vaultID, ownerAccountID: owner.accountID))
        await accept.read()
        guard case .compareOwner(let ownerComparison) = accept.step else {
            Issue.record("expected the owner's fingerprint, got \(accept.step)")
            return
        }
        let acceptShown = String(describing: accept.step)
        let ownerGroups: [String] = SharingCodes.groups(of: ownerImpostor.bundle.fingerprint.safetyNumber)
        for group in ownerGroups {
            #expect(!acceptShown.contains(group), "the directory's digits for the owner are on the screen")
        }
        #expect(ownerComparison.own.safetyNumber == invitee.safetyNumber)
    }
}

extension SharingScreenTests {
    /// A joiner's scan through the screen (V18): the scan waits for the starter's device, then names the account it is
    /// for and pins it only on the person's yes; "not them" ends the session with nothing pinned.
    @Test("a scanned code names its account and is pinned only on the person's yes")
    func scanNamesTheAccountFirst() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 681)
        let invitee = try await household.account(seed: 682)
        let pins = VerifiedContacts(store: invitee.contacts, account: invitee.bundle)

        let declined = AcceptInvitationModel(context: ContextProbe().context(invitee.session))
        let first = try await owner.session.startSharingCodeSession()
        #expect(first.ownAccount == owner.accountID)
        await declined.cameraScanned(try #require(first.scanPayload))
        #expect(declined.step == .waiting, "\(declined.errorMessage ?? "")")
        _ = try await owner.session.refreshSharingCodeSession()
        await declined.refresh()
        guard case .confirmScan(let named, let code, _) = declined.step else {
            Issue.record("expected the account to be named, got \(declined.step)")
            return
        }
        #expect(named == owner.accountID && code != nil)
        await declined.decline()
        #expect(try await pins.pinned(owner.accountID) == nil)

        let accept = AcceptInvitationModel(context: ContextProbe().context(invitee.session))
        let second = try await owner.session.startSharingCodeSession()
        await accept.cameraScanned(try #require(second.scanPayload))
        _ = try await owner.session.refreshSharingCodeSession()
        await accept.refresh()
        await accept.confirmScannedAccount()
        guard case .awaitingInvitation = accept.step else {
            Issue.record("expected to wait for the invitation, got \(accept.step) \(accept.errorMessage ?? "")")
            return
        }
        #expect(try await pins.pinned(owner.accountID)?.method == .scannedCode)
    }
}

extension SharingScreenTests {
    /// A shared vault whose saved ledger does not restore (the owner's pin deleted, V19) is listed as shared and closed,
    /// never as the account's own, and its screen does not offer to share it again.
    @Test("an unrestored shared vault is listed as shared and closed, and not offered for sharing")
    func unrestoredSharedVaultOnScreen() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 691)
        let member = home.members[0]
        await member.contacts.removePin(for: home.owner.accountID)
        let relaunched = member.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)

        let vaults = VaultsModel(context: ContextProbe().context(relaunched.session))
        await vaults.load()
        let row = try #require(vaults.row(home.vaultID))
        #expect(row.awaitingOwnerCheck && row.isShared && row.isReadOnly && !row.mayRename)
        #expect(row.badge == "Shared · check its owner")
        let detail = SharedVaultModel(vaultID: home.vaultID, context: ContextProbe().context(relaunched.session))
        await detail.load()
        #expect(detail.awaitingOwnerCheck && !detail.isShared)
        await detail.share()
        #expect(detail.errorMessage == ErrorWording.sharedVaultUnavailable)
    }
}

extension SharingScreenTests {
    /// The invitation slot taken by someone who heard the number (V22): the screen says so and hands the invitation
    /// over as text, which the invitee, who checked the inviter in the session, pastes and accepts.
    @Test("an invitation that cannot be delivered in the session is offered as text")
    func undeliveredInvitationAsText() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 701)
        let invitee = try await household.account(seed: 702)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let invitation = InvitationModel(vaultID: vaultID, context: ContextProbe().context(owner.session))
        await invitation.startSession()
        guard case .showCode(let number, _) = invitation.step else {
            Issue.record("expected the code, got \(invitation.step)")
            return
        }
        _ = try await invitee.session.joinSharingCodeSession(number: number)
        await invitation.refresh()
        let shown = try await invitee.session.refreshSharingCodeSession()
        invitation.typedCode = try #require(shown.ownCode)
        await invitation.confirmTheirCode()
        _ = try await invitee.session.enterSharingCode(try #require(invitation.status?.ownCode))
        let parsed = try #require(SharingSessionNumber(typed: number))
        let commitBytes = try #require(await household.board.allObjects[SharingBoardName.commit(parsed)])
        let commit = try SharingSessionMessage.parse(commitBytes, expecting: .commit)
        await household.board.tamper(
            SharingBoardName.invitation(parsed, session: commit.session), contents: Array(repeating: 1, count: 9))

        await invitation.invite()
        guard case .issued(let text?, _) = invitation.step else {
            Issue.record("expected the invitation as text, got \(invitation.step)")
            return
        }
        #expect(invitation.errorMessage == ErrorWording.invitationNotDelivered)
        let accept = AcceptInvitationModel(context: ContextProbe().context(invitee.session))
        await accept.useFullCode()
        accept.codeText = text
        await accept.read()
        guard case .confirmJoin = accept.step else {
            Issue.record("expected to be asked, got \(accept.step) \(accept.errorMessage ?? "")")
            return
        }
        await accept.confirmJoin()
        #expect(accept.step == .joined(vaultID: vaultID), "\(accept.errorMessage ?? "")")
    }
}

extension SharingScreenTests {
    /// A4, or A1 through a careless administrator: the chain lists a member with keys they do not hold, and the owner
    /// has no pin for them (V24). The owner checks the real member in a session, which pins their real keys; the
    /// screen must not say "verified" while the vault wraps its key to the listed ones, and says to remove and invite
    /// them again.
    @Test("a member check says verified only when the vault lists the keys checked")
    func memberCheckAgainstTheListedKeys() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.administrator], seed: 711)
        let administrator = home.members[0]
        let member = try await household.account(seed: 719)
        let listed = try SharingParty(accountID: member.accountID, seed: 720)
        await household.directory.publish(listed.bundle)
        try await administrator.session.verifyContact(
            member.accountID, evidence: .safetyNumber(listed.bundle.fingerprint.safetyNumber))
        _ = try await administrator.session.invite(member.accountID, to: home.vaultID, as: .readWrite)
        try await administrator.session.sync()
        try await home.owner.session.sync()
        await household.directory.publish(member.bundle)

        let check = MemberVerificationModel(
            vaultID: home.vaultID, memberID: member.accountID, context: ContextProbe().context(home.owner.session))
        await check.startSession()
        guard case .showCode(let number, _) = check.step else {
            Issue.record("expected the code, got \(check.step)")
            return
        }
        _ = try await member.session.joinSharingCodeSession(number: number)
        await check.refresh()
        let shown = try await member.session.refreshSharingCodeSession()
        check.typedCode = try #require(shown.ownCode)
        await check.confirmTheirCode()
        guard case .notListed = check.step else {
            Issue.record("expected the keys-not-listed step, got \(check.step) \(check.errorMessage ?? "")")
            return
        }
        let rows = SharedVaultModel.rows(
            members: [(member.accountID, .readWrite)], substituted: [member.accountID], unverified: [], verified: [],
            me: nil)
        #expect(rows.first?.trustText?.contains("remove them and invite them again") == true)
    }
}

extension SharingScreenTests {
    /// Two sharing screens over one session, as two windows on a Mac (V25): one invites Bob to the first vault, the
    /// other starts a session and checks Carol. Send in the first window invited the second window's partner, Carol,
    /// into the first window's vault, while that window named Bob; and leaving one screen ended the other's session.
    /// Each screen now drives only the session it started.
    @Test("each sharing screen drives only its own session, so Send never invites another window's partner")
    func screensDoNotShareASession() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 721)
        let bob = try await household.account(seed: 722)
        let carol = try await household.account(seed: 723)
        let first = try await owner.session.createVault(name: "First").id
        let second = try await owner.session.createVault(name: "Second").id
        try await owner.session.shareVault(first)
        try await owner.session.shareVault(second)

        let window1 = InvitationModel(vaultID: first, context: ContextProbe().context(owner.session))
        await window1.startSession()
        guard case .showCode(let number1, _) = window1.step else {
            Issue.record("expected the code, got \(window1.step)")
            return
        }
        _ = try await bob.session.joinSharingCodeSession(number: number1)
        await window1.refresh()
        window1.typedCode = try #require(try await bob.session.refreshSharingCodeSession().ownCode)
        await window1.confirmTheirCode()
        guard case .chooseRole(_, let shownContact) = window1.step else {
            Issue.record("expected the role step, got \(window1.step)")
            return
        }
        #expect(shownContact.accountID == bob.accountID)

        let window2 = InvitationModel(vaultID: second, context: ContextProbe().context(owner.session))
        await window2.startSession()
        guard case .showCode(let number2, _) = window2.step else {
            Issue.record("expected the code, got \(window2.step)")
            return
        }
        _ = try await carol.session.joinSharingCodeSession(number: number2)
        await window2.refresh()
        window2.typedCode = try #require(try await carol.session.refreshSharingCodeSession().ownCode)
        await window2.confirmTheirCode()

        await window1.invite()
        #expect(window1.invitation == nil, "window 1 sent an invitation through window 2's session")
        let firstStatus = try await owner.session.sharedVaultStatus(first)
        let firstMembers: [UUID] = firstStatus.membership.members.map(\.accountID)
        #expect(!firstMembers.contains(carol.accountID))

        // Leaving the first window's screen leaves the second's session running, and it still invites Carol.
        await window1.startOver()
        #expect(await owner.session.sharingCodeStatus() != nil)
        await window2.invite()
        guard case .issued(nil, _) = window2.step else {
            Issue.record("expected the invitation sent, got \(window2.step) \(window2.errorMessage ?? "")")
            return
        }
        let secondStatus = try await owner.session.sharedVaultStatus(second)
        let secondMembers: [UUID] = secondStatus.membership.members.map(\.accountID)
        #expect(secondMembers.contains(carol.accountID))
    }
}

extension SharingScreenTests {
    /// No vouching, through the screens (V27): an administrator's invitation names an owner the invitee has not
    /// checked. The screen told the person to check the owner "then accept again", but its only button dropped the
    /// invitation and the session, and nothing could accept it later. It now keeps the invitation, runs a session with
    /// the owner (who checks them from the member list), and offers the invitation again.
    @Test("an administrator's invitation waits while the invitee checks the owner, and is then offered again")
    func checkTheOwnerThenJoin() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.administrator], seed: 731)
        let (owner, administrator) = (home.owner, home.members[0])
        let invitee = try await household.account(seed: 739)
        let accept = AcceptInvitationModel(context: ContextProbe().context(invitee.session))

        let started = try await administrator.session.startSharingCodeSession()
        accept.numberText = try #require(started.number)
        await accept.joinWithNumber()
        _ = try await administrator.session.refreshSharingCodeSession()
        await accept.refresh()
        let inviteeCode = try #require(accept.status?.ownCode)
        let checked = try await administrator.session.enterSharingCode(inviteeCode)
        accept.typedCode = try #require(checked.ownCode)
        await accept.confirmTheirCode()
        _ = try await administrator.session.inviteThroughSharingCode(to: home.vaultID, as: .readWrite, checked: checked)
        try await administrator.session.sync()
        await accept.refresh()
        guard case .ownerNotVerified(let ownerID) = accept.step else {
            Issue.record("expected the owner to be checked first, got \(accept.step) \(accept.errorMessage ?? "")")
            return
        }
        #expect(ownerID == owner.accountID)

        await accept.checkOwner()
        #expect(accept.step == .enterNumber && accept.checkingOwner == owner.accountID)
        try await owner.session.sync()
        let ownerSession = try await owner.session.startSharingCodeSession()
        accept.numberText = try #require(ownerSession.number)
        await accept.joinWithNumber()
        _ = try await owner.session.refreshSharingCodeSession()
        await accept.refresh()
        let ownerChecked = try await owner.session.enterSharingCode(try #require(accept.status?.ownCode))
        accept.typedCode = try #require(ownerChecked.ownCode)
        await accept.confirmTheirCode()
        guard case .confirmJoin(let shown) = accept.step else {
            Issue.record("expected the kept invitation again, got \(accept.step) \(accept.errorMessage ?? "")")
            return
        }
        #expect(shown.accountID == owner.accountID)
        await accept.confirmJoin()
        #expect(accept.step == .joined(vaultID: home.vaultID), "\(accept.errorMessage ?? "")")
    }
}
