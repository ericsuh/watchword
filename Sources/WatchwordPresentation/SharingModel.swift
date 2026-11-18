import Foundation
import Observation
import WatchwordKit
import WatchwordSharing

/// One member of a shared vault, as the member list shows them (PRD F4.3, F4.5; review finding D17).
public struct MemberRow: Hashable, Sendable, Identifiable {
    public enum Trust: Hashable, Sendable {
        case you
        /// This device compared their fingerprint, and the chain lists the keys compared.
        case verified
        /// Trusted through the chain only: whoever added them compared fingerprints, this device did not.
        case unverified
        /// The chain lists keys for them that differ from the ones this device compared: a warning, never accepted
        /// silently (SEC3).
        case keysChanged
        /// No comparison of the chain with this device's pins has been made on the current head (the vault is
        /// locked, or the contacts could not be read). Never shown as verified (D17).
        case notChecked
    }

    public let id: UUID
    public let role: MemberRole
    public let trust: Trust

    /// "You", or the first digits of their account ID: the chain names accounts, not people.
    public var name: String {
        trust == .you ? "You" : "Member \(shortIdentifier(id))"
    }

    public var roleName: String { Self.name(of: role) }

    public var trustText: String? {
        switch trust {
        case .you, .verified: return nil
        case .unverified: return "Not verified by you"
        case .keysChanged: return "Keys changed: check a vault sharing code with them again"
        case .notChecked: return "Not checked yet"
        }
    }

    public static func name(of role: MemberRole) -> String {
        switch role {
        case .owner: return "Owner"
        case .administrator: return "Administrator"
        case .readWrite: return "Can edit"
        case .readOnly: return "Read only"
        }
    }
}

/// One shared vault's members and what can be done with them: share, change roles, remove, leave, rotate (PRD F4).
/// The session enforces every rule; what is offered here only follows them, so nothing is offered that would be
/// refused.
@MainActor
@Observable
public final class SharedVaultModel {
    public let vaultID: UUID
    public private(set) var isShared = false
    public private(set) var sharingAvailable = true
    public private(set) var members: [MemberRow] = []
    public private(set) var sharing: VaultSharing?
    /// "Pending rotation" and the other reasons a rotation is unfinished, worded (F4.3).
    public private(set) var pending: [String] = []
    public private(set) var ownRole: MemberRole?
    public private(set) var fingerprint: OwnFingerprint?
    public private(set) var isWorking = false
    public var errorMessage: String?
    /// What the last change did, in words.
    public private(set) var notice: String?

    private let context: ScreenContext
    private var accountID: UUID?

    public init(vaultID: UUID, context: ScreenContext) {
        self.vaultID = vaultID
        self.context = context
    }

    public var isReadOnly: Bool { sharing?.readOnlyReason != nil }
    public var requiresNewerVersion: Bool { sharing?.requiresNewerVersion ?? false }
    public var mayInvite: Bool { ownRole?.isAdministrator == true && !isReadOnly }
    public var mayLeave: Bool { ownRole != nil && ownRole != .owner && !requiresNewerVersion }
    public var mayRotate: Bool { ownRole?.isAdministrator == true && !isReadOnly }

    /// The roles `member` can be given by this account: the owner gives any role but owner to anyone else, an
    /// administrator moves members who are not administrators between editing and reading (§8.3).
    public func roles(assignableTo member: MemberRow) -> [MemberRole] {
        guard !isReadOnly, member.trust != .you, member.role != .owner, let ownRole else { return [] }
        let choices: [MemberRole]
        switch ownRole {
        case .owner: choices = [.administrator, .readWrite, .readOnly]
        case .administrator: choices = member.role == .administrator ? [] : [.readWrite, .readOnly]
        case .readWrite, .readOnly: choices = []
        }
        return choices.filter { $0 != member.role }
    }

    public func mayRemove(_ member: MemberRow) -> Bool {
        guard !isReadOnly, member.trust != .you, member.role != .owner, let ownRole else { return false }
        return ownRole == .owner || (ownRole == .administrator && member.role != .administrator)
    }

    public func load() async {
        await perform { try await reload() }
    }

    /// Makes the vault shareable: its membership chain starts, with this account as owner (F4.1).
    public func share() async {
        await perform {
            try await context.session.shareVault(vaultID)
            try await reload()
            notice = "The vault can now be shared. Invite someone to it."
        }
    }

    /// Changes a member's role (F4.5). A demotion to read-only is followed by a key rotation, so that someone
    /// invited later need not trust what only vouching attributes to them (review finding S42).
    public func changeRole(of member: MemberRow, to role: MemberRole) async {
        await perform {
            try await context.session.changeRole(of: member.id, in: vaultID, to: role)
            if member.role.mayWrite && !role.mayWrite {
                _ = try await context.session.rotateVaultKey(vaultID)
            }
            try await reload()
            notice = "\(member.name) is now \(MemberRow.name(of: role).lowercased())."
        }
    }

    /// Removes a member (F4.3): off the share, then the key is rotated and everything sealed again.
    public func remove(_ member: MemberRow) async {
        await perform {
            let status = try await context.session.removeMember(member.id, from: vaultID)
            try await reload()
            notice = "\(member.name) was removed. " + Self.describe(status)
        }
    }

    /// Asks to leave (F4.4). Until an administrator's device rotates the key, this account is still listed.
    public func leave() async {
        await perform {
            try await context.session.leaveSharedVault(vaultID)
            try await reload()
            notice =
                "You asked to leave. The vault goes from your devices once an administrator's device has "
                + "rotated its key."
        }
    }

    public func rotate() async {
        await perform {
            let status = try await context.session.rotateVaultKey(vaultID)
            try await reload()
            notice = Self.describe(status)
        }
    }

    static func describe(_ status: RotationStatus) -> String {
        switch status {
        case .complete: return "The vault's key was replaced and everything in it sealed again."
        case .resealing(let remaining):
            return "The key was replaced; \(remaining) item(s) wait to be sealed again at the next sync."
        case .awaitingPublication: return "The new key goes out at the next sync."
        case .superseded: return "Another administrator changed the vault at the same time. Review it and try again."
        }
    }

    private func reload() async throws {
        let session = context.session
        if fingerprint == nil, let bundle = try? await session.publicKeyBundle() {
            fingerprint = OwnFingerprint(bundle)
        }
        accountID = fingerprint?.accountID
        let shared: [UUID]
        do {
            shared = try await session.sharedVaultIDs()
        } catch is SharedVaultError {
            sharingAvailable = false
            isShared = false
            return
        }
        guard shared.contains(vaultID) else {
            isShared = false
            members = []
            return
        }
        let status = try await session.sharedVaultStatus(vaultID)
        isShared = true
        sharing = VaultSharing(status)
        ownRole = status.role
        members = Self.rows(status, me: accountID)
        pending = status.pendingRotation.map(Self.describe)
    }

    nonisolated static func rows(_ status: SharedVaultStatus, me: UUID?) -> [MemberRow] {
        rows(
            members: status.membership.members.map { ($0.accountID, $0.role) }, substituted: status.substitutedMembers,
            unverified: status.unverifiedMembers, verified: status.verifiedMembers, me: me)
    }

    /// The member list: changed keys first of all, then unverified; verified only for a member the comparison on the
    /// current head lists as verified (`SharedVaultStatus.verifiedMembers`), and "not checked yet" for anyone else. An
    /// account that is in no list is never taken for verified.
    public nonisolated static func rows(
        members: [(accountID: UUID, role: MemberRole)], substituted: [UUID], unverified: [UUID], verified: [UUID]?,
        me: UUID?
    ) -> [MemberRow] {
        let substituted = Set(substituted)
        let unverified = Set(unverified)
        let verified = Set(verified ?? [])
        return members.map { member in
            let trust: MemberRow.Trust
            if member.accountID == me {
                trust = .you
            } else if substituted.contains(member.accountID) {
                trust = .keysChanged
            } else if unverified.contains(member.accountID) {
                trust = .unverified
            } else if verified.contains(member.accountID) {
                trust = .verified
            } else {
                trust = .notChecked
            }
            return MemberRow(id: member.accountID, role: member.role, trust: trust)
        }
        .sorted { ($0.role.rawValue, $0.id.uuidString) < ($1.role.rawValue, $1.id.uuidString) }
    }

    static func describe(_ pending: PendingRotation) -> String {
        switch pending {
        case .departureRequested(let id):
            return "Member \(shortIdentifier(id)) asked to leave. Until the key is rotated, new items are still "
                + "sealed under a key they hold."
        case .removalOwed(let id):
            return "Removing member \(shortIdentifier(id)) has to be done again: a change made at the same time won."
        case .awaitingPublication:
            return "A key rotation from this device goes out at the next sync."
        case .resealing(let remaining):
            return "\(remaining) item(s) are still sealed under an earlier key and wait to be sealed again."
        case .awaitingKey:
            return "This device has not received the vault's current key yet."
        }
    }

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        notice = nil
        errorMessage = await ScreenOperation(context: context).run(body)
    }
}

/// Inviting someone to a shared vault (PRD F4.1, F4.2; ADR 0010): show the vault sharing code, type the six digits
/// on their screen (or scan it), let them type this device's six, choose a role, and send the invitation inside the
/// session. The check cannot be skipped: the session pins the invitee only from a completed session, and refuses to
/// invite an account that is not pinned. The full vault sharing code (sixty digits, typed) is the fallback, behind
/// `useFullCode()`, for two people who cannot be at their devices together.
@MainActor
@Observable
public final class InvitationModel {
    public enum Step: Hashable, Sendable {
        /// What happens, and the button that shows the vault sharing code.
        case start
        /// The vault sharing code, read out or scanned; waiting for their device to answer.
        case showCode(number: String, scanPayload: String)
        /// Their device answered: type the six digits on their screen, or scan it.
        case typeTheirCode(attemptsLeft: Int)
        /// They are checked and pinned. `code` is this device's six digits, for them to type (nil on the fallback).
        case chooseRole(code: String?, contact: ContactSummary)
        /// The session checked keys that differ from the ones checked before for that account.
        case keysChanged(accountID: UUID)
        /// The session stopped; nothing was pinned or sent.
        case failed(message: String)
        // The fallback, the full vault sharing code:
        case nameAccount
        case compareFingerprint(ContactSummary)
        /// The invitation went out. Through a session there is nothing to send (`code` nil); on the fallback, the
        /// invitation as text.
        case issued(code: String?)
    }

    public let vaultID: UUID
    public var accountText = ""
    public var confirmation = FingerprintConfirmation()
    /// The six digits typed from their screen.
    public var typedCode = ""
    public var role: MemberRole = .readWrite
    public private(set) var step: Step = .start
    public private(set) var isWorking = false
    public var errorMessage: String?
    /// The invitation just issued, for a UI-test hook that hands it to the other person (fallback path).
    public private(set) var invitation: Invitation?
    /// The vault sharing code and this device's code, for the UI-test household (`UITestPeer`), which stands in for
    /// the other person reading them off this screen.
    public private(set) var status: SharingCodeStatus?

    private let context: ScreenContext
    private var reference: AccountReference?
    private var throughSession = false

    public init(vaultID: UUID, context: ScreenContext) {
        self.vaultID = vaultID
        self.context = context
    }

    /// The roles an invitation can carry: never owner.
    public static let roles: [MemberRole] = [.readWrite, .readOnly, .administrator]

    /// Whether the person named the account with a fingerprint code (fallback). It only says which account: the check
    /// is still theirs to make.
    public var usesFingerprintCode: Bool { reference?.fingerprintCode != nil }

    /// While waiting for the other device: the view refreshes on a timer.
    public var isWaiting: Bool {
        if case .showCode = step { return true }
        return false
    }

    /// Who is being invited, as the role step names them: the chain names accounts, not people.
    public var inviteeName: String {
        switch step {
        case .compareFingerprint(let contact), .chooseRole(_, let contact):
            return "the account \(shortIdentifier(contact.accountID)) (Watchword ID \(contact.accountID.uuidString))"
        default: return ""
        }
    }

    /// How the invitee's keys were checked, for the role step; never claims a check that was not made.
    public private(set) var verificationText = ""

    // MARK: The vault sharing code

    public func startSession() async {
        await perform {
            throughSession = true
            try await apply(try await context.session.startSharingCodeSession())
        }
    }

    /// Looks for their device's answer. Called on a timer while `isWaiting`, and by "Check Again".
    public func refresh() async {
        guard throughSession, !isWorking else { return }
        await perform { try await apply(try await context.session.refreshSharingCodeSession()) }
    }

    /// Checks the six digits the person typed from the other screen.
    public func confirmTheirCode() async {
        guard case .typeTheirCode = step else { return }
        let typed = typedCode
        await perform {
            let status = try await context.session.enterSharingCode(typed)
            typedCode = ""
            if case .typeTheirCode = status.step {
                stepMessage = SharingCodeWording.wrongCode(attemptsLeft: status.attemptsLeft)
            }
            try await apply(status)
        }
    }

    /// What the camera read from the other person's screen (their `FingerprintCode`). Only the scanner view calls
    /// this; nothing typed or pasted reaches it.
    public func cameraScanned(_ payload: String) async {
        guard case .typeTheirCode = step else { return }
        await perform {
            let status = try await context.session.scanSharingPartnerCode(payload)
            if case .typeTheirCode = status.step {
                stepMessage = SharingCodeWording.wrongCode(attemptsLeft: status.attemptsLeft)
            }
            try await apply(status)
        }
    }

    /// The person chose to use the session's new keys after "keys changed" for someone in no vault of theirs, or
    /// listed with those keys.
    public func useNewKeys() async {
        guard case .keysChanged = step else { return }
        await perform {
            try await context.session.replacePinFromSharingCode()
            if let status = await context.session.sharingCodeStatus() { try await apply(status) }
        }
    }

    // MARK: The fallback

    /// Leaves the session for the full vault sharing code.
    public func useFullCode() async {
        await context.session.endSharingCodeSession()
        throughSession = false
        status = nil
        step = .nameAccount
        errorMessage = nil
    }

    public func lookUp() async {
        guard let reference = SharingCodes.account(from: accountText) else {
            errorMessage = "Enter the other person's Watchword ID or fingerprint code, as they sent it."
            return
        }
        self.reference = reference
        await perform {
            let contact = ContactSummary(try await context.session.contactCandidate(reference.accountID))
            verificationText = contact.isVerified ? "You checked their keys before, and they have not changed." : ""
            step = contact.isVerified ? .chooseRole(code: nil, contact: contact) : .compareFingerprint(contact)
        }
    }

    public func confirmFingerprint() async {
        guard case .compareFingerprint(let contact) = step else { return }
        guard let evidence = confirmation.evidence() else {
            errorMessage = "Type their full vault sharing code."
            return
        }
        await perform {
            try await context.session.verifyContact(contact.accountID, evidence: evidence)
            verificationText = FingerprintConfirmation.describe(evidence)
            confirmation = FingerprintConfirmation()
            step = .chooseRole(
                code: nil, contact: ContactSummary(try await context.session.contactCandidate(contact.accountID)))
        }
    }

    // MARK: Inviting

    public func invite() async {
        guard case .chooseRole(_, let contact) = step else { return }
        await perform {
            if throughSession {
                invitation = try await context.session.inviteThroughSharingCode(to: vaultID, as: role)
                step = .issued(code: nil)
            } else {
                let issued = try await context.session.invite(contact.accountID, to: vaultID, as: role)
                invitation = issued
                step = .issued(code: SharingCodes.text(for: issued))
            }
            // The proposal and the grant reach the shared storage now, not at the next scheduled sync.
            _ = try? await context.session.sync()
        }
    }

    public func startOver() async {
        await context.session.endSharingCodeSession()
        step = .start
        throughSession = false
        status = nil
        accountText = ""
        typedCode = ""
        confirmation = FingerprintConfirmation()
        reference = nil
        errorMessage = nil
    }

    private func apply(_ status: SharingCodeStatus) async throws {
        self.status = status
        switch status.step {
        case .showNumber:
            step = .showCode(number: status.number ?? "", scanPayload: status.scanPayload ?? "")
        case .typeTheirCode:
            step = .typeTheirCode(attemptsLeft: status.attemptsLeft)
        case .verified:
            guard let partner = status.partner else { return }
            if status.keysDifferFromPin {
                step = .keysChanged(accountID: partner)
            } else if status.pinned {
                verificationText = FingerprintConfirmation.describe(status)
                // Their bundle as the directory gives it now: `invite` checks it against the pin again.
                step = .chooseRole(
                    code: status.ownCode, contact: ContactSummary(try await context.session.contactCandidate(partner)))
            }
        case .failed(let error):
            step = .failed(message: SharingCodeWording.failure(error))
        case .waiting, .showCodeAndTypeTheirs:
            step = .failed(message: SharingCodeWording.failure(.notReady))
        }
    }

    /// What a step that succeeded has to say (a wrong code with tries left), shown when nothing failed.
    private var stepMessage: String?

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        stepMessage = nil
        let failure = await ScreenOperation(context: context).run(body)
        errorMessage = failure ?? stepMessage
    }
}

/// Accepting an invitation (PRD F4.2; ADR 0010): type the vault sharing code the inviter reads out (or scan it),
/// read this device's six digits back, type the six on their screen, and join once their invitation arrives. Nothing
/// is held before the owner is pinned; the session checks the chain back to them. An invitation from an administrator
/// who is not the owner needs the owner checked as well, by a session of the person's own: nobody vouches for an
/// owner. The fallback is a pasted invitation and the owner's full vault sharing code.
@MainActor
@Observable
public final class AcceptInvitationModel {
    public enum Step: Hashable, Sendable {
        /// Type the eight digits they read out, or scan their screen.
        case enterNumber
        /// Answered: waiting for their device.
        case waiting
        /// Show this device's six digits for them to type, and type the six on their screen.
        case showCodeAndType(code: String, scanPayload: String, attemptsLeft: Int)
        /// They are checked and pinned; still showing this device's six digits (`code`, nil until the session can show
        /// them) for a device that types; waiting for their invitation.
        case awaitingInvitation(code: String?, scanPayload: String)
        /// The invitation arrived and its owner is pinned: the person still says yes to joining their vault, which
        /// nothing an invitation says can skip (review of the account screens, finding 8).
        case confirmJoin(ContactSummary)
        /// The invitation's owner is not the account just checked, and has not been checked by this device.
        case ownerNotVerified(ownerID: UUID)
        case keysChanged(accountID: UUID)
        case failed(message: String)
        case joined(vaultID: UUID)
        // The fallback: a pasted invitation and the owner's full vault sharing code.
        case enterCode
        case compareOwner(ContactSummary)
    }

    public var numberText = ""
    public var typedCode = ""
    public var codeText = ""
    public var confirmation = FingerprintConfirmation()
    public private(set) var step: Step = .enterNumber
    public private(set) var isWorking = false
    public var errorMessage: String?
    /// The session as it stands, for the UI-test household that stands in for the other person.
    public private(set) var status: SharingCodeStatus?

    private let context: ScreenContext
    private var invitation: Invitation?

    public init(context: ScreenContext) {
        self.context = context
    }

    /// While waiting for the other device: the view refreshes on a timer.
    public var isWaiting: Bool {
        switch step {
        case .waiting, .awaitingInvitation: return true
        default: return false
        }
    }

    public func joinWithNumber() async {
        let typed = numberText
        await perform { try await apply(try await context.session.joinSharingCodeSession(number: typed)) }
    }

    /// What the camera read from the inviter's screen (`ScannedSharingCode`). Only the scanner view calls this.
    public func cameraScanned(_ payload: String) async {
        guard case .enterNumber = step else { return }
        await perform { try await apply(try await context.session.joinSharingCodeSession(scanned: payload)) }
    }

    /// Looks for the inviter's next message, and then for their invitation. Called on a timer while `isWaiting`.
    public func refresh() async {
        guard !isWorking else { return }
        await perform {
            var status = try await context.session.refreshSharingCodeSession()
            try await apply(status)
            guard case .awaitingInvitation = step else { return }
            if status.ownCode == nil {
                status = try await context.session.refreshSharingCodeSession()
                try await apply(status)
            }
            guard let invitation = try await context.session.sharingCodeInvitation() else { return }
            self.invitation = invitation
            let owner = ContactSummary(try await context.session.contactCandidate(invitation.ownerAccountID))
            step = owner.isVerified ? .confirmJoin(owner) : .ownerNotVerified(ownerID: invitation.ownerAccountID)
        }
    }

    public func confirmTheirCode() async {
        guard case .showCodeAndType = step else { return }
        let typed = typedCode
        await perform {
            let status = try await context.session.enterSharingCode(typed)
            typedCode = ""
            if case .showCodeAndTypeTheirs = status.step {
                stepMessage = SharingCodeWording.wrongCode(attemptsLeft: status.attemptsLeft)
            }
            try await apply(status)
        }
    }

    public func useNewKeys() async {
        guard case .keysChanged = step else { return }
        await perform {
            try await context.session.replacePinFromSharingCode()
            if let status = await context.session.sharingCodeStatus() { try await apply(status) }
        }
    }

    /// Joins the vault of the invitation that arrived, once the person has said yes.
    public func confirmJoin() async {
        guard case .confirmJoin = step, let invitation else { return }
        await perform { try await join(invitation, evidence: nil) }
    }

    /// Goes back to the start without joining.
    public func decline() async {
        await context.session.endSharingCodeSession()
        step = .enterNumber
        invitation = nil
        numberText = ""
        typedCode = ""
        codeText = ""
        status = nil
    }

    // MARK: The fallback

    public func useFullCode() async {
        await context.session.endSharingCodeSession()
        status = nil
        step = .enterCode
        errorMessage = nil
    }

    public func read() async {
        guard let invitation = SharingCodes.invitation(from: codeText) else {
            errorMessage = "That is not a Watchword invitation. Copy it again, exactly as it was sent."
            return
        }
        self.invitation = invitation
        await perform {
            let owner = ContactSummary(try await context.session.contactCandidate(invitation.ownerAccountID))
            step = owner.isVerified ? .confirmJoin(owner) : .compareOwner(owner)
        }
    }

    public func accept() async {
        guard case .compareOwner = step, let invitation else { return }
        guard let evidence = confirmation.evidence() else {
            errorMessage = "Type the owner's full vault sharing code."
            return
        }
        await perform { try await join(invitation, evidence: evidence) }
    }

    private func join(_ invitation: Invitation, evidence: VerificationEvidence?) async throws {
        let vaultID = try await context.session.acceptInvitation(invitation, ownerEvidence: evidence)
        await context.session.endSharingCodeSession()
        // The vault's items arrive with a sync; a failure here leaves the next sync to fetch them.
        _ = try? await context.session.sync()
        confirmation = FingerprintConfirmation()
        step = .joined(vaultID: vaultID)
    }

    private func apply(_ status: SharingCodeStatus) async throws {
        self.status = status
        switch status.step {
        case .waiting:
            step = .waiting
        case .showCodeAndTypeTheirs:
            step = .showCodeAndType(
                code: status.ownCode ?? "", scanPayload: status.scanPayload ?? "", attemptsLeft: status.attemptsLeft)
        case .verified:
            if status.keysDifferFromPin, let partner = status.partner {
                step = .keysChanged(accountID: partner)
            } else if status.pinned {
                step = .awaitingInvitation(code: status.ownCode, scanPayload: status.scanPayload ?? "")
            }
        case .failed(let error):
            step = .failed(message: SharingCodeWording.failure(error))
        case .showNumber, .typeTheirCode:
            step = .failed(message: SharingCodeWording.failure(.notReady))
        }
    }

    /// What a step that succeeded has to say (a wrong code with tries left), shown when nothing failed.
    private var stepMessage: String?

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        stepMessage = nil
        let failure = await ScreenOperation(context: context).run(body)
        errorMessage = failure ?? stepMessage
    }
}

/// Checking a member of a shared vault with a vault sharing code session, from the member list (ADR 0010): for a
/// member trusted through the chain only ("not verified by you"), or one whose keys in the chain differ from this
/// device's pin ("keys changed"). This device starts; the member's device joins. Only the member asked about may
/// answer: a session another account answers is ended before anything is pinned. A "keys changed" warning is settled
/// only if the keys the session checked are the ones the chain lists (`replacePinFromSharingCode(listedIn:)`); if they
/// are not, nothing changes and the person is told to remove the member.
@MainActor
@Observable
public final class MemberVerificationModel {
    public enum Step: Hashable, Sendable {
        case start
        case showCode(number: String, scanPayload: String)
        case typeTheirCode(attemptsLeft: Int)
        /// Checked and pinned: show this device's six digits for the member to type.
        case verified(code: String?)
        /// The session checked keys other than the ones pinned before: replace the pin only on the person's word,
        /// and only to the keys the vault's chain lists.
        case keysChanged
        case failed(message: String)
    }

    public let vaultID: UUID
    public let memberID: UUID
    public var typedCode = ""
    public private(set) var step: Step = .start
    public private(set) var isWorking = false
    public var errorMessage: String?
    public private(set) var status: SharingCodeStatus?

    private let context: ScreenContext

    public init(vaultID: UUID, memberID: UUID, context: ScreenContext) {
        self.vaultID = vaultID
        self.memberID = memberID
        self.context = context
    }

    public var memberName: String { "Member \(shortIdentifier(memberID))" }

    public var isWaiting: Bool {
        if case .showCode = step { return true }
        return false
    }

    public func startSession() async {
        await perform { try await apply(try await context.session.startSharingCodeSession()) }
    }

    public func refresh() async {
        guard !isWorking else { return }
        await perform { try await apply(try await context.session.refreshSharingCodeSession()) }
    }

    public func confirmTheirCode() async {
        guard case .typeTheirCode = step else { return }
        let typed = typedCode
        await perform {
            let status = try await context.session.enterSharingCode(typed)
            typedCode = ""
            if case .typeTheirCode = status.step {
                stepMessage = SharingCodeWording.wrongCode(attemptsLeft: status.attemptsLeft)
            }
            try await apply(status)
        }
    }

    public func cameraScanned(_ payload: String) async {
        guard case .typeTheirCode = step else { return }
        await perform {
            let status = try await context.session.scanSharingPartnerCode(payload)
            if case .typeTheirCode = status.step {
                stepMessage = SharingCodeWording.wrongCode(attemptsLeft: status.attemptsLeft)
            }
            try await apply(status)
        }
    }

    /// The person chose to trust the keys the session checked, which the vault's chain lists for the member.
    public func useNewKeys() async {
        guard case .keysChanged = step else { return }
        await perform {
            try await context.session.replacePinFromSharingCode(listedIn: vaultID)
            if let status = await context.session.sharingCodeStatus() { try await apply(status) }
        }
    }

    public func end() async {
        await context.session.endSharingCodeSession()
    }

    private func apply(_ status: SharingCodeStatus) async throws {
        self.status = status
        // Another account answered: end the session before anything about it is pinned.
        if let partner = status.partner, partner != memberID {
            await context.session.endSharingCodeSession()
            step = .failed(
                message: "Another account's device answered, so this was stopped and nothing was changed. Make sure "
                    + "\(memberName) types the code on their own device.")
            return
        }
        switch status.step {
        case .showNumber:
            step = .showCode(number: status.number ?? "", scanPayload: status.scanPayload ?? "")
        case .typeTheirCode:
            step = .typeTheirCode(attemptsLeft: status.attemptsLeft)
        case .verified:
            if status.keysDifferFromPin {
                step = .keysChanged
            } else if status.pinned {
                step = .verified(code: status.ownCode)
            }
        case .failed(let error):
            step = .failed(message: SharingCodeWording.failure(error))
        case .waiting, .showCodeAndTypeTheirs:
            step = .failed(message: SharingCodeWording.failure(.notReady))
        }
    }

    /// What a step that succeeded has to say (a wrong code with tries left), shown when nothing failed.
    private var stepMessage: String?

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        stepMessage = nil
        let failure = await ScreenOperation(context: context).run(body)
        errorMessage = failure ?? stepMessage
    }
}
