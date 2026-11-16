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
        case .keysChanged: return "Keys changed: compare safety numbers again"
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

    static func rows(_ status: SharedVaultStatus, me: UUID?) -> [MemberRow] {
        let substituted = Set(status.substitutedMembers)
        let unverified = Set(status.unverifiedMembers)
        return status.membership.members.map { member in
            let trust: MemberRow.Trust =
                member.accountID == me
                ? .you
                : substituted.contains(member.accountID)
                    ? .keysChanged : unverified.contains(member.accountID) ? .unverified : .verified
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

/// Inviting someone to a shared vault (PRD F4.1, F4.2): name the account, compare fingerprints, choose a role, and
/// send the invitation. The fingerprint step cannot be skipped: the session refuses to invite an unverified contact.
@MainActor
@Observable
public final class InvitationModel {
    public enum Step: Hashable, Sendable {
        case nameAccount
        case compareFingerprint(ContactSummary)
        case chooseRole(ContactSummary)
        /// The invitation, as text to send to the invitee.
        case issued(code: String)
    }

    public let vaultID: UUID
    public var accountText = ""
    public var confirmation = FingerprintConfirmation()
    public var role: MemberRole = .readWrite
    public private(set) var step: Step = .nameAccount
    public private(set) var isWorking = false
    public var errorMessage: String?
    /// The invitation just issued, for a UI-test hook that hands it to the other person.
    public private(set) var invitation: Invitation?

    private let context: ScreenContext
    private var reference: AccountReference?

    public init(vaultID: UUID, context: ScreenContext) {
        self.vaultID = vaultID
        self.context = context
    }

    /// The roles an invitation can carry: never owner.
    public static let roles: [MemberRole] = [.readWrite, .readOnly, .administrator]

    /// Whether the person named the account with a fingerprint code, which is then what their keys are checked
    /// against.
    public var usesFingerprintCode: Bool { reference?.fingerprintCode != nil }

    public func lookUp() async {
        guard let reference = SharingCodes.account(from: accountText) else {
            errorMessage = "Enter the other person's Watchword ID or fingerprint code, as they sent it."
            return
        }
        self.reference = reference
        await perform {
            let contact = ContactSummary(try await context.session.contactCandidate(reference.accountID))
            step = contact.isVerified ? .chooseRole(contact) : .compareFingerprint(contact)
        }
    }

    public func confirmFingerprint() async {
        guard case .compareFingerprint(let contact) = step else { return }
        guard let evidence = confirmation.evidence(code: reference?.fingerprintCode) else {
            errorMessage = "Type their safety number, or confirm that you compared the two."
            return
        }
        await perform {
            try await context.session.verifyContact(contact.accountID, evidence: evidence)
            confirmation = FingerprintConfirmation()
            step = .chooseRole(ContactSummary(try await context.session.contactCandidate(contact.accountID)))
        }
    }

    public func invite() async {
        guard case .chooseRole(let contact) = step else { return }
        await perform {
            let issued = try await context.session.invite(contact.accountID, to: vaultID, as: role)
            invitation = issued
            step = .issued(code: SharingCodes.text(for: issued))
            // The proposal and the grant reach the shared storage now, not at the next scheduled sync.
            _ = try? await context.session.sync()
        }
    }

    public func startOver() {
        step = .nameAccount
        accountText = ""
        confirmation = FingerprintConfirmation()
        reference = nil
        errorMessage = nil
    }

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        errorMessage = await ScreenOperation(context: context).run(body)
    }
}

/// Accepting an invitation (PRD F4.2): read it, compare the owner's fingerprint, and join. Nothing is held before
/// the owner is verified; the session checks the chain back to them.
@MainActor
@Observable
public final class AcceptInvitationModel {
    public enum Step: Hashable, Sendable {
        case enterCode
        case compareOwner(ContactSummary)
        case joined(vaultID: UUID)
    }

    public var codeText = ""
    public var confirmation = FingerprintConfirmation()
    public private(set) var step: Step = .enterCode
    public private(set) var isWorking = false
    public var errorMessage: String?

    private let context: ScreenContext
    private var invitation: Invitation?

    public init(context: ScreenContext) {
        self.context = context
    }

    public func read() async {
        guard let invitation = SharingCodes.invitation(from: codeText) else {
            errorMessage = "That is not a Watchword invitation. Copy it again, exactly as it was sent."
            return
        }
        self.invitation = invitation
        await perform {
            let owner = ContactSummary(try await context.session.contactCandidate(invitation.ownerAccountID))
            if owner.isVerified {
                try await join(invitation, evidence: nil)
            } else {
                step = .compareOwner(owner)
            }
        }
    }

    public func accept() async {
        guard case .compareOwner = step, let invitation else { return }
        guard let evidence = confirmation.evidence(code: nil) else {
            errorMessage = "Type the owner's safety number, or confirm that you compared the two."
            return
        }
        await perform { try await join(invitation, evidence: evidence) }
    }

    private func join(_ invitation: Invitation, evidence: VerificationEvidence?) async throws {
        let vaultID = try await context.session.acceptInvitation(invitation, ownerEvidence: evidence)
        // The vault's items arrive with a sync; a failure here leaves the next sync to fetch them.
        _ = try? await context.session.sync()
        confirmation = FingerprintConfirmation()
        step = .joined(vaultID: vaultID)
    }

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        errorMessage = await ScreenOperation(context: context).run(body)
    }
}
