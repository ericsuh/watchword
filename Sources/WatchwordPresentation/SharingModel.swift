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
        /// Their account's own devices disagree about which of them are the account's: its device registry holds a
        /// second first entry, or a password change beside the one this device follows, made by someone who holds
        /// their account key (review finding Z6). Nothing a device in question signs counts here, and nothing in this
        /// version settles it (review finding Z11): comparing safety numbers again verifies their account's keys,
        /// not which of its devices are theirs.
        case devicesDisagree
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
        case .keysChanged: return "Keys changed: compare safety numbers again"
        case .devicesDisagree:
            return "This person's devices disagree. What their devices in question write is held aside here"
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
    /// The vault is shared and not set up on this device (`VaultInfo.isSharedUnavailable`): the screen says so and
    /// offers neither "Share" nor a member list. `setUpCode` is the invitation to accept here, when this device knows
    /// the vault's owner from its account's own marker; otherwise the person uses the invitation they were sent.
    public private(set) var needsSetUp = false
    public private(set) var setUpCode: String?
    public static let setUpNotice =
        "This vault is shared, and this device has not joined it yet: another of your devices shared or joined it. "
        + "Until you accept its invitation on this device, nothing in it can be changed from here, and this device "
        + "does not receive what the other members write."
    public private(set) var sharingAvailable = true
    public private(set) var members: [MemberRow] = []
    public private(set) var sharing: VaultSharing?
    /// "Pending rotation" and the other reasons a rotation is unfinished, worded (F4.3).
    public private(set) var pending: [String] = []
    public private(set) var ownRole: MemberRole?
    /// Changes this device made in a vault its account is no longer in that nobody else has: what
    /// `removeFromThisDevice` would discard, and the number its confirmation shows.
    public private(set) var unsharedChanges = 0
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
    /// This account is no longer a member (it left, or was removed), and this device still holds the vault: the
    /// screen says so and offers to remove what it holds (`removeFromThisDevice`).
    public var membershipEnded: Bool { isShared && ownRole == nil }

    /// What leaving does and does not do, for the confirmation and the notice after it (PRD F4.4; review finding
    /// Z45). Leaving is a request: an administrator's device carries it out. And nothing takes the vault's items off
    /// this device; it stops receiving changes, AutoFill stops offering them, and the person removes them.
    public static let leaveExplanation =
        "You stay a member until an administrator's device has replaced the vault's key. After that this device "
        + "no longer receives the vault's changes and AutoFill stops offering its items. What this device already "
        + "holds stays on it until you remove it from the vault's screen, and the other members keep their copies."

    /// What removing a member does and does not do (PRD F4.3: the app must say that copies may have been kept).
    public static let removalExplanation =
        "They lose access to new changes. The vault's key is replaced and every item sealed again, but what they "
        + "already copied cannot be taken back, and their own devices keep what they hold until they remove it."

    public static let removeCopiesExplanation =
        "This removes the vault's items from this device only. The vault's members keep theirs."

    /// What the removal would discard that is not a copy (review finding Z57): changes made here that never
    /// reached anyone else. "The vault's members keep theirs" is not true of those.
    public static func unsharedWarning(_ count: Int) -> String {
        "\(count) change(s) made on this device never reached the other members. Nobody else has them, and "
            + "removing discards them for good."
    }

    /// The text for the confirmation, as it stands for this vault now.
    public var removeCopiesMessage: String {
        unsharedChanges == 0
            ? Self.removeCopiesExplanation
            : Self.removeCopiesExplanation + " " + Self.unsharedWarning(unsharedChanges)
    }
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
            notice = "You asked to leave. " + Self.leaveExplanation
        }
    }

    /// Removes from this device what it holds of a vault this account is no longer a member of (review finding Z45):
    /// the only thing that does.
    public func removeFromThisDevice() async {
        await perform {
            // The number the confirmation showed: more than that, and the session refuses (Z57).
            let shown = unsharedChanges
            do {
                let removed = try await context.session.removeLocalCopies(
                    ofSharedVault: vaultID, discardingUnshared: shown)
                try await reload()
                notice = "\(removed) item(s) of this vault were removed from this device."
            } catch let error as SharedVaultError {
                // The count moved since it was shown: show the new one before anything is asked again.
                try? await reload()
                throw error
            }
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
            needsSetUp =
                (try? await session.vaults(includingDeleted: true))?
                .first { $0.id == vaultID }?.isSharedUnavailable ?? false
            setUpCode =
                needsSetUp
                ? (try? await session.sharedVaultInvitation(vaultID)).flatMap { $0 }.map(SharingCodes.text(for:)) : nil
            return
        }
        needsSetUp = false
        setUpCode = nil
        let status = try await session.sharedVaultStatus(vaultID)
        isShared = true
        sharing = VaultSharing(status)
        ownRole = status.role
        unsharedChanges = status.role == nil ? ((try? await session.unsharedWork(inSharedVault: vaultID)) ?? 0) : 0
        members = Self.rows(status, me: accountID)
        pending = status.pendingRotation.map(Self.describe)
    }

    nonisolated static func rows(_ status: SharedVaultStatus, me: UUID?) -> [MemberRow] {
        rows(
            members: status.membership.members.map { ($0.accountID, $0.role) }, substituted: status.substitutedMembers,
            unverified: status.unverifiedMembers, verified: status.verifiedMembers,
            devicesDisagree: status.membersWithDisagreeingDevices, me: me)
    }

    /// The member list: changed keys first of all, then unverified; verified only for a member the comparison on the
    /// current head lists as verified (`SharedVaultStatus.verifiedMembers`), and "not checked yet" for anyone else. An
    /// account that is in no list is never taken for verified.
    public nonisolated static func rows(
        members: [(accountID: UUID, role: MemberRole)], substituted: [UUID], unverified: [UUID], verified: [UUID]?,
        devicesDisagree: [UUID] = [], me: UUID?
    ) -> [MemberRow] {
        let substituted = Set(substituted)
        let devicesDisagree = Set(devicesDisagree)
        let unverified = Set(unverified)
        let verified = Set(verified ?? [])
        return members.map { member in
            let trust: MemberRow.Trust
            if member.accountID == me {
                trust = .you
            } else if substituted.contains(member.accountID) {
                trust = .keysChanged
            } else if devicesDisagree.contains(member.accountID) {
                // Above "verified": the keys compared are the right ones, and someone else holds them too.
                trust = .devicesDisagree
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
        case .keyHeldOutsideTheVault(let id):
            return "The account \(shortIdentifier(id)) was invited and removed again while another change was being "
                + "made, and still holds this vault's key. Until an administrator's device rotates the key, new items "
                + "are sealed under a key it holds."
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

    /// What the roles mean, under the role picker. Read-only is a rule the apps keep, not encryption, and the screen
    /// must say so (PRD F4.5): a read-only member holds the vault's key like any other.
    public static let roleExplanation =
        "Administrators can invite and remove others. Read-only is a rule Watchword keeps, not encryption: a "
        + "read-only member holds the vault's key like everyone else, and their copy of the app does not change items."

    /// Whether the person named the account with a fingerprint code. It only says which account: the comparison is
    /// still theirs to make.
    public var usesFingerprintCode: Bool { reference?.fingerprintCode != nil }

    /// Who is being invited, as the role step names them: the chain names accounts, not people.
    public var inviteeName: String {
        switch step {
        case .compareFingerprint(let contact), .chooseRole(let contact):
            return "the account \(shortIdentifier(contact.accountID)) (Watchword ID \(contact.accountID.uuidString))"
        case .nameAccount, .issued: return ""
        }
    }

    /// How the invitee's keys were confirmed, for the role step; never claims a comparison that was not made.
    public private(set) var verificationText = ""

    public func lookUp() async {
        guard let reference = SharingCodes.account(from: accountText) else {
            errorMessage = "Enter the other person's Watchword ID or fingerprint code, as they sent it."
            return
        }
        self.reference = reference
        await perform {
            let contact = ContactSummary(try await context.session.contactCandidate(reference.accountID))
            verificationText =
                contact.isVerified ? "You compared their safety number before, and their keys have not changed." : ""
            step = contact.isVerified ? .chooseRole(contact) : .compareFingerprint(contact)
        }
    }

    public func confirmFingerprint() async {
        guard case .compareFingerprint(let contact) = step else { return }
        guard let evidence = confirmation.evidence(showing: contact.fingerprint) else {
            errorMessage = "Type their safety number, or confirm that you compared the two."
            return
        }
        await perform {
            try await context.session.verifyContact(contact.accountID, evidence: evidence)
            verificationText = FingerprintConfirmation.describe(evidence)
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
        /// The owner was verified before: the person still says yes to joining their vault, which nothing an
        /// invitation says can skip (review of the account screens, finding 8).
        case confirmJoin(ContactSummary)
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
            step = owner.isVerified ? .confirmJoin(owner) : .compareOwner(owner)
        }
    }

    public func accept() async {
        guard case .compareOwner(let owner) = step, let invitation else { return }
        guard let evidence = confirmation.evidence(showing: owner.fingerprint) else {
            errorMessage = "Type the owner's safety number, or confirm that you compared the two."
            return
        }
        await perform { try await join(invitation, evidence: evidence) }
    }

    /// Joins a vault whose owner was verified before, once the person has said yes.
    public func confirmJoin() async {
        guard case .confirmJoin = step, let invitation else { return }
        await perform { try await join(invitation, evidence: nil) }
    }

    /// Goes back to the code without joining.
    public func decline() {
        step = .enterCode
        invitation = nil
        codeText = ""
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
