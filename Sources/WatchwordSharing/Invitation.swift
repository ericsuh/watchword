import Foundation
import WatchwordCrypto

/// What an invitation tells the invitee before anything is verified: which vault, and whose it is
/// (docs/02-architecture.md §8.4). It travels with the transport's share (a CloudKit share URL, a shared folder), so
/// it is hostile input: it only says whose fingerprint to ask the person about.
///
/// ```
/// magic "WWIV"  formatVersion u8 = 1  vaultID 16  owner account 16
/// ```
public struct Invitation: Sendable, Hashable {
    static let magic: [UInt8] = Array("WWIV".utf8)
    static let formatVersion: UInt8 = 1
    public static let encodedLength = 4 + 1 + 16 + 16

    public let vaultID: UUID
    public let ownerAccountID: UUID

    public init(vaultID: UUID, ownerAccountID: UUID) {
        self.vaultID = vaultID
        self.ownerAccountID = ownerAccountID
    }

    public func encoded() -> [UInt8] {
        Invitation.magic + [Invitation.formatVersion] + vaultID.sharingBytes + ownerAccountID.sharingBytes
    }

    public static func parse(_ bytes: [UInt8]) throws -> Invitation {
        guard bytes.count <= encodedLength else { throw SharingFormatError.tooLarge(bytes.count) }
        var reader = SharingReader(bytes)
        try reader.header(magic: magic, version: formatVersion)
        let invitation = Invitation(vaultID: try reader.uuid(), ownerAccountID: try reader.uuid())
        try reader.finish()
        return invitation
    }
}

/// What issuing an invitation produces: the objects to publish and the invitation to send.
public struct InvitationPackage: Sendable, Hashable {
    public let invitation: Invitation
    /// The membership record that adds the invitee.
    public let record: SharingObject
    /// The current vault key wrapped to the invitee.
    public let grant: SharingObject

    /// In publishing order: the grant first, so that whoever sees the record can find the key.
    public var objects: [SharingObject] {
        [grant, record]
    }
}

/// The inviting side of an invitation (docs/02-architecture.md §8.4; PRD F4.1, F4.2).
///
/// ```
/// begin ──► awaitingVerification ──confirm──► verified ──issue──► issued
///              (show the invitee's safety number)     (wrap the vault key, sign the record)
/// ```
///
/// The vault key is wrapped to the invitee only in `issue`, and `issue` works only from `verified`, which holds a
/// `VerifiedContact`: there is no path from a bundle the directory returned to a wrapped key that does not pass
/// through the person confirming a fingerprint. An invitee already pinned from an earlier vault starts at `verified`;
/// one whose published bundle differs from their pin stops at `begin` with `SharingError.keySubstituted`.
public struct OutgoingInvitation: Sendable {
    public enum State: Sendable, Hashable {
        /// The directory's bundle for the invitee, not yet confirmed.
        case awaitingVerification(PublicKeyBundle)
        case verified(VerifiedContact)
        case issued(InvitationPackage)
    }

    public let vaultID: UUID
    public let invitee: UUID
    public let role: MemberRole
    public private(set) var state: State

    /// Looks up the invitee's published bundle and checks it against the verified contacts.
    public static func begin(
        vaultID: UUID, inviting invitee: UUID, as role: MemberRole, directory: any KeyBundleDirectory,
        contacts: VerifiedContacts
    ) async throws -> OutgoingInvitation {
        guard role != .owner else { throw MembershipError.ownerIsFixed }
        let candidate = try await directory.candidateBundle(for: invitee)
        switch try await contacts.trust(of: candidate) {
        case .verified(let contact):
            return OutgoingInvitation(vaultID: vaultID, invitee: invitee, role: role, state: .verified(contact))
        case .unverified:
            return OutgoingInvitation(
                vaultID: vaultID, invitee: invitee, role: role, state: .awaitingVerification(candidate))
        }
    }

    /// The fingerprint to show while waiting for the person to confirm it, or `nil` once that is done.
    public var fingerprintToConfirm: Fingerprint? {
        guard case .awaitingVerification(let candidate) = state else { return nil }
        return candidate.fingerprint
    }

    /// Records the person's confirmation of the invitee's fingerprint and pins the invitee.
    public mutating func confirm(
        _ evidence: VerificationEvidence, contacts: VerifiedContacts, signedBy keyset: Keyset, at now: Date
    ) async throws {
        guard case .awaitingVerification(let candidate) = state else {
            throw SharingError.invitationAlreadyCompleted
        }
        state = .verified(try await contacts.verify(candidate, evidence: evidence, signedBy: keyset, at: now))
    }

    /// Signs the record that adds the invitee and wraps the current vault key to them.
    public mutating func issue(ledger: MembershipLedger, vaultKey: VaultKey, signedBy keyset: Keyset) throws
        -> InvitationPackage
    {
        switch state {
        case .awaitingVerification: throw SharingError.fingerprintNotVerified
        case .issued: throw SharingError.invitationAlreadyCompleted
        case .verified(let contact):
            guard ledger.vaultID == vaultID, vaultKey.vaultID == vaultID,
                vaultKey.key.keyID == ledger.state.vaultKeyID
            else { throw SharingError.notCurrentKey }
            let record = try ledger.proposeAddition(of: contact, as: role, signedBy: keyset)
            let grant = try VaultKeyGrantRecord(VaultKeyGrant.seal(vaultKey, to: contact.bundle, from: keyset))
            let package = InvitationPackage(
                invitation: Invitation(vaultID: vaultID, ownerAccountID: ledger.owner.accountID),
                record: SharingObject(record), grant: SharingObject(grant))
            state = .issued(package)
            return package
        }
    }
}

/// A vault this account has just joined: its verified chain and its current key.
public struct JoinedVault: Sendable {
    public let ledger: MembershipLedger
    /// Store it wrapped under the account's own key (`VaultKey.wrap(for:)`), like a vault the account owns.
    public let vaultKey: VaultKey
}

/// The accepting side of an invitation (docs/02-architecture.md §8.4; PRD F4.2).
///
/// ```
/// begin ──► awaitingVerification ──confirm──► verified ──accept──► accepted
///              (show the owner's safety number)        (verify the chain, open the grant)
/// ```
///
/// Nothing from the store is believed before `verified`: the chain is anchored to the owner's bundle only once the
/// person has confirmed its fingerprint, and the vault key is opened only from a grant whose sender that chain
/// entitles. The invitee verifies the *owner*, whoever sent the invitation: an administrator's key is in the chain
/// under the owner's signature.
public struct IncomingInvitation: Sendable {
    public enum State: Sendable, Hashable {
        /// The directory's bundle for the owner, not yet confirmed.
        case awaitingVerification(PublicKeyBundle)
        case verified(VerifiedContact)
        case accepted
    }

    public let invitation: Invitation
    public private(set) var state: State

    /// Looks up the owner's published bundle and checks it against the verified contacts.
    ///
    /// - Parameter knownOwner: the owner of the vault this device already holds under the invitation's vault ID, or
    ///   `nil` if it holds none. For a vault this account created (its Personal vault included) that is the account
    ///   itself. An invitation to a vault ID the device already knows under another owner is refused
    ///   (`SharingError.vaultOwnerConflict`): vault IDs are not secret, and accepting it would let whoever sent it
    ///   stand in as the owner of a vault that is someone else's, with a key of their choosing (review finding S6).
    public static func begin(
        _ invitation: Invitation, knownOwner: UUID?, directory: any KeyBundleDirectory, contacts: VerifiedContacts
    ) async throws -> IncomingInvitation {
        if let knownOwner, knownOwner != invitation.ownerAccountID {
            throw SharingError.vaultOwnerConflict(vaultID: invitation.vaultID)
        }
        let candidate = try await directory.candidateBundle(for: invitation.ownerAccountID)
        switch try await contacts.trust(of: candidate) {
        case .verified(let contact):
            return IncomingInvitation(invitation: invitation, state: .verified(contact))
        case .unverified:
            return IncomingInvitation(invitation: invitation, state: .awaitingVerification(candidate))
        }
    }

    public var fingerprintToConfirm: Fingerprint? {
        guard case .awaitingVerification(let candidate) = state else { return nil }
        return candidate.fingerprint
    }

    /// Records the person's confirmation of the owner's fingerprint and pins the owner.
    public mutating func confirm(
        _ evidence: VerificationEvidence, contacts: VerifiedContacts, signedBy keyset: Keyset, at now: Date
    ) async throws {
        guard case .awaitingVerification(let candidate) = state else {
            throw SharingError.invitationAlreadyCompleted
        }
        state = .verified(try await contacts.verify(candidate, evidence: evidence, signedBy: keyset, at: now))
    }

    /// Verifies the vault's chain against the confirmed owner and opens this account's grant of the current key.
    ///
    /// - Parameters:
    ///   - candidates: every object under `SharingObjectLocation.membershipPrefix(vaultID)`.
    ///   - grants: every object under `SharingObjectLocation.grantPrefix` for the chain's current key and this
    ///     account. Since the current key is known only once the chain is verified, an integrator may simply pass
    ///     everything under the vault's `grant/` prefix; what does not apply is skipped.
    public mutating func accept(
        membership candidates: [[UInt8]], grants: [(name: String, contents: [UInt8])], as keyset: Keyset
    ) throws -> JoinedVault {
        switch state {
        case .awaitingVerification: throw SharingError.fingerprintNotVerified
        case .accepted: throw SharingError.invitationAlreadyCompleted
        case .verified(let owner):
            let ledger = try MembershipLedger.join(
                vaultID: invitation.vaultID, owner: owner, candidates: candidates
            ).ledger
            let current = ledger.state
            guard !current.isDeleted else { throw SharingError.vaultDeleted }
            guard let me = current.member(keyset.accountID) else {
                throw SharingError.notAMember(keyset.accountID)
            }
            guard me.bundle.hasSameKeys(as: try keyset.publicKeyBundle()) else {
                throw SharingError.ownKeySubstituted
            }
            let vaultKey = try ledger.openGrant(of: current.vaultKeyID, from: grants, as: keyset)
            state = .accepted
            return JoinedVault(ledger: ledger, vaultKey: vaultKey)
        }
    }
}
