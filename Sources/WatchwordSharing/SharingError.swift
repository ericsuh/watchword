import Foundation
import WatchwordCrypto

/// Why bytes are not one of the sharing formats (docs/02-architecture.md §8.2). Every parser in this module is
/// bounded and exact: a size is checked before anything is copied, a count before anything is allocated, and bytes
/// that do not re-encode to themselves are refused (PRD SEC9).
public enum SharingFormatError: Error, Hashable, Sendable {
    case truncated
    case badMagic
    case unsupportedFormatVersion(UInt8)
    /// Larger than the format allows; refused before parsing.
    case tooLarge(Int)
    case trailingBytes
    /// Members out of order or repeated: one canonical encoding per record.
    case notCanonical
    case unknownRole(UInt8)
    case unknownOperation(UInt8)
    /// No members, or more than `MembershipLimits.maximumMembers`.
    case memberCountOutOfRange(Int)
    /// Above `MembershipLimits.maximumEpoch`, or a field naming an epoch later than the record's own.
    case epochOutOfRange(UInt64)
    /// A field that must have one exact length (a key, a signature, a hash) has another.
    case badFieldLength
    /// A scanned fingerprint code or an object name that is not exactly the canonical spelling.
    case malformedText
    /// A count larger than the bytes that remain could hold; refused before allocating.
    case countTooLarge
}

/// Why a membership record is not accepted into a vault's chain (docs/02-architecture.md §8.3). The verifier fails
/// closed: a record that is refused changes nothing.
public enum MembershipError: Error, Hashable, Sendable {
    /// The record names another vault than the one whose chain it was found in.
    case wrongVault(expected: UUID, actual: UUID)
    /// Epoch 0 must be the owner's `createVault`, and `createVault` appears nowhere else.
    case malformedGenesis
    /// The genesis is not signed by, or does not list, the owner whose fingerprint was verified.
    case ownerMismatch
    case epochNotNext(expected: UInt64, actual: UInt64)
    case previousHashMismatch
    /// The signer is not in the previous member list (never a member, or removed: a stale signature).
    case signerNotAMember(UUID)
    /// The signer is a member but was not an administrator in the previous state.
    case signerNotAdministrator(UUID)
    /// Granting or revoking the administrator role, removing an administrator and deleting the vault are the owner's
    /// alone (§8.3), so the set of accounts that may sign changes only in records the owner signed.
    case ownerOnly
    /// The owner is fixed for the life of the vault: never removed, never given another role, and nobody else is
    /// made owner. This is what makes a lock-out impossible.
    case ownerIsFixed
    case signatureInvalid
    case memberAlreadyPresent(UUID)
    case memberNotFound(UUID)
    case tooManyMembers
    case roleUnchanged
    /// The member list in the record is not the previous list with the record's operation applied.
    case resultingMembersMismatch
    /// A removal or departure that keeps the vault key (principle 5: rotate on every removal).
    case keyNotRotated
    /// A record that changes the vault key without being a removal, a departure or a rotation; or whose key epoch is
    /// not the epoch that introduced its key.
    case unexpectedKeyChange
    /// A key ID the chain has used before, or the zero UUID.
    case keyReused(UUID)
    /// A new member's key bundle is invalid: bad self-signature, low-order point, or naming another account.
    case invalidKeyBundle(UUID)
    /// A departure whose embedded leave request was not signed by the departing member for this stint (§8.6).
    case leaveRequestInvalid
    /// The vault was deleted; nothing may follow.
    case vaultDeleted
    /// Past `MembershipLimits.maximumAdministratorEpoch`: the last epochs are the owner's, so an administrator cannot
    /// use up the chain and leave the owner unable to remove them.
    case epochReservedForOwner
}

/// Why a ledger could not be created or restored.
public enum LedgerError: Error, Hashable, Sendable {
    /// No valid genesis for the vault among the records offered.
    case noGenesis
    /// More candidates than one call accepts; feed the chain in batches, in name order.
    case tooManyCandidates(Int)
    /// The persisted ledger's checkpoint was not signed by this account, or names another vault or owner.
    case checkpointInvalid
    /// The persisted records do not reach the head this device signed for: local state was truncated, replaced or
    /// forked. The device must not continue from it (§8.3).
    case rolledBack(expectedEpoch: UInt64)
}

/// Why a sharing operation refused (docs/02-architecture.md §8).
public enum SharingError: Error, Hashable, Sendable {
    /// The key directory returned a bundle for another account than the one asked for.
    case directoryMismatch(asked: UUID, returned: UUID)
    /// The key directory has no bundle for the account.
    case unknownAccount(UUID)
    /// A bundle that differs from the one pinned for the account when its fingerprint was verified. Reported, never
    /// silently accepted (PRD F4.2, SEC3): the store substituted a key, or the person has a new account key and must
    /// be verified again.
    case keySubstituted(accountID: UUID)
    /// What the person typed or scanned does not match the bundle's fingerprint.
    case fingerprintMismatch
    /// A step of an invitation taken out of order: issuing before the invitee's fingerprint is confirmed, accepting
    /// before the owner's is (PRD F4.2).
    case fingerprintNotVerified
    case invitationAlreadyCompleted
    /// An invitation to a vault ID this device already holds under a different owner.
    case vaultOwnerConflict(vaultID: UUID)
    /// The account accepting is not in the verified member list.
    case notAMember(UUID)
    /// The chain lists a key bundle for this account that is not this account's own: whoever added it was given a
    /// substituted key, so a vault key wrapped to it would be readable by someone else.
    case ownKeySubstituted
    /// No acceptable grant of the vault key was among the objects offered.
    case grantNotFound
    /// A grant found somewhere other than where its vault, key and recipient say it belongs, or under a name that is
    /// not its own.
    case grantMisfiled
    /// The recipient was never a member while the key was current, so nobody is entitled to grant it to them.
    case notEntitledToKey(UUID)
    /// The chain never introduced this key ID.
    case unknownKey(UUID)
    /// The vault key offered is not the vault's current one.
    case notCurrentKey
    /// The operation needs an administrator (or the owner) and this account is not one.
    case notPermitted
    /// The vault's owner cannot leave it; they delete it instead.
    case ownerCannotLeave
    case vaultDeleted
    /// A leave request for another vault, another stint of membership, or not signed by the member.
    case leaveRequestInvalid
    /// What a rotation was planned for is already true of the vault (the member is gone).
    case nothingToDo
}
