import Foundation
import WatchwordCrypto

/// What a member of a shared vault may do (docs/02-architecture.md §8.1, PRD F4.1).
///
/// Raw values are part of the record format; never renumber them.
public enum MemberRole: UInt8, Sendable, Hashable, CaseIterable {
    /// The account that created the vault. Exactly one, fixed for the life of the vault: never removed, never given
    /// another role. Does everything an administrator does, and alone grants or revokes the administrator role,
    /// removes an administrator and deletes the vault.
    case owner = 0
    /// May invite and remove members who are not administrators, change them between read-write and read-only, and
    /// rotate the vault key.
    case administrator = 1
    case readWrite = 2
    /// Holds the vault key like every member, so this is a rule the clients keep, not a cryptographic one (PRD F4.5).
    case readOnly = 3

    /// Whether the role may sign membership records.
    public var isAdministrator: Bool {
        self == .owner || self == .administrator
    }

    public var mayWrite: Bool {
        self != .readOnly
    }
}

/// Bounds on everything a membership record can say (PRD SEC9). Two-sided where a floor exists: a vault has at least
/// its owner.
public enum MembershipLimits {
    /// A household, generously.
    public static let maximumMembers = 64
    /// The chain's last epoch. One record per membership change, so a household uses a few dozen in years.
    public static let maximumEpoch: UInt64 = 65_535
    /// The last epoch a record signed by an administrator other than the owner may have. The rest are reserved for
    /// the owner, so an administrator cannot use up the chain and leave the owner unable to remove them.
    public static let maximumAdministratorEpoch: UInt64 = maximumEpoch - 4_096
    /// The most candidate records one `MembershipLedger.ingest` examines.
    public static let maximumCandidates = 4_096
    /// The most `MembershipLedger.join` examines: a whole chain of the greatest length, and as many strays again as
    /// one `ingest` allows.
    public static let maximumJoinCandidates = Int(maximumEpoch) + 1 + maximumCandidates
}

/// One member of a vault, as a verified chain lists it.
public struct Member: Sendable, Hashable {
    public let accountID: UUID
    public let role: MemberRole
    /// The epoch of the record that added the account. A removed member who is invited again starts a new stint with
    /// a new value, which is what a leave request is bound to (§8.6).
    public let since: UInt64
    /// The member's public keys. The owner's is the one whose fingerprint was verified out of band; every other
    /// member's was put in the chain by an administrator who verified it, under a signature that leads back to the
    /// owner (§8.4).
    public let bundle: PublicKeyBundle

    init(accountID: UUID, role: MemberRole, since: UInt64, bundle: PublicKeyBundle) {
        self.accountID = accountID
        self.role = role
        self.since = since
        self.bundle = bundle
    }

    func with(role: MemberRole) -> Member {
        Member(accountID: accountID, role: role, since: since, bundle: bundle)
    }
}

/// Whether an account may write to a vault (docs/02-architecture.md §8.7, PRD F4.5).
public enum WritePermission: Sendable, Hashable {
    case allowed
    case refused(WriteRefusal)

    public var isAllowed: Bool {
        self == .allowed
    }
}

public enum WriteRefusal: Sendable, Hashable {
    /// Never a member, or removed.
    case notAMember
    case readOnly
    case vaultDeleted
    /// The ledger holds no state for the epoch asked about.
    case unknownEpoch
}

/// A vault's membership after one verified record: who the members are, in which roles, and which vault key is
/// current (docs/02-architecture.md §8.1). Only `MembershipLedger` produces one, so a value of this type has been
/// verified back to the owner's pinned key.
public struct MembershipState: Sendable, Hashable {
    public let vaultID: UUID
    public let epoch: UInt64
    /// The hash of the record that produced this state.
    public let hash: MembershipHash
    /// In ascending order of account ID.
    public let members: [Member]
    public let vaultKeyID: UUID
    /// The epoch of the record that introduced `vaultKeyID`.
    public let keyEpoch: UInt64
    /// The owner deleted the vault; nothing follows, and nobody may write.
    public let isDeleted: Bool

    public func member(_ accountID: UUID) -> Member? {
        members.first { $0.accountID == accountID }
    }

    public var owner: Member {
        // A verified state always has exactly one owner (`MembershipRules`).
        members.first { $0.role == .owner }!
    }

    /// Whether `accountID` may write to the vault in this state: the one answer the client enforces on its own
    /// writes and on what it accepts from others (PRD F4.5).
    ///
    /// **Not cryptographic.** A read-only member holds the vault key and a former member holds every key from their
    /// time, so either can produce a ciphertext that decrypts. What stops it counting is that every member's client
    /// asks this question before merging a write, and the transport's own permission where it has one (CloudKit's
    /// read-only participant). The UI must say so.
    public func writePermission(for accountID: UUID) -> WritePermission {
        guard !isDeleted else { return .refused(.vaultDeleted) }
        guard let member = member(accountID) else { return .refused(.notAMember) }
        return member.role.mayWrite ? .allowed : .refused(.readOnly)
    }
}

/// The identity of a membership record: `SHA-256("WW-membership-hash-v1" ‖ signed content)`.
///
/// The signature is left out on purpose. Ed25519 signing may be randomised, and a verifier that tolerated a second
/// encoding of one signature would give one record two identities; a hash over the signed content alone gives every
/// copy of a record the same name and the same place in the chain (review finding S3).
public struct MembershipHash: Sendable, Hashable, Comparable {
    public static let byteCount = 32
    static let domain = Array("WW-membership-hash-v1".utf8)
    /// What a genesis record names as its predecessor.
    public static let none = MembershipHash(unchecked: [UInt8](repeating: 0, count: byteCount))

    public let bytes: [UInt8]

    init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    public init(bytes: [UInt8]) throws {
        guard bytes.count == MembershipHash.byteCount else { throw SharingFormatError.badFieldLength }
        self.bytes = bytes
    }

    init(signedContent: [UInt8]) {
        bytes = SharingBytes.sha256(MembershipHash.domain, signedContent)
    }

    /// Lower-case hex, as it appears in an object name.
    public var hex: String {
        SharingBytes.hex(bytes)
    }

    public static func < (lhs: MembershipHash, rhs: MembershipHash) -> Bool {
        lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
    }
}
