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
    /// The most valid records outside its accepted chain that a `MembershipLedger` keeps (records on branches that
    /// lost a fork). Only an account that is or was an administrator can sign one, and a household produces a handful
    /// in years; past this the ledger keeps the best-ranked and says so (`IngestReport.forgotten`).
    public static let maximumRetainedBranchRecords = 1_024
    /// Records of a later format a ledger holds (`MembershipLedger.laterFormatRecords`). One is enough to stop the
    /// chain; each needs the owner's signature, so more than a few is an owner's device misbehaving.
    public static let maximumLaterFormatRecords = 16
    /// The most bytes a `WriteCut` may hold: room for a position and a digest per device of one account.
    public static let maximumWriteCutLength = 2_048
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
    /// A record that removes the member, signed by an account that may still remove them, is on a branch that lost a
    /// fork (`MembershipLedger.owedRemovals`). The removal is about to be planned again; until it is, the member's
    /// writes count as that record left them (`MembershipLedger.OwedRemoval.standing`).
    case removalPending
    /// The vault has gone on in a format this version cannot read (`MembershipLedger.continuesInLaterFormat`): a
    /// later version's operation, signed by the owner. Nothing is written until the app is updated (§8.9).
    case requiresNewerVersion
}

/// Which of an account's writes count once it may no longer write: the commitment an administrator's device puts in
/// the record that removes a member who could write, carries out their departure, or makes them read-only
/// (docs/02-architecture.md §8.7). The record that ends an administrator's role carries one too, a demotion to
/// read-write included: it is then the bound on what only an administrator may write, the vault's description
/// (`AdministratorStanding`), and says nothing about the items of a member who may still write.
///
/// The bytes are the integrator's: this module signs them, bounds them, and gives every device the same ones. What
/// they must do is let any device decide, from the cut and a write alone, whether that write is inside it, with the
/// same answer everywhere and no way for the account to add to the set afterwards. For sync's per-device logs that is,
/// for each of the account's devices, how far into its log the signing device had merged and a digest that binds
/// which objects those were; a bare count is not enough, because a former member with a helpful store can still
/// create an object at a position nobody has filled on some device (§8.8).
///
/// Empty bytes are a cut like any other, and the integrator's reading of them must be "nothing": no write of the
/// account's counts by itself.
public struct WriteCut: Sendable, Hashable {
    /// The cut that holds nothing.
    public static let nothing = WriteCut(unchecked: [])

    public let bytes: [UInt8]

    init(unchecked bytes: [UInt8]) {
        self.bytes = bytes
    }

    /// Refuses more than `MembershipLimits.maximumWriteCutLength` bytes (PRD SEC9).
    public init(_ bytes: [UInt8]) throws {
        guard bytes.count <= MembershipLimits.maximumWriteCutLength else {
            throw SharingFormatError.tooLarge(bytes.count)
        }
        self.bytes = bytes
    }
}

/// Which of an account's writes count in a vault, as one device's ledger knows it: the question to ask before
/// merging anything another account wrote, and again about everything already merged whenever the ledger's head
/// changes (docs/02-architecture.md §8.7, PRD F4.5).
public enum WriteStanding: Sendable, Hashable {
    /// The account may write now. Every write that carries its signature counts.
    case mayWrite
    /// The account could write once and may not now. Exactly the writes inside `cut` count: on every device,
    /// whenever it meets them, and never one more. `author` is the member as the chain listed them when that ended,
    /// for checking the signature on what they wrote. `refusal` says why they may not write now.
    case ended(cut: WriteCut, author: Member, refusal: WriteRefusal)
    /// Nothing the account wrote counts: it never could write here, or the vault was deleted.
    case nothingCounts(WriteRefusal)

    /// Why the account may not write now; `nil` if it may.
    public var refusal: WriteRefusal? {
        switch self {
        case .mayWrite: return nil
        case .ended(_, _, let refusal), .nothingCounts(let refusal): return refusal
        }
    }
}

/// Which of an account's descriptions of the vault count: what only the owner and administrators may write, its name
/// (docs/02-architecture.md §8.7; owner decision of 2026-11-17). Asked, like `WriteStanding`, before merging a
/// description another account wrote and again about the one held whenever the ledger's head changes; and, like it, a
/// rule the clients keep, not cryptography: every member holds the vault key.
public enum AdministratorStanding: Sendable, Hashable {
    /// The owner, or an administrator now. Every description the account signed counts.
    case holdsRole
    /// An administrator once, not now: demoted (to read-write as to read-only), removed or gone. Exactly the
    /// descriptions inside `cut` count, on every device, whenever it meets them. `author` is the member as the chain
    /// listed them when the role ended.
    case ended(cut: WriteCut, author: Member)
    /// Never an administrator here, or the vault was deleted: no description of the account's counts.
    case neverHeld
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
    /// judges the author of what it merges (`MembershipLedger.writeStanding(of:)`), and the transport's own
    /// permission where it has one (CloudKit's read-only participant). The UI must say so.
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
