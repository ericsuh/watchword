import Foundation
import WatchwordCrypto

/// One link of a vault's membership chain (docs/02-architecture.md §8.2): the operation an administrator performed,
/// the member list and vault key that result, and the hash of the record before it, signed by that administrator
/// under `SignatureDomain.membership`.
///
/// Binary, little-endian, one canonical encoding:
///
/// ```
/// magic "WWMR"  formatVersion u8 = 2
/// vaultID 16  epoch u64  previousHash 32  signer 16
/// operation u8, then its operands:
///   0 createVault   —
///   1 addMember     account 16, role u8
///   2 removeMember  account 16
///   3 memberLeft    account 16, leave request signature 64
///   4 changeRole    account 16, role u8
///   5 rotateKey     —
///   6 deleteVault   —
/// vaultKeyID 16  keyEpoch u64
/// writeCutLength u16 (0...2048), write cut       (empty unless the operation ends an account's permission to write)
/// memberCount u16 (1...64), then per member, strictly ascending by account ID:
///   account 16  role u8  since u64  X25519 key 32  Ed25519 key 32  bundle self-signature 64
/// signature 64                                   (nothing after)
/// ```
///
/// **Everything is in the clear, and signed; nothing is sealed under the vault key.** An invitee must be able to
/// check the whole chain back to the owner *before* holding the key, and a member added after a rotation holds no
/// earlier key at all. What a sync store (A1) learns from it is the vault's shape: pseudonymous account IDs and
/// public keys, roles, and when membership changed, which the transport's own share list (CloudKit participants, a
/// shared folder) already tells it. What it must not be able to do is change any of it, which the signatures and the
/// hash chain prevent. Names never enter a record: the label a person sees for a member is the one they chose when
/// they verified that member's fingerprint, kept in their own verified-contacts store (§8.4).
///
/// A parsed record is only well-formed. Nothing in it is trusted until `MembershipLedger` has verified it against
/// the state before it.
public struct MembershipRecord: Sendable, Hashable {
    static let magic: [UInt8] = Array("WWMR".utf8)
    static let formatVersion: UInt8 = 2
    static let signatureLength = 64
    static let entryLength = 16 + 1 + 8 + 32 + 32 + 64
    static let fixedLength = 4 + 1 + 16 + 8 + 32 + 16 + 1 + 16 + 8 + 2 + 2 + signatureLength
    static let longestOperandLength = 16 + 64
    /// The most a record can encode to; anything longer is refused before it is parsed (SEC9).
    public static let maximumLength =
        fixedLength + longestOperandLength + MembershipLimits.maximumWriteCutLength
        + MembershipLimits.maximumMembers * entryLength

    public enum Operation: Sendable, Hashable {
        /// Epoch 0: the owner creates the vault with themselves as its only member.
        case createVault
        case addMember(UUID, role: MemberRole)
        /// Removal by an administrator. Always names a new vault key (principle 5).
        case removeMember(UUID)
        /// A member's own departure, carried out by an administrator: the signature is the member's, over their
        /// `LeaveRequest` for this stint of membership. Always names a new vault key.
        case memberLeft(UUID, requestSignature: [UInt8])
        case changeRole(UUID, to: MemberRole)
        /// A new vault key with the same members.
        case rotateKey
        /// The owner deletes the vault. Nothing may follow.
        case deleteVault

        var code: UInt8 {
            switch self {
            case .createVault: return 0
            case .addMember: return 1
            case .removeMember: return 2
            case .memberLeft: return 3
            case .changeRole: return 4
            case .rotateKey: return 5
            case .deleteVault: return 6
            }
        }

        /// Whether the operation must introduce a new vault key.
        var rotatesKey: Bool {
            switch self {
            case .removeMember, .memberLeft, .rotateKey: return true
            case .createVault, .addMember, .changeRole, .deleteVault: return false
            }
        }
    }

    /// A member as a record spells it. The key bundle is raw bytes here: validating it costs a signature check, so
    /// the verifier does that only for a member the record adds, and only after the record's own signature has
    /// passed. Carried-over members are compared with the already verified previous state instead.
    public struct Entry: Sendable, Hashable {
        public let accountID: UUID
        public let role: MemberRole
        public let since: UInt64
        public let agreementKey: [UInt8]
        public let signingKey: [UInt8]
        public let selfSignature: [UInt8]

        init(
            accountID: UUID, role: MemberRole, since: UInt64, agreementKey: [UInt8], signingKey: [UInt8],
            selfSignature: [UInt8]
        ) {
            self.accountID = accountID
            self.role = role
            self.since = since
            self.agreementKey = agreementKey
            self.signingKey = signingKey
            self.selfSignature = selfSignature
        }

        init(_ member: Member) {
            self.init(
                accountID: member.accountID, role: member.role, since: member.since,
                agreementKey: member.bundle.agreementKey, signingKey: member.bundle.signingKey,
                selfSignature: member.bundle.selfSignature)
        }

        init(bundle: PublicKeyBundle, role: MemberRole, since: UInt64) {
            self.init(
                accountID: bundle.accountID, role: role, since: since, agreementKey: bundle.agreementKey,
                signingKey: bundle.signingKey, selfSignature: bundle.selfSignature)
        }

        /// Validates the key bundle (`PublicKeyBundle.init`: lengths, low-order X25519, small-order Ed25519,
        /// self-signature).
        func member() throws -> Member {
            guard
                let bundle = try? PublicKeyBundle(
                    accountID: accountID, agreementKey: agreementKey, signingKey: signingKey,
                    selfSignature: selfSignature)
            else { throw MembershipError.invalidKeyBundle(accountID) }
            return Member(accountID: accountID, role: role, since: since, bundle: bundle)
        }
    }

    public let vaultID: UUID
    public let epoch: UInt64
    public let previousHash: MembershipHash
    /// The account that signed the record. Its key comes from the state before this record, never from the record.
    public let signer: UUID
    public let operation: Operation
    public let vaultKeyID: UUID
    public let keyEpoch: UInt64
    /// Which of an account's writes still count, when the operation ends that account's permission to write: a
    /// removal or departure of a member who could write, or a change of role to read-only (§8.7). `WriteCut.nothing`
    /// on every other record. Being signed with the rest, it is the same on every device that accepts the record.
    public let writeCut: WriteCut
    /// The member list after the operation, in ascending order of account ID.
    public let entries: [Entry]
    public let signature: [UInt8]

    init(
        vaultID: UUID, epoch: UInt64, previousHash: MembershipHash, signer: UUID, operation: Operation,
        vaultKeyID: UUID, keyEpoch: UInt64, writeCut: WriteCut, entries: [Entry], signature: [UInt8]
    ) {
        self.vaultID = vaultID
        self.epoch = epoch
        self.previousHash = previousHash
        self.signer = signer
        self.operation = operation
        self.vaultKeyID = vaultKeyID
        self.keyEpoch = keyEpoch
        self.writeCut = writeCut
        self.entries = entries.sorted { $0.accountID.sharingPrecedes($1.accountID) }
        self.signature = signature
    }

    /// Builds and signs a record as `keyset`'s account.
    static func signed(
        vaultID: UUID, epoch: UInt64, previousHash: MembershipHash, operation: Operation, vaultKeyID: UUID,
        keyEpoch: UInt64, writeCut: WriteCut = .nothing, entries: [Entry], by keyset: Keyset
    ) throws -> MembershipRecord {
        let unsigned = MembershipRecord(
            vaultID: vaultID, epoch: epoch, previousHash: previousHash, signer: keyset.accountID,
            operation: operation, vaultKeyID: vaultKeyID, keyEpoch: keyEpoch, writeCut: writeCut, entries: entries,
            signature: [])
        return MembershipRecord(
            vaultID: vaultID, epoch: epoch, previousHash: previousHash, signer: keyset.accountID,
            operation: operation, vaultKeyID: vaultKeyID, keyEpoch: keyEpoch, writeCut: writeCut,
            entries: unsigned.entries, signature: try keyset.sign(unsigned.signedContent, domain: .membership))
    }

    /// Every byte before the signature: what the signature covers and what the record's hash is taken over.
    public var signedContent: [UInt8] {
        var out = MembershipRecord.magic
        out.append(MembershipRecord.formatVersion)
        out += vaultID.sharingBytes + SharingBytes.littleEndian(epoch) + previousHash.bytes + signer.sharingBytes
        out.append(operation.code)
        switch operation {
        case .createVault, .rotateKey, .deleteVault:
            break
        case .addMember(let account, let role), .changeRole(let account, let role):
            out += account.sharingBytes
            out.append(role.rawValue)
        case .removeMember(let account):
            out += account.sharingBytes
        case .memberLeft(let account, let requestSignature):
            out += account.sharingBytes + requestSignature
        }
        out += vaultKeyID.sharingBytes + SharingBytes.littleEndian(keyEpoch)
        out += SharingBytes.littleEndian(UInt16(truncatingIfNeeded: writeCut.bytes.count)) + writeCut.bytes
        out += SharingBytes.littleEndian(UInt16(truncatingIfNeeded: entries.count))
        for entry in entries {
            out += entry.accountID.sharingBytes
            out.append(entry.role.rawValue)
            out += SharingBytes.littleEndian(entry.since)
            out += entry.agreementKey + entry.signingKey + entry.selfSignature
        }
        return out
    }

    public func encoded() -> [UInt8] {
        signedContent + signature
    }

    public var hash: MembershipHash {
        MembershipHash(signedContent: signedContent)
    }

    /// Parses a record from hostile bytes. Size first, then every field with its bound; a declared member count must
    /// account for exactly the bytes that remain, so nothing is allocated on a count's say-so.
    public static func parse(_ bytes: [UInt8]) throws -> MembershipRecord {
        guard bytes.count <= maximumLength else { throw SharingFormatError.tooLarge(bytes.count) }
        var reader = SharingReader(bytes)
        try reader.header(magic: magic, version: formatVersion)
        let vaultID = try reader.uuid()
        let epoch = try reader.uint64()
        guard epoch <= MembershipLimits.maximumEpoch else { throw SharingFormatError.epochOutOfRange(epoch) }
        let previousHash = MembershipHash(unchecked: try reader.read(MembershipHash.byteCount))
        let signer = try reader.uuid()

        let operation: Operation
        let code = try reader.byte()
        switch code {
        case 0: operation = .createVault
        case 1: operation = .addMember(try reader.uuid(), role: try role(reader.byte()))
        case 2: operation = .removeMember(try reader.uuid())
        case 3: operation = .memberLeft(try reader.uuid(), requestSignature: try reader.read(signatureLength))
        case 4: operation = .changeRole(try reader.uuid(), to: try role(reader.byte()))
        case 5: operation = .rotateKey
        case 6: operation = .deleteVault
        default: throw SharingFormatError.unknownOperation(code)
        }

        let vaultKeyID = try reader.uuid()
        let keyEpoch = try reader.uint64()
        guard keyEpoch <= epoch else { throw SharingFormatError.epochOutOfRange(keyEpoch) }
        // The length is bounded before the bytes are read, and `WriteCut.init` holds the same bound.
        let cutLength = Int(try reader.uint16())
        guard cutLength <= MembershipLimits.maximumWriteCutLength else {
            throw SharingFormatError.tooLarge(cutLength)
        }
        let writeCut = try WriteCut(reader.read(cutLength))

        let count = Int(try reader.uint16())
        guard (1...MembershipLimits.maximumMembers).contains(count) else {
            throw SharingFormatError.memberCountOutOfRange(count)
        }
        let expected = count * entryLength + signatureLength
        guard reader.remaining >= expected else { throw SharingFormatError.truncated }
        guard reader.remaining == expected else { throw SharingFormatError.trailingBytes }
        var entries: [Entry] = []
        entries.reserveCapacity(count)
        for _ in 0..<count {
            let accountID = try reader.uuid()
            let entryRole = try role(reader.byte())
            let since = try reader.uint64()
            guard since <= epoch else { throw SharingFormatError.epochOutOfRange(since) }
            let entry = Entry(
                accountID: accountID, role: entryRole, since: since, agreementKey: try reader.read(32),
                signingKey: try reader.read(32), selfSignature: try reader.read(signatureLength))
            if let last = entries.last, !last.accountID.sharingPrecedes(accountID) {
                throw SharingFormatError.notCanonical
            }
            entries.append(entry)
        }
        let signature = try reader.read(signatureLength)
        try reader.finish()
        return MembershipRecord(
            vaultID: vaultID, epoch: epoch, previousHash: previousHash, signer: signer, operation: operation,
            vaultKeyID: vaultKeyID, keyEpoch: keyEpoch, writeCut: writeCut, entries: entries, signature: signature)
    }

    /// A record in a format this version cannot read (a later format version, or this one with an operation it does
    /// not know), as far as the part every format keeps can tell: the vault, the epoch, the record it follows and
    /// who signed it, and the signature over everything before it.
    struct LaterFormat: Sendable {
        let vaultID: UUID
        let epoch: UInt64
        let previousHash: MembershipHash
        let signer: UUID
        let signedContent: [UInt8]
        let signature: [UInt8]
        let encoded: [UInt8]
    }

    /// Reads `bytes` as a record of a later format, which is how a version that has a new operation (ownership
    /// transfer, docs/02-architecture.md §8.9) makes this one stop instead of carrying on without it. Every later
    /// format keeps this version's prefix (`magic`, a version byte, vault ID 16, epoch u64, previous hash 32, signer
    /// 16, then the operation code where the version is this one), ends in a 64-byte signature under
    /// `SignatureDomain.membership` over everything before it, and fits in `maximumLength`. `nil` for anything else,
    /// including every record this version can parse: those go through `parse`, never through here.
    static func laterFormat(_ bytes: [UInt8]) -> LaterFormat? {
        let prefixLength = 4 + 1 + 16 + 8 + MembershipHash.byteCount + 16
        guard bytes.count <= maximumLength, bytes.count >= prefixLength + 1 + signatureLength,
            Array(bytes[0..<4]) == magic
        else { return nil }
        let version = bytes[4]
        guard version > formatVersion || (version == formatVersion && bytes[prefixLength] > Operation.deleteVault.code)
        else { return nil }
        var reader = SharingReader(Array(bytes[5..<prefixLength]))
        guard let vaultID = try? reader.uuid(), let epoch = try? reader.uint64(),
            epoch <= MembershipLimits.maximumEpoch,
            let previousHash = try? reader.read(MembershipHash.byteCount), let signer = try? reader.uuid()
        else { return nil }
        return LaterFormat(
            vaultID: vaultID, epoch: epoch, previousHash: MembershipHash(unchecked: previousHash), signer: signer,
            signedContent: Array(bytes.dropLast(signatureLength)), signature: Array(bytes.suffix(signatureLength)),
            encoded: bytes)
    }

    private static func role(_ raw: UInt8) throws -> MemberRole {
        guard let role = MemberRole(rawValue: raw) else { throw SharingFormatError.unknownRole(raw) }
        return role
    }
}
