import Foundation
import WatchwordCrypto

/// A member's signed wish to leave a vault (docs/02-architecture.md §8.6, PRD F4.4).
///
/// The member who leaves cannot write the membership record that removes them: it names a new vault key, which they
/// must not hold. So their device publishes this request (and leaves the transport share), and the next unlocked
/// device of an administrator turns it into a rotation. The record that results carries the request's signature, so
/// "left" in the chain always means the member said so.
///
/// ```
/// magic "WWLR"  formatVersion u8 = 1  vaultID 16  account 16  memberSince u64  signature 64
/// ```
///
/// The signature is the member's, under `SignatureDomain.membership` like every signature of the membership protocol;
/// the leading magic keeps a request from ever verifying as a membership record or the reverse.
///
/// **Replay.** The request is bound to the vault and to one stint of membership, through `memberSince`: the epoch of
/// the record that added the member. Replayed into another vault, or after the member has been removed and invited
/// again, it is refused (`SharingError.leaveRequestInvalid`). Within the stint it was made for it stays valid until
/// carried out; a departure cannot be withdrawn.
public struct LeaveRequest: Sendable, Hashable {
    static let magic: [UInt8] = Array("WWLR".utf8)
    static let formatVersion: UInt8 = 1
    public static let encodedLength = 4 + 1 + 16 + 16 + 8 + 64

    public let vaultID: UUID
    public let accountID: UUID
    public let memberSince: UInt64
    public let signature: [UInt8]

    init(vaultID: UUID, accountID: UUID, memberSince: UInt64, signature: [UInt8]) {
        self.vaultID = vaultID
        self.accountID = accountID
        self.memberSince = memberSince
        self.signature = signature
    }

    /// Signs a request to leave `state`'s vault as `keyset`'s account. The owner cannot leave.
    public static func make(leaving state: MembershipState, as keyset: Keyset) throws -> LeaveRequest {
        guard !state.isDeleted else { throw SharingError.vaultDeleted }
        guard let member = state.member(keyset.accountID) else { throw SharingError.notAMember(keyset.accountID) }
        guard member.role != .owner else { throw SharingError.ownerCannotLeave }
        let content = signedContent(vaultID: state.vaultID, accountID: member.accountID, memberSince: member.since)
        return LeaveRequest(
            vaultID: state.vaultID, accountID: member.accountID, memberSince: member.since,
            signature: try keyset.sign(content, domain: .membership))
    }

    static func signedContent(vaultID: UUID, accountID: UUID, memberSince: UInt64) -> [UInt8] {
        magic + [formatVersion] + vaultID.sharingBytes + accountID.sharingBytes
            + SharingBytes.littleEndian(memberSince)
    }

    public func encoded() -> [UInt8] {
        LeaveRequest.signedContent(vaultID: vaultID, accountID: accountID, memberSince: memberSince) + signature
    }

    public static func parse(_ bytes: [UInt8]) throws -> LeaveRequest {
        guard bytes.count <= encodedLength else { throw SharingFormatError.tooLarge(bytes.count) }
        var reader = SharingReader(bytes)
        try reader.header(magic: magic, version: formatVersion)
        let vaultID = try reader.uuid()
        let accountID = try reader.uuid()
        let memberSince = try reader.uint64()
        guard memberSince <= MembershipLimits.maximumEpoch else {
            throw SharingFormatError.epochOutOfRange(memberSince)
        }
        let signature = try reader.read(64)
        try reader.finish()
        return LeaveRequest(vaultID: vaultID, accountID: accountID, memberSince: memberSince, signature: signature)
    }

    /// Checks the request against a verified state: this vault, a current member who is not the owner, this stint,
    /// and the member's own signature under the key the chain lists for them.
    public func validate(against state: MembershipState) throws {
        guard vaultID == state.vaultID, !state.isDeleted, let member = state.member(accountID),
            member.role != .owner, member.since == memberSince
        else { throw SharingError.leaveRequestInvalid }
        guard LeaveRequest.verify(signature, vaultID: vaultID, member: member) else {
            throw SharingError.leaveRequestInvalid
        }
    }

    /// Whether `signature` is `member`'s signature over their request to leave `vaultID` in their current stint.
    static func verify(_ signature: [UInt8], vaultID: UUID, member: Member) -> Bool {
        let content = signedContent(vaultID: vaultID, accountID: member.accountID, memberSince: member.since)
        return
            (try? Signatures.verify(
                signature, for: content, domain: .membership, signingKey: member.bundle.signingKey)) != nil
    }
}
